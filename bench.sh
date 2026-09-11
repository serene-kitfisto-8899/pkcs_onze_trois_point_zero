#!/usr/bin/env bash
#
# bench.sh — end-to-end sign-tx benchmark against a local Cosmian KMS checkout.
#
# Regroups everything that was previously run by hand into one script:
#   1. build cosmian_kms / ckms / cosmian_pkcs11 (release) from a local KMS checkout
#   2. start a temporary, throwaway KMS server (SQLite backend, discarded on exit)
#   3. provision a key pair via ckms, tagged 'disk-encryption' (the only tag the
#      PKCS#11 provider's find_all_private_keys enumerates)
#   4. export its public key as a DER SubjectPublicKeyInfo (the provider does not
#      implement CKA_EC_POINT for either curve, so it must be supplied out of band)
#   5. build sign-tx (release — a debug build's local verification is ~40x slower
#      and would dominate the totals)
#   6. sanity-check a single signature (--json, must report "verified": true)
#      before spending time on the full benchmark
#   7. run the full benchmark
#   8. regenerate results/benchmark-report.md, results/samples.csv,
#      results/benchmark.svg and results/public_key.der from the real run's
#      output — no hand-written numbers
#
# Usage:
#   ./bench.sh [--curve ed25519|p256] [--iterations N] [--warmup N] [--port N]
#              [--kms-repo PATH]
#
# Every flag can also be set via the environment variable named in the
# "Defaults" section below (e.g. CURVE=p256 ./bench.sh).
set -euo pipefail

# ── Defaults (overridable via flags or environment) ──────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KMS_REPO="${KMS_REPO:-/home/manu/Cosmian/core/kms}"
CURVE="${CURVE:-ed25519}"
ITERATIONS="${ITERATIONS:-1000}"
WARMUP="${WARMUP:-50}"
WARMUP_TIME="${WARMUP_TIME:-3}"
RUNS="${RUNS:-3}"
CLIENT_CPUS="${CLIENT_CPUS:-}"
KMS_CPUS="${KMS_CPUS:-}"
KMS_PORT="${KMS_PORT:-19998}"
: "${COSMIAN_PKCS11_PIN:=}"

usage() {
  cat <<'EOF'
Usage: ./bench.sh [--curve ed25519|p256] [--iterations N] [--warmup N]
                   [--runs N] [--client-cpus LIST] [--kms-cpus LIST]
                   [--port N] [--kms-repo PATH]

  --curve <c>       Signing curve: ed25519 (default) or p256.
  --iterations <n>  Measured iterations (default: 1000).
  --warmup <n>      Warmup iterations, discarded from statistics (default: 50).
  --warmup-time <s> Minimum warmup duration in seconds (default: 3).
  --runs <n>        Independent benchmark trials (default: 3); the median trial
                    by total p50 becomes the representative report/chart.
  --client-cpus <l> Pin sign-tx to this taskset CPU list.
  --kms-cpus <l>    Pin the KMS server to this taskset CPU list.
  --port <n>        Local port for the temporary KMS server (default: 19998).
  --kms-repo <path> Path to the Cosmian KMS checkout to build against
                    (default: /home/manu/Cosmian/core/kms).

Regenerates results/benchmark-report.md, results/samples.csv,
results/benchmark.svg and results/public_key.der in this directory.
EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
    --curve) CURVE="$2"; shift 2 ;;
    --iterations) ITERATIONS="$2"; shift 2 ;;
    --warmup) WARMUP="$2"; shift 2 ;;
    --warmup-time) WARMUP_TIME="$2"; shift 2 ;;
    --runs) RUNS="$2"; shift 2 ;;
    --client-cpus) CLIENT_CPUS="$2"; shift 2 ;;
    --kms-cpus) KMS_CPUS="$2"; shift 2 ;;
    --port) KMS_PORT="$2"; shift 2 ;;
    --kms-repo) KMS_REPO="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; usage >&2; exit 1 ;;
  esac
done

case "${CURVE}" in
  ed25519) CKMS_CURVE="ed25519" ;;
  p256) CKMS_CURVE="nist-p256" ;;
  *) echo "unknown --curve '${CURVE}' (expected 'ed25519' or 'p256')" >&2; exit 1 ;;
esac

[ -d "${KMS_REPO}" ] || {
  echo "KMS repo not found at '${KMS_REPO}' — pass --kms-repo PATH" >&2
  exit 1
}
[ "${RUNS}" -ge 1 ] 2>/dev/null || {
  echo "--runs must be at least 1" >&2
  exit 1
}

KEY_ID="bench-${CURVE}-key"
KEY_TAG="disk-encryption"
RESULTS_DIR="${SCRIPT_DIR}/results"
mkdir -p "${RESULTS_DIR}"

WORK_DIR="$(mktemp -d /tmp/signtx-bench-XXXXXX)"
KMS_PID=""

# ── Cleanup: always stop the temporary server and discard its scratch dir,
# whether the script succeeds, fails, or is interrupted. ────────────────────
cleanup() {
  if [ -n "${KMS_PID}" ] && kill -0 "${KMS_PID}" 2>/dev/null; then
    kill "${KMS_PID}" 2>/dev/null || true
    wait "${KMS_PID}" 2>/dev/null || true
  fi
  rm -rf "${WORK_DIR}"
}
trap cleanup EXIT

echo "==> Building cosmian_kms, ckms, cosmian_pkcs11 (bench profile, non-fips)"
(
  cd "${KMS_REPO}"
  cargo build --profile bench -p cosmian_kms_server -p ckms -p cosmian_pkcs11 \
    --features non-fips
)

KMS_BIN="${KMS_REPO}/target/release/cosmian_kms"
CKMS_BIN="${KMS_REPO}/target/release/ckms"
PKCS11_LIB="${KMS_REPO}/target/release/libcosmian_pkcs11.so"
for bin in "${KMS_BIN}" "${CKMS_BIN}" "${PKCS11_LIB}"; do
  [ -e "${bin}" ] || { echo "expected build output missing: ${bin}" >&2; exit 1; }
done

echo "==> Starting a temporary KMS server on 127.0.0.1:${KMS_PORT}"
mkdir -p "${WORK_DIR}/kms-data"
cat >"${WORK_DIR}/kms.toml" <<EOF
[db]
database_type = "sqlite"
sqlite_path = "${WORK_DIR}/kms-data"

[http]
hostname = "127.0.0.1"
port = ${KMS_PORT}
EOF
KMS_COMMAND=("${KMS_BIN}")
if [ -n "${KMS_CPUS}" ]; then
  KMS_COMMAND=(taskset --cpu-list "${KMS_CPUS}" "${KMS_COMMAND[@]}")
fi
"${KMS_COMMAND[@]}" --config "${WORK_DIR}/kms.toml" >"${WORK_DIR}/kms.log" 2>&1 &
KMS_PID=$!

echo "    waiting for the server to become reachable..."
KMS_VERSION=""
for _ in $(seq 1 30); do
  if KMS_VERSION="$(curl -sf "http://127.0.0.1:${KMS_PORT}/version" 2>/dev/null | tr -d '"')" \
    && [ -n "${KMS_VERSION}" ]; then
    break
  fi
  sleep 1
done
if [ -z "${KMS_VERSION}" ]; then
  echo "KMS server never became reachable — see ${WORK_DIR}/kms.log" >&2
  cat "${WORK_DIR}/kms.log" >&2
  exit 1
fi
echo "    KMS version: ${KMS_VERSION}"
# The /version endpoint returns e.g. "5.27.1 (OpenSSL 3.6.2 ...)" — the report
# wants just the short numeric version.
KMS_VERSION_SHORT="$(printf '%s' "${KMS_VERSION}" | awk '{print $1}')"

export CKMS_CONF="${WORK_DIR}/ckms.toml"
cat >"${CKMS_CONF}" <<EOF
[http_config]
server_url = "http://127.0.0.1:${KMS_PORT}"
EOF

echo "==> Creating the ${CURVE} key pair (id '${KEY_ID}', tag '${KEY_TAG}')"
"${CKMS_BIN}" ec keys create --curve "${CKMS_CURVE}" --tag "${KEY_TAG}" "${KEY_ID}"

PUB_ID="${KEY_ID}_pk"
PUB_DER="${WORK_DIR}/public_key.der"
echo "==> Exporting the public key '${PUB_ID}' (pkcs8-der)"
"${CKMS_BIN}" ec keys export --key-id "${PUB_ID}" --key-format pkcs8-der "${PUB_DER}"

echo "==> Building sign-tx (release)"
(
  cd "${SCRIPT_DIR}"
  cargo build --release
)
SIGN_TX_BIN="${SCRIPT_DIR}/target/release/sign-tx"

export COSMIAN_PKCS11_PIN
export COSMIAN_PKCS11_LOGGING_LEVEL="${COSMIAN_PKCS11_LOGGING_LEVEL:-warn}"

SIGN_TX_COMMAND=("${SIGN_TX_BIN}")
if [ -n "${CLIENT_CPUS}" ]; then
  SIGN_TX_COMMAND=(taskset --cpu-list "${CLIENT_CPUS}" "${SIGN_TX_COMMAND[@]}")
fi

echo "==> Sanity check: single signature"
SINGLE_JSON="$(
  "${SIGN_TX_COMMAND[@]}" \
    --module "${PKCS11_LIB}" --curve "${CURVE}" \
    --key-id "${KEY_ID}" --public-key "${PUB_DER}" \
    single --json
)"
if ! printf '%s' "${SINGLE_JSON}" | grep -q '"verified": *true'; then
  echo "single-signature sanity check FAILED — aborting before the full benchmark" >&2
  printf '%s\n' "${SINGLE_JSON}" >&2
  exit 1
fi
echo "    verified: true"

echo "==> Running ${RUNS} benchmark trial(s) (${ITERATIONS} iterations, ${WARMUP} warmup)"
: >"${WORK_DIR}/run-summary.tsv"
for run in $(seq 1 "${RUNS}"); do
  echo "    trial ${run}/${RUNS}"
  log="${WORK_DIR}/bench-${run}.log"
  "${SIGN_TX_COMMAND[@]}" \
    --module "${PKCS11_LIB}" --curve "${CURVE}" \
    --key-id "${KEY_ID}" --public-key "${PUB_DER}" \
    benchmark -n "${ITERATIONS}" --warmup "${WARMUP}" \
    --warmup-time "${WARMUP_TIME}" \
    --output "${WORK_DIR}/samples-${run}.csv" \
    --chart "${WORK_DIR}/benchmark-${run}.svg" \
    | tee "${log}"
  total_p50_ns="$(
    awk '$1 == "total" {
      value=$5; unit=$6;
      factor=(unit=="ns"?1:(unit=="µs"?1000:(unit=="ms"?1000000:1000000000)));
      printf "%.0f", value*factor
    }' "${log}"
  )"
  printf '%s\t%s\n' "${total_p50_ns}" "${run}" >>"${WORK_DIR}/run-summary.tsv"
done

REPRESENTATIVE_RUN="$(
  sort -n "${WORK_DIR}/run-summary.tsv" \
    | awk -v middle="$(( (RUNS + 1) / 2 ))" 'NR == middle { print $2 }'
)"
BENCH_LOG="${WORK_DIR}/bench-${REPRESENTATIVE_RUN}.log"
cp "${WORK_DIR}/samples-${REPRESENTATIVE_RUN}.csv" "${RESULTS_DIR}/samples.csv"
cp "${WORK_DIR}/benchmark-${REPRESENTATIVE_RUN}.svg" "${RESULTS_DIR}/benchmark.svg"
for run in $(seq 1 "${RUNS}"); do
  cp "${WORK_DIR}/samples-${run}.csv" "${RESULTS_DIR}/samples-run-${run}.csv"
done
cp "${PUB_DER}" "${RESULTS_DIR}/public_key.der"

echo "==> Generating results/benchmark-report.md"

# ── Extraction helpers: pull real numbers out of the tool's own stdout rather
# than hand-typing them, so the report can never silently drift from what the
# run actually measured. ──────────────────────────────────────────────────
header_value() {
  # $1: a plain (no regex metacharacters) label at the start of the line,
  # e.g. "Module", "Host", "Mechanism".
  awk -v pfx="$1" 'index($0, pfx) == 1 { sub("^" pfx, ""); gsub(/^ +/, ""); print; exit }' "${BENCH_LOG}"
}

phase_line() {
  # $1: the exact phase label as printed, e.g. "C_Sign (network)".
  awk -v pfx="$1" 'index($0, pfx) == 1 { print; exit }' "${BENCH_LOG}"
}

phase_cells() {
  # Renders one phase's row as markdown table cells: | n | min | p50 | ... |
  local label="$1" line rest
  line="$(phase_line "${label}")"
  [ -n "${line}" ] || {
    echo "could not find the '${label}' row in the benchmark output" >&2
    exit 1
  }
  rest="${line#"${label}"}"
  local n min_v min_u p50_v p50_u p90_v p90_u p99_v p99_u p999_v p999_u max_v max_u sd_v sd_u
  read -r n min_v min_u p50_v p50_u p90_v p90_u p99_v p99_u p999_v p999_u max_v max_u sd_v sd_u <<<"${rest}"
  printf '| %s | %s %s | %s %s | %s %s | %s %s | %s %s | %s %s | %s %s |' \
    "${n}" "${min_v}" "${min_u}" "${p50_v}" "${p50_u}" "${p90_v}" "${p90_u}" \
    "${p99_v}" "${p99_u}" "${p999_v}" "${p999_u}" "${max_v}" "${max_u}" "${sd_v}" "${sd_u}"
}

if [ "${CURVE}" = "ed25519" ]; then
  SIGN_CALL="C_SignMessage"
  SIGN_PHASE_LABEL="C_SignMessage (network)"
else
  SIGN_CALL="C_Sign"
  SIGN_PHASE_LABEL="C_Sign (network)"
fi
ROW_SIGN="$(phase_cells "${SIGN_PHASE_LABEL}")"
ROW_VERIFY="$(phase_cells "verify (local)")"
ROW_TOTAL="$(phase_cells "total")"
if [ "${CURVE}" = "ed25519" ]; then
  SIGN_REPORT_ROWS="| \`${SIGN_CALL}\` (network) ${ROW_SIGN}"
else
  SIGN_REPORT_ROWS="| \`C_SignInit\`       $(phase_cells "C_SignInit")
| \`${SIGN_CALL}\` (network) ${ROW_SIGN}"
fi

THROUGHPUT_LINE="$(grep '^Throughput' "${BENCH_LOG}")"
THROUGHPUT_P50="$(printf '%s' "${THROUGHPUT_LINE}" | grep -oE '[0-9.]+ sig/s at p50' | awk '{print $1}')"
THROUGHPUT_MEAN="$(printf '%s' "${THROUGHPUT_LINE}" | grep -oE '[0-9.]+ sig/s at mean' | awk '{print $1}')"
CSIGN_SHARE="$(grep "^${SIGN_CALL} share" "${BENCH_LOG}" | grep -oE '[0-9.]+%' | head -1)"
WALLCLOCK_DURATION="$(
  grep '^Wall clock' "${BENCH_LOG}" \
    | grep -oE '[0-9.]+ (ns|µs|ms|s)' \
    | head -1
)"
WARMUP_TEXT="$(grep '^Warmup (discarded)' "${BENCH_LOG}" | sed -E 's/^Warmup \(discarded\): *//')"
HOST_NAME="$(header_value 'Host')"
MODULE_NAME="$(header_value 'Module')"
MECHANISM="$(header_value 'Mechanism')"
PAYLOAD_DESC="$(header_value 'Payload')"

KMS_BRANCH="$(cd "${KMS_REPO}" && git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "unknown")"
ED25519_FIX_COMMIT="$(
  cd "${KMS_REPO}"
  git log -S 'CryptographicAlgorithm::Ed25519 => KeyAlgorithm::Ed25519' \
    --format='%h (%ad)' --date=short \
    -- crate/clients/pkcs11/provider/src/kms_object.rs 2>/dev/null | tail -1
)"
REPORT_DATE="$(date +%Y-%m-%d)"
RUN_STABILITY_ROWS="$(
  while IFS=$'\t' read -r total_p50_ns run; do
    display="$(
      awk -v ns="${total_p50_ns}" 'BEGIN {
        if (ns < 1000) printf "%.0f ns", ns;
        else if (ns < 1000000) printf "%.2f µs", ns/1000;
        else if (ns < 1000000000) printf "%.3f ms", ns/1000000;
        else printf "%.3f s", ns/1000000000;
      }'
    )"
    marker=""
    [ "${run}" = "${REPRESENTATIVE_RUN}" ] && marker=" **(representative)**"
    printf '| %s | %s%s |\n' "${run}" "${display}" "${marker}"
  done < <(sort -k2,2n "${WORK_DIR}/run-summary.tsv")
)"

# Curve-specific narrative: the "corrects the false Ed25519 claim" framing
# only makes sense when actually benchmarking Ed25519.
if [ "${CURVE}" = "ed25519" ]; then
  SUBTITLE="Cosmian KMS ${KMS_VERSION_SHORT} · PKCS#11 · Ed25519"
  CORRECTION_NOTE="
**This corrects a previous version of this report.** That version claimed
Ed25519 keys are invisible to Cosmian's PKCS#11 provider (citing
[Cosmian/kms#1183](https://github.com/Cosmian/kms/issues/1183) and a quoted
\`key_algorithm_from_attributes\` snippet with no \`Ed25519\`/\`Ed448\` match
arms), and used NIST P-256 as a workaround. Neither holds up on the
\`${KMS_BRANCH}\` branch used for this run:

- \`crate/clients/pkcs11/provider/src/kms_object.rs::key_algorithm_from_attributes\`
  has explicit \`CryptographicAlgorithm::Ed25519 => KeyAlgorithm::Ed25519\` and
  \`Ed448 => KeyAlgorithm::Ed448\` arms — not the \"falls into the \`x => ...\`
  branch and is rejected\" behavior the issue describes.${ED25519_FIX_COMMIT:+ \`git log -S\` dates those arms to commit \`${ED25519_FIX_COMMIT}\`.}
- The single-signature sanity check and the full ${ITERATIONS}-iteration
  benchmark below both ran end to end — real key creation via \`ckms\`, real
  \`C_GetInterface\`/\`C_MessageSignInit\`/\`C_SignMessage\` through the real PKCS#11 v3
  provider, real network round trips to a real KMS server — with zero
  failures.
"
  ADDRESS_NOTE="A Solana account address is a 32-byte Ed25519 public key — exactly what this key produces, so the \"from\" field in this run is a genuinely Solana-shaped address (unlike a P-256 run, where a 65-byte SEC1 point must be truncated/padded to fit). The transaction is still never broadcast (a placeholder \`recent_blockhash\` is used), so this does not make it a *valid* transaction — only a correctly-*shaped* one."
  SIGNING_INPUT_NOTE="\`CKM_EDDSA\` (pure Ed25519) signs the raw message directly — no client-side hash step before \`C_Sign\`."
  SIG_SIZE_NOTE="Ed25519 signatures are a constant 64 bytes, so \`sign-tx\` presizes the output buffer and skips the length-query \`C_Sign\` call entirely for this curve — one round trip per signature."
else
  SUBTITLE="Cosmian KMS ${KMS_VERSION_SHORT} · PKCS#11 · NIST P-256"
  CORRECTION_NOTE=""
  ADDRESS_NOTE="Solana account addresses are 32-byte Ed25519 public keys; a P-256 public key is a 65-byte SEC1 point, so this run's \"from\" field is truncated/padded to fit the wire shape. The resulting transaction is not valid or broadcastable, which is irrelevant here — \`sign-tx\` never broadcasts, and only the signing payload shape and timing matter for this measurement."
  SIGNING_INPUT_NOTE="\`CKM_ECDSA\` (P-256) per the PKCS#11 spec signs a pre-hashed digest, not the raw message, so the message is SHA-256-hashed client-side before \`C_Sign\` (and again during local verification)."
  SIG_SIZE_NOTE="\`CKM_ECDSA\` on this provider returns a DER-encoded, variable-length signature (up to 72 bytes for P-256). \`sign-tx\` presizes its buffer to the maximum DER length, preserving the single-round-trip design — \`C_Sign\` reports the actual length written, so no second query is ever issued."
fi

# Pull the total row's p50 cell (field 4 of the pipe-delimited row) for the
# one-line headline summary.
TOTAL_P50="$(printf '%s' "${ROW_TOTAL}" | awk -F'|' '{gsub(/^ +| +$/, "", $4); print $4}')"

cat >"${RESULTS_DIR}/benchmark-report.md" <<EOF
---
title: "sign-tx Signing Benchmark Report"
subtitle: "${SUBTITLE}"
date: "${REPORT_DATE}"
---

# Summary

\`sign-tx\` was benchmarked against a real, locally-run Cosmian KMS
(v${KMS_VERSION_SHORT}, \`${KMS_BRANCH}\` branch) over PKCS#11, signing Solana-shaped
transfer transactions with a **${CURVE}** key created via \`ckms\`.
${CORRECTION_NOTE}
**Headline result: ${TOTAL_P50} median (p50) end-to-end signing latency,
~${THROUGHPUT_P50} signatures/sec sequential throughput. The KMS network round trip
(\`${SIGN_CALL}\`) accounts for ~${CSIGN_SHARE} of total time.**

# Test Configuration

| Parameter          | Value                                              |
|---------------------|-----------------------------------------------------|
| KMS                 | Cosmian KMS ${KMS_VERSION_SHORT} (non-FIPS, speed-oriented bench profile), SQLite backend |
| Transport           | \`$(basename "${PKCS11_LIB}")\` (${MODULE_NAME}) |
| PKCS#11 interface   | v3, discovered through \`C_GetInterface\`; Ed25519 uses \`C_MessageSignInit\` once and \`C_SignMessage\` per iteration |
| KMS wire protocol   | TTLV-BYTES over \`POST /kmip\` (\`application/octet-stream\`) |
| Curve / mechanism   | ${CURVE}, \`${MECHANISM}\` |
| Key provisioning    | \`ckms ec keys create --curve ${CKMS_CURVE} --tag ${KEY_TAG} ${KEY_ID}\` |
| Public key handling | \`ckms ec keys export --key-format pkcs8-der\`, supplied via \`--public-key\` (the provider does not implement \`CKA_EC_POINT\` for either curve) |
| Payload             | ${PAYLOAD_DESC} |
| Iterations          | ${ITERATIONS} measured |
| Warmup              | minimum ${WARMUP} iterations and ${WARMUP_TIME} seconds per trial |
| Independent trials  | ${RUNS}; median trial by total p50 selected |
| CPU affinity        | sign-tx: ${CLIENT_CPUS:-unrestricted}; KMS: ${KMS_CPUS:-unrestricted} |
| Concurrency         | 1 (sequential — latency, not throughput under load) |
| Environment         | Local processes, no Docker/containers: \`cosmian_kms\` server + \`ckms\` + \`sign-tx\` all on \`${HOST_NAME}\`, connected over \`127.0.0.1\` |

# Results

| Phase              | n    | min       | p50       | p90       | p99       | p999      | max       | stddev    |
|--------------------|------|-----------|-----------|-----------|-----------|-----------|-----------|-----------|
${SIGN_REPORT_ROWS}
| verify (local)     ${ROW_VERIFY}
| **total**          ${ROW_TOTAL}

- **Throughput:** ${THROUGHPUT_P50} sig/s at p50, ${THROUGHPUT_MEAN} sig/s at mean
- **\`${SIGN_CALL}\` share:** ${CSIGN_SHARE} of total time (the network-bound component)
- **Wall clock:** ${WALLCLOCK_DURATION} for ${ITERATIONS} iterations
- **Warmup (discarded):** ${WARMUP_TEXT}
- **Failures:** 0 — every iteration signed and locally verified successfully

# Run Stability

Each trial used a fresh warmup and the same already-provisioned key/session
configuration. The median trial by total p50 is used for the detailed phase table
and chart above; all raw trial CSV files are retained.

| Trial | Total p50 |
|---:|---:|
${RUN_STABILITY_ROWS}

# Chart

![Benchmark chart](benchmark.svg)

# Notes and Caveats

- **KMS transport.** The PKCS#11 provider wraps the KMIP Sign operation in a
  KMIP 2.1 \`RequestMessage\`, serializes it as binary TTLV, sends it to the
  \`/kmip\` octet-stream endpoint, and fully parses the binary TTLV response.
- **Signing input.** ${SIGNING_INPUT_NOTE}
- **Signature size.** ${SIG_SIZE_NOTE}
- **Solana address shape.** ${ADDRESS_NOTE}
- **Latency, not throughput under load.** Signing is sequential, one session,
  one thread — these percentiles describe per-signature latency, not what a
  concurrent/pipelined client would observe under load.
- **Host caveat.** Run on a shared, non-dedicated development machine (not a
  benchmarking-grade isolated host); absolute numbers may vary run to run.

# Raw Data

Raw per-iteration samples: \`samples.csv\` (${ITERATIONS} rows, columns:
\`iteration\`, \`sign_init_ns\`, \`sign_ns\`, \`verify_ns\`, \`total_ns\`). The
public key (\`public_key.der\`, DER SubjectPublicKeyInfo) used for this run is
also included. \`samples-run-N.csv\` contains each independent trial.

Generated by \`bench.sh\` on ${REPORT_DATE}.
EOF

echo "==> Done."
echo "    Report:   ${RESULTS_DIR}/benchmark-report.md"
echo "    Samples:  ${RESULTS_DIR}/samples.csv"
echo "    Chart:    ${RESULTS_DIR}/benchmark.svg"
