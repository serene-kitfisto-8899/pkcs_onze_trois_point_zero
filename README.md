# sign-tx

Signs Solana transfer transactions with a key held in a Cosmian KMS, reached
through the Cosmian PKCS#11 module. Supports Ed25519 and NIST P-256 keys
(`--curve`, default `ed25519`). Two modes: a single signature, and a latency
benchmark that measures each signing step separately.

The current Cosmian KMS provider exposes Ed25519 keys created through
`ckms`/KMIP and implements the PKCS#11 v3 one-shot message-signing flow.

## Building

```sh
cargo build --release
```

Use the release build for benchmarking. In a debug build the local signature
verification is roughly 40× slower and dominates the totals.

## Usage

The PIN is read from `COSMIAN_PKCS11_PIN` and is deliberately not a CLI flag:
command-line arguments are world-readable through `/proc` and land in shell
history.

```sh
export COSMIAN_PKCS11_PIN=…

# Single signature, verified locally, never broadcast
sign-tx --module /path/to/libcosmian_pkcs11.so single \
    --to <base58-address> --lamports 1000000

# Machine-readable
sign-tx --module … single --json

# Benchmark, with an SVG chart of the results
sign-tx --module … benchmark -n 1000 --warmup 50 \
    --warmup-time 3 \
    --output samples.csv --chart bench.svg

# NIST P-256 instead of the default Ed25519 (also settable via
# SIGN_TX_CURVE=p256)
sign-tx --module … --curve p256 benchmark -n 1000
```

`--slot` is auto-selected when exactly one token is present. `--key-id`
reuses an existing key instead of creating one.

To build the local KMS, provision an Ed25519 key, run three independent
trials, and regenerate all files under `results/`, use:

```sh
./bench.sh --client-cpus 10 --kms-cpus 8,12,14
```

Choose non-overlapping physical cores appropriate for the host. Omitting the
CPU options leaves both processes unrestricted.

## Design

**Raw PKCS#11 v3.** The module is discovered through `C_GetInterface` and the
returned v3.1 `CK_FUNCTION_LIST_3_0`, rather than the legacy
`C_GetFunctionList` table or a high-level wrapper. Ed25519 uses the v3 message
flow: `C_MessageSignInit` runs once during signer setup, then every measured
iteration calls one `C_SignMessage` into a reused, pre-sized 64-byte buffer.
There is no per-message init or length-query call. P-256 falls back to the
classic `C_SignInit`/`C_Sign` functions because the provider's v3 message API
currently implements the EdDSA flow only; its DER signature buffer is still
pre-sized to avoid the length-query round trip.

**Signing input.** `CKM_EDDSA` (Ed25519, pure mode) signs the message
directly. `CKM_ECDSA` (P-256) per the PKCS#11 spec signs a pre-hashed digest,
not the raw message, so for that curve the message is SHA-256-hashed before
being handed to `C_Sign` (and again during local verification, which must use
the identical digest).

**Key lifecycle.** By default each run generates a fresh key labelled
`bench-<uuid>` via `C_GenerateKeyPair` (`CKM_EC_EDWARDS_KEY_PAIR_GEN` for
Ed25519, `CKM_EC_KEY_PAIR_GEN` for P-256), and destroys it on exit, including
on SIGINT/SIGTERM. A key supplied through `--key-label` belongs to the caller
and is never destroyed. If the module does not implement key generation for
the selected curve the program fails loudly rather than falling back to a
non-PKCS#11 path.

**Public key handling.** `CKA_EC_POINT` encoding varies between
implementations, so raw, DER `OCTET STRING`-wrapped, and full
SubjectPublicKeyInfo forms are all accepted for both curves. A mandatory setup
self-test signs and verifies a known message before any measurement, so a
mis-parsed key fails immediately instead of silently producing invalid
signatures.

**Never broadcast.** Transactions are built and signed offline and verified
locally (`ed25519-dalek` or `p256`, depending on curve). Benchmark mode must
not broadcast — that would measure a validator rather than the KMS, and would
require a fresh blockhash per signature. Solana account addresses are 32-byte
Ed25519 public keys; a P-256 public key (65-byte SEC1 point) doesn't fit that
shape, so `--curve p256` benchmarks produce byte streams of the same shape and
size as a real transaction but are not valid, broadcastable Solana
transactions — irrelevant here since nothing is ever broadcast.

### Benchmark methodology

- **Clock.** `std::time::Instant`, with every sample retained as `u64`
  nanoseconds in a preallocated buffer. Its ~30 ns overhead is negligible
  against a network round trip, and is reported in the run header so the noise
  floor is explicit. An RDTSC-based clock would add precision far below the
  signal.

- **Phases.** Ed25519 reports `C_SignMessage` (the network-bound component) and
  local verification separately, plus the total. `C_MessageSignInit` runs once
  during setup and is not part of a per-message sample. P-256 reports
  `C_SignInit` and `C_Sign`. Serialization is measured once during setup rather
  than per iteration.

- **Payloads.** All messages are pre-generated before the timed loop, so
  serialization never lands inside a measurement. Each varies its recent
  blockhash, making every payload unique — defeating any caching in the module
  or the KMS — while keeping the byte length constant.

- **Warmup.** Runs until both a minimum iteration count and minimum elapsed time
  are satisfied, using the identical measured code path. This absorbs TLS
  handshake, connection setup, KMS-side cache population, and CPU frequency
  ramp. Warmup samples are discarded from the statistics but summarized so the
  cold-start cost remains visible.

- **Repeatability.** `bench.sh` runs three independent trials and selects the
  median trial by total p50 while retaining every trial's CSV. Optional CPU
  affinity keeps the single-threaded client and multithreaded KMS on separate
  physical cores, avoiding scheduler migration that otherwise dominated local
  measurements on the development host.

- **Sequential.** One session, one thread. This measures *latency*. Concurrent
  signing would report percentiles containing queueing delay at the KMS, which
  is a different quantity.

- **Statistics.** min / p50 / p90 / p99 / p999 / max / mean / stddev per phase.
  Percentiles are emphasised over the mean: with network-bound latency a single
  retransmit drags the mean while p50 still describes the typical case.

- **Errors abort the run.** No retries and no skipped iterations — retries would
  mask exactly the tail latency that p99 and p999 exist to expose.

### Charts

`--chart bench.svg` renders a self-contained SVG (no plotting dependency, no
rendering backend) containing:

- **A composition bar** showing what share of total time each phase accounts
  for, computed from cumulative elapsed time rather than a percentile.
- **A histogram per phase**, with p50 and p99 marked. The x-axis is clamped at
  p999 so a single outlier cannot squash the distribution into one bucket; any
  excluded samples are annotated with the true maximum.
- **A timeline per phase**, plotting latency against iteration number. This is
  what exposes drift, periodic spikes, and residual warmup effects — patterns a
  percentile table cannot show. Runs above 1500 samples switch from individual
  points to a min/max envelope to avoid overplotting.

## Testing

```sh
cargo test
```

The payload builder, the `CKA_EC_POINT`/SPKI normalisation (for both curves)
and the statistics are unit-tested without a KMS. For an end-to-end check
against another real PKCS#11 module, SoftHSM2 can also be used:

```sh
export SOFTHSM2_CONF=/path/to/softhsm2.conf
softhsm2-util --init-token --slot 0 --label test --so-pin 1234 --pin 1234
COSMIAN_PKCS11_PIN=1234 sign-tx --module /usr/lib/softhsm/libsofthsm2.so \
    --slot <id> benchmark -n 100
```
