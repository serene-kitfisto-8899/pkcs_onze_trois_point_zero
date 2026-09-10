---
title: "sign-tx Signing Benchmark Report"
subtitle: "Cosmian KMS 5.27.1 · PKCS#11 · NIST P-256"
date: "2026-09-09"
---

# Summary

`sign-tx` was benchmarked against a real Cosmian KMS (v5.27.1) over PKCS#11,
signing Solana-shaped transfer transactions with a NIST P-256 key created via
`ckms`. Ed25519 could not be benchmarked against this KMS because of an
upstream bug: Cosmian's PKCS#11 provider does not expose Ed25519 private keys
created through `ckms`/KMIP (filed as
[Cosmian/kms#1183](https://github.com/Cosmian/kms/issues/1183)). P-256 support
was added to `sign-tx` as a permanent feature (`--curve p256`) to work around
this and obtain real, KMS-backed signing latency numbers.

**Headline result: ~2.8 ms median (p50) end-to-end signing latency,
~355 signatures/sec sequential throughput. The KMS network round trip
(`C_Sign`) accounts for ~90% of total time.**

# Test Configuration

| Parameter          | Value                                              |
|---------------------|-----------------------------------------------------|
| KMS                 | Cosmian KMS 5.27.1 (non-FIPS), PostgreSQL backend   |
| Transport           | Cosmian PKCS#11 provider (`libcosmian_pkcs11.so`)   |
| Curve / mechanism   | NIST P-256, `CKM_ECDSA` (DER-encoded, over SHA-256 digest) |
| Key provisioning    | `ckms ec keys create --curve nist-p256`             |
| Payload             | Solana transfer message, 150 bytes                  |
| Iterations          | 200 (+ 20 warmup)                                   |
| Concurrency         | 1 (sequential — latency, not throughput under load) |
| Environment         | Docker Compose (KMS + PostgreSQL + bench client)    |

# Results

| Phase              | n   | min       | p50       | p90       | p99       | p999      | max       | stddev    |
|--------------------|-----|-----------|-----------|-----------|-----------|-----------|-----------|-----------|
| `C_SignInit`       | 200 | 2.60 µs   | 6.37 µs   | 9.54 µs   | 19.50 µs  | 29.82 µs  | 29.82 µs  | 3.47 µs   |
| `C_Sign` (network) | 200 | 1.204 ms  | 2.480 ms  | 3.236 ms  | 4.060 ms  | 5.632 ms  | 5.632 ms  | 641.27 µs |
| verify (local)     | 200 | 141.15 µs | 279.66 µs | 332.35 µs | 379.22 µs | 397.25 µs | 397.25 µs | 53.88 µs  |
| **total**          | 200 | 1.348 ms  | 2.819 ms  | 3.541 ms  | 4.411 ms  | 5.929 ms  | 5.929 ms  | 660.82 µs |

- **Throughput:** 354.7 sig/s at p50, 360.7 sig/s at mean
- **`C_Sign` share:** 89.8% of total time (the network-bound component)
- **Wall clock:** 554.828 ms for 200 iterations
- **Warmup (discarded):** first = 2.415 ms, p50 = 2.168 ms, last-min = 1.622 ms

# Chart

![Benchmark chart](benchmark.svg)

# Notes and Caveats

- **Why P-256, not Ed25519.** Cosmian's PKCS#11 provider's
  `key_algorithm_from_attributes` function does not recognise the bare
  `Ed25519` `CryptographicAlgorithm` KMIP attribute (only `AES`/`RSA`/`EC`/
  `ECDH` are handled), so Ed25519 private keys created via `ckms` are
  invisible to the provider and unusable for signing. This is tracked
  upstream as
  [Cosmian/kms#1183](https://github.com/Cosmian/kms/issues/1183).
- **Signature format.** `CKM_ECDSA` on this provider returns a DER-encoded,
  variable-length ECDSA signature (up to 72 bytes for P-256) over a
  SHA-256 digest of the message — not a raw fixed-length `r || s` pair, and
  not over the raw message. `sign-tx` presizes its buffer to the maximum DER
  length and hashes client-side before calling `C_Sign`, preserving the
  single-round-trip design.
- **Not a broadcastable Solana transaction.** Solana account addresses are
  32-byte Ed25519 public keys; a P-256 public key is a 65-byte SEC1 point, so
  the benchmark's "from" field is truncated/padded to fit the wire shape. The
  resulting transaction is not valid or broadcastable, which is irrelevant
  here — `sign-tx` never broadcasts, and only the signing payload shape and
  timing matter for this measurement.
- **Latency, not throughput under load.** Signing is sequential, one session,
  one thread — these percentiles describe per-signature latency, not what a
  concurrent/pipelined client would observe under load.

# Raw Data

Raw per-iteration samples: `samples.csv` (200 rows, columns: `iteration`,
`sign_init_ns`, `sign_ns`, `verify_ns`, `total_ns`).
