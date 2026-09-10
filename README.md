# sign-tx

Signs Solana transfer transactions with a key held in a Cosmian KMS, reached
through the Cosmian PKCS#11 module. Supports Ed25519 and NIST P-256 keys
(`--curve`, default `ed25519`). Two modes: a single signature, and a latency
benchmark that measures each signing step separately.

> **Note on Ed25519 against a real KMS:** Cosmian/kms's own PKCS#11 provider
> currently fails to expose Ed25519 keys created via `ckms`/KMIP — see
> [Cosmian/kms#1183](https://github.com/Cosmian/kms/issues/1183). Until that
> is fixed upstream, use `--curve p256` for an end-to-end run against a real
> KMS; `--curve ed25519` still works against PKCS#11 modules that don't have
> this bug (e.g. SoftHSM2, see Testing below).

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
    --output samples.csv --chart bench.svg

# NIST P-256 instead of the default Ed25519 (also settable via
# SIGN_TX_CURVE=p256)
sign-tx --module … --curve p256 benchmark -n 1000
```

`--slot` is auto-selected when exactly one token is present. `--key-label`
reuses an existing key instead of creating one.

## Design

**Raw PKCS#11.** The signing path drives the `CK_FUNCTION_LIST` directly rather
than using the high-level `cryptoki` wrapper. `cryptoki`'s `Session::sign()`
issues `C_SignInit` and then *two* `C_Sign` calls — one to query the signature
length, one to retrieve it — which against a network-backed KMS risks two round
trips per signature, and which collapses the `C_SignInit`/`C_Sign` split we want
to measure. Ed25519 signatures are a fixed 64 bytes, so for that curve the
buffer is presized and the length query skipped entirely: one round trip.
`CKM_ECDSA` (P-256) returns a DER-encoded signature of variable length (up to
72 bytes), so that path presizes to the maximum and still needs only one round
trip — `C_Sign` reports the actual length written, so no second query is ever
issued.

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

- **Phases.** `C_SignInit`, `C_Sign` (the network-bound component), and local
  verification are timed separately, plus the total. Serialization is measured
  once during setup rather than per iteration.

- **Payloads.** All messages are pre-generated before the timed loop, so
  serialization never lands inside a measurement. Each varies its recent
  blockhash, making every payload unique — defeating any caching in the module
  or the KMS — while keeping the byte length constant.

- **Warmup.** Fixed iteration count, running the identical code path, absorbing
  TLS handshake, connection setup, KMS-side cache population and CPU frequency
  ramp. Discarded from the statistics but reported, so the cold-start cost is
  visible rather than hidden.

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
against a real PKCS#11 module, SoftHSM2 works (Ed25519 is unaffected by the
Cosmian KMS bug noted above since SoftHSM2 is a different provider):

```sh
export SOFTHSM2_CONF=/path/to/softhsm2.conf
softhsm2-util --init-token --slot 0 --label test --so-pin 1234 --pin 1234
COSMIAN_PKCS11_PIN=1234 sign-tx --module /usr/lib/softhsm/libsofthsm2.so \
    --slot <id> benchmark -n 100
```
