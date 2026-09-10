//! The two execution modes: a single signature, and the benchmark.

use crate::pkcs11::{Curve, Module, SIGNATURE_LEN};
use crate::signer::{Signer, SignerConfig};
use crate::solana::{Transfer, encode_pubkey};
use crate::stats::{Phase, Samples, format_nanos, measure_clock_overhead};
use anyhow::{Context, Result, bail};
use std::io::Write;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

/// Solana account addresses are 32 bytes (Ed25519 public keys). A P-256
/// public key does not fit that shape, so when benchmarking with `--curve
/// p256` the "from" field is the first 32 bytes of the uncompressed SEC1
/// point. The resulting transaction is not a valid, broadcastable Solana
/// transaction in that case — this tool never broadcasts, so only the
/// signing payload shape and size matter for the measurement.
fn account_bytes(public_key: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let n = public_key.len().min(32);
    out[..n].copy_from_slice(&public_key[..n]);
    out
}

pub struct SingleOptions {
    pub to: [u8; 32],
    pub lamports: u64,
    pub blockhash: [u8; 32],
    pub json: bool,
}

pub struct BenchOptions {
    pub iterations: usize,
    pub warmup: usize,
    pub lamports: u64,
    pub to: [u8; 32],
    pub output: Option<std::path::PathBuf>,
    pub chart: Option<std::path::PathBuf>,
}

/// One timed iteration, in nanoseconds per phase.
struct Iteration {
    sign_init: u64,
    sign: u64,
    verify: u64,
    total: u64,
    /// Actual bytes written by `C_Sign`: always `SIGNATURE_LEN` for
    /// Ed25519, variable (DER-encoded) for P-256.
    signature_len: usize,
}

/// The measured region. Identical in warmup and measurement so warmup
/// exercises exactly the code path it is warming.
#[inline]
fn sign_once(signer: &Signer<'_>, message: &[u8], signature: &mut [u8]) -> Result<Iteration> {
    let handle = signer.private_handle();
    let session = signer.session();
    let curve = signer.curve();

    // Hashing (P-256 only; Ed25519 signs the message directly) happens
    // before the clock starts, matching how message serialization is kept
    // out of the timed region elsewhere in this module.
    let input = curve.signing_input(message);

    let start = Instant::now();

    session.sign_init(handle, curve)?;
    let after_init = Instant::now();

    let len = session.sign_into(&input, signature)?;
    let after_sign = Instant::now();

    if curve == Curve::Ed25519 && len != SIGNATURE_LEN {
        bail!("expected a {SIGNATURE_LEN}-byte signature, module returned {len} bytes");
    }
    signer.verify(message, &signature[..len])?;
    let after_verify = Instant::now();

    // Consume the signature so the optimiser cannot elide the work.
    std::hint::black_box(&signature[0]);

    Ok(Iteration {
        sign_init: after_init.duration_since(start).as_nanos() as u64,
        sign: after_sign.duration_since(after_init).as_nanos() as u64,
        verify: after_verify.duration_since(after_sign).as_nanos() as u64,
        total: after_verify.duration_since(start).as_nanos() as u64,
        signature_len: len,
    })
}

pub fn run_single(
    module: &Module,
    signer_config: &SignerConfig,
    options: &SingleOptions,
) -> Result<()> {
    let signer = Signer::connect(module, signer_config)?;
    let from = account_bytes(&signer.public_key_bytes());

    let transfer = Transfer {
        from,
        to: options.to,
        lamports: options.lamports,
        recent_blockhash: options.blockhash,
    };
    let message = transfer.message_bytes();

    let mut signature = vec![0u8; signer.curve().max_signature_len()];
    let timing = sign_once(&signer, &message, &mut signature)?;
    let signature = &signature[..timing.signature_len];
    let wire = transfer.to_wire(signature);

    if options.json {
        let report = serde_json::json!({
            "key_id": signer.label(),
            "from": encode_pubkey(&from),
            "to": encode_pubkey(&options.to),
            "lamports": options.lamports,
            "recent_blockhash": encode_pubkey(&options.blockhash),
            "message_len": message.len(),
            "message_base58": bs58::encode(&message).into_string(),
            "signature_base58": bs58::encode(signature).into_string(),
            "transaction_base58": bs58::encode(&wire).into_string(),
            "verified": true,
            "broadcast": false,
            "timings_ns": {
                "sign_init": timing.sign_init,
                "sign": timing.sign,
                "verify": timing.verify,
                "total": timing.total,
            }
        });
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("Key id          {}", signer.label());
        println!("From            {}", encode_pubkey(&from));
        println!("To              {}", encode_pubkey(&options.to));
        println!("Lamports        {}", options.lamports);
        println!("Blockhash       {}", encode_pubkey(&options.blockhash));
        println!("Message         {} bytes", message.len());
        println!("Signature       {}", bs58::encode(signature).into_string());
        println!("Verified        yes (locally, {})", verifier_name(signer.curve()));
        println!("Broadcast       no");
        println!();
        println!(
            "  {:<18} {}",
            "C_SignInit",
            format_nanos(timing.sign_init as f64)
        );
        println!(
            "  {:<18} {}",
            "C_Sign (network)",
            format_nanos(timing.sign as f64)
        );
        println!(
            "  {:<18} {}",
            "verify (local)",
            format_nanos(timing.verify as f64)
        );
        println!("  {:<18} {}", "total", format_nanos(timing.total as f64));
        println!();
        println!("Transaction (base58, not broadcast):");
        println!("{}", bs58::encode(&wire).into_string());
    }

    Ok(())
}

fn verifier_name(curve: Curve) -> &'static str {
    match curve {
        Curve::Ed25519 => "ed25519-dalek",
        Curve::P256 => "p256 (ecdsa)",
    }
}

pub fn run_benchmark(
    module: &Module,
    signer_config: &SignerConfig,
    options: &BenchOptions,
) -> Result<()> {
    if options.iterations == 0 {
        bail!("--iterations must be at least 1");
    }

    let clock_overhead = measure_clock_overhead(10_000);
    let signer = Signer::connect(module, signer_config)?;
    let from = account_bytes(&signer.public_key_bytes());

    // Pre-generate every message so serialization never lands in the timed
    // loop. Varying only the blockhash keeps each payload unique — defeating
    // any caching in the module or KMS — at a constant byte length.
    let total_messages = options.warmup + options.iterations;
    let serialize_start = Instant::now();
    let messages: Vec<Vec<u8>> = (0..total_messages)
        .map(|i| {
            let mut blockhash = [0u8; 32];
            blockhash[..8].copy_from_slice(&(i as u64).to_le_bytes());
            blockhash[8..16].copy_from_slice(&uuid::Uuid::new_v4().as_u128().to_le_bytes()[..8]);
            Transfer {
                from,
                to: options.to,
                lamports: options.lamports,
                recent_blockhash: blockhash,
            }
            .message_bytes()
        })
        .collect();
    let serialize_total = serialize_start.elapsed();

    let payload_len = messages[0].len();
    if messages.iter().any(|m| m.len() != payload_len) {
        bail!("internal error: pre-generated payloads differ in length");
    }

    print_header(
        module,
        &signer,
        options,
        payload_len,
        clock_overhead,
        serialize_total.as_nanos() as f64 / total_messages as f64,
    )?;

    let interrupted = Arc::new(AtomicBool::new(false));
    signal_hook::flag::register(signal_hook::consts::SIGINT, Arc::clone(&interrupted))
        .context("failed to install the SIGINT handler")?;
    signal_hook::flag::register(signal_hook::consts::SIGTERM, Arc::clone(&interrupted))
        .context("failed to install the SIGTERM handler")?;

    let mut signature = vec![0u8; signer.curve().max_signature_len()];

    // Warmup absorbs TLS handshake, connection setup, KMS-side cache
    // population and CPU frequency ramp. Discarded from the statistics but
    // reported, so the cold-start cost is visible rather than hidden.
    let mut warmup_samples = Samples::with_capacity(options.warmup);
    if options.warmup > 0 {
        print!("Warming up ({} iterations)... ", options.warmup);
        std::io::stdout().flush().ok();
        for message in messages.iter().take(options.warmup) {
            if interrupted.load(Ordering::Relaxed) {
                bail!("interrupted during warmup");
            }
            let timing =
                sign_once(&signer, message, &mut signature).context("warmup iteration failed")?;
            warmup_samples.push(timing.total);
        }
        println!("done");
    }

    let mut phases: Vec<(Phase, Samples)> = Phase::ALL
        .iter()
        .map(|phase| (*phase, Samples::with_capacity(options.iterations)))
        .collect();

    print!("Measuring ({} iterations)... ", options.iterations);
    std::io::stdout().flush().ok();

    let run_start = Instant::now();
    let mut completed = 0usize;
    for message in messages.iter().skip(options.warmup) {
        if interrupted.load(Ordering::Relaxed) {
            println!();
            eprintln!("interrupted after {completed} iterations");
            break;
        }
        // Abort on the first failure: a run with retried or skipped
        // iterations is a corrupted measurement, and retries would mask the
        // very tail latency p99/p999 exists to expose.
        let timing = sign_once(&signer, message, &mut signature).with_context(|| {
            format!(
                "signing failed at iteration {completed} of {}",
                options.iterations
            )
        })?;
        for (phase, samples) in phases.iter_mut() {
            samples.push(match phase {
                Phase::SignInit => timing.sign_init,
                Phase::Sign => timing.sign,
                Phase::Verify => timing.verify,
                Phase::Total => timing.total,
            });
        }
        completed += 1;
    }
    let wall = run_start.elapsed();
    if completed == options.iterations {
        println!("done");
    }

    if completed == 0 {
        bail!("no iterations completed");
    }

    println!();
    report(&phases, &warmup_samples, completed, wall);

    if let Some(path) = &options.output {
        write_samples(path, &phases)?;
        println!("\nRaw samples written to {}", path.display());
    }

    if let Some(path) = &options.chart {
        let title = format!(
            "{} — {completed} signatures via PKCS#11",
            module
                .info()
                .map(|i| i.library_description)
                .unwrap_or_else(|_| "PKCS#11 module".into())
        );
        let svg = crate::chart::render(&phases, &title);
        std::fs::write(path, svg).with_context(|| format!("failed to write {}", path.display()))?;
        println!("Chart written to {}", path.display());
    }

    Ok(())
}

fn print_header(
    module: &Module,
    signer: &Signer<'_>,
    options: &BenchOptions,
    payload_len: usize,
    clock_overhead: f64,
    serialize_per_message: f64,
) -> Result<()> {
    let info = module.info()?;
    println!("=== sign-tx benchmark ===");
    println!(
        "Host              {}",
        hostname::get()
            .map(|h| h.to_string_lossy().into_owned())
            .unwrap_or_else(|_| "unknown".into())
    );
    println!(
        "Module            {} {}.{} (Cryptoki {}.{})",
        info.library_description,
        info.library_version.0,
        info.library_version.1,
        info.cryptoki_version.0,
        info.cryptoki_version.1
    );
    println!("Manufacturer      {}", info.manufacturer);
    println!("Key id            {}", signer.label());
    println!("Mechanism         {}", signer.curve().mechanism_name());
    println!("Payload           Solana transfer message, {payload_len} bytes");
    println!("Iterations        {}", options.iterations);
    println!("Warmup            {}", options.warmup);
    println!("Concurrency       1 (sequential — latency, not throughput under load)");
    println!(
        "Clock             std::time::Instant, overhead ~{}",
        format_nanos(clock_overhead)
    );
    println!(
        "Serialize         {} per message (pre-generated, outside the timed loop)",
        format_nanos(serialize_per_message)
    );
    println!("Broadcast         no");
    println!();
    Ok(())
}

fn report(
    phases: &[(Phase, Samples)],
    warmup: &Samples,
    completed: usize,
    wall: std::time::Duration,
) {
    if let Some(summary) = warmup.summary() {
        println!(
            "Warmup (discarded): n={} first={} p50={} last-min={}",
            summary.n,
            format_nanos(warmup.raw()[0] as f64),
            format_nanos(summary.p50 as f64),
            format_nanos(summary.min as f64)
        );
        println!();
    }

    println!(
        "{:<18} {:>8} {:>11} {:>11} {:>11} {:>11} {:>11} {:>11} {:>11}",
        "phase", "n", "min", "p50", "p90", "p99", "p999", "max", "stddev"
    );
    println!("{}", "-".repeat(116));
    for (phase, samples) in phases {
        let Some(s) = samples.summary() else { continue };
        println!(
            "{:<18} {:>8} {:>11} {:>11} {:>11} {:>11} {:>11} {:>11} {:>11}",
            phase.label(),
            s.n,
            format_nanos(s.min as f64),
            format_nanos(s.p50 as f64),
            format_nanos(s.p90 as f64),
            format_nanos(s.p99 as f64),
            format_nanos(s.p999 as f64),
            format_nanos(s.max as f64),
            format_nanos(s.stddev),
        );
    }

    println!();
    for (phase, samples) in phases {
        let Some(s) = samples.summary() else { continue };
        if *phase == Phase::Total {
            println!(
                "Throughput        {:.1} sig/s at p50, {:.1} sig/s at mean",
                s.throughput_p50(),
                s.throughput_mean()
            );
        }
    }

    let sign_share = phases
        .iter()
        .find(|(p, _)| *p == Phase::Sign)
        .and_then(|(_, s)| s.summary())
        .zip(
            phases
                .iter()
                .find(|(p, _)| *p == Phase::Total)
                .and_then(|(_, s)| s.summary()),
        )
        .map(|(sign, total)| sign.total as f64 / total.total as f64 * 100.0);
    if let Some(share) = sign_share {
        println!("C_Sign share      {share:.1}% of total (the network-bound component)");
    }
    println!(
        "Wall clock        {} for {completed} iterations",
        format_nanos(wall.as_nanos() as f64)
    );
}

fn write_samples(path: &std::path::Path, phases: &[(Phase, Samples)]) -> Result<()> {
    let is_json = path
        .extension()
        .is_some_and(|e| e.eq_ignore_ascii_case("json"));

    let mut file = std::fs::File::create(path)
        .with_context(|| format!("failed to create {}", path.display()))?;

    if is_json {
        let mut map = serde_json::Map::new();
        for (phase, samples) in phases {
            map.insert(
                phase.key().to_string(),
                serde_json::to_value(samples.raw())?,
            );
        }
        serde_json::to_writer_pretty(&mut file, &serde_json::Value::Object(map))?;
    } else {
        writeln!(
            file,
            "iteration,{}",
            phases
                .iter()
                .map(|(p, _)| format!("{}_ns", p.key()))
                .collect::<Vec<_>>()
                .join(",")
        )?;
        let n = phases.first().map(|(_, s)| s.len()).unwrap_or(0);
        for i in 0..n {
            let row = phases
                .iter()
                .map(|(_, s)| s.raw()[i].to_string())
                .collect::<Vec<_>>()
                .join(",");
            writeln!(file, "{i},{row}")?;
        }
    }
    Ok(())
}
