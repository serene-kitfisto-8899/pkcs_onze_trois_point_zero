use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use sign_tx::pkcs11::{Curve, Module};
use sign_tx::run::{BenchOptions, SingleOptions, run_benchmark, run_single};
use sign_tx::signer::SignerConfig;
use sign_tx::solana::decode_pubkey;
use std::path::PathBuf;

/// Environment variable carrying the PKCS#11 PIN.
///
/// Deliberately not a CLI flag: command-line arguments are world-readable
/// via /proc and land in shell history.
const PIN_ENV: &str = "COSMIAN_PKCS11_PIN";

#[derive(Parser)]
#[command(
    name = "sign-tx",
    about = "Sign Solana transactions with an Ed25519 or P-256 key in a Cosmian KMS via PKCS#11",
    long_about = None
)]
struct Cli {
    /// Path to the Cosmian PKCS#11 module (libcosmian_pkcs11.so).
    #[arg(long, env = "COSMIAN_PKCS11_MODULE")]
    module: String,

    /// Slot to use. Auto-selected when exactly one token is present.
    #[arg(long)]
    slot: Option<u64>,

    /// Curve of the signing key.
    #[arg(long, value_enum, default_value_t = Curve::Ed25519, env = "SIGN_TX_CURVE")]
    curve: Curve,

    /// Reuse an existing key with this id instead of creating one.
    ///
    /// Matched against CKA_ID. The Cosmian provider maps CKA_ID to the KMS
    /// object id and ignores CKA_LABEL entirely.
    #[arg(long, alias = "key-label", env = "SIGN_TX_KEY_ID")]
    key_id: Option<String>,

    /// File holding the DER SubjectPublicKeyInfo of the signing key.
    ///
    /// Required with Cosmian, whose PKCS#11 module cannot return Ed25519
    /// public keys through CKA_EC_POINT.
    #[arg(long, env = "SIGN_TX_PUBLIC_KEY")]
    public_key: Option<PathBuf>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Sign a single transaction and verify it locally.
    Single {
        /// Recipient address, base58.
        #[arg(long, default_value = "11111111111111111111111111111112")]
        to: String,

        /// Amount to transfer.
        #[arg(long, default_value_t = 1_000_000)]
        lamports: u64,

        /// Recent blockhash, base58. Defaults to a placeholder, since the
        /// transaction is never broadcast.
        #[arg(long)]
        blockhash: Option<String>,

        /// Emit JSON instead of a human-readable summary.
        #[arg(long)]
        json: bool,
    },

    /// Measure per-step signing latency.
    Benchmark {
        /// Measured iterations.
        #[arg(short = 'n', long, default_value_t = 1000)]
        iterations: usize,

        /// Warmup iterations, discarded from the statistics.
        #[arg(long, default_value_t = 50)]
        warmup: usize,

        /// Minimum warmup duration in seconds. Warmup continues until both this
        /// duration and --warmup iterations have completed.
        #[arg(long, default_value_t = 3)]
        warmup_time: u64,

        /// Recipient address, base58.
        #[arg(long, default_value = "11111111111111111111111111111112")]
        to: String,

        /// Amount to transfer.
        #[arg(long, default_value_t = 1_000_000)]
        lamports: u64,

        /// Write raw per-iteration samples here (.csv or .json).
        #[arg(long)]
        output: Option<PathBuf>,

        /// Write an SVG chart of the results here.
        #[arg(long)]
        chart: Option<PathBuf>,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    // Validate arguments before touching the module, so bad input fails fast
    // rather than after a dlopen and a KMS connection.
    let command = match &cli.command {
        Command::Single {
            to,
            lamports,
            blockhash,
            json,
        } => Action::Single(SingleOptions {
            to: decode_pubkey(to).context("invalid --to address")?,
            lamports: *lamports,
            blockhash: match blockhash {
                Some(value) => decode_pubkey(value).context("invalid --blockhash")?,
                None => [0u8; 32],
            },
            json: *json,
        }),
        Command::Benchmark {
            iterations,
            warmup,
            warmup_time,
            to,
            lamports,
            output,
            chart,
        } => {
            if *iterations == 0 {
                anyhow::bail!("--iterations must be at least 1");
            }
            Action::Benchmark(BenchOptions {
                iterations: *iterations,
                warmup: *warmup,
                warmup_time: std::time::Duration::from_secs(*warmup_time),
                lamports: *lamports,
                to: decode_pubkey(to).context("invalid --to address")?,
                output: output.clone(),
                chart: chart.clone(),
            })
        }
    };

    let public_key_der = match &cli.public_key {
        Some(path) => Some(
            std::fs::read(path)
                .with_context(|| format!("failed to read --public-key {}", path.display()))?,
        ),
        None => None,
    };

    let module = Module::load(&cli.module)?;
    let signer_config = SignerConfig {
        slot: cli.slot,
        key_id: cli.key_id.clone(),
        pin: std::env::var(PIN_ENV).ok().filter(|p| !p.is_empty()),
        curve: cli.curve,
        public_key_der,
    };

    match &command {
        Action::Single(options) => run_single(&module, &signer_config, options),
        Action::Benchmark(options) => run_benchmark(&module, &signer_config, options),
    }
}

enum Action {
    Single(SingleOptions),
    Benchmark(BenchOptions),
}
