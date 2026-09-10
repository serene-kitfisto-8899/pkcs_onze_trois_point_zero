//! Sign Solana transfer transactions with an Ed25519 key held in a Cosmian
//! KMS, reached through its PKCS#11 module.
//!
//! The logic lives in the library so the payload builder and the statistics
//! can be unit-tested without a live KMS.

pub mod chart;
pub mod pkcs11;
pub mod run;
pub mod signer;
pub mod solana;
pub mod stats;
