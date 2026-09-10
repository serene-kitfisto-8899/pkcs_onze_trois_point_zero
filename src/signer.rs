//! Key provisioning, the signing hot path, and cleanup.

use crate::pkcs11::{
    Curve, KeyPair, Module, SIGNATURE_LEN, Session, normalize_ec_point, normalize_p256_point,
    parse_spki_ed25519, parse_spki_p256,
};
use anyhow::{Context, Result, bail};
use cryptoki_sys::{CK_SLOT_ID, CKA_EC_POINT};
use ed25519_dalek::{Signature as Ed25519Signature, Verifier as _, VerifyingKey as Ed25519VerifyingKey};
use p256::ecdsa::signature::hazmat::PrehashVerifier;
use p256::ecdsa::{Signature as P256Signature, VerifyingKey as P256VerifyingKey};

pub struct SignerConfig {
    pub slot: Option<CK_SLOT_ID>,
    /// Object id of an existing key, looked up via `CKA_ID`.
    pub key_id: Option<String>,
    pub pin: Option<String>,
    /// The curve of the key: dictates the mechanism, keygen, and public-key
    /// parsing used throughout.
    pub curve: Curve,
    /// DER SubjectPublicKeyInfo holding the public key.
    ///
    /// Needed when the module cannot serve the public key itself. Cosmian's
    /// `CKA_EC_POINT` is hardcoded to P-256 and returns an error for
    /// Ed25519, so the key is supplied out-of-band in that case.
    pub public_key_der: Option<Vec<u8>>,
}

/// The public key, in whichever curve-specific representation lets us
/// verify locally.
enum VerifyingKey {
    Ed25519(Ed25519VerifyingKey),
    P256(P256VerifyingKey),
}

pub struct Signer<'a> {
    session: Session<'a>,
    keys: KeyPair,
    verifying_key: VerifyingKey,
    curve: Curve,
    label: String,
    /// Keys we created ourselves are ours to clean up; a key supplied via
    /// `--key-id` belongs to the caller and is left alone.
    owns_key: bool,
}

impl<'a> Signer<'a> {
    pub fn connect(module: &'a Module, config: &SignerConfig) -> Result<Self> {
        let slot = resolve_slot(module, config.slot)?;
        let session = module
            .open_session(slot)
            .with_context(|| format!("failed to open a session on slot {slot}"))?;

        if let Some(pin) = &config.pin {
            session.login(pin).context("C_Login failed")?;
        }

        let (label, keys, owns_key) = match &config.key_id {
            Some(id) => match session.find_key(id)? {
                Some(keys) => (id.clone(), keys, false),
                None => bail!(
                    "no private key found with CKA_ID '{id}'. The Cosmian PKCS#11 \
                     provider only exposes private keys carrying the 'disk-encryption' or \
                     'ssh-auth' KMIP tag — check the key was created with one of those tags"
                ),
            },
            None => {
                let label = format!("bench-{}", uuid::Uuid::new_v4());
                let keys = session
                    .generate_key(&label, config.curve)
                    .context("key generation failed")?;
                (label, keys, true)
            }
        };

        let verifying_key = Self::resolve_public_key(&session, &keys, config)?;

        let signer = Self {
            session,
            keys,
            verifying_key,
            curve: config.curve,
            label,
            owns_key,
        };
        signer.self_test()?;
        Ok(signer)
    }

    /// Obtain the public key, preferring an explicitly supplied one.
    ///
    /// Falling back to `CKA_EC_POINT` keeps the tool usable against modules
    /// that do implement it for the curve in question; the error names both
    /// causes because a module can either omit the attribute or reject it
    /// outright.
    fn resolve_public_key(
        session: &Session<'_>,
        keys: &KeyPair,
        config: &SignerConfig,
    ) -> Result<VerifyingKey> {
        if let Some(der) = &config.public_key_der {
            return match config.curve {
                Curve::Ed25519 => {
                    let raw = parse_spki_ed25519(der).context(
                        "the supplied public key is not a valid Ed25519 SubjectPublicKeyInfo",
                    )?;
                    Ed25519VerifyingKey::from_bytes(&raw)
                        .map(VerifyingKey::Ed25519)
                        .context("the supplied public key is not a valid Ed25519 point")
                }
                Curve::P256 => {
                    let raw = parse_spki_p256(der).context(
                        "the supplied public key is not a valid P-256 SubjectPublicKeyInfo",
                    )?;
                    P256VerifyingKey::from_sec1_bytes(&raw)
                        .map(VerifyingKey::P256)
                        .context("the supplied public key is not a valid P-256 point")
                }
            };
        }

        if keys.public == 0 {
            bail!(
                "no public key object was found and none was supplied; pass --public-key \
                 with the DER SubjectPublicKeyInfo of the signing key"
            );
        }

        let point = session.attribute(keys.public, CKA_EC_POINT).context(
            "failed to read CKA_EC_POINT. The Cosmian provider cannot return Ed25519 public \
             keys this way — supply the key with --public-key instead",
        )?;
        match config.curve {
            Curve::Ed25519 => {
                let raw = normalize_ec_point(&point)?;
                Ed25519VerifyingKey::from_bytes(&raw)
                    .map(VerifyingKey::Ed25519)
                    .context("CKA_EC_POINT is not a valid Ed25519 point")
            }
            Curve::P256 => {
                let raw = normalize_p256_point(&point)?;
                P256VerifyingKey::from_sec1_bytes(&raw)
                    .map(VerifyingKey::P256)
                    .context("CKA_EC_POINT is not a valid P-256 point")
            }
        }
    }

    /// Sign and verify a known message once, before any measurement.
    ///
    /// This is what catches a mismatched public key: it fails here in setup
    /// rather than silently producing thousands of invalid signatures.
    fn self_test(&self) -> Result<()> {
        let probe = b"sign-tx setup self-test";
        let mut signature = vec![0u8; self.curve.max_signature_len()];
        let input = self.curve.signing_input(probe);
        self.session.sign_init(self.keys.private, self.curve)?;
        let len = self.session.sign_into(&input, &mut signature)?;
        signature.truncate(len);
        if self.curve == Curve::Ed25519 && len != SIGNATURE_LEN {
            bail!("expected a {SIGNATURE_LEN}-byte signature, module returned {len} bytes");
        }
        self.verify(probe, &signature).context(
            "setup self-test failed: the signature did not verify against the public key",
        )
    }

    /// The public key, as a DER SubjectPublicKeyInfo-independent raw
    /// encoding: 32 bytes for Ed25519, the 65-byte uncompressed SEC1 point
    /// for P-256.
    pub fn public_key_bytes(&self) -> Vec<u8> {
        match &self.verifying_key {
            VerifyingKey::Ed25519(key) => key.to_bytes().to_vec(),
            VerifyingKey::P256(key) => key.to_sec1_bytes().to_vec(),
        }
    }

    pub fn curve(&self) -> Curve {
        self.curve
    }

    pub fn label(&self) -> &str {
        &self.label
    }

    pub fn session(&self) -> &Session<'a> {
        &self.session
    }

    pub fn private_handle(&self) -> cryptoki_sys::CK_OBJECT_HANDLE {
        self.keys.private
    }

    /// Verify a signature over `message`.
    ///
    /// Ed25519 (`CKM_EDDSA`, pure mode) signs the message directly.
    /// `CKM_ECDSA` per the PKCS#11 spec signs a pre-hashed digest, not the
    /// raw message, so P-256 verification hashes `message` with SHA-256
    /// first — matching what the KMS/PKCS#11 provider did when producing
    /// the signature.
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<()> {
        let input = self.curve.signing_input(message);
        match &self.verifying_key {
            VerifyingKey::Ed25519(key) => {
                let signature: &[u8; SIGNATURE_LEN] = signature
                    .try_into()
                    .context("expected a 64-byte Ed25519 signature")?;
                let signature = Ed25519Signature::from_bytes(signature);
                key.verify(&input, &signature)
                    .context("Ed25519 signature verification failed")
            }
            VerifyingKey::P256(key) => {
                let signature = P256Signature::from_der(signature)
                    .context("not a valid DER-encoded P-256 ECDSA signature")?;
                key.verify_prehash(&input, &signature)
                    .context("P-256 signature verification failed")
            }
        }
    }

    /// Destroy the key pair if this run created it.
    pub fn cleanup(&self) {
        if !self.owns_key {
            return;
        }
        for handle in [self.keys.private, self.keys.public] {
            if let Err(error) = self.session.destroy(handle) {
                eprintln!("warning: failed to destroy key object: {error:#}");
            }
        }
    }
}

impl Drop for Signer<'_> {
    fn drop(&mut self) {
        self.cleanup();
    }
}

/// Pick the slot to use, auto-selecting when exactly one token is present.
fn resolve_slot(module: &Module, requested: Option<CK_SLOT_ID>) -> Result<CK_SLOT_ID> {
    let slots = module
        .slots()
        .context("failed to enumerate PKCS#11 slots")?;

    if let Some(id) = requested {
        if slots.iter().any(|slot| slot.id == id) {
            return Ok(id);
        }
        bail!(
            "slot {id} has no token present; available: {}",
            describe_slots(&slots)
        );
    }

    match slots.len() {
        0 => bail!("no PKCS#11 slot has a token present"),
        1 => Ok(slots[0].id),
        _ => bail!(
            "several slots have tokens present, pass --slot to choose: {}",
            describe_slots(&slots)
        ),
    }
}

fn describe_slots(slots: &[crate::pkcs11::Slot]) -> String {
    if slots.is_empty() {
        return "(none)".to_string();
    }
    slots
        .iter()
        .map(|slot| format!("{} ({})", slot.id, slot.token_label))
        .collect::<Vec<_>>()
        .join(", ")
}

