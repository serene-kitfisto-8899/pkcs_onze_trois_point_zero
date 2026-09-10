//! Minimal Solana transfer transaction construction.
//!
//! Only what is needed to produce the exact bytes that get signed: a legacy
//! message containing a single System Program transfer instruction. The
//! signed payload is the serialized message, with no pre-hashing — Ed25519
//! over Solana is signed natively.

use anyhow::{Result, bail};

/// The System Program address, `11111111111111111111111111111111`.
const SYSTEM_PROGRAM_ID: [u8; 32] = [0u8; 32];

/// System Program instruction index for `Transfer`.
const INSTRUCTION_TRANSFER: u32 = 2;

#[derive(Debug, Clone)]
pub struct Transfer {
    pub from: [u8; 32],
    pub to: [u8; 32],
    pub lamports: u64,
    pub recent_blockhash: [u8; 32],
}

impl Transfer {
    /// Serialize the legacy message. These are the bytes handed to `C_Sign`.
    ///
    /// The length is constant for a given account set, which matters for the
    /// benchmark: varying only the blockhash keeps every payload unique
    /// without changing its size.
    pub fn message_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(160);

        // Message header: 1 required signature, 0 readonly signed accounts,
        // 1 readonly unsigned account (the System Program).
        out.push(1);
        out.push(0);
        out.push(1);

        // Account keys, ordered: writable signer, writable, readonly program.
        push_compact_u16(&mut out, 3);
        out.extend_from_slice(&self.from);
        out.extend_from_slice(&self.to);
        out.extend_from_slice(&SYSTEM_PROGRAM_ID);

        out.extend_from_slice(&self.recent_blockhash);

        // A single instruction.
        push_compact_u16(&mut out, 1);
        out.push(2); // program id index -> System Program
        push_compact_u16(&mut out, 2); // account indices
        out.push(0);
        out.push(1);
        push_compact_u16(&mut out, 12); // instruction data length
        out.extend_from_slice(&INSTRUCTION_TRANSFER.to_le_bytes());
        out.extend_from_slice(&self.lamports.to_le_bytes());

        out
    }

    /// The full wire transaction: signature count, signature, then message.
    ///
    /// Solana wire format expects a fixed 64-byte Ed25519 signature per
    /// signer. A `CKM_ECDSA` (P-256) signature is DER-encoded and
    /// variable-length, so it does not fit that slot; callers benchmarking
    /// P-256 get a byte stream of the same shape (count-prefixed signature
    /// + message) but not a valid, broadcastable Solana transaction. This
    /// tool never broadcasts, so only the payload shape/size matters here.
    pub fn to_wire(&self, signature: &[u8]) -> Vec<u8> {
        let message = self.message_bytes();
        let mut out = Vec::with_capacity(1 + signature.len() + message.len());
        push_compact_u16(&mut out, 1);
        out.extend_from_slice(signature);
        out.extend_from_slice(&message);
        out
    }
}

/// Solana's ShortVec length prefix.
fn push_compact_u16(out: &mut Vec<u8>, mut value: u16) {
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value == 0 {
            out.push(byte);
            return;
        }
        byte |= 0x80;
        out.push(byte);
    }
}

pub fn decode_pubkey(encoded: &str) -> Result<[u8; 32]> {
    let bytes = bs58::decode(encoded)
        .into_vec()
        .map_err(|e| anyhow::anyhow!("invalid base58 public key: {e}"))?;
    if bytes.len() != 32 {
        bail!("public key must decode to 32 bytes, got {}", bytes.len());
    }
    Ok(bytes.try_into().unwrap())
}

pub fn encode_pubkey(key: &[u8; 32]) -> String {
    bs58::encode(key).into_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(blockhash: [u8; 32]) -> Transfer {
        Transfer {
            from: [1u8; 32],
            to: [2u8; 32],
            lamports: 1_000_000,
            recent_blockhash: blockhash,
        }
    }

    #[test]
    fn message_length_is_stable_across_blockhashes() {
        let a = sample([3u8; 32]).message_bytes();
        let b = sample([4u8; 32]).message_bytes();
        assert_eq!(a.len(), b.len());
        assert_ne!(a, b);
    }

    #[test]
    fn message_encodes_transfer_instruction() {
        let bytes = sample([0u8; 32]).message_bytes();
        // 3 header + 1 count + 96 keys + 32 blockhash = 132, then instructions.
        assert_eq!(&bytes[0..3], &[1, 0, 1]);
        assert_eq!(bytes[3], 3);
        let tail = &bytes[132..];
        assert_eq!(tail[0], 1); // one instruction
        assert_eq!(tail[1], 2); // system program index
        assert_eq!(&tail[6..10], &INSTRUCTION_TRANSFER.to_le_bytes());
        assert_eq!(&tail[10..18], &1_000_000u64.to_le_bytes());
    }

    #[test]
    fn wire_transaction_prefixes_signature() {
        let tx = sample([0u8; 32]);
        let wire = tx.to_wire(&[7u8; 64]);
        assert_eq!(wire[0], 1);
        assert_eq!(&wire[1..65], &[7u8; 64]);
        assert_eq!(&wire[65..], &tx.message_bytes()[..]);
    }

    #[test]
    fn compact_u16_matches_shortvec() {
        let mut out = Vec::new();
        push_compact_u16(&mut out, 0);
        assert_eq!(out, vec![0]);

        out.clear();
        push_compact_u16(&mut out, 127);
        assert_eq!(out, vec![127]);

        out.clear();
        push_compact_u16(&mut out, 128);
        assert_eq!(out, vec![0x80, 0x01]);

        out.clear();
        push_compact_u16(&mut out, 300);
        assert_eq!(out, vec![0xac, 0x02]);
    }

    #[test]
    fn pubkey_round_trips() {
        let key = [42u8; 32];
        assert_eq!(decode_pubkey(&encode_pubkey(&key)).unwrap(), key);
    }

    #[test]
    fn rejects_wrong_length_pubkey() {
        assert!(decode_pubkey(&bs58::encode([1u8; 16]).into_string()).is_err());
    }
}
