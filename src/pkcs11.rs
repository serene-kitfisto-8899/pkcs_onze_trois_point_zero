//! Raw PKCS#11 access.
//!
//! The high-level `cryptoki` crate's `Session::sign()` issues `C_SignInit`
//! followed by two `C_Sign` calls (one to query the signature length, one to
//! retrieve it). Against a network-backed KMS that is potentially two round
//! trips per signature, and it collapses the `C_SignInit`/`C_Sign` split we
//! need to measure. So we drive the function list directly and presize the
//! signature buffer.

use anyhow::{Context, Result, anyhow, bail};
use cryptoki_sys::*;
use libloading::Library;
use sha2::Digest as _;
use std::ffi::c_void;
use std::ptr;

/// Ed25519 signatures (RFC 8032) are always exactly 64 bytes. `CKM_ECDSA`
/// signatures from the Cosmian PKCS#11 provider are DER-encoded (`SEQUENCE
/// { INTEGER r, INTEGER s }`), not raw `r || s`, so their length varies
/// slightly run to run depending on whether `r`/`s` need a leading zero byte
/// for their high bit. `SIGNATURE_LEN` is Ed25519's exact length;
/// `Curve::max_signature_len` is the upper bound used to presize the
/// buffer for whichever curve is in use.
pub const SIGNATURE_LEN: usize = 64;

/// Upper bound on a DER-encoded P-256 ECDSA signature: outer `SEQUENCE`
/// header (2 bytes) plus two `INTEGER`s, each up to 35 bytes (1 tag + 1
/// length + up to 33 bytes of content, the extra byte for a leading zero
/// when the top bit of `r`/`s` is set) = 72 bytes.
pub const MAX_P256_SIGNATURE_LEN: usize = 72;

/// id-Ed25519 (RFC 8410), DER-encoded, as required for `CKA_EC_PARAMS`.
const ED25519_OID_DER: [u8; 5] = [0x06, 0x03, 0x2b, 0x65, 0x70];

/// prime256v1 / secp256r1 (SEC 2 / RFC 5480), DER-encoded, as required for
/// `CKA_EC_PARAMS`.
const P256_OID_DER: [u8; 10] = [0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];

/// The elliptic curve a key is generated on or signs with.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum Curve {
    /// Twisted Edwards Ed25519 (RFC 8032), signed via `CKM_EDDSA`.
    Ed25519,
    /// NIST P-256 / secp256r1, signed via `CKM_ECDSA`.
    P256,
}

impl std::fmt::Display for Curve {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Curve::Ed25519 => "ed25519",
            Curve::P256 => "p256",
        })
    }
}

impl Curve {
    fn keygen_mechanism(self) -> CK_MECHANISM_TYPE {
        match self {
            Curve::Ed25519 => CKM_EC_EDWARDS_KEY_PAIR_GEN,
            Curve::P256 => CKM_EC_KEY_PAIR_GEN,
        }
    }

    fn sign_mechanism(self) -> CK_MECHANISM_TYPE {
        match self {
            Curve::Ed25519 => CKM_EDDSA,
            Curve::P256 => CKM_ECDSA,
        }
    }

    fn ec_params(self) -> &'static [u8] {
        match self {
            Curve::Ed25519 => &ED25519_OID_DER,
            Curve::P256 => &P256_OID_DER,
        }
    }

    /// Upper bound on the signature buffer needed for this curve: exact for
    /// Ed25519, a safe maximum for P-256's variable-length DER encoding.
    pub fn max_signature_len(self) -> usize {
        match self {
            Curve::Ed25519 => SIGNATURE_LEN,
            Curve::P256 => MAX_P256_SIGNATURE_LEN,
        }
    }

    /// The bytes actually handed to `C_Sign`/verification: the message
    /// itself for Ed25519 (`CKM_EDDSA` signs the message directly), or its
    /// SHA-256 digest for P-256 (`CKM_ECDSA` per the PKCS#11 spec signs a
    /// pre-hashed digest, not the raw message).
    pub fn signing_input(self, message: &[u8]) -> Vec<u8> {
        match self {
            Curve::Ed25519 => message.to_vec(),
            Curve::P256 => sha2::Sha256::digest(message).to_vec(),
        }
    }

    pub fn mechanism_name(self) -> &'static str {
        match self {
            Curve::Ed25519 => "CKM_EDDSA (Ed25519, pure)",
            Curve::P256 => "CKM_ECDSA (P-256, DER-encoded, over SHA-256 digest)",
        }
    }
}

pub struct Module {
    functions: CK_FUNCTION_LIST,
    // Held to keep the shared object mapped; the function pointers above
    // point into it.
    _library: Library,
    initialized: bool,
}

pub struct Slot {
    pub id: CK_SLOT_ID,
    pub description: String,
    pub token_label: String,
    pub manufacturer: String,
    pub model: String,
}

pub struct ModuleInfo {
    pub cryptoki_version: (u8, u8),
    pub manufacturer: String,
    pub library_description: String,
    pub library_version: (u8, u8),
}

fn trim_padded(raw: &[u8]) -> String {
    String::from_utf8_lossy(raw).trim_end().to_string()
}

fn check(rv: CK_RV, op: &str) -> Result<()> {
    if rv == CKR_OK {
        Ok(())
    } else {
        bail!("{op} failed: {}", rv_name(rv))
    }
}

fn rv_name(rv: CK_RV) -> String {
    let name = match rv {
        CKR_CANCEL => "CKR_CANCEL",
        CKR_FUNCTION_NOT_SUPPORTED => "CKR_FUNCTION_NOT_SUPPORTED",
        CKR_MECHANISM_INVALID => "CKR_MECHANISM_INVALID",
        CKR_MECHANISM_PARAM_INVALID => "CKR_MECHANISM_PARAM_INVALID",
        CKR_DEVICE_ERROR => "CKR_DEVICE_ERROR",
        CKR_DEVICE_REMOVED => "CKR_DEVICE_REMOVED",
        CKR_TOKEN_NOT_PRESENT => "CKR_TOKEN_NOT_PRESENT",
        CKR_PIN_INCORRECT => "CKR_PIN_INCORRECT",
        CKR_PIN_INVALID => "CKR_PIN_INVALID",
        CKR_SESSION_HANDLE_INVALID => "CKR_SESSION_HANDLE_INVALID",
        CKR_SESSION_CLOSED => "CKR_SESSION_CLOSED",
        CKR_KEY_HANDLE_INVALID => "CKR_KEY_HANDLE_INVALID",
        CKR_ATTRIBUTE_TYPE_INVALID => "CKR_ATTRIBUTE_TYPE_INVALID",
        CKR_ATTRIBUTE_VALUE_INVALID => "CKR_ATTRIBUTE_VALUE_INVALID",
        CKR_TEMPLATE_INCOMPLETE => "CKR_TEMPLATE_INCOMPLETE",
        CKR_TEMPLATE_INCONSISTENT => "CKR_TEMPLATE_INCONSISTENT",
        CKR_USER_NOT_LOGGED_IN => "CKR_USER_NOT_LOGGED_IN",
        CKR_USER_ALREADY_LOGGED_IN => "CKR_USER_ALREADY_LOGGED_IN",
        CKR_BUFFER_TOO_SMALL => "CKR_BUFFER_TOO_SMALL",
        CKR_ARGUMENTS_BAD => "CKR_ARGUMENTS_BAD",
        CKR_GENERAL_ERROR => "CKR_GENERAL_ERROR",
        CKR_HOST_MEMORY => "CKR_HOST_MEMORY",
        CKR_OPERATION_ACTIVE => "CKR_OPERATION_ACTIVE",
        CKR_OPERATION_NOT_INITIALIZED => "CKR_OPERATION_NOT_INITIALIZED",
        CKR_ACTION_PROHIBITED => "CKR_ACTION_PROHIBITED",
        _ => return format!("CKR_0x{rv:08x}"),
    };
    name.to_string()
}

impl Module {
    pub fn load(path: &str) -> Result<Self> {
        let library = unsafe { Library::new(path) }
            .with_context(|| format!("failed to dlopen PKCS#11 module at {path}"))?;

        let functions = unsafe {
            let get_list = library
                .get::<unsafe extern "C" fn(*mut CK_FUNCTION_LIST_PTR) -> CK_RV>(
                    b"C_GetFunctionList\0",
                )
                .context("module does not export C_GetFunctionList")?;

            let mut list_ptr: CK_FUNCTION_LIST_PTR = ptr::null_mut();
            check(get_list(&mut list_ptr), "C_GetFunctionList")?;
            if list_ptr.is_null() {
                bail!("C_GetFunctionList returned a null function list");
            }
            *list_ptr
        };

        let mut module = Self {
            functions,
            _library: library,
            initialized: false,
        };

        let init = module
            .functions
            .C_Initialize
            .ok_or_else(|| anyhow!("module does not implement C_Initialize"))?;
        unsafe { check(init(ptr::null_mut()), "C_Initialize")? };
        module.initialized = true;

        Ok(module)
    }

    pub fn info(&self) -> Result<ModuleInfo> {
        let f = self
            .functions
            .C_GetInfo
            .ok_or_else(|| anyhow!("module does not implement C_GetInfo"))?;
        let mut info = CK_INFO::default();
        unsafe { check(f(&mut info), "C_GetInfo")? };
        Ok(ModuleInfo {
            cryptoki_version: (info.cryptokiVersion.major, info.cryptokiVersion.minor),
            manufacturer: trim_padded(&info.manufacturerID),
            library_description: trim_padded(&info.libraryDescription),
            library_version: (info.libraryVersion.major, info.libraryVersion.minor),
        })
    }

    /// Slots with a token present.
    pub fn slots(&self) -> Result<Vec<Slot>> {
        let get_slot_list = self
            .functions
            .C_GetSlotList
            .ok_or_else(|| anyhow!("module does not implement C_GetSlotList"))?;

        let mut count: CK_ULONG = 0;
        unsafe {
            check(
                get_slot_list(CK_TRUE as CK_BBOOL, ptr::null_mut(), &mut count),
                "C_GetSlotList (count)",
            )?
        };

        let mut ids = vec![0 as CK_SLOT_ID; count as usize];
        if count > 0 {
            unsafe {
                check(
                    get_slot_list(CK_TRUE as CK_BBOOL, ids.as_mut_ptr(), &mut count),
                    "C_GetSlotList",
                )?
            };
        }
        ids.truncate(count as usize);

        let get_slot_info = self.functions.C_GetSlotInfo;
        let get_token_info = self.functions.C_GetTokenInfo;

        let mut slots = Vec::with_capacity(ids.len());
        for id in ids {
            let mut description = String::new();
            let mut manufacturer = String::new();
            if let Some(f) = get_slot_info {
                let mut si = CK_SLOT_INFO::default();
                if unsafe { f(id, &mut si) } == CKR_OK {
                    description = trim_padded(&si.slotDescription);
                    manufacturer = trim_padded(&si.manufacturerID);
                }
            }
            let mut token_label = String::new();
            let mut model = String::new();
            if let Some(f) = get_token_info {
                let mut ti = CK_TOKEN_INFO::default();
                if unsafe { f(id, &mut ti) } == CKR_OK {
                    token_label = trim_padded(&ti.label);
                    model = trim_padded(&ti.model);
                }
            }
            slots.push(Slot {
                id,
                description,
                token_label,
                manufacturer,
                model,
            });
        }
        Ok(slots)
    }

    pub fn open_session(&self, slot: CK_SLOT_ID) -> Result<Session<'_>> {
        let f = self
            .functions
            .C_OpenSession
            .ok_or_else(|| anyhow!("module does not implement C_OpenSession"))?;
        let mut handle: CK_SESSION_HANDLE = 0;
        unsafe {
            check(
                f(
                    slot,
                    CKF_SERIAL_SESSION | CKF_RW_SESSION,
                    ptr::null_mut(),
                    None,
                    &mut handle,
                ),
                "C_OpenSession",
            )?
        };
        Ok(Session {
            module: self,
            handle,
        })
    }
}

impl Drop for Module {
    fn drop(&mut self) {
        if self.initialized
            && let Some(f) = self.functions.C_Finalize
        {
            unsafe {
                let _ = f(ptr::null_mut());
            }
        }
    }
}

pub struct Session<'a> {
    module: &'a Module,
    handle: CK_SESSION_HANDLE,
}

/// An Ed25519 key pair living in the KMS.
pub struct KeyPair {
    pub public: CK_OBJECT_HANDLE,
    pub private: CK_OBJECT_HANDLE,
}

impl Session<'_> {
    pub fn login(&self, pin: &str) -> Result<()> {
        let f = self
            .module
            .functions
            .C_Login
            .ok_or_else(|| anyhow!("module does not implement C_Login"))?;
        let rv = unsafe {
            f(
                self.handle,
                CKU_USER,
                pin.as_ptr() as CK_UTF8CHAR_PTR,
                pin.len() as CK_ULONG,
            )
        };
        if rv == CKR_USER_ALREADY_LOGGED_IN {
            return Ok(());
        }
        check(rv, "C_Login")
    }

    /// Generate a key pair on the given curve.
    ///
    /// Hard-fails if the module does not implement `C_GenerateKeyPair`, by
    /// design: key creation must go through PKCS#11.
    pub fn generate_key(&self, label: &str, curve: Curve) -> Result<KeyPair> {
        let f = self
            .module
            .functions
            .C_GenerateKeyPair
            .ok_or_else(|| anyhow!("module does not implement C_GenerateKeyPair"))?;

        let mut mechanism = CK_MECHANISM {
            mechanism: curve.keygen_mechanism(),
            pParameter: ptr::null_mut(),
            ulParameterLen: 0,
        };

        let mut ck_true: CK_BBOOL = CK_TRUE as CK_BBOOL;
        let mut ec_params = curve.ec_params().to_vec();
        let label_bytes = label.as_bytes().to_vec();

        let mut public_template = vec![
            attr(CKA_TOKEN, &mut ck_true),
            attr(CKA_VERIFY, &mut ck_true),
            attr_slice(CKA_EC_PARAMS, &mut ec_params),
            attr_bytes(CKA_LABEL, &label_bytes),
        ];
        let mut private_template = vec![
            attr(CKA_TOKEN, &mut ck_true),
            attr(CKA_SIGN, &mut ck_true),
            attr(CKA_PRIVATE, &mut ck_true),
            attr(CKA_SENSITIVE, &mut ck_true),
            attr_bytes(CKA_LABEL, &label_bytes),
        ];

        let mut public: CK_OBJECT_HANDLE = 0;
        let mut private: CK_OBJECT_HANDLE = 0;

        let rv = unsafe {
            f(
                self.handle,
                &mut mechanism,
                public_template.as_mut_ptr(),
                public_template.len() as CK_ULONG,
                private_template.as_mut_ptr(),
                private_template.len() as CK_ULONG,
                &mut public,
                &mut private,
            )
        };

        if rv == CKR_FUNCTION_NOT_SUPPORTED || rv == CKR_MECHANISM_INVALID {
            bail!(
                "the PKCS#11 module does not support key generation on this curve \
                 ({:?}): {}",
                curve,
                rv_name(rv)
            );
        }
        check(rv, "C_GenerateKeyPair")?;

        Ok(KeyPair { public, private })
    }

    /// Locate a private key by its KMS object id.
    ///
    /// Lookup is by `CKA_ID`, not `CKA_LABEL`. The Cosmian module builds its
    /// search only from `CKA_ID`; a `CKA_LABEL` in the template is ignored and
    /// the search silently degrades to "return everything". `CKA_LABEL` on a
    /// private key is also the constant string "Private Key", so it carries no
    /// identifying information.
    ///
    /// The matching public key is optional: it is looked up when present, but
    /// the public key needed for verification is generally supplied separately
    /// because Ed25519 public material is not reachable through `CKA_EC_POINT`.
    pub fn find_key(&self, id: &str) -> Result<Option<KeyPair>> {
        let Some(private) = self.find_one(id, CKO_PRIVATE_KEY)? else {
            return Ok(None);
        };
        let public = self.find_one(id, CKO_PUBLIC_KEY)?.unwrap_or(0);
        Ok(Some(KeyPair { public, private }))
    }

    fn find_one(&self, id: &str, class: CK_OBJECT_CLASS) -> Result<Option<CK_OBJECT_HANDLE>> {
        let fns = &self.module.functions;
        let init = fns
            .C_FindObjectsInit
            .ok_or_else(|| anyhow!("module does not implement C_FindObjectsInit"))?;
        let find = fns
            .C_FindObjects
            .ok_or_else(|| anyhow!("module does not implement C_FindObjects"))?;
        let fin = fns
            .C_FindObjectsFinal
            .ok_or_else(|| anyhow!("module does not implement C_FindObjectsFinal"))?;

        let mut class_val = class;
        let id_bytes = id.as_bytes().to_vec();
        let mut template = vec![attr(CKA_CLASS, &mut class_val), attr_bytes(CKA_ID, &id_bytes)];

        unsafe {
            check(
                init(
                    self.handle,
                    template.as_mut_ptr(),
                    template.len() as CK_ULONG,
                ),
                "C_FindObjectsInit",
            )?
        };

        let mut handle: CK_OBJECT_HANDLE = 0;
        let mut count: CK_ULONG = 0;
        let rv = unsafe { find(self.handle, &mut handle, 1, &mut count) };
        unsafe {
            let _ = fin(self.handle);
        }
        check(rv, "C_FindObjects")?;

        Ok(if count > 0 { Some(handle) } else { None })
    }

    /// Read a byte-valued attribute.
    pub fn attribute(&self, object: CK_OBJECT_HANDLE, kind: CK_ATTRIBUTE_TYPE) -> Result<Vec<u8>> {
        let f = self
            .module
            .functions
            .C_GetAttributeValue
            .ok_or_else(|| anyhow!("module does not implement C_GetAttributeValue"))?;

        let mut template = [CK_ATTRIBUTE {
            type_: kind,
            pValue: ptr::null_mut(),
            ulValueLen: 0,
        }];
        unsafe {
            check(
                f(self.handle, object, template.as_mut_ptr(), 1),
                "C_GetAttributeValue (length)",
            )?
        };

        let len = template[0].ulValueLen;
        if len == CK_UNAVAILABLE_INFORMATION || len == 0 {
            bail!("attribute 0x{kind:08x} is unavailable on this object");
        }

        let mut buffer = vec![0u8; len as usize];
        template[0].pValue = buffer.as_mut_ptr() as *mut c_void;
        unsafe {
            check(
                f(self.handle, object, template.as_mut_ptr(), 1),
                "C_GetAttributeValue",
            )?
        };
        buffer.truncate(template[0].ulValueLen as usize);
        Ok(buffer)
    }

    /// `C_SignInit` with the mechanism appropriate for the given curve,
    /// timed independently of `C_Sign`.
    ///
    /// Neither Ed25519 (RFC 8032 pure mode) nor raw `CKM_ECDSA` need a
    /// mechanism parameter.
    pub fn sign_init(&self, key: CK_OBJECT_HANDLE, curve: Curve) -> Result<()> {
        let f = self
            .module
            .functions
            .C_SignInit
            .ok_or_else(|| anyhow!("module does not implement C_SignInit"))?;
        let mut mechanism = CK_MECHANISM {
            mechanism: curve.sign_mechanism(),
            pParameter: ptr::null_mut(),
            ulParameterLen: 0,
        };
        unsafe { check(f(self.handle, &mut mechanism, key), "C_SignInit") }
    }

    /// A single `C_Sign` into a caller-owned, presized buffer.
    ///
    /// The buffer is reused across iterations so allocation never lands
    /// inside the timed region. Ed25519 signatures are exactly 64 bytes;
    /// `CKM_ECDSA` returns a DER-encoded signature whose length varies by a
    /// byte or two run to run, so the caller presizes to
    /// `Curve::max_signature_len` and this reports the actual length
    /// written, avoiding the length-query round trip either way.
    pub fn sign_into(&self, data: &[u8], signature: &mut [u8]) -> Result<usize> {
        let f = self
            .module
            .functions
            .C_Sign
            .ok_or_else(|| anyhow!("module does not implement C_Sign"))?;
        let mut len = signature.len() as CK_ULONG;
        let rv = unsafe {
            f(
                self.handle,
                data.as_ptr() as *mut u8,
                data.len() as CK_ULONG,
                signature.as_mut_ptr(),
                &mut len,
            )
        };
        check(rv, "C_Sign")?;
        Ok(len as usize)
    }

    pub fn destroy(&self, object: CK_OBJECT_HANDLE) -> Result<()> {
        let f = self
            .module
            .functions
            .C_DestroyObject
            .ok_or_else(|| anyhow!("module does not implement C_DestroyObject"))?;
        unsafe { check(f(self.handle, object), "C_DestroyObject") }
    }
}

impl Drop for Session<'_> {
    fn drop(&mut self) {
        if let Some(f) = self.module.functions.C_CloseSession {
            unsafe {
                let _ = f(self.handle);
            }
        }
    }
}

fn attr<T>(kind: CK_ATTRIBUTE_TYPE, value: &mut T) -> CK_ATTRIBUTE {
    CK_ATTRIBUTE {
        type_: kind,
        pValue: value as *mut T as *mut c_void,
        ulValueLen: size_of::<T>() as CK_ULONG,
    }
}

fn attr_slice(kind: CK_ATTRIBUTE_TYPE, value: &mut [u8]) -> CK_ATTRIBUTE {
    CK_ATTRIBUTE {
        type_: kind,
        pValue: value.as_mut_ptr() as *mut c_void,
        ulValueLen: value.len() as CK_ULONG,
    }
}

fn attr_bytes(kind: CK_ATTRIBUTE_TYPE, value: &[u8]) -> CK_ATTRIBUTE {
    CK_ATTRIBUTE {
        type_: kind,
        pValue: value.as_ptr() as *mut c_void,
        ulValueLen: value.len() as CK_ULONG,
    }
}

/// Extract a raw 32-byte Ed25519 public key from a `CKA_EC_POINT` value.
///
/// Encoding varies between implementations: raw 32 bytes, a DER OCTET STRING
/// wrapper, or a full SubjectPublicKeyInfo. All three are accepted.
pub fn normalize_ec_point(raw: &[u8]) -> Result<[u8; 32]> {
    if raw.len() == 32 {
        return Ok(raw.try_into().unwrap());
    }

    // DER OCTET STRING: 04 20 <32 bytes>
    if raw.len() == 34 && raw[0] == 0x04 && raw[1] == 0x20 {
        return Ok(raw[2..].try_into().unwrap());
    }

    // SubjectPublicKeyInfo: ends with a BIT STRING carrying the 32-byte key.
    if raw.len() == 44
        && raw[0] == 0x30
        && let Some(pos) = raw.windows(2).position(|w| w == [0x03, 0x21])
        && raw.len() >= pos + 3 + 32
    {
        return Ok(raw[pos + 3..pos + 35].try_into().unwrap());
    }

    bail!(
        "unrecognised CKA_EC_POINT encoding ({} bytes): {}",
        raw.len(),
        raw.iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join("")
    )
}

/// Extract the raw 65-byte uncompressed point (`0x04 || X || Y`) from a
/// P-256 `CKA_EC_POINT` value.
///
/// PKCS#11 wraps the point in a DER OCTET STRING: `04 41 <65 bytes>`. Some
/// modules return the bare point instead, so both are accepted.
pub fn normalize_p256_point(raw: &[u8]) -> Result<[u8; 65]> {
    if raw.len() == 65 && raw[0] == 0x04 {
        return Ok(raw.try_into().unwrap());
    }

    // DER OCTET STRING: 04 41 <65 bytes>
    if raw.len() == 67 && raw[0] == 0x04 && raw[1] == 0x41 && raw[2] == 0x04 {
        return Ok(raw[2..].try_into().unwrap());
    }

    bail!(
        "unrecognised P-256 CKA_EC_POINT encoding ({} bytes): {}",
        raw.len(),
        raw.iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join("")
    )
}

/// Extract the raw 65-byte uncompressed P-256 point from a DER
/// SubjectPublicKeyInfo.
pub fn parse_spki_p256(der: &[u8]) -> Result<[u8; 65]> {
    // Locate the BIT STRING carrying the uncompressed point: 03 42 00 04 ...
    if der.first() == Some(&0x30)
        && let Some(pos) = der.windows(4).position(|w| w == [0x03, 0x42, 0x00, 0x04])
        && der.len() >= pos + 3 + 65
    {
        return Ok(der[pos + 3..pos + 68].try_into().unwrap());
    }

    if der.len() == 65 && der[0] == 0x04 {
        return Ok(der.try_into().unwrap());
    }

    bail!(
        "not a valid P-256 SubjectPublicKeyInfo ({} bytes)",
        der.len()
    )
}

/// Extract the raw 32-byte Ed25519 key from a DER SubjectPublicKeyInfo.
///
/// Needed because the Cosmian module cannot serve Ed25519 public material
/// through `CKA_EC_POINT` — that path is hardcoded to P-256 and returns an
/// error for any other curve — so the public key is supplied out-of-band.
pub fn parse_spki_ed25519(der: &[u8]) -> Result<[u8; 32]> {
    // SEQUENCE { SEQUENCE { OID 1.3.101.112 }, BIT STRING { 32 bytes } }
    if der.len() == 44
        && der[0] == 0x30
        && der[4..9] == ED25519_OID_DER[..]
        && der[9] == 0x03
        && der[10] == 0x21
        && der[11] == 0x00
    {
        return Ok(der[12..44].try_into().unwrap());
    }

    // Fall back to locating the BIT STRING, tolerating header variations.
    if der.first() == Some(&0x30)
        && let Some(pos) = der.windows(3).position(|w| w == [0x03, 0x21, 0x00])
        && der.len() >= pos + 3 + 32
    {
        return Ok(der[pos + 3..pos + 35].try_into().unwrap());
    }

    if der.len() == 32 {
        return Ok(der.try_into().unwrap());
    }

    bail!(
        "not a valid Ed25519 SubjectPublicKeyInfo ({} bytes)",
        der.len()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_raw_32_bytes() {
        let raw = [7u8; 32];
        assert_eq!(normalize_ec_point(&raw).unwrap(), raw);
    }

    #[test]
    fn strips_der_octet_string_wrapper() {
        let mut wrapped = vec![0x04, 0x20];
        wrapped.extend_from_slice(&[9u8; 32]);
        assert_eq!(normalize_ec_point(&wrapped).unwrap(), [9u8; 32]);
    }

    #[test]
    fn extracts_key_from_spki() {
        let mut spki = vec![0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70];
        spki.extend_from_slice(&[0x03, 0x21, 0x00]);
        spki.extend_from_slice(&[5u8; 32]);
        assert_eq!(spki.len(), 44);
        assert_eq!(normalize_ec_point(&spki).unwrap(), [5u8; 32]);
    }

    #[test]
    fn rejects_unknown_encoding() {
        assert!(normalize_ec_point(&[1, 2, 3]).is_err());
    }

    fn spki_of(key: [u8; 32]) -> Vec<u8> {
        let mut der = vec![0x30, 0x2a, 0x30, 0x05];
        der.extend_from_slice(&ED25519_OID_DER);
        der.extend_from_slice(&[0x03, 0x21, 0x00]);
        der.extend_from_slice(&key);
        der
    }

    #[test]
    fn parses_ed25519_spki() {
        let key = [11u8; 32];
        let der = spki_of(key);
        assert_eq!(der.len(), 44);
        assert_eq!(parse_spki_ed25519(&der).unwrap(), key);
    }

    #[test]
    fn accepts_bare_32_byte_public_key() {
        assert_eq!(parse_spki_ed25519(&[3u8; 32]).unwrap(), [3u8; 32]);
    }

    #[test]
    fn rejects_non_spki_bytes() {
        assert!(parse_spki_ed25519(&[0u8; 10]).is_err());
        assert!(parse_spki_ed25519(&[]).is_err());
    }

    #[test]
    fn accepts_raw_p256_point() {
        let mut raw = [0u8; 65];
        raw[0] = 0x04;
        assert_eq!(normalize_p256_point(&raw).unwrap(), raw);
    }

    #[test]
    fn strips_p256_der_octet_string_wrapper() {
        let mut wrapped = vec![0x04, 0x41, 0x04];
        wrapped.extend_from_slice(&[6u8; 64]);
        let mut expected = [0u8; 65];
        expected[0] = 0x04;
        expected[1..].copy_from_slice(&[6u8; 64]);
        assert_eq!(normalize_p256_point(&wrapped).unwrap(), expected);
    }

    #[test]
    fn rejects_unknown_p256_encoding() {
        assert!(normalize_p256_point(&[1, 2, 3]).is_err());
    }

    fn spki_of_p256(point: [u8; 65]) -> Vec<u8> {
        let mut der = vec![0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48];
        der.extend_from_slice(&[0xce, 0x3d, 0x02, 0x01]);
        der.extend_from_slice(&P256_OID_DER);
        der.extend_from_slice(&[0x03, 0x42, 0x00]);
        der.extend_from_slice(&point);
        der
    }

    #[test]
    fn parses_p256_spki() {
        let mut point = [0u8; 65];
        point[0] = 0x04;
        point[1..].copy_from_slice(&[8u8; 64]);
        let der = spki_of_p256(point);
        assert_eq!(parse_spki_p256(&der).unwrap(), point);
    }

    #[test]
    fn accepts_bare_p256_point() {
        let mut point = [0u8; 65];
        point[0] = 0x04;
        assert_eq!(parse_spki_p256(&point).unwrap(), point);
    }

    #[test]
    fn rejects_non_spki_p256_bytes() {
        assert!(parse_spki_p256(&[0u8; 10]).is_err());
        assert!(parse_spki_p256(&[]).is_err());
    }
}
