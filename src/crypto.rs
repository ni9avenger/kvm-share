// crypto.rs — the small set of primitives pairing and packet signing need.
//
// Why these and nothing more:
//   v0.1.x accepted input from any host that could reach the UDP port. v0.2
//   adds file transfer, which raises the stakes, so every packet is now
//   authenticated with a key both PCs agreed on once, at pairing time.
//   This is authentication, NOT encryption: traffic is still readable on the
//   LAN. Encryption is a later roadmap item.
//
//   - X25519 (x25519-dalek) for the one-time key agreement during pairing.
//   - HMAC-SHA256 (hmac + sha2) for every frame/datagram tag, and HKDF built
//     on it (RFC 5869, ~15 lines) for deriving per-purpose keys.
//   - Randomness from BCryptGenRandom and at-rest protection of the stored
//     pairing key with DPAPI (current user) — both are already in Windows,
//     so no extra crates. Non-Windows arms exist only so the crate builds.

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

/// Length of the truncated HMAC tag on every frame and datagram.
pub const TAG_LEN: usize = 16;

// ── Randomness ───────────────────────────────────────────────────────────────

pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut buf = [0u8; N];
    fill_random(&mut buf);
    buf
}

#[cfg(windows)]
fn fill_random(buf: &mut [u8]) {
    use windows_sys::Win32::Security::Cryptography::{
        BCryptGenRandom, BCRYPT_USE_SYSTEM_PREFERRED_RNG,
    };
    let status = unsafe {
        BCryptGenRandom(
            std::ptr::null_mut(),
            buf.as_mut_ptr(),
            buf.len() as u32,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG,
        )
    };
    // A failing system RNG is not something to limp along with: keys and
    // nonces from a broken RNG would silently defeat the whole scheme.
    assert!(status >= 0, "BCryptGenRandom failed: {status:#x}");
}

#[cfg(not(windows))]
fn fill_random(buf: &mut [u8]) {
    use std::io::Read;
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(buf))
        .expect("/dev/urandom");
}

// ── Hashing / MAC / KDF ─────────────────────────────────────────────────────

pub fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

pub fn hmac(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut m = HmacSha256::new_from_slice(key).expect("hmac accepts any key length");
    for p in parts {
        m.update(p);
    }
    m.finalize().into_bytes().into()
}

/// Truncated tag for frames and datagrams.
pub fn tag(key: &[u8], parts: &[&[u8]]) -> [u8; TAG_LEN] {
    let full = hmac(key, parts);
    let mut t = [0u8; TAG_LEN];
    t.copy_from_slice(&full[..TAG_LEN]);
    t
}

/// Constant-time tag check (via the hmac crate's verify).
pub fn verify_tag(key: &[u8], parts: &[&[u8]], tag: &[u8]) -> bool {
    if tag.len() != TAG_LEN {
        return false;
    }
    let mut m = HmacSha256::new_from_slice(key).expect("hmac accepts any key length");
    for p in parts {
        m.update(p);
    }
    m.verify_truncated_left(tag).is_ok()
}

/// HKDF-SHA256 (RFC 5869) producing one 32-byte key.
pub fn hkdf(ikm: &[u8], salt: &[u8], info: &[u8]) -> [u8; 32] {
    let prk = hmac(salt, &[ikm]);
    hmac(&prk, &[info, &[1u8]])
}

// ── Key agreement ────────────────────────────────────────────────────────────

pub struct EphemeralKey {
    secret: x25519_dalek::StaticSecret,
    pub public: [u8; 32],
}

impl EphemeralKey {
    pub fn generate() -> Self {
        let secret = x25519_dalek::StaticSecret::from(random_bytes::<32>());
        let public = x25519_dalek::PublicKey::from(&secret).to_bytes();
        Self { secret, public }
    }

    pub fn agree(&self, peer_public: &[u8; 32]) -> [u8; 32] {
        let peer = x25519_dalek::PublicKey::from(*peer_public);
        self.secret.diffie_hellman(&peer).to_bytes()
    }
}

/// Result of a completed key exchange, before the owner confirms the code.
pub struct PairingSecret {
    pub key: [u8; 32],
    /// 6-digit code both PCs display; the owner checks they match.
    pub code: u32,
}

/// Derive the long-term pairing key and the comparison code. Inputs are
/// ordered initiator-first so both sides compute identical values.
pub fn derive_pairing(
    shared: &[u8; 32],
    pub_initiator: &[u8; 32],
    pub_responder: &[u8; 32],
    nonce_initiator: &[u8; 16],
    nonce_responder: &[u8; 16],
) -> PairingSecret {
    let salt = [&nonce_initiator[..], &nonce_responder[..]].concat();
    let key = hkdf(shared, &salt, b"kvm-share pairing key v2");
    let sas = sha256(&[
        b"kvm-share sas v2",
        pub_initiator,
        pub_responder,
        nonce_initiator,
        nonce_responder,
    ]);
    let n = u32::from_le_bytes([sas[0], sas[1], sas[2], sas[3]]);
    PairingSecret {
        key,
        code: n % 1_000_000,
    }
}

// ── At-rest protection of the pairing key ────────────────────────────────────

/// Encrypt for the current Windows user (DPAPI). Another user account or a
/// copy of config-v2.json on another PC cannot decrypt it.
#[cfg(windows)]
pub fn protect(data: &[u8]) -> Option<Vec<u8>> {
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Cryptography::{
        CryptProtectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
    };
    unsafe {
        let input = CRYPT_INTEGER_BLOB {
            cbData: data.len() as u32,
            pbData: data.as_ptr() as *mut u8,
        };
        let mut out = CRYPT_INTEGER_BLOB {
            cbData: 0,
            pbData: std::ptr::null_mut(),
        };
        let ok = CryptProtectData(
            &input,
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut out,
        );
        if ok == 0 {
            return None;
        }
        let v = std::slice::from_raw_parts(out.pbData, out.cbData as usize).to_vec();
        LocalFree(out.pbData as _);
        Some(v)
    }
}

#[cfg(windows)]
pub fn unprotect(data: &[u8]) -> Option<Vec<u8>> {
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Cryptography::{
        CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
    };
    unsafe {
        let input = CRYPT_INTEGER_BLOB {
            cbData: data.len() as u32,
            pbData: data.as_ptr() as *mut u8,
        };
        let mut out = CRYPT_INTEGER_BLOB {
            cbData: 0,
            pbData: std::ptr::null_mut(),
        };
        let ok = CryptUnprotectData(
            &input,
            std::ptr::null_mut(),
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut out,
        );
        if ok == 0 {
            return None;
        }
        let v = std::slice::from_raw_parts(out.pbData, out.cbData as usize).to_vec();
        LocalFree(out.pbData as _);
        Some(v)
    }
}

#[cfg(not(windows))]
pub fn protect(data: &[u8]) -> Option<Vec<u8>> {
    Some(data.to_vec())
}

#[cfg(not(windows))]
pub fn unprotect(data: &[u8]) -> Option<Vec<u8>> {
    Some(data.to_vec())
}

// ── Hex (config storage) ─────────────────────────────────────────────────────

pub fn to_hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

pub fn from_hex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hkdf_rfc5869_case1() {
        // RFC 5869 test case 1, first 32 bytes of OKM.
        let ikm = [0x0bu8; 22];
        let salt = from_hex("000102030405060708090a0b0c").unwrap();
        let info = from_hex("f0f1f2f3f4f5f6f7f8f9").unwrap();
        let okm = hkdf(&ikm, &salt, &info);
        assert_eq!(
            to_hex(&okm),
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
        );
    }

    #[test]
    fn both_sides_derive_same_pairing() {
        let a = EphemeralKey::generate();
        let b = EphemeralKey::generate();
        let (na, nb) = (random_bytes::<16>(), random_bytes::<16>());
        let sa = derive_pairing(&a.agree(&b.public), &a.public, &b.public, &na, &nb);
        let sb = derive_pairing(&b.agree(&a.public), &a.public, &b.public, &na, &nb);
        assert_eq!(sa.key, sb.key);
        assert_eq!(sa.code, sb.code);
        assert!(sa.code < 1_000_000);
    }

    #[test]
    fn tag_rejects_tampering() {
        let k = random_bytes::<32>();
        let t = tag(&k, &[b"hello", b"world"]);
        assert!(verify_tag(&k, &[b"hello", b"world"], &t));
        assert!(!verify_tag(&k, &[b"hello", b"worle"], &t));
        assert!(!verify_tag(
            &random_bytes::<32>(),
            &[b"hello", b"world"],
            &t
        ));
    }

    #[test]
    fn dpapi_round_trip() {
        let secret = random_bytes::<32>();
        let sealed = protect(&secret).unwrap();
        assert_ne!(sealed, secret.to_vec());
        assert_eq!(unprotect(&sealed).unwrap(), secret.to_vec());
    }

    #[test]
    fn hex_round_trip() {
        let b = random_bytes::<20>();
        assert_eq!(from_hex(&to_hex(&b)).unwrap(), b.to_vec());
        assert!(from_hex("abc").is_none());
        assert!(from_hex("zz").is_none());
    }
}
