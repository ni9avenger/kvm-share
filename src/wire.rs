// wire.rs — protocol v2 framing: signed UDP datagrams and signed TCP frames.
//
// Why a new layer instead of extending protocol.rs:
//   protocol.rs defines WHAT is sent (NetEvent). This file defines HOW it is
//   packaged so the receiver can trust it: who sent it (HMAC with the pairing
//   key), that it is fresh (session id + sequence window on UDP, implicit
//   counter on TCP), and that the peer speaks the same protocol version.
//
// UDP datagram:  ["K2"][u32 session][u64 seq][bincode NetEvent][16-byte tag]
//   Sliding 64-packet replay window, not "seq must increase": UDP reorders,
//   and dropping a reordered key-up would leave a key stuck on the peer.
//
// TCP frame:     [u32 LE len][body][16-byte tag if keyed]
//   The very first frame each way is the Hello: ["KVMS"][u16 proto][bincode].
//   The proto number sits OUTSIDE bincode so a future version can still read
//   it and report "different version" instead of failing to parse.

use crate::crypto::{self, TAG_LEN};
use crate::protocol::NetEvent;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Bump on any incompatible change to wire.rs, protocol.rs or control flow.
pub const PROTO_VERSION: u16 = 2;
pub const APP_VERSION: &str = env!("CARGO_PKG_VERSION");

const UDP_MAGIC: &[u8; 2] = b"K2";
const HELLO_MAGIC: &[u8; 4] = b"KVMS";
/// Clipboard text is capped at 10 MB; leave room for framing.
pub const MAX_FRAME: usize = 11 * 1024 * 1024;

// ── UDP ──────────────────────────────────────────────────────────────────────

pub fn udp_key(pair_key: &[u8; 32], session: u32) -> [u8; 32] {
    crypto::hkdf(pair_key, &session.to_le_bytes(), b"kvm-share udp v2")
}

pub fn seal_udp(key: &[u8; 32], session: u32, seq: u64, ev: &NetEvent) -> Vec<u8> {
    let mut out = Vec::with_capacity(48);
    out.extend_from_slice(UDP_MAGIC);
    out.extend_from_slice(&session.to_le_bytes());
    out.extend_from_slice(&seq.to_le_bytes());
    out.extend_from_slice(&bincode::serialize(ev).unwrap_or_default());
    let t = crypto::tag(key, &[&out]);
    out.extend_from_slice(&t);
    out
}

/// Parsed header of a datagram, before the tag is checked.
pub struct UdpHeader {
    pub session: u32,
    pub seq: u64,
}

pub fn peek_udp(data: &[u8]) -> Option<UdpHeader> {
    if data.len() < 2 + 4 + 8 + TAG_LEN || &data[..2] != UDP_MAGIC {
        return None;
    }
    Some(UdpHeader {
        session: u32::from_le_bytes(data[2..6].try_into().ok()?),
        seq: u64::from_le_bytes(data[6..14].try_into().ok()?),
    })
}

/// Verify the tag and decode. Replay checking is the caller's job (it owns
/// the window), and must happen only after this returns Some.
pub fn open_udp(key: &[u8; 32], data: &[u8]) -> Option<NetEvent> {
    peek_udp(data)?;
    let (body, t) = data.split_at(data.len() - TAG_LEN);
    if !crypto::verify_tag(key, &[body], t) {
        return None;
    }
    bincode::deserialize(&body[14..]).ok()
}

/// IPsec-style anti-replay window over the last 64 sequence numbers.
#[derive(Default)]
pub struct ReplayWindow {
    top: u64,
    bits: u64,
    any: bool,
}

impl ReplayWindow {
    /// True if `seq` is new (and records it); false for duplicates or
    /// packets older than the window.
    pub fn accept(&mut self, seq: u64) -> bool {
        if !self.any {
            self.any = true;
            self.top = seq;
            self.bits = 1;
            return true;
        }
        if seq > self.top {
            let shift = seq - self.top;
            self.bits = if shift >= 64 { 0 } else { self.bits << shift };
            self.bits |= 1;
            self.top = seq;
            return true;
        }
        let age = self.top - seq;
        if age >= 64 {
            return false;
        }
        let mask = 1u64 << age;
        if self.bits & mask != 0 {
            return false;
        }
        self.bits |= mask;
        true
    }
}

// ── TCP control messages ────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Purpose {
    /// Normal paired session.
    Session,
    /// First-time pairing (no key yet).
    Pair,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hello {
    pub app_version: String,
    pub name: String,
    pub nonce: [u8; 16],
    /// Session id this side signs its UDP datagrams with.
    pub udp_session: u32,
    pub purpose: Purpose,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Msg {
    Auth {
        mac: [u8; 32],
    },
    PairCommit {
        name: String,
        commit: [u8; 32],
    },
    PairReveal {
        name: String,
        public: [u8; 32],
        nonce: [u8; 16],
    },
    PairConfirm {
        mac: [u8; 32],
    },
    PairCancel,
    Ping,
    ClipText(String),
    /// Polite close with a reason the peer can show the owner.
    Bye(String),
}

#[derive(Debug)]
pub enum WireError {
    Io(std::io::Error),
    TooLarge(usize),
    BadTag,
    Decode,
    /// Hello from a different protocol version (value = peer's version).
    Version(u16),
    NotKvm,
}

impl std::fmt::Display for WireError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WireError::Io(e) => write!(f, "io: {e}"),
            WireError::TooLarge(n) => write!(f, "frame too large ({n} bytes)"),
            WireError::BadTag => write!(f, "bad signature (wrong pairing key or tampered)"),
            WireError::Decode => write!(f, "undecodable frame"),
            WireError::Version(v) => write!(f, "peer protocol v{v}, this build v{PROTO_VERSION}"),
            WireError::NotKvm => write!(f, "not a kvm-share peer"),
        }
    }
}

impl From<std::io::Error> for WireError {
    fn from(e: std::io::Error) -> Self {
        WireError::Io(e)
    }
}

async fn write_raw<W: AsyncWrite + Unpin>(w: &mut W, body: &[u8]) -> Result<(), WireError> {
    w.write_all(&(body.len() as u32).to_le_bytes()).await?;
    w.write_all(body).await?;
    w.flush().await?;
    Ok(())
}

async fn read_raw<R: AsyncRead + Unpin>(r: &mut R) -> Result<Vec<u8>, WireError> {
    let mut len = [0u8; 4];
    r.read_exact(&mut len).await?;
    let n = u32::from_le_bytes(len) as usize;
    if n > MAX_FRAME {
        return Err(WireError::TooLarge(n));
    }
    let mut body = vec![0u8; n];
    r.read_exact(&mut body).await?;
    Ok(body)
}

pub async fn write_hello<W: AsyncWrite + Unpin>(w: &mut W, h: &Hello) -> Result<(), WireError> {
    let mut body = Vec::new();
    body.extend_from_slice(HELLO_MAGIC);
    body.extend_from_slice(&PROTO_VERSION.to_le_bytes());
    body.extend_from_slice(&bincode::serialize(h).map_err(|_| WireError::Decode)?);
    write_raw(w, &body).await
}

pub async fn read_hello<R: AsyncRead + Unpin>(r: &mut R) -> Result<Hello, WireError> {
    let body = read_raw(r).await?;
    if body.len() < 6 || &body[..4] != HELLO_MAGIC {
        return Err(WireError::NotKvm);
    }
    let proto = u16::from_le_bytes([body[4], body[5]]);
    if proto != PROTO_VERSION {
        return Err(WireError::Version(proto));
    }
    bincode::deserialize(&body[6..]).map_err(|_| WireError::Decode)
}

/// One direction of a framed connection. With a key, every frame carries a
/// tag over (counter ‖ body); the counter is implicit because TCP is ordered,
/// so replayed, dropped or reordered frames fail verification.
pub struct FrameCodec {
    key: Option<[u8; 32]>,
    counter: u64,
}

impl FrameCodec {
    pub fn plain() -> Self {
        Self {
            key: None,
            counter: 0,
        }
    }
    pub fn keyed(key: [u8; 32]) -> Self {
        Self {
            key: Some(key),
            counter: 0,
        }
    }

    pub async fn write<W: AsyncWrite + Unpin>(
        &mut self,
        w: &mut W,
        m: &Msg,
    ) -> Result<(), WireError> {
        let mut body = bincode::serialize(m).map_err(|_| WireError::Decode)?;
        if let Some(k) = &self.key {
            let t = crypto::tag(k, &[&self.counter.to_le_bytes(), &body]);
            body.extend_from_slice(&t);
            self.counter += 1;
        }
        write_raw(w, &body).await
    }

    pub async fn read<R: AsyncRead + Unpin>(&mut self, r: &mut R) -> Result<Msg, WireError> {
        let mut body = read_raw(r).await?;
        if let Some(k) = &self.key {
            if body.len() < TAG_LEN {
                return Err(WireError::BadTag);
            }
            let t = body.split_off(body.len() - TAG_LEN);
            if !crypto::verify_tag(k, &[&self.counter.to_le_bytes(), &body], &t) {
                return Err(WireError::BadTag);
            }
            self.counter += 1;
        }
        bincode::deserialize(&body).map_err(|_| WireError::Decode)
    }
}

/// Per-direction keys for one authenticated connection.
pub fn session_keys(
    pair_key: &[u8; 32],
    nonce_c: &[u8; 16],
    nonce_s: &[u8; 16],
) -> ([u8; 32], [u8; 32]) {
    let salt = [&nonce_c[..], &nonce_s[..]].concat();
    (
        crypto::hkdf(pair_key, &salt, b"kvm-share c2s v2"),
        crypto::hkdf(pair_key, &salt, b"kvm-share s2c v2"),
    )
}

/// Proof of key possession bound to this connection's nonces and role.
pub fn auth_mac(
    pair_key: &[u8; 32],
    role: &[u8],
    nonce_c: &[u8; 16],
    nonce_s: &[u8; 16],
) -> [u8; 32] {
    crypto::hmac(pair_key, &[b"kvm-share auth v2", role, nonce_c, nonce_s])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn udp_round_trip_and_tamper() {
        let k = udp_key(&[7u8; 32], 42);
        let ev = NetEvent::MouseMove { dx: 3.0, dy: -2.0 };
        let pkt = seal_udp(&k, 42, 9, &ev);
        let h = peek_udp(&pkt).unwrap();
        assert_eq!((h.session, h.seq), (42, 9));
        assert!(matches!(
            open_udp(&k, &pkt),
            Some(NetEvent::MouseMove { .. })
        ));

        let mut bad = pkt.clone();
        bad[15] ^= 1;
        assert!(open_udp(&k, &bad).is_none());
        assert!(open_udp(&udp_key(&[8u8; 32], 42), &pkt).is_none());
        // v0.1.x bincode datagram is rejected outright.
        assert!(open_udp(&k, &bincode::serialize(&ev).unwrap()).is_none());
    }

    #[test]
    fn replay_window() {
        let mut w = ReplayWindow::default();
        assert!(w.accept(10));
        assert!(!w.accept(10)); // duplicate
        assert!(w.accept(12));
        assert!(w.accept(11)); // reordered, still new
        assert!(!w.accept(11));
        assert!(w.accept(100));
        assert!(!w.accept(36)); // older than 64 behind
        assert!(w.accept(37)); // exactly 63 behind
        assert!(w.accept(1000)); // big jump clears window
        assert!(!w.accept(100));
    }

    #[tokio::test]
    async fn frames_keyed_and_plain() {
        let (mut a, mut b) = tokio::io::duplex(1 << 16);
        let mut tx = FrameCodec::keyed([1u8; 32]);
        let mut rx = FrameCodec::keyed([1u8; 32]);
        tx.write(&mut a, &Msg::Ping).await.unwrap();
        tx.write(&mut a, &Msg::ClipText("hi".into())).await.unwrap();
        assert!(matches!(rx.read(&mut b).await.unwrap(), Msg::Ping));
        assert!(matches!(rx.read(&mut b).await.unwrap(), Msg::ClipText(s) if s == "hi"));

        // Wrong key fails.
        let mut wrong = FrameCodec::keyed([2u8; 32]);
        tx.write(&mut a, &Msg::Ping).await.unwrap();
        assert!(matches!(wrong.read(&mut b).await, Err(WireError::BadTag)));

        // Counter mismatch (replayed frame) fails.
        let (mut c, mut d) = tokio::io::duplex(1 << 16);
        let mut tx2 = FrameCodec::keyed([1u8; 32]);
        tx2.write(&mut c, &Msg::Ping).await.unwrap();
        let mut rx2 = FrameCodec::keyed([1u8; 32]);
        rx2.counter = 5;
        assert!(matches!(rx2.read(&mut d).await, Err(WireError::BadTag)));

        let mut p = FrameCodec::plain();
        p.write(&mut c, &Msg::PairCancel).await.unwrap();
        assert!(matches!(
            FrameCodec::plain().read(&mut d).await.unwrap(),
            Msg::PairCancel
        ));
    }

    #[tokio::test]
    async fn hello_version_mismatch_is_reported() {
        let (mut a, mut b) = tokio::io::duplex(1 << 16);
        let mut body = Vec::new();
        body.extend_from_slice(HELLO_MAGIC);
        body.extend_from_slice(&3u16.to_le_bytes());
        body.extend_from_slice(b"future format");
        write_raw(&mut a, &body).await.unwrap();
        assert!(matches!(
            read_hello(&mut b).await,
            Err(WireError::Version(3))
        ));

        write_raw(&mut a, b"GET / HTTP/1.1").await.unwrap();
        assert!(matches!(read_hello(&mut b).await, Err(WireError::NotKvm)));
    }

    #[tokio::test]
    async fn oversized_frame_rejected() {
        let (mut a, mut b) = tokio::io::duplex(64);
        a.write_all(&((MAX_FRAME as u32) + 1).to_le_bytes())
            .await
            .unwrap();
        assert!(matches!(
            read_raw(&mut b).await,
            Err(WireError::TooLarge(_))
        ));
    }
}
