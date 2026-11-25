// net.rs — UDP input channel (protocol v2).
//
//   UDP port 4252 — input events (mouse/keyboard), signed.
//     Fire-and-forget: a dropped mouse-move doesn't matter, the next arrives
//     immediately. TCP would queue stale events behind a lost one.
//
// v2 changes:
//   - Every datagram is signed with a key derived from the pairing key and
//     the sender's session id (wire.rs). Unsigned, wrongly-signed, replayed,
//     or v0.1.x datagrams are dropped before anything is injected.
//   - The receiver only accepts the session id the peer announced over the
//     authenticated control channel, so replays from an earlier run fail.
//   - The sender follows a watch of the peer address, so an IP change takes
//     effect on the next packet (v0.1.x kept the startup address, §7.1).
//
// Clipboard moved to the control channel (control.rs).

use crate::protocol::NetEvent;
use crate::wire::{self, ReplayWindow};
use log::{debug, info, warn};
use std::net::{IpAddr, SocketAddr};
use tokio::net::UdpSocket;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::sync::watch;

const UDP_BUF: usize = 4096;

// ── UDP input sender ─────────────────────────────────────────────────────────

pub struct UdpOut {
    pub port: u16,
    pub session: u32,
    pub peer: watch::Receiver<Option<IpAddr>>,
    pub key: watch::Receiver<Option<[u8; 32]>>,
}

/// Sign NetEvents from the capture layer and send them to the current peer.
pub async fn run_udp_sender(mut rx: Receiver<NetEvent>, mut out: UdpOut) {
    let socket = match UdpSocket::bind("0.0.0.0:0").await {
        Ok(s) => s,
        Err(e) => {
            warn!("udp sender: bind failed: {e}");
            return;
        }
    };
    info!("udp sender: ready (session {:08x})", out.session);

    let mut seq: u64 = 0;
    let mut udp_key: Option<[u8; 32]> = None;
    let mut key_seen = false;

    while let Some(event) = rx.recv().await {
        if !key_seen || out.key.has_changed().unwrap_or(false) {
            udp_key = out.key.borrow_and_update().map(|k| wire::udp_key(&k, out.session));
            key_seen = true;
        }
        let (Some(k), Some(ip)) = (udp_key.as_ref(), *out.peer.borrow()) else {
            continue; // not paired / no peer: nothing to send to
        };
        seq += 1;
        let pkt = wire::seal_udp(k, out.session, seq, &event);
        if let Err(e) = socket.send_to(&pkt, SocketAddr::new(ip, out.port)).await {
            debug!("udp sender: {e}");
        }
    }
}

// ── UDP input receiver ────────────────────────────────────────────────────────

pub struct UdpIn {
    pub bind: String,
    pub key: watch::Receiver<Option<[u8; 32]>>,
    /// Session the authenticated peer announced; None = accept nothing.
    pub accepted: watch::Receiver<Option<u32>>,
}

/// Verify incoming datagrams and forward them, with the sender's address, to
/// the coordinator.
pub async fn run_udp_receiver(tx: Sender<(NetEvent, SocketAddr)>, inp: UdpIn) {
    let socket = match UdpSocket::bind(&inp.bind).await {
        Ok(s) => s,
        Err(e) => {
            warn!("udp receiver: bind failed on {}: {e}", inp.bind);
            return;
        }
    };
    info!("udp receiver: listening on {}", inp.bind);
    receive_loop(socket, tx, inp).await;
}

async fn receive_loop(socket: UdpSocket, tx: Sender<(NetEvent, SocketAddr)>, inp: UdpIn) {
    let mut buf = vec![0u8; UDP_BUF];
    // (session, derived key) cache and the replay window for that session.
    let mut cached: Option<(u32, [u8; 32], [u8; 32])> = None;
    let mut window = ReplayWindow::default();
    let mut rejected: u64 = 0;

    loop {
        let (len, from) = match socket.recv_from(&mut buf).await {
            Ok(x) => x,
            Err(e) => {
                // Windows reports ICMP "port unreachable" from earlier sends
                // as a recv error on UDP sockets; it is harmless.
                debug!("udp receiver: {e}");
                continue;
            }
        };
        let data = &buf[..len];
        let accepted = *inp.accepted.borrow();
        let pair_key = *inp.key.borrow();
        let (Some(session), Some(pair_key), Some(hdr)) = (accepted, pair_key, wire::peek_udp(data)) else {
            rejected += 1;
            if rejected.is_power_of_two() {
                debug!("udp receiver: dropped {rejected} unauthenticated datagram(s), last from {from}");
            }
            continue;
        };
        if hdr.session != session {
            rejected += 1;
            continue;
        }
        let key = match cached {
            Some((s, pk, k)) if s == session && pk == pair_key => k,
            _ => {
                let k = wire::udp_key(&pair_key, session);
                cached = Some((session, pair_key, k));
                window = ReplayWindow::default();
                k
            }
        };
        let Some(event) = wire::open_udp(&key, data) else {
            rejected += 1;
            continue;
        };
        if !window.accept(hdr.seq) {
            continue; // replay or too old
        }
        if tx.send((event, from)).await.is_err() {
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::mpsc;
    use tokio::time::{timeout, Duration};

    #[tokio::test]
    async fn signed_datagrams_only() {
        let pair_key = [5u8; 32];
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = sock.local_addr().unwrap().port();
        let (_k_tx, key) = watch::channel(Some(pair_key));
        let (acc_tx, accepted) = watch::channel(Some(77u32));
        let (tx, mut rx) = mpsc::channel(16);
        tokio::spawn(receive_loop(sock, tx, UdpIn { bind: String::new(), key, accepted }));

        let s = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let k = wire::udp_key(&pair_key, 77);
        let ev = NetEvent::Key { key: rdev::Key::KeyA, pressed: true };
        let good = wire::seal_udp(&k, 77, 1, &ev);
        let dest = ("127.0.0.1", port);

        s.send_to(&bincode::serialize(&ev).unwrap(), dest).await.unwrap(); // v0.1.x style
        s.send_to(&wire::seal_udp(&wire::udp_key(&[6u8; 32], 77), 77, 1, &ev), dest).await.unwrap(); // wrong key
        s.send_to(&wire::seal_udp(&wire::udp_key(&pair_key, 78), 78, 1, &ev), dest).await.unwrap(); // wrong session
        s.send_to(&good, dest).await.unwrap();
        s.send_to(&good, dest).await.unwrap(); // replay

        let got = timeout(Duration::from_secs(2), rx.recv()).await.unwrap().unwrap();
        assert!(matches!(got.0, NetEvent::Key { pressed: true, .. }));
        assert!(timeout(Duration::from_millis(300), rx.recv()).await.is_err(), "only one datagram may pass");

        // Peer gone (session cleared) → nothing accepted.
        acc_tx.send_replace(None);
        s.send_to(&wire::seal_udp(&k, 77, 2, &ev), dest).await.unwrap();
        assert!(timeout(Duration::from_millis(300), rx.recv()).await.is_err());
    }

    #[tokio::test]
    async fn sender_follows_peer_address() {
        let a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = a.local_addr().unwrap().port();
        let (_kt, key) = watch::channel(Some([1u8; 32]));
        let (peer_tx, peer) = watch::channel(None);
        let (tx, rx) = mpsc::channel(8);
        tokio::spawn(run_udp_sender(rx, UdpOut { port, session: 3, peer, key }));

        tx.send(NetEvent::Ping).await.unwrap(); // no peer yet → dropped
        peer_tx.send_replace(Some("127.0.0.1".parse().unwrap()));
        tx.send(NetEvent::Ping).await.unwrap();
        let mut buf = [0u8; 256];
        let (n, _) = timeout(Duration::from_secs(2), a.recv_from(&mut buf)).await.unwrap().unwrap();
        let h = wire::peek_udp(&buf[..n]).unwrap();
        assert_eq!(h.session, 3);
        assert_eq!(h.seq, 1, "the packet sent before a peer existed must not consume a sequence number");
    }
}
