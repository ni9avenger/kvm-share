// net.rs — networking layer
//
// Two channels:
//
//   UDP port 4242  — input events (mouse/keyboard)
//     Both machines bind a UDP socket and send/receive to each other's IP.
//     Fire-and-forget: a dropped mouse-move doesn't matter, the next arrives immediately.
//
//   TCP port 4243  — clipboard sync
//     Length-prefixed UTF-8 payload. Both machines run a server + client.
//     Protocol: [4 bytes u32-LE length][N bytes UTF-8 text]

use crate::protocol::NetEvent;
use log::{debug, info, warn};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::time::{sleep, Duration};

const UDP_BUF: usize = 4096;
const MAX_CLIPBOARD_BYTES: usize = 10 * 1024 * 1024; // 10 MB
const RECONNECT_MS: u64 = 2_000;

// ── UDP input sender ─────────────────────────────────────────────────────────

/// Receive NetEvents from the capture layer and send them over UDP to the peer.
pub async fn run_udp_sender(mut rx: Receiver<NetEvent>, peer_addr: String) {
    let socket = match UdpSocket::bind("0.0.0.0:0").await {
        Ok(s) => s,
        Err(e) => { warn!("udp sender: bind failed: {e}"); return; }
    };

    info!("udp sender: sending to {peer_addr}");

    loop {
        match rx.recv().await {
            Some(event) => {
                let bytes = event.to_bytes();
                if let Err(e) = socket.send_to(&bytes, &peer_addr).await {
                    debug!("udp sender: {e}");
                }
            }
            None => break,
        }
    }
}

// ── UDP input receiver ────────────────────────────────────────────────────────

/// Listen for incoming NetEvents from the peer and forward to the inject layer.
/// Includes the sender's SocketAddr so the coordinator can learn the peer's IP
/// automatically (needed for the auto-return path when being controlled).
pub async fn run_udp_receiver(tx: Sender<(NetEvent, std::net::SocketAddr)>, bind_addr: String) {
    let socket = match UdpSocket::bind(&bind_addr).await {
        Ok(s) => s,
        Err(e) => { warn!("udp receiver: bind failed on {bind_addr}: {e}"); return; }
    };

    info!("udp receiver: listening on {bind_addr}");
    let mut buf = vec![0u8; UDP_BUF];

    loop {
        match socket.recv_from(&mut buf).await {
            Ok((len, from)) => {
                if let Some(event) = NetEvent::from_bytes(&buf[..len]) {
                    let _ = tx.send((event, from)).await;
                }
            }
            Err(e) => debug!("udp receiver: {e}"),
        }
    }
}

// ── TCP clipboard server ──────────────────────────────────────────────────────

/// Accept clipboard payloads from a peer and forward to the clipboard layer.
pub async fn run_clipboard_server(tx: Sender<String>, bind_addr: String) {
    let listener = match TcpListener::bind(&bind_addr).await {
        Ok(l) => l,
        Err(e) => { warn!("clipboard server: bind failed on {bind_addr}: {e}"); return; }
    };

    info!("clipboard server: listening on {bind_addr}");

    loop {
        match listener.accept().await {
            Ok((stream, peer)) => {
                info!("clipboard: peer connected from {peer}");
                let tx2 = tx.clone();
                tokio::spawn(handle_clipboard_recv(stream, tx2));
            }
            Err(e) => warn!("clipboard server: accept error: {e}"),
        }
    }
}

async fn handle_clipboard_recv(mut stream: TcpStream, tx: Sender<String>) {
    loop {
        let mut len_buf = [0u8; 4];
        if stream.read_exact(&mut len_buf).await.is_err() {
            debug!("clipboard: peer disconnected");
            break;
        }
        let len = u32::from_le_bytes(len_buf) as usize;

        if len > MAX_CLIPBOARD_BYTES {
            warn!("clipboard: payload too large ({len} bytes), dropping connection");
            break;
        }

        let mut payload = vec![0u8; len];
        if stream.read_exact(&mut payload).await.is_err() {
            break;
        }

        match String::from_utf8(payload) {
            Ok(text) => { let _ = tx.send(text).await; }
            Err(e) => warn!("clipboard: non-UTF8 payload: {e}"),
        }
    }
}

// ── TCP clipboard client ──────────────────────────────────────────────────────

/// Connect to the peer's clipboard server and send local clipboard changes.
/// Reconnects automatically on disconnect.
pub async fn run_clipboard_client(mut rx: Receiver<String>, peer_addr: String) {
    loop {
        info!("clipboard client: connecting to {peer_addr}");
        match TcpStream::connect(&peer_addr).await {
            Ok(mut stream) => {
                info!("clipboard client: connected");
                loop {
                    match rx.recv().await {
                        Some(text) => {
                            if let Err(e) = send_clipboard_payload(&mut stream, &text).await {
                                debug!("clipboard client: send error: {e}");
                                break; // reconnect
                            }
                            debug!("clipboard client: sent {} chars", text.len());
                        }
                        None => return, // channel closed, shut down
                    }
                }
            }
            Err(e) => {
                debug!("clipboard client: could not connect to {peer_addr}: {e}");
                sleep(Duration::from_millis(RECONNECT_MS)).await;
            }
        }
    }
}

async fn send_clipboard_payload(stream: &mut TcpStream, text: &str) -> tokio::io::Result<()> {
    let bytes = text.as_bytes();
    stream.write_all(&(bytes.len() as u32).to_le_bytes()).await?;
    stream.write_all(bytes).await?;
    stream.flush().await
}
