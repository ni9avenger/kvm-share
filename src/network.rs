// network.rs — reliable TCP sidecar for clipboard sync (port 4243).
//
// Why TCP for clipboard (not UDP like lan-mouse uses for input)?
//   Clipboard content must arrive intact and in order. A dropped packet means
//   a corrupted paste. Clipboard changes are infrequent, so TCP's overhead
//   is irrelevant here.
//
// Wire protocol (dead simple):
//   [4 bytes: payload length as u32 little-endian][N bytes: UTF-8 text]
//
// Both machines run a server AND a client simultaneously:
//   server: listens on 0.0.0.0:4243, accepts one peer connection
//   client: connects to peer_ip:4243 and sends clipboard updates
//
// This symmetric design means neither machine is "primary" — either side
// can copy and the other will receive it.

use crate::AppState;
use log::{debug, info, warn};
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::time::{sleep, Duration};

const CLIPBOARD_PORT: u16 = 4243;
const RECONNECT_DELAY_MS: u64 = 3_000;

// ── Server ───────────────────────────────────────────────────────────────────

/// Listen for incoming clipboard payloads from a peer.
/// Sends received text to `recv_tx` so clipboard.rs can apply it locally.
pub async fn run_server(recv_tx: Sender<String>) {
    let addr = format!("0.0.0.0:{CLIPBOARD_PORT}");
    let listener = TcpListener::bind(&addr)
        .await
        .expect("failed to bind clipboard port {CLIPBOARD_PORT}");
    info!("clipboard server listening on {addr}");

    loop {
        match listener.accept().await {
            Ok((stream, peer)) => {
                info!("clipboard: peer connected from {peer}");
                let tx = recv_tx.clone();
                tokio::spawn(handle_incoming(stream, tx));
            }
            Err(e) => warn!("clipboard: accept error: {e}"),
        }
    }
}

async fn handle_incoming(mut stream: TcpStream, recv_tx: Sender<String>) {
    loop {
        // Read 4-byte length header
        let mut len_buf = [0u8; 4];
        if stream.read_exact(&mut len_buf).await.is_err() {
            debug!("clipboard: peer disconnected (server side)");
            break;
        }
        let len = u32::from_le_bytes(len_buf) as usize;

        // Sanity-check: reject absurdly large payloads (> 10 MB)
        if len > 10 * 1024 * 1024 {
            warn!("clipboard: received suspiciously large payload ({len} bytes), dropping");
            break;
        }

        // Read payload
        let mut buf = vec![0u8; len];
        if stream.read_exact(&mut buf).await.is_err() {
            debug!("clipboard: peer disconnected mid-payload");
            break;
        }

        match String::from_utf8(buf) {
            Ok(text) => {
                debug!("clipboard: received {} chars from peer", text.len());
                let _ = recv_tx.send(text).await;
            }
            Err(e) => warn!("clipboard: received non-UTF8 payload: {e}"),
        }
    }
}

// ── Client ───────────────────────────────────────────────────────────────────

/// Connect to the peer and send clipboard updates.
/// Reconnects automatically if the connection drops.
///
/// - `clip_rx`:  receives local clipboard changes from clipboard.rs
/// - `peer_rx`:  receives peer IP updates from the tray UI
/// - `state`:    shared AppState (read peer IP)
pub async fn run_client(
    mut clip_rx: Receiver<String>,
    mut peer_rx: Receiver<Option<String>>,
    state: Arc<Mutex<AppState>>,
) {
    let mut current_peer: Option<String> = {
        state.lock().unwrap().peer_ip.clone()
    };

    loop {
        // Check for peer IP update from tray
        while let Ok(new_peer) = peer_rx.try_recv() {
            info!("clipboard: peer IP updated to {:?}", new_peer);
            current_peer = new_peer.clone();
            state.lock().unwrap().peer_ip = new_peer;
        }

        let peer_ip = match &current_peer {
            Some(ip) => ip.clone(),
            None => {
                // No peer set yet — wait for tray to set one
                sleep(Duration::from_millis(500)).await;
                // Check for updates
                while let Ok(new_peer) = peer_rx.try_recv() {
                    current_peer = new_peer.clone();
                    state.lock().unwrap().peer_ip = new_peer;
                }
                continue;
            }
        };

        let addr = format!("{peer_ip}:{CLIPBOARD_PORT}");
        info!("clipboard: connecting to {addr}");

        match TcpStream::connect(&addr).await {
            Ok(mut stream) => {
                info!("clipboard: connected to peer at {addr}");
                loop {
                    // Check for peer IP change
                    if let Ok(new_peer) = peer_rx.try_recv() {
                        current_peer = new_peer.clone();
                        state.lock().unwrap().peer_ip = new_peer;
                        break; // reconnect to new peer
                    }

                    // Wait for clipboard change
                    match clip_rx.recv().await {
                        Some(text) => {
                            if let Err(e) = send_payload(&mut stream, &text).await {
                                warn!("clipboard: send error: {e}");
                                break; // reconnect
                            }
                            debug!("clipboard: sent {} chars to peer", text.len());
                        }
                        None => break, // channel closed, shut down
                    }
                }
            }
            Err(e) => {
                debug!("clipboard: could not connect to {addr}: {e}");
                sleep(Duration::from_millis(RECONNECT_DELAY_MS)).await;
            }
        }
    }
}

/// Send a length-prefixed UTF-8 payload.
async fn send_payload(stream: &mut TcpStream, text: &str) -> tokio::io::Result<()> {
    let bytes = text.as_bytes();
    let len = (bytes.len() as u32).to_le_bytes();
    stream.write_all(&len).await?;
    stream.write_all(bytes).await?;
    stream.flush().await?;
    Ok(())
}
