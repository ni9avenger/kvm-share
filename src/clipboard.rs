// clipboard.rs — monitor local clipboard for changes, apply received content.
//
// Two responsibilities:
//   1. MONITOR: poll local clipboard every 200 ms; if content changed, send
//      the new text to `out_tx` so the network layer can broadcast it.
//   2. APPLY:   when `in_rx` receives text from the network, set the local
//      clipboard — but track what we just set so we don't echo it back.

use arboard::Clipboard;
use log::{debug, warn};
use std::time::Duration;
use tokio::sync::mpsc::{Receiver, Sender};

const POLL_INTERVAL_MS: u64 = 200;

/// Run the clipboard monitor loop.
///
/// - `out_tx`: send locally-changed clipboard text to the network layer.
/// - `in_rx`:  receive clipboard text from the network layer to apply locally.
pub async fn monitor(out_tx: Sender<String>, mut in_rx: Receiver<String>) {
    // arboard is not Send, so we run it on a dedicated blocking thread and
    // bridge to the async world via channels.
    let (read_tx, mut read_rx) = tokio::sync::mpsc::channel::<String>(16);
    let (write_tx, mut write_rx) = tokio::sync::mpsc::channel::<String>(16);

    // ── Blocking clipboard thread ────────────────────────────────────────────
    std::thread::spawn(move || {
        let mut cb = match Clipboard::new() {
            Ok(c) => c,
            Err(e) => {
                warn!("clipboard: failed to open: {e}");
                return;
            }
        };

        let mut last_text: Option<String> = None;
        // Track the last value *we* set so we don't re-broadcast it.
        let mut last_applied: Option<String> = None;

        loop {
            // ── Apply incoming text ──────────────────────────────────────────
            while let Ok(text) = write_rx.try_recv() {
                if cb.set_text(text.clone()).is_ok() {
                    debug!("clipboard: applied from peer ({} chars)", text.len());
                    last_applied = Some(text.clone());
                    last_text = Some(text);
                }
            }

            // ── Detect local changes ─────────────────────────────────────────
            match cb.get_text() {
                Ok(text) if !text.is_empty() => {
                    // Skip if this is text we just applied from the network
                    let is_our_own = last_applied.as_deref() == Some(text.as_str());
                    let changed = last_text.as_deref() != Some(text.as_str());

                    if changed && !is_our_own {
                        debug!("clipboard: local change detected ({} chars)", text.len());
                        last_text = Some(text.clone());
                        // Clear last_applied so a subsequent local edit is picked up
                        last_applied = None;
                        let _ = read_tx.blocking_send(text);
                    }
                }
                Ok(_) => {} // empty clipboard, ignore
                Err(e) => {
                    // Clipboard can fail temporarily (e.g. another app holds it)
                    debug!("clipboard: read error: {e}");
                }
            }

            std::thread::sleep(Duration::from_millis(POLL_INTERVAL_MS));
        }
    });

    // ── Async bridge ────────────────────────────────────────────────────────
    loop {
        tokio::select! {
            // Local clipboard changed → forward to network
            Some(text) = read_rx.recv() => {
                let _ = out_tx.send(text).await;
            }
            // Network delivered clipboard → apply locally
            Some(text) = in_rx.recv() => {
                let _ = write_tx.send(text).await;
            }
        }
    }
}
