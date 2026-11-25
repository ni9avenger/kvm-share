#![cfg_attr(target_os = "windows", windows_subsystem = "windows")]

mod capture;
mod clipboard;
mod config;
mod control;
mod crypto;
mod debug_window;
mod inject;
mod logging;
mod net;
mod protocol;
mod tray;
mod wire;

use capture::CaptureMsg;
use config::{Config, PairingRecord};
use control::{Notice, PairDecision};
use log::{info, warn};
use protocol::{opposite_edge, NetEvent};
use std::sync::{
    atomic::{AtomicBool, AtomicU8, Ordering},
    Arc,
};
use std::thread;
use tokio::runtime::Runtime;
use tokio::sync::{mpsc, watch};
use tokio::time::Duration;
use tray::{TrayCmd, TrayUpdate};

fn main() {
    let cfg = Config::load();
    logging::init(&cfg.log_level);
    info!(
        "kvm-share v{} (protocol v{}) starting as {:?}; peer={:?} edge={:?} ports udp {} / tcp {}",
        wire::APP_VERSION,
        wire::PROTO_VERSION,
        cfg.name(),
        cfg.peer_ip,
        cfg.switch_edge,
        cfg.input_port,
        cfg.control_port
    );

    let (tray_cmd_tx, tray_cmd_rx) = mpsc::channel::<TrayCmd>(16);
    let (tray_upd_tx, tray_upd_rx) = std::sync::mpsc::channel::<TrayUpdate>();

    // Raw Input deltas (Windows tray thread â†’ coordinator â†’ peer).
    // On non-Windows this channel exists but is never written to.
    let (raw_tx, raw_rx) = std::sync::mpsc::sync_channel::<(f64, f64)>(512);

    let being_controlled = Arc::new(AtomicBool::new(false));
    let return_edge = Arc::new(AtomicU8::new(protocol::EDGE_LEFT));
    // True only while the peer is connected AND authenticated both ways.
    // The hook reads it before crossing, so the cursor never leaves for a
    // machine that cannot receive it.
    let peer_ready = Arc::new(AtomicBool::new(false));

    let (capture_rx, remote_mode) = capture::start(
        cfg.clone(),
        Arc::clone(&being_controlled),
        Arc::clone(&return_edge),
        Arc::clone(&peer_ready),
    );

    let inject_tx = inject::start();

    let flags = Flags {
        remote_mode: Arc::clone(&remote_mode),
        being_controlled: Arc::clone(&being_controlled),
        return_edge: Arc::clone(&return_edge),
        peer_ready,
    };
    let cfg2 = cfg.clone();
    thread::Builder::new()
        .name("runtime".into())
        .spawn(move || {
            Runtime::new()
                .expect("tokio runtime")
                .block_on(coordinator(cfg2, capture_rx, inject_tx, flags, tray_cmd_rx, tray_upd_tx, raw_rx));
        })
        .expect("runtime thread");

    // Main thread: tray (and Raw Input on Windows)
    tray::run(cfg, tray_cmd_tx, tray_upd_rx, Arc::clone(&remote_mode), raw_tx);
}

struct Flags {
    remote_mode: Arc<AtomicBool>,
    being_controlled: Arc<AtomicBool>,
    return_edge: Arc<AtomicU8>,
    peer_ready: Arc<AtomicBool>,
}

/// What the tray shows, derived from coordinator state.
#[derive(Default)]
struct Status {
    paired_with: Option<String>,
    inbound: Option<(u64, String)>,
    outbound: bool,
    pairing_code: Option<(u32, String)>,
    problem: Option<String>,
}

impl Status {
    fn ready(&self) -> bool {
        self.paired_with.is_some() && self.inbound.is_some() && self.outbound
    }

    fn text(&self) -> String {
        if let Some((code, peer)) = &self.pairing_code {
            return format!("Pairing code {:03} {:03} â€” must match on {peer}", code / 1000, code % 1000);
        }
        let Some(peer) = &self.paired_with else {
            return self.problem.clone().unwrap_or_else(|| "Not paired".into());
        };
        if self.ready() {
            let name = self.inbound.as_ref().map(|(_, n)| n.as_str()).unwrap_or(peer);
            return format!("Connected to {name}");
        }
        self.problem.clone().unwrap_or_else(|| format!("Waiting for {peer}â€¦"))
    }
}

#[allow(clippy::too_many_arguments)]
async fn coordinator(
    mut cfg: Config,
    capture_rx: std::sync::mpsc::Receiver<CaptureMsg>,
    inject_tx: std::sync::mpsc::SyncSender<NetEvent>,
    flags: Flags,
    mut tray_rx: mpsc::Receiver<TrayCmd>,
    tray_tx: std::sync::mpsc::Sender<TrayUpdate>,
    raw_rx: std::sync::mpsc::Receiver<(f64, f64)>,
) {
    let Flags { remote_mode, being_controlled, return_edge, peer_ready } = flags;

    // â”€â”€ Shared state the network tasks watch â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    let mut status = Status::default();
    let initial_key = match &cfg.pairing {
        Some(rec) => match rec.key() {
            Some(k) => {
                status.paired_with = Some(rec.peer_name.clone());
                Some(k)
            }
            None => {
                warn!("pairing key in config could not be decrypted (other Windows user or corrupt) â€” pair again");
                status.problem = Some("Saved pairing is unreadable â€” pair again".into());
                None
            }
        },
        None => None,
    };
    let (key_tx, key_rx) = watch::channel(initial_key);
    let (peer_tx, peer_rx) = watch::channel(cfg.peer_addr());
    let (accepted_tx, accepted_rx) = watch::channel::<Option<u32>>(None);
    let udp_session = u32::from_le_bytes(crypto::random_bytes::<4>());

    // â”€â”€ Channels â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    let (udp_out_tx, udp_out_rx) = mpsc::channel::<NetEvent>(512);
    let (udp_in_tx, mut udp_in_rx) = mpsc::channel::<(NetEvent, std::net::SocketAddr)>(512);
    let (clip_local_tx, mut clip_local_rx) = mpsc::channel::<String>(32);
    let (clip_recv_tx, clip_recv_rx) = mpsc::channel::<String>(32);
    let (clip_send_tx, clip_send_rx) = mpsc::channel::<String>(32);
    let (notice_tx, mut notice_rx) = mpsc::channel::<Notice>(64);
    let (decision_tx, _) = watch::channel(PairDecision::Pending);

    let ctx = control::Ctx {
        name: cfg.name(),
        port: cfg.control_port,
        udp_session,
        key: key_rx.clone(),
        peer: peer_rx.clone(),
        notices: notice_tx,
        decision: decision_tx,
        pairing_busy: Arc::new(AtomicBool::new(false)),
    };

    // â”€â”€ Tasks â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    tokio::spawn(net::run_udp_receiver(
        udp_in_tx,
        net::UdpIn { bind: format!("0.0.0.0:{}", cfg.input_port), key: key_rx.clone(), accepted: accepted_rx },
    ));
    tokio::spawn(net::run_udp_sender(
        udp_out_rx,
        net::UdpOut { port: cfg.input_port, session: udp_session, peer: peer_rx.clone(), key: key_rx.clone() },
    ));
    tokio::spawn(control::run_server(ctx.clone()));
    tokio::spawn(control::run_client(ctx.clone(), clip_send_rx));
    tokio::spawn(clipboard::monitor(clip_local_tx, clip_recv_rx));

    // â”€â”€ Bridge: sync capture thread â†’ async â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    let (bridge_tx, mut bridge_rx) = mpsc::channel::<CaptureMsg>(512);
    tokio::task::spawn_blocking(move || {
        while let Ok(msg) = capture_rx.recv() {
            let _ = bridge_tx.blocking_send(msg);
        }
    });

    // â”€â”€ Bridge: sync Raw Input (tray/Windows) â†’ async â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    let (raw_async_tx, mut raw_async_rx) = mpsc::channel::<(f64, f64)>(512);
    tokio::task::spawn_blocking(move || {
        while let Ok(delta) = raw_rx.recv() {
            if raw_async_tx.blocking_send(delta).is_err() {
                break;
            }
        }
    });

    let push = |status: &Status| {
        peer_ready.store(status.ready(), Ordering::Relaxed);
        let _ = tray_tx.send(TrayUpdate {
            status: status.text(),
            pairing: status.pairing_code.is_some(),
            paired: status.paired_with.is_some(),
        });
    };
    push(&status);

    let mut keepalive = tokio::time::interval(Duration::from_secs(2));

    loop {
        tokio::select! {
            // â”€â”€ Raw Input mouse deltas (Windows) â†’ send to peer â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
            Some((dx, dy)) = raw_async_rx.recv() => {
                if remote_mode.load(Ordering::Relaxed) {
                    let _ = udp_out_tx.send(NetEvent::MouseMove { dx, dy }).await;
                }
            }

            // â”€â”€ Tray commands â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
            Some(cmd) = tray_rx.recv() => {
                match cmd {
                    TrayCmd::Reload(new_cfg) => {
                        cfg.peer_ip = new_cfg.peer_ip;
                        let addr = cfg.peer_addr();
                        if cfg.peer_ip.is_some() && addr.is_none() {
                            status.problem = Some(format!("peer_ip {:?} is not a valid IP address", cfg.peer_ip));
                        }
                        info!("config reloaded: peer={addr:?}");
                        // Sender and client follow this watch: the new address
                        // takes effect immediately (v0.1.x needed a restart).
                        peer_tx.send_replace(addr);
                    }
                    TrayCmd::PairStart => match cfg.peer_addr() {
                        Some(ip) => {
                            status.problem = None;
                            control::start_pairing(ctx.clone(), ip);
                        }
                        None => status.problem = Some("Set peer_ip in the config file first, then Reload".into()),
                    },
                    TrayCmd::PairConfirm => { ctx.decision.send_replace(PairDecision::Confirm); }
                    TrayCmd::PairCancel => { ctx.decision.send_replace(PairDecision::Cancel); }
                    TrayCmd::Unpair => {
                        cfg.pairing = None;
                        cfg.save();
                        status.paired_with = None;
                        status.problem = None;
                        accepted_tx.send_replace(None);
                        key_tx.send_replace(None);
                        release_all(&remote_mode, &being_controlled);
                        info!("unpaired");
                    }
                }
                push(&status);
            }

            // â”€â”€ Control-channel notices â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
            Some(n) = notice_rx.recv() => {
                match n {
                    Notice::OutboundUp => {
                        status.outbound = true;
                        status.problem = None;
                    }
                    Notice::OutboundDown => status.outbound = false,
                    Notice::InboundUp { conn, name, addr, udp_session } => {
                        status.inbound = Some((conn, name.clone()));
                        accepted_tx.send_replace(Some(udp_session));
                        // The peer proved it holds our pairing key, so its
                        // current address is authoritative: adopt it if DHCP
                        // moved it (the cause of the one-way clipboard seen in
                        // the 2026-11-24 diagnostic logs).
                        if cfg.peer_addr() != Some(addr.ip()) {
                            info!("peer {name} is now at {} (was {:?}) â€” updating config", addr.ip(), cfg.peer_ip);
                            cfg.peer_ip = Some(addr.ip().to_string());
                            cfg.save();
                            peer_tx.send_replace(Some(addr.ip()));
                        }
                    }
                    Notice::InboundDown { conn } => {
                        if status.inbound.as_ref().map(|(c, _)| *c) == Some(conn) {
                            status.inbound = None;
                            accepted_tx.send_replace(None);
                            if remote_mode.load(Ordering::Relaxed) || being_controlled.load(Ordering::Relaxed) {
                                warn!("peer gone while sharing control â€” returning control to this PC");
                            }
                            release_all(&remote_mode, &being_controlled);
                        }
                    }
                    Notice::Clip(text) => { let _ = clip_recv_tx.send(text).await; }
                    Notice::Problem(p) => {
                        warn!("{p}");
                        status.problem = Some(p);
                    }
                    Notice::PairCode { code, peer_name } => {
                        info!("pairing: code {code:06} with {peer_name} â€” waiting for confirmation");
                        status.pairing_code = Some((code, peer_name));
                    }
                    Notice::PairDone { peer_name, key, peer_ip } => {
                        status.pairing_code = None;
                        match PairingRecord::new(peer_name.clone(), &key) {
                            Some(rec) => {
                                cfg.pairing = Some(rec);
                                cfg.peer_ip = Some(peer_ip.to_string());
                                cfg.save();
                                status.paired_with = Some(peer_name);
                                status.problem = None;
                                peer_tx.send_replace(Some(peer_ip));
                                key_tx.send_replace(Some(key));
                            }
                            None => status.problem = Some("Could not store the pairing key (DPAPI failed)".into()),
                        }
                    }
                    Notice::PairEnded(why) => {
                        status.pairing_code = None;
                        status.problem = Some(why);
                    }
                }
                push(&status);
            }

            // â”€â”€ Input captured locally â†’ send to peer â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
            Some(msg) = bridge_rx.recv() => {
                match msg {
                    CaptureMsg::Event(event) => {
                        let _ = udp_out_tx.send(event).await;
                    }
                    CaptureMsg::EnterRemote { edge, pos_frac } => {
                        remote_mode.store(true, Ordering::Relaxed);
                        let _ = udp_out_tx.send(NetEvent::CursorEnter { from_edge: edge, pos_frac }).await;
                        info!("entered remote mode (edge={edge})");
                    }
                    CaptureMsg::ReturnControl { edge, pos_frac } => {
                        if being_controlled.swap(false, Ordering::Relaxed) {
                            let _ = udp_out_tx.send(NetEvent::CursorLeave { to_edge: edge, pos_frac }).await;
                            info!("returned control to peer");
                        }
                    }
                    CaptureMsg::ForceRelease => {
                        remote_mode.store(false, Ordering::Relaxed);
                        being_controlled.store(false, Ordering::Relaxed);
                        let _ = udp_out_tx.send(NetEvent::CursorLeave { to_edge: 0, pos_frac: 0.5 }).await;
                        info!("force-released");
                    }
                }
            }

            // â”€â”€ Events from peer â†’ inject locally â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
            Some((event, _src)) = udp_in_rx.recv() => {
                match &event {
                    NetEvent::CursorEnter { from_edge, .. } => {
                        let ret = opposite_edge(*from_edge);
                        return_edge.store(ret, Ordering::Relaxed);
                        being_controlled.store(true, Ordering::Relaxed);
                        info!("being controlled by peer â€” return edge={ret}");
                    }
                    NetEvent::CursorLeave { .. } => {
                        being_controlled.store(false, Ordering::Relaxed);
                        remote_mode.store(false, Ordering::Relaxed);
                        capture::show_cursor();
                        info!("controller released us");
                    }
                    _ => {}
                }
                let _ = inject_tx.try_send(event);
            }

            // â”€â”€ Local clipboard â†’ peer â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
            Some(text) = clip_local_rx.recv() => {
                let _ = clip_send_tx.send(text).await;
            }

            // â”€â”€ Keepalive â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
            _ = keepalive.tick() => {
                if remote_mode.load(Ordering::Relaxed) {
                    let _ = udp_out_tx.send(NetEvent::Ping).await;
                }
            }
        }
    }
}

/// Hand control back to this PC. remote_mode=false makes the capture hook
/// restore the cursor on the next event (see capture.rs was_remote).
fn release_all(remote_mode: &AtomicBool, being_controlled: &AtomicBool) {
    remote_mode.store(false, Ordering::Relaxed);
    being_controlled.store(false, Ordering::Relaxed);
}

#[cfg(test)]
mod tests {
    use super::Status;

    #[test]
    fn status_text() {
        let mut s = Status::default();
        assert_eq!(s.text(), "Not paired");
        s.paired_with = Some("HP".into());
        assert_eq!(s.text(), "Waiting for HPâ€¦");
        assert!(!s.ready());
        s.inbound = Some((1, "HP-LAPTOP".into()));
        s.outbound = true;
        assert!(s.ready());
        assert_eq!(s.text(), "Connected to HP-LAPTOP");
        s.pairing_code = Some((42_917, "HP".into()));
        assert_eq!(s.text(), "Pairing code 042 917 â€” must match on HP");
    }
}
