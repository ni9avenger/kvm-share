#![cfg_attr(target_os = "windows", windows_subsystem = "windows")]

mod capture;
mod clipboard;
mod config;
mod debug_window;
mod inject;
mod net;
mod protocol;
mod tray;

use capture::CaptureMsg;
use config::Config;
use log::info;
use protocol::{NetEvent, opposite_edge};
use std::sync::{
    atomic::{AtomicBool, AtomicU8, Ordering},
    Arc,
};
use std::thread;
use tokio::net::UdpSocket;
use tokio::runtime::Runtime;
use tokio::sync::mpsc;
use tokio::time::Duration;

fn main() {
    env_logger::init();
    info!("kvm-share starting");

    let cfg = Config::load();

    let (peer_tx, peer_rx) = mpsc::channel::<Option<String>>(8);

    // Raw Input deltas (Windows tray thread → coordinator → peer).
    // On non-Windows this channel exists but is never written to.
    let (raw_tx, raw_rx) = std::sync::mpsc::sync_channel::<(f64, f64)>(512);

    let being_controlled = Arc::new(AtomicBool::new(false));
    let return_edge      = Arc::new(AtomicU8::new(protocol::EDGE_LEFT));

    let (capture_rx, remote_mode) = capture::start(
        cfg.clone(),
        Arc::clone(&being_controlled),
        Arc::clone(&return_edge),
    );

    let inject_tx = inject::start();

    let cfg2      = cfg.clone();
    let mode_flag = Arc::clone(&remote_mode);
    let bc_flag   = Arc::clone(&being_controlled);
    let re_flag   = Arc::clone(&return_edge);
    thread::Builder::new()
        .name("runtime".into())
        .spawn(move || {
            Runtime::new()
                .expect("tokio runtime")
                .block_on(coordinator(
                    cfg2, capture_rx, inject_tx, mode_flag, peer_rx,
                    bc_flag, re_flag, raw_rx,
                ));
        })
        .expect("runtime thread");

    // Main thread: tray (and Raw Input on Windows)
    tray::run(cfg, peer_tx, Arc::clone(&remote_mode), raw_tx);
}

async fn coordinator(
    mut cfg: Config,
    capture_rx: std::sync::mpsc::Receiver<CaptureMsg>,
    inject_tx: std::sync::mpsc::SyncSender<NetEvent>,
    remote_mode: Arc<AtomicBool>,
    mut peer_rx: mpsc::Receiver<Option<String>>,
    being_controlled: Arc<AtomicBool>,
    return_edge: Arc<AtomicU8>,
    raw_rx: std::sync::mpsc::Receiver<(f64, f64)>,
) {
    // ── Channels ─────────────────────────────────────────────────────────────
    let (udp_out_tx, udp_out_rx)           = mpsc::channel::<NetEvent>(512);
    let (udp_in_tx, mut udp_in_rx)         = mpsc::channel::<(NetEvent, std::net::SocketAddr)>(512);
    let (clip_local_tx, mut clip_local_rx) = mpsc::channel::<String>(32);
    let (clip_recv_tx, clip_recv_rx)       = mpsc::channel::<String>(32);
    let (clip_send_tx, clip_send_rx)       = mpsc::channel::<String>(32);

    // ── Always-on tasks ───────────────────────────────────────────────────────
    tokio::spawn(net::run_udp_receiver(udp_in_tx, cfg.input_addr()));
    tokio::spawn(net::run_clipboard_server(
        clip_recv_tx,
        format!("0.0.0.0:{}", cfg.clipboard_port),
    ));
    tokio::spawn(clipboard::monitor(clip_local_tx, clip_recv_rx));

    // ── Tasks that need a peer IP (started once via Option::take) ────────────
    let mut udp_out_rx_opt   = Some(udp_out_rx);
    let mut clip_send_rx_opt = Some(clip_send_rx);

    if let Some(addr) = cfg.peer_input_addr() {
        if let Some(rx) = udp_out_rx_opt.take() {
            tokio::spawn(net::run_udp_sender(rx, addr));
        }
    }
    if let Some(addr) = cfg.peer_clipboard_addr() {
        if let Some(rx) = clip_send_rx_opt.take() {
            tokio::spawn(net::run_clipboard_client(rx, addr));
        }
    }

    // ── Bridge: sync capture thread → async ───────────────────────────────────
    let (bridge_tx, mut bridge_rx) = mpsc::channel::<CaptureMsg>(512);
    tokio::task::spawn_blocking(move || {
        while let Ok(msg) = capture_rx.recv() {
            let _ = bridge_tx.blocking_send(msg);
        }
    });

    // ── Bridge: sync Raw Input (tray/Windows) → async ────────────────────────
    // On non-Windows this goroutine just blocks forever waiting on an empty channel.
    let (raw_async_tx, mut raw_async_rx) = mpsc::channel::<(f64, f64)>(512);
    tokio::task::spawn_blocking(move || {
        while let Ok(delta) = raw_rx.recv() {
            if raw_async_tx.blocking_send(delta).is_err() { break; }
        }
    });

    let mut controller_ip: Option<String> = None;
    let mut keepalive = tokio::time::interval(Duration::from_secs(2));

    loop {
        tokio::select! {
            // ── Raw Input mouse deltas (Windows) → send to peer ───────────
            Some((dx, dy)) = raw_async_rx.recv() => {
                let in_remote = remote_mode.load(Ordering::Relaxed);
                debug_window::log(format!(
                    "RAW DELTA dx={dx:.1} dy={dy:.1}  remote_mode={in_remote}"
                ));
                if in_remote {
                    let _ = udp_out_tx.send(NetEvent::MouseMove { dx, dy }).await;
                }
            }

            // ── User reloaded config from tray ────────────────────────────
            Some(new_peer) = peer_rx.recv() => {
                cfg.peer_ip = new_peer;
                cfg.save();
                if let Some(addr) = cfg.peer_input_addr() {
                    if let Some(rx) = udp_out_rx_opt.take() {
                        tokio::spawn(net::run_udp_sender(rx, addr));
                    }
                }
                if let Some(addr) = cfg.peer_clipboard_addr() {
                    if let Some(rx) = clip_send_rx_opt.take() {
                        tokio::spawn(net::run_clipboard_client(rx, addr));
                    }
                }
            }

            // ── Input captured locally → send to peer ─────────────────────
            Some(msg) = bridge_rx.recv() => {
                match msg {
                    CaptureMsg::Event(event) => {
                        let _ = udp_out_tx.send(event).await;
                    }

                    CaptureMsg::EnterRemote { edge, pos_frac } => {
                        remote_mode.store(true, Ordering::Relaxed);
                        let _ = udp_out_tx.send(NetEvent::CursorEnter {
                            from_edge: edge,
                            pos_frac,
                        }).await;
                        debug_window::log(format!(
                            "ENTERED REMOTE MODE  edge={edge}  pos={pos_frac:.3}  peer={:?}",
                            cfg.peer_ip
                        ));
                        info!("entered remote mode (edge={edge})");
                    }

                    CaptureMsg::ReturnControl { edge, pos_frac } => {
                        being_controlled.store(false, Ordering::Relaxed);
                        if let Some(ctrl_addr) = controller_ip.take() {
                            let leave = NetEvent::CursorLeave { to_edge: edge, pos_frac };
                            let bytes = leave.to_bytes();
                            let addr  = ctrl_addr.clone();
                            tokio::spawn(async move {
                                if let Ok(sock) = UdpSocket::bind("0.0.0.0:0").await {
                                    let _ = sock.send_to(&bytes, &addr).await;
                                }
                            });
                            info!("returned control to {ctrl_addr}");
                        }
                    }

                    CaptureMsg::ForceRelease => {
                        remote_mode.store(false, Ordering::Relaxed);
                        if let Some(ctrl_addr) = controller_ip.take() {
                            being_controlled.store(false, Ordering::Relaxed);
                            let leave = NetEvent::CursorLeave { to_edge: 0, pos_frac: 0.5 };
                            let bytes = leave.to_bytes();
                            let addr  = ctrl_addr.clone();
                            tokio::spawn(async move {
                                if let Ok(sock) = UdpSocket::bind("0.0.0.0:0").await {
                                    let _ = sock.send_to(&bytes, &addr).await;
                                }
                            });
                        } else {
                            let _ = udp_out_tx.send(NetEvent::CursorLeave {
                                to_edge: 0, pos_frac: 0.5,
                            }).await;
                        }
                        info!("force-released");
                    }
                }
            }

            // ── Events from peer → inject locally ─────────────────────────
            Some((event, src_addr)) = udp_in_rx.recv() => {
                match &event {
                    NetEvent::CursorEnter { from_edge, .. } => {
                        let ret = opposite_edge(*from_edge);
                        return_edge.store(ret, Ordering::Relaxed);
                        being_controlled.store(true, Ordering::Relaxed);
                        let ctrl = format!("{}:{}", src_addr.ip(), cfg.input_port);
                        info!("being controlled by {ctrl} — return edge={ret}");
                        controller_ip = Some(ctrl);
                    }
                    NetEvent::CursorLeave { .. } => {
                        being_controlled.store(false, Ordering::Relaxed);
                        remote_mode.store(false, Ordering::Relaxed);
                        capture::show_cursor();
                        controller_ip = None;
                        info!("controller released us");
                    }
                    _ => {}
                }
                let _ = inject_tx.try_send(event);
            }

            // ── Local clipboard → peer ─────────────────────────────────────
            Some(text) = clip_local_rx.recv() => {
                let _ = clip_send_tx.send(text).await;
            }

            // ── Keepalive ──────────────────────────────────────────────────
            _ = keepalive.tick() => {
                if remote_mode.load(Ordering::Relaxed) {
                    let _ = udp_out_tx.send(NetEvent::Ping).await;
                }
            }
        }
    }
}
