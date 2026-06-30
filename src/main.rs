#![cfg_attr(target_os = "windows", windows_subsystem = "windows")]

mod capture;
mod clipboard;
mod config;
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

    // Channel: tray → runtime when user updates config and reloads
    let (peer_tx, peer_rx) = mpsc::channel::<Option<String>>(8);

    // Shared flags accessible from both capture thread and async runtime.
    // being_controlled: true while a remote machine is injecting input here.
    // return_edge: which edge to watch for when being controlled
    //              (auto-set from CursorEnter's from_edge via opposite_edge).
    let being_controlled = Arc::new(AtomicBool::new(false));
    let return_edge      = Arc::new(AtomicU8::new(protocol::EDGE_LEFT));

    // Start input capture (rdev::grab — its own blocking thread)
    let (capture_rx, remote_mode) = capture::start(
        cfg.clone(),
        Arc::clone(&being_controlled),
        Arc::clone(&return_edge),
    );

    // Start input injection (enigo — its own blocking thread)
    let inject_tx = inject::start();

    // Background tokio runtime (keeps main thread free for the tray pump)
    let cfg2       = cfg.clone();
    let mode_flag  = Arc::clone(&remote_mode);
    let bc_flag    = Arc::clone(&being_controlled);
    let re_flag    = Arc::clone(&return_edge);
    thread::Builder::new()
        .name("runtime".into())
        .spawn(move || {
            Runtime::new()
                .expect("tokio runtime")
                .block_on(coordinator(
                    cfg2, capture_rx, inject_tx, mode_flag, peer_rx,
                    bc_flag, re_flag,
                ));
        })
        .expect("runtime thread");

    // Main thread: tray (OS requirement on Windows and macOS)
    tray::run(cfg, peer_tx);
}

async fn coordinator(
    mut cfg: Config,
    capture_rx: std::sync::mpsc::Receiver<CaptureMsg>,
    inject_tx: std::sync::mpsc::SyncSender<NetEvent>,
    remote_mode: Arc<AtomicBool>,
    mut peer_rx: mpsc::Receiver<Option<String>>,
    being_controlled: Arc<AtomicBool>,
    return_edge: Arc<AtomicU8>,
) {
    // ── Channels ─────────────────────────────────────────────────────────────
    let (udp_out_tx, udp_out_rx)         = mpsc::channel::<NetEvent>(512);
    // UDP receiver now includes source address so we can learn the controller's IP.
    let (udp_in_tx, mut udp_in_rx)       = mpsc::channel::<(NetEvent, std::net::SocketAddr)>(512);
    let (clip_local_tx, mut clip_local_rx) = mpsc::channel::<String>(32);
    let (clip_recv_tx, clip_recv_rx)     = mpsc::channel::<String>(32);
    let (clip_send_tx, clip_send_rx)     = mpsc::channel::<String>(32);

    // ── Always-on tasks ───────────────────────────────────────────────────────
    tokio::spawn(net::run_udp_receiver(udp_in_tx, cfg.input_addr()));
    tokio::spawn(net::run_clipboard_server(
        clip_recv_tx,
        format!("0.0.0.0:{}", cfg.clipboard_port),
    ));
    tokio::spawn(clipboard::monitor(clip_local_tx, clip_recv_rx));

    // ── Tasks that need a peer IP — started once (use Option::take) ──────────
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

    // IP of the machine that is currently controlling us (set from CursorEnter).
    // Used to send CursorLeave back when we return control.
    let mut controller_ip: Option<String> = None;

    let mut keepalive = tokio::time::interval(Duration::from_secs(2));

    loop {
        tokio::select! {
            // ── User reloaded config from the tray ────────────────────────
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

            // ── Input captured locally → send to peer ────────────────────
            Some(msg) = bridge_rx.recv() => {
                match msg {
                    CaptureMsg::Event(event) => {
                        let _ = udp_out_tx.send(event).await;
                    }

                    CaptureMsg::EnterRemote { edge, pos_frac } => {
                        // remote_mode already set inside capture callback.
                        remote_mode.store(true, Ordering::Relaxed);
                        let _ = udp_out_tx.send(NetEvent::CursorEnter {
                            from_edge: edge,
                            pos_frac,
                        }).await;
                        info!("entered remote mode (edge={edge})");
                    }

                    CaptureMsg::ReturnControl { edge, pos_frac } => {
                        // Our cursor reached the return edge while being controlled.
                        // Send CursorLeave directly to the controller's UDP port.
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
                            info!("returned control to {ctrl_addr} (edge={edge})");
                        }
                    }

                    CaptureMsg::ForceRelease => {
                        // ScrollLock — release whichever mode is active.
                        remote_mode.store(false, Ordering::Relaxed);

                        if let Some(ctrl_addr) = controller_ip.take() {
                            // We were being controlled — tell the controller.
                            being_controlled.store(false, Ordering::Relaxed);
                            let leave = NetEvent::CursorLeave { to_edge: 0, pos_frac: 0.5 };
                            let bytes = leave.to_bytes();
                            tokio::spawn(async move {
                                if let Ok(sock) = UdpSocket::bind("0.0.0.0:0").await {
                                    let _ = sock.send_to(&bytes, &ctrl_addr).await;
                                }
                            });
                        } else {
                            // We were controlling — tell the remote.
                            let _ = udp_out_tx.send(NetEvent::CursorLeave {
                                to_edge: 0,
                                pos_frac: 0.5,
                            }).await;
                        }
                        info!("force-released");
                    }
                }
            }

            // ── Events received from peer (injection + control messages) ──
            Some((event, src_addr)) = udp_in_rx.recv() => {
                match &event {
                    NetEvent::CursorEnter { from_edge, .. } => {
                        // A peer is now controlling us.
                        // Learn the return edge and the controller's address automatically.
                        let ret = opposite_edge(*from_edge);
                        return_edge.store(ret, Ordering::Relaxed);
                        being_controlled.store(true, Ordering::Relaxed);
                        let ctrl = format!("{}:{}", src_addr.ip(), cfg.input_port);
                        info!("being controlled by {ctrl} — return edge={ret}");
                        controller_ip = Some(ctrl);
                    }
                    NetEvent::CursorLeave { .. } => {
                        // Controller released us (ScrollLock on their side, etc.)
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

            // ── Local clipboard change → forward to peer ──────────────────
            Some(text) = clip_local_rx.recv() => {
                let _ = clip_send_tx.send(text).await;
            }

            // ── Keepalive ping ────────────────────────────────────────────
            _ = keepalive.tick() => {
                if remote_mode.load(Ordering::Relaxed) {
                    let _ = udp_out_tx.send(NetEvent::Ping).await;
                }
            }
        }
    }
}
