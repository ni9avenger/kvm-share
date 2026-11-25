// control.rs â€” the TCP control channel: pairing, authenticated sessions,
// liveness, and clipboard text.
//
// Shape (unchanged idea from v0.1.x's clipboard link): each PC runs a server
// AND a client. Our outbound connection carries what WE send (clipboard,
// pings, our UDP session id in the Hello); the peer's connection into our
// server carries what THEY send. That keeps every connection one-directional
// after the handshake and makes "peer has gone quiet" a simple read timeout
// on the inbound side.
//
// Why liveness lives here and not in UDP: input is UDP and can legitimately
// be silent for minutes. The control link pings every 2 s, so 6 s of silence
// on the inbound connection means the peer is gone (crashed, unplugged, IP
// changed, asleep) â€” the coordinator then hands control back locally instead
// of leaving the cursor stranded on a dead machine (owner's issue 3).
//
// Pairing uses numeric comparison with a commitment (see docs/v0.2.0-phase1.md):
// the initiator commits to its key before seeing the responder's, so a
// man-in-the-middle cannot search for keys that make the two codes match.

use crate::crypto;
use crate::wire::{self, FrameCodec, Hello, Msg, Purpose, WireError};
use log::{debug, info, warn};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use tokio::io::AsyncReadExt;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, watch};
use tokio::time::{sleep, timeout, Duration, Instant};

pub const PING_EVERY: Duration = Duration::from_secs(2);
pub const PEER_TIMEOUT: Duration = Duration::from_secs(6);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
const PAIR_TIMEOUT: Duration = Duration::from_secs(120);
const BACKOFF_MAX: Duration = Duration::from_secs(5);
/// A session shorter than this counts as a failed connect for backoff.
const MIN_HEALTHY_SESSION: Duration = Duration::from_secs(2);

/// What the control layer tells the coordinator.
#[derive(Debug)]
pub enum Notice {
    OutboundUp,
    OutboundDown,
    InboundUp {
        conn: u64,
        name: String,
        addr: SocketAddr,
        udp_session: u32,
    },
    InboundDown {
        conn: u64,
    },
    Clip(String),
    /// Something the owner should see in the tray (version mismatch, wrong key â€¦).
    Problem(String),
    PairCode {
        code: u32,
        peer_name: String,
    },
    PairDone {
        peer_name: String,
        key: [u8; 32],
        peer_ip: IpAddr,
    },
    PairEnded(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PairDecision {
    Pending,
    Confirm,
    Cancel,
}

#[derive(Clone)]
pub struct Ctx {
    pub name: String,
    pub port: u16,
    /// Session id our UDP datagrams are signed with (random per process run).
    pub udp_session: u32,
    pub key: watch::Receiver<Option<[u8; 32]>>,
    pub peer: watch::Receiver<Option<IpAddr>>,
    pub notices: mpsc::Sender<Notice>,
    pub decision: watch::Sender<PairDecision>,
    pub pairing_busy: Arc<AtomicBool>,
}

static CONN_IDS: AtomicU64 = AtomicU64::new(1);

impl Ctx {
    fn notify(&self, n: Notice) {
        // Never block the network on a slow coordinator.
        if self.notices.try_send(n).is_err() {
            warn!("control: notice channel full, dropped a notice");
        }
    }

    fn hello(&self, purpose: Purpose) -> Hello {
        Hello {
            app_version: wire::APP_VERSION.into(),
            name: self.name.clone(),
            nonce: crypto::random_bytes::<16>(),
            udp_session: self.udp_session,
            purpose,
        }
    }
}

// â”€â”€ Server (inbound) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

pub async fn run_server(ctx: Ctx) {
    let bind = format!("0.0.0.0:{}", ctx.port);
    let listener = match TcpListener::bind(&bind).await {
        Ok(l) => l,
        Err(e) => {
            warn!("control server: bind failed on {bind}: {e}");
            ctx.notify(Notice::Problem(format!(
                "Port {} is in use â€” is another copy running?",
                ctx.port
            )));
            return;
        }
    };
    info!("control server: listening on {bind}");
    serve(listener, ctx).await;
}

/// Split out so tests can bind an ephemeral port.
pub async fn serve(listener: TcpListener, ctx: Ctx) {
    loop {
        match listener.accept().await {
            Ok((stream, addr)) => {
                let _ = stream.set_nodelay(true);
                let ctx = ctx.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_inbound(stream, addr, ctx.clone()).await {
                        debug!("control: inbound {addr} ended: {e}");
                    }
                });
            }
            Err(e) => warn!("control server: accept error: {e}"),
        }
    }
}

async fn handle_inbound(stream: TcpStream, addr: SocketAddr, ctx: Ctx) -> Result<(), WireError> {
    let (mut rd, mut wr) = stream.into_split();
    let theirs = timeout(HANDSHAKE_TIMEOUT, wire::read_hello(&mut rd)).await;
    // Always answer with our Hello first, even when we are about to refuse:
    // that is how the connecting side learns our protocol version.
    let purpose = match &theirs {
        Ok(Ok(h)) => h.purpose,
        _ => Purpose::Session,
    };
    let ours = ctx.hello(purpose);
    let _ = wire::write_hello(&mut wr, &ours).await;
    let theirs = match theirs {
        Ok(Ok(h)) => h,
        Ok(Err(WireError::Version(v))) => {
            ctx.notify(Notice::Problem(format!(
                "PC at {} runs a different kvm-share version (protocol v{v}, this PC v{})",
                addr.ip(),
                wire::PROTO_VERSION
            )));
            return Err(WireError::Version(v));
        }
        Ok(Err(e)) => return Err(e),
        Err(_) => return Err(WireError::Io(std::io::ErrorKind::TimedOut.into())),
    };

    match theirs.purpose {
        Purpose::Pair => pair_responder(rd, wr, addr, theirs, ctx).await,
        Purpose::Session => inbound_session(rd, wr, addr, theirs, ours, ctx).await,
    }
}

async fn inbound_session(
    mut rd: OwnedReadHalf,
    mut wr: OwnedWriteHalf,
    addr: SocketAddr,
    theirs: Hello,
    ours: Hello,
    ctx: Ctx,
) -> Result<(), WireError> {
    let mut plain = FrameCodec::plain();
    // Copy out of the watch before any .await (its guard is not Send).
    let current_key = *ctx.key.borrow();
    let Some(key) = current_key else {
        let _ = plain
            .write(
                &mut wr,
                &Msg::Bye("This PC is not paired. Pair the two PCs first.".into()),
            )
            .await;
        ctx.notify(Notice::Problem(format!(
            "{} ({}) tried to connect, but this PC is not paired",
            theirs.name,
            addr.ip()
        )));
        return Ok(());
    };

    let mac = match timeout(HANDSHAKE_TIMEOUT, plain.read(&mut rd)).await {
        Ok(Ok(Msg::Auth { mac })) => mac,
        Ok(Ok(_)) => return Err(WireError::Decode),
        Ok(Err(e)) => return Err(e),
        Err(_) => return Err(WireError::Io(std::io::ErrorKind::TimedOut.into())),
    };
    let expect = wire::auth_mac(&key, b"client", &theirs.nonce, &ours.nonce);
    if !ct_eq(&mac, &expect) {
        let _ = plain
            .write(
                &mut wr,
                &Msg::Bye("Pairing key does not match. Pair the two PCs again.".into()),
            )
            .await;
        ctx.notify(Notice::Problem(format!(
            "{} ({}) has a different pairing key â€” pair again",
            theirs.name,
            addr.ip()
        )));
        return Err(WireError::BadTag);
    }
    let server_mac = wire::auth_mac(&key, b"server", &theirs.nonce, &ours.nonce);
    plain.write(&mut wr, &Msg::Auth { mac: server_mac }).await?;

    let (c2s, _s2c) = wire::session_keys(&key, &theirs.nonce, &ours.nonce);
    let mut rx = FrameCodec::keyed(c2s);
    let conn = CONN_IDS.fetch_add(1, Ordering::Relaxed);
    info!(
        "control: {} ({}) connected in, app v{}",
        theirs.name, addr, theirs.app_version
    );
    ctx.notify(Notice::InboundUp {
        conn,
        name: theirs.name.clone(),
        addr,
        udp_session: theirs.udp_session,
    });

    // A cloned receiver inherits the "seen" version of ctx.key, which nobody
    // marks seen — so after pairing at runtime, changed() fired at once and
    // every session hung up straight away. Mark the current key as seen.
    let mut key_rx = ctx.key.clone();
    key_rx.borrow_and_update();
    let result = loop {
        tokio::select! {
            r = timeout(PEER_TIMEOUT, rx.read(&mut rd)) => match r {
                Ok(Ok(Msg::Ping)) => {}
                Ok(Ok(Msg::ClipText(t))) => {
                    debug!("control: clipboard text from peer ({} bytes)", t.len());
                    ctx.notify(Notice::Clip(t));
                }
                Ok(Ok(Msg::Bye(why))) => { info!("control: peer closed: {why}"); break Ok(()); }
                Ok(Ok(other)) => debug!("control: ignoring {other:?}"),
                Ok(Err(e)) => break Err(e),
                Err(_) => {
                    warn!("control: no data from {} for {}s â€” treating peer as gone", theirs.name, PEER_TIMEOUT.as_secs());
                    break Ok(());
                }
            },
            // Unpaired or re-paired while connected: this session is stale.
            _ = key_rx.changed() => break Ok(()),
        }
    };
    ctx.notify(Notice::InboundDown { conn });
    result
}

fn ct_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    a.iter()
        .zip(b.iter())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}

// â”€â”€ Client (outbound) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Keep an authenticated outbound connection to the configured peer, sending
/// clipboard text and pings. Reconnects immediately when the peer address or
/// pairing key changes (fixes v0.1.x's "Reload config does nothing", Â§7.1).
pub async fn run_client(ctx: Ctx, mut out_rx: mpsc::Receiver<String>) {
    let mut peer_rx = ctx.peer.clone();
    let mut key_rx = ctx.key.clone();
    let mut backoff = Duration::from_secs(1);

    loop {
        let target = *peer_rx.borrow_and_update();
        let key = *key_rx.borrow_and_update();
        let (Some(ip), Some(key)) = (target, key) else {
            // Nothing to connect to yet: wait for config/pairing to change.
            tokio::select! {
                _ = peer_rx.changed() => {}
                _ = key_rx.changed() => {}
                Some(_) = out_rx.recv() => debug!("control client: not connected, clipboard change not sent"),
            }
            continue;
        };

        let addr = SocketAddr::new(ip, ctx.port);
        match connect_session(&ctx, addr, &key).await {
            Ok((rd, wr, tx, peer_name)) => {
                ctx.notify(Notice::OutboundUp);
                info!("control client: connected to {peer_name} at {addr}");
                let started = Instant::now();
                let why = outbound_loop(rd, wr, tx, &mut out_rx, &mut peer_rx, &mut key_rx).await;
                info!("control client: disconnected from {addr}: {why}");
                ctx.notify(Notice::OutboundDown);
                // Reconnect at once after a session that actually ran. One that
                // dies instantly goes through the backoff, so a bug like the
                // 2026-11-24 one can't turn into 60 reconnects a second.
                if started.elapsed() >= MIN_HEALTHY_SESSION {
                    backoff = Duration::from_secs(1);
                    continue;
                }
            }
            Err(e) => {
                debug!("control client: {addr}: {e}");
                if let WireError::Version(v) = e {
                    ctx.notify(Notice::Problem(format!(
                        "{ip} runs a different kvm-share version (protocol v{v}, this PC v{})",
                        wire::PROTO_VERSION
                    )));
                    backoff = BACKOFF_MAX;
                }
            }
        }

        let until = Instant::now() + backoff;
        backoff = (backoff * 2).min(BACKOFF_MAX);
        loop {
            tokio::select! {
                _ = tokio::time::sleep_until(until) => break,
                _ = peer_rx.changed() => { backoff = Duration::from_secs(1); break; }
                _ = key_rx.changed() => { backoff = Duration::from_secs(1); break; }
                Some(_) = out_rx.recv() => debug!("control client: not connected, clipboard change not sent"),
            }
        }
    }
}

type Session = (OwnedReadHalf, OwnedWriteHalf, FrameCodec, String);

async fn connect_session(
    ctx: &Ctx,
    addr: SocketAddr,
    key: &[u8; 32],
) -> Result<Session, WireError> {
    let stream = timeout(CONNECT_TIMEOUT, TcpStream::connect(addr))
        .await
        .map_err(|_| WireError::Io(std::io::ErrorKind::TimedOut.into()))??;
    let _ = stream.set_nodelay(true);
    let (mut rd, mut wr) = stream.into_split();

    let ours = ctx.hello(Purpose::Session);
    wire::write_hello(&mut wr, &ours).await?;
    let theirs = timeout(HANDSHAKE_TIMEOUT, wire::read_hello(&mut rd))
        .await
        .map_err(|_| WireError::Io(std::io::ErrorKind::TimedOut.into()))??;

    let mut plain = FrameCodec::plain();
    let mac = wire::auth_mac(key, b"client", &ours.nonce, &theirs.nonce);
    plain.write(&mut wr, &Msg::Auth { mac }).await?;
    match timeout(HANDSHAKE_TIMEOUT, plain.read(&mut rd)).await {
        Ok(Ok(Msg::Auth { mac })) => {
            let expect = wire::auth_mac(key, b"server", &ours.nonce, &theirs.nonce);
            if !ct_eq(&mac, &expect) {
                ctx.notify(Notice::Problem(format!(
                    "{} ({}) has a different pairing key â€” pair again",
                    theirs.name,
                    addr.ip()
                )));
                return Err(WireError::BadTag);
            }
        }
        Ok(Ok(Msg::Bye(why))) => {
            ctx.notify(Notice::Problem(format!("{}: {why}", theirs.name)));
            return Err(WireError::BadTag);
        }
        Ok(Ok(_)) => return Err(WireError::Decode),
        Ok(Err(e)) => return Err(e),
        Err(_) => return Err(WireError::Io(std::io::ErrorKind::TimedOut.into())),
    }
    let (c2s, _s2c) = wire::session_keys(key, &ours.nonce, &theirs.nonce);
    Ok((rd, wr, FrameCodec::keyed(c2s), theirs.name))
}

async fn outbound_loop(
    mut rd: OwnedReadHalf,
    mut wr: OwnedWriteHalf,
    mut tx: FrameCodec,
    out_rx: &mut mpsc::Receiver<String>,
    peer_rx: &mut watch::Receiver<Option<IpAddr>>,
    key_rx: &mut watch::Receiver<Option<[u8; 32]>>,
) -> String {
    let mut ping = tokio::time::interval(PING_EVERY);
    let mut probe = [0u8; 1];
    loop {
        tokio::select! {
            _ = ping.tick() => {
                if let Err(e) = tx.write(&mut wr, &Msg::Ping).await { return format!("ping failed: {e}"); }
            }
            m = out_rx.recv() => match m {
                Some(text) => {
                    let n = text.len();
                    if let Err(e) = tx.write(&mut wr, &Msg::ClipText(text)).await {
                        return format!("clipboard send failed: {e}");
                    }
                    debug!("control client: sent clipboard text ({n} bytes)");
                }
                None => return "shutting down".into(),
            },
            // The server never writes after the handshake, so any read result
            // (EOF, reset, unexpected data) means the connection is over.
            r = rd.read(&mut probe) => return match r {
                Ok(0) => "peer closed the connection".into(),
                Ok(_) => "unexpected data from peer".into(),
                Err(e) => format!("read error: {e}"),
            },
            _ = peer_rx.changed() => return "peer address changed".into(),
            _ = key_rx.changed() => return "pairing changed".into(),
        }
    }
}

// â”€â”€ Pairing â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Start pairing with `ip` (owner clicked "Pair with â€¦" on this PC).
pub fn start_pairing(ctx: Ctx, ip: IpAddr) {
    if ctx.pairing_busy.swap(true, Ordering::SeqCst) {
        ctx.notify(Notice::PairEnded("A pairing is already in progress".into()));
        return;
    }
    ctx.decision.send_replace(PairDecision::Pending);
    tokio::spawn(async move {
        let r = pair_initiator(&ctx, ip).await;
        finish_pairing(&ctx, r);
    });
}

fn finish_pairing(ctx: &Ctx, r: Result<([u8; 32], String, IpAddr), String>) {
    ctx.pairing_busy.store(false, Ordering::SeqCst);
    match r {
        Ok((key, peer_name, peer_ip)) => {
            info!("pairing: paired with {peer_name} ({peer_ip})");
            ctx.notify(Notice::PairDone {
                peer_name,
                key,
                peer_ip,
            });
        }
        Err(why) => {
            warn!("pairing: {why}");
            ctx.notify(Notice::PairEnded(why));
        }
    }
}

async fn pair_initiator(ctx: &Ctx, ip: IpAddr) -> Result<([u8; 32], String, IpAddr), String> {
    let addr = SocketAddr::new(ip, ctx.port);
    let stream = timeout(CONNECT_TIMEOUT, TcpStream::connect(addr))
        .await
        .map_err(|_| {
            format!(
                "No answer from {ip}. Is kvm-share v{} running there?",
                wire::APP_VERSION
            )
        })?
        .map_err(|e| format!("Cannot reach {ip}: {e}"))?;
    let (mut rd, mut wr) = stream.into_split();
    let w = |e: WireError| match e {
        WireError::Version(v) => format!("{ip} runs a different kvm-share version (protocol v{v})"),
        e => format!("Pairing connection failed: {e}"),
    };
    wire::write_hello(&mut wr, &ctx.hello(Purpose::Pair))
        .await
        .map_err(w)?;
    let theirs = timeout(HANDSHAKE_TIMEOUT, wire::read_hello(&mut rd))
        .await
        .map_err(|_| "The other PC did not answer".to_string())?
        .map_err(w)?;

    let mut codec = FrameCodec::plain();
    let eph = crypto::EphemeralKey::generate();
    let nonce_i = crypto::random_bytes::<16>();
    let commit = crypto::sha256(&[&eph.public, &nonce_i]);
    codec
        .write(
            &mut wr,
            &Msg::PairCommit {
                name: ctx.name.clone(),
                commit,
            },
        )
        .await
        .map_err(w)?;

    let (peer_name, pub_r, nonce_r) = match timeout(PAIR_TIMEOUT, codec.read(&mut rd)).await {
        Ok(Ok(Msg::PairReveal {
            name,
            public,
            nonce,
        })) => (name, public, nonce),
        Ok(Ok(Msg::Bye(why))) => return Err(why),
        Ok(Ok(Msg::PairCancel)) => return Err("Cancelled on the other PC".into()),
        _ => return Err("Pairing failed: no reply from the other PC".into()),
    };
    codec
        .write(
            &mut wr,
            &Msg::PairReveal {
                name: ctx.name.clone(),
                public: eph.public,
                nonce: nonce_i,
            },
        )
        .await
        .map_err(w)?;

    let s = crypto::derive_pairing(&eph.agree(&pub_r), &eph.public, &pub_r, &nonce_i, &nonce_r);
    let peer_name = if peer_name.is_empty() {
        theirs.name
    } else {
        peer_name
    };
    ctx.notify(Notice::PairCode {
        code: s.code,
        peer_name: peer_name.clone(),
    });
    confirm_phase(ctx, rd, wr, codec, &s.key, b"initiator", b"responder").await?;
    Ok((s.key, peer_name, ip))
}

async fn pair_responder(
    mut rd: OwnedReadHalf,
    mut wr: OwnedWriteHalf,
    addr: SocketAddr,
    theirs: Hello,
    ctx: Ctx,
) -> Result<(), WireError> {
    let mut codec = FrameCodec::plain();
    if ctx.pairing_busy.swap(true, Ordering::SeqCst) {
        let _ = codec
            .write(&mut wr, &Msg::Bye("The other PC is busy pairing".into()))
            .await;
        return Ok(());
    }
    ctx.decision.send_replace(PairDecision::Pending);
    info!("pairing: request from {} ({})", theirs.name, addr.ip());

    let r: Result<([u8; 32], String, IpAddr), String> = async {
        let (peer_name, commit) = match timeout(HANDSHAKE_TIMEOUT, codec.read(&mut rd)).await {
            Ok(Ok(Msg::PairCommit { name, commit })) => (name, commit),
            _ => return Err("Pairing failed: bad request".to_string()),
        };
        let eph = crypto::EphemeralKey::generate();
        let nonce_r = crypto::random_bytes::<16>();
        codec
            .write(
                &mut wr,
                &Msg::PairReveal {
                    name: ctx.name.clone(),
                    public: eph.public,
                    nonce: nonce_r,
                },
            )
            .await
            .map_err(|e| e.to_string())?;
        let (pub_i, nonce_i) = match timeout(HANDSHAKE_TIMEOUT, codec.read(&mut rd)).await {
            Ok(Ok(Msg::PairReveal { public, nonce, .. })) => (public, nonce),
            _ => return Err("Pairing failed: bad reveal".to_string()),
        };
        if crypto::sha256(&[&pub_i, &nonce_i]) != commit {
            return Err(
                "Pairing failed: the other PC broke its commitment (possible interception)".into(),
            );
        }
        let s = crypto::derive_pairing(&eph.agree(&pub_i), &pub_i, &eph.public, &nonce_i, &nonce_r);
        ctx.notify(Notice::PairCode {
            code: s.code,
            peer_name: peer_name.clone(),
        });
        confirm_phase(&ctx, rd, wr, codec, &s.key, b"responder", b"initiator").await?;
        Ok((s.key, peer_name, addr.ip()))
    }
    .await;
    finish_pairing(&ctx, r);
    Ok(())
}

/// Wait until the owner confirms on this PC AND the peer's confirmation
/// arrives. The confirmation MAC also proves both sides derived the same key,
/// so a tampered exchange fails here even if the owner misreads the code.
async fn confirm_phase(
    ctx: &Ctx,
    rd: OwnedReadHalf,
    mut wr: OwnedWriteHalf,
    mut codec: FrameCodec,
    key: &[u8; 32],
    me: &[u8],
    them: &[u8],
) -> Result<(), String> {
    // Frame reads are not cancel-safe, so a task owns the read half.
    let (msg_tx, mut msg_rx) = mpsc::channel::<Msg>(4);
    let reader = tokio::spawn(async move {
        let mut rd = rd;
        let mut c = FrameCodec::plain();
        while let Ok(m) = c.read(&mut rd).await {
            if msg_tx.send(m).await.is_err() {
                break;
            }
        }
    });

    let mut decision = ctx.decision.subscribe();
    let deadline = sleep(PAIR_TIMEOUT);
    tokio::pin!(deadline);
    let (mut sent, mut peer_ok) = (false, false);
    let result = loop {
        if sent && peer_ok {
            break Ok(());
        }
        // Covers a decision made before we subscribed.
        if !sent {
            let now = *decision.borrow_and_update(); // copy: guard is not Send
            match now {
                PairDecision::Confirm => {
                    let mac = crypto::hmac(key, &[b"kvm-share confirm v2", me]);
                    if codec
                        .write(&mut wr, &Msg::PairConfirm { mac })
                        .await
                        .is_err()
                    {
                        break Err("Connection lost while pairing".into());
                    }
                    sent = true;
                    continue;
                }
                PairDecision::Cancel => {
                    let _ = codec.write(&mut wr, &Msg::PairCancel).await;
                    break Err("Pairing cancelled".into());
                }
                PairDecision::Pending => {}
            }
        }
        tokio::select! {
            _ = &mut deadline => {
                let _ = codec.write(&mut wr, &Msg::PairCancel).await;
                break Err("Pairing timed out (2 minutes)".into());
            }
            _ = decision.changed(), if !sent => {}
            m = msg_rx.recv() => match m {
                Some(Msg::PairConfirm { mac }) => {
                    let expect = crypto::hmac(key, &[b"kvm-share confirm v2", them]);
                    if !ct_eq(&mac, &expect) {
                        break Err("Pairing failed: the two PCs did not agree on the key".into());
                    }
                    peer_ok = true;
                }
                Some(Msg::PairCancel) => break Err("Pairing cancelled on the other PC".into()),
                Some(Msg::Bye(why)) => break Err(why),
                Some(_) => {}
                None => break Err("Connection lost while pairing".into()),
            },
        }
    };
    reader.abort();
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Node {
        ctx: Ctx,
        notices: mpsc::Receiver<Notice>,
        key_tx: watch::Sender<Option<[u8; 32]>>,
        peer_tx: watch::Sender<Option<IpAddr>>,
    }

    fn node(name: &str, port: u16, key: Option<[u8; 32]>) -> Node {
        let (key_tx, key_rx) = watch::channel(key);
        let (peer_tx, peer_rx) = watch::channel(None);
        let (n_tx, notices) = mpsc::channel(64);
        let (decision, _) = watch::channel(PairDecision::Pending);
        Node {
            ctx: Ctx {
                name: name.into(),
                port,
                udp_session: 7,
                key: key_rx,
                peer: peer_rx,
                notices: n_tx,
                decision,
                pairing_busy: Arc::new(AtomicBool::new(false)),
            },
            notices,
            key_tx,
            peer_tx,
        }
    }

    async fn listen() -> (TcpListener, u16) {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let p = l.local_addr().unwrap().port();
        (l, p)
    }

    async fn next(rx: &mut mpsc::Receiver<Notice>, secs: u64) -> Notice {
        timeout(Duration::from_secs(secs), rx.recv())
            .await
            .expect("notice timeout")
            .unwrap()
    }

    #[tokio::test]
    async fn session_connects_carries_clipboard_and_times_out() {
        let key = Some([9u8; 32]);
        let (l, port) = listen().await;
        let mut server = node("SERVER", port, key);
        tokio::spawn(serve(l, server.ctx.clone()));

        let client = node("CLIENT", port, key);
        let (out_tx, out_rx) = mpsc::channel(8);
        client
            .peer_tx
            .send_replace(Some("127.0.0.1".parse().unwrap()));
        let handle = tokio::spawn(run_client(client.ctx.clone(), out_rx));

        let conn = match next(&mut server.notices, 5).await {
            Notice::InboundUp {
                conn,
                name,
                udp_session,
                ..
            } => {
                assert_eq!(name, "CLIENT");
                assert_eq!(udp_session, 7);
                conn
            }
            n => panic!("unexpected {n:?}"),
        };
        out_tx.send("hello".into()).await.unwrap();
        match next(&mut server.notices, 5).await {
            Notice::Clip(t) => assert_eq!(t, "hello"),
            n => panic!("unexpected {n:?}"),
        }
        // Client vanishes â†’ server reports the peer gone (connection reset
        // here; a silent peer would hit the 6 s timeout instead).
        handle.abort();
        drop(client);
        match next(&mut server.notices, 10).await {
            Notice::InboundDown { conn: c } => assert_eq!(c, conn),
            n => panic!("unexpected {n:?}"),
        }
    }

    /// Regression (two-PC test 2026-11-24): after pairing at runtime the key
    /// watch had a fresh version, and every inbound session's cloned receiver
    /// saw it as "changed" at once and hung up — a reconnect storm.
    #[tokio::test]
    async fn session_survives_key_set_at_runtime() {
        let (l, port) = listen().await;
        let mut server = node("SERVER", port, None);
        tokio::spawn(serve(l, server.ctx.clone()));
        let client = node("CLIENT", port, None);
        let (_out_tx, out_rx) = mpsc::channel(8);
        tokio::spawn(run_client(client.ctx.clone(), out_rx));

        // Same as main.rs on PairDone: key and peer arrive after startup.
        server.key_tx.send_replace(Some([5u8; 32]));
        client.key_tx.send_replace(Some([5u8; 32]));
        client
            .peer_tx
            .send_replace(Some("127.0.0.1".parse().unwrap()));

        assert!(matches!(
            next(&mut server.notices, 5).await,
            Notice::InboundUp { .. }
        ));
        // Pings keep it up; nothing may arrive (no InboundDown, no reconnect).
        assert!(timeout(Duration::from_millis(2500), server.notices.recv())
            .await
            .is_err());
    }

    #[tokio::test]
    async fn silent_peer_times_out() {
        let key = [3u8; 32];
        let (l, port) = listen().await;
        let mut server = node("SERVER", port, Some(key));
        tokio::spawn(serve(l, server.ctx.clone()));

        // Hand-rolled client: authenticates, then never pings.
        let stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let (mut rd, mut wr) = stream.into_split();
        let c = node("SILENT", port, Some(key));
        let ours = c.ctx.hello(Purpose::Session);
        wire::write_hello(&mut wr, &ours).await.unwrap();
        let theirs = wire::read_hello(&mut rd).await.unwrap();
        let mut p = FrameCodec::plain();
        p.write(
            &mut wr,
            &Msg::Auth {
                mac: wire::auth_mac(&key, b"client", &ours.nonce, &theirs.nonce),
            },
        )
        .await
        .unwrap();
        assert!(matches!(p.read(&mut rd).await.unwrap(), Msg::Auth { .. }));
        assert!(matches!(
            next(&mut server.notices, 5).await,
            Notice::InboundUp { .. }
        ));
        let t0 = Instant::now();
        assert!(matches!(
            next(&mut server.notices, 10).await,
            Notice::InboundDown { .. }
        ));
        assert!(t0.elapsed() >= PEER_TIMEOUT - Duration::from_millis(200));
        drop((rd, wr));
    }

    #[tokio::test]
    async fn wrong_key_is_refused() {
        let (l, port) = listen().await;
        let mut server = node("SERVER", port, Some([1u8; 32]));
        tokio::spawn(serve(l, server.ctx.clone()));
        let mut client = node("CLIENT", port, Some([2u8; 32]));
        let (_out_tx, out_rx) = mpsc::channel(8);
        client
            .peer_tx
            .send_replace(Some("127.0.0.1".parse().unwrap()));
        tokio::spawn(run_client(client.ctx.clone(), out_rx));

        assert!(
            matches!(next(&mut server.notices, 5).await, Notice::Problem(p) if p.contains("different pairing key"))
        );
        assert!(matches!(
            next(&mut client.notices, 5).await,
            Notice::Problem(_)
        ));
        // Never reports up.
        assert!(timeout(Duration::from_millis(500), async {
            loop {
                if let Some(Notice::InboundUp { .. }) = server.notices.recv().await {
                    break;
                }
            }
        })
        .await
        .is_err());
        let _ = client.key_tx; // keep alive
    }

    #[tokio::test]
    async fn pairing_both_confirm() {
        let (l, port) = listen().await;
        let mut resp = node("RESP", port, None);
        tokio::spawn(serve(l, resp.ctx.clone()));
        let mut init = node("INIT", port, None);

        start_pairing(init.ctx.clone(), "127.0.0.1".parse().unwrap());
        let code_i = match next(&mut init.notices, 5).await {
            Notice::PairCode { code, peer_name } => {
                assert_eq!(peer_name, "RESP");
                code
            }
            n => panic!("unexpected {n:?}"),
        };
        let code_r = match next(&mut resp.notices, 5).await {
            Notice::PairCode { code, peer_name } => {
                assert_eq!(peer_name, "INIT");
                code
            }
            n => panic!("unexpected {n:?}"),
        };
        assert_eq!(code_i, code_r);

        resp.ctx.decision.send_replace(PairDecision::Confirm);
        init.ctx.decision.send_replace(PairDecision::Confirm);
        let k_i = match next(&mut init.notices, 5).await {
            Notice::PairDone { key, peer_name, .. } => {
                assert_eq!(peer_name, "RESP");
                key
            }
            n => panic!("unexpected {n:?}"),
        };
        let k_r = match next(&mut resp.notices, 5).await {
            Notice::PairDone { key, .. } => key,
            n => panic!("unexpected {n:?}"),
        };
        assert_eq!(k_i, k_r);
        assert!(!init.ctx.pairing_busy.load(Ordering::SeqCst));
        let _ = (&init.key_tx, &init.peer_tx, &resp.key_tx, &resp.peer_tx);
    }

    #[tokio::test]
    async fn pairing_cancel_on_one_side() {
        let (l, port) = listen().await;
        let mut resp = node("RESP", port, None);
        tokio::spawn(serve(l, resp.ctx.clone()));
        let mut init = node("INIT", port, None);
        start_pairing(init.ctx.clone(), "127.0.0.1".parse().unwrap());
        assert!(matches!(
            next(&mut init.notices, 5).await,
            Notice::PairCode { .. }
        ));
        assert!(matches!(
            next(&mut resp.notices, 5).await,
            Notice::PairCode { .. }
        ));
        init.ctx.decision.send_replace(PairDecision::Confirm);
        resp.ctx.decision.send_replace(PairDecision::Cancel);
        assert!(matches!(
            next(&mut resp.notices, 5).await,
            Notice::PairEnded(_)
        ));
        assert!(
            matches!(next(&mut init.notices, 5).await, Notice::PairEnded(w) if w.contains("other PC"))
        );
    }

    #[tokio::test]
    async fn version_mismatch_reported_on_both_sides() {
        let (l, port) = listen().await;
        let mut server = node("SERVER", port, Some([1u8; 32]));
        tokio::spawn(serve(l, server.ctx.clone()));
        // Fake future client: Hello with proto 3.
        let stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let (mut rd, mut wr) = stream.into_split();
        use tokio::io::AsyncWriteExt;
        let mut body = b"KVMS".to_vec();
        body.extend_from_slice(&3u16.to_le_bytes());
        wr.write_all(&(body.len() as u32).to_le_bytes())
            .await
            .unwrap();
        wr.write_all(&body).await.unwrap();
        assert!(
            matches!(next(&mut server.notices, 5).await, Notice::Problem(p) if p.contains("protocol v3"))
        );
        // The future client still gets our Hello and can tell the owner.
        assert!(wire::read_hello(&mut rd).await.is_ok());
    }
}
