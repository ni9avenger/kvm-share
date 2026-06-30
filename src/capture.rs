// capture.rs — intercept ALL input before the OS sees it.
//
// Key design decisions:
//
//   VIRTUAL SCREEN DIMENSIONS (Windows).
//   rdev::display_size() returns only the PRIMARY monitor. On a 2-monitor
//   machine (3840×1080 total), the edge threshold would fire at x=1917 —
//   exactly where the cursor crosses between the machine's own monitors!
//   We use GetSystemMetrics(SM_CXVIRTUALSCREEN) for the true full bounds.
//
//   NO cursor warping.
//   Windows LLMHF hooks receive the raw proposed position before OS clamping.
//   Even at the screen edge, pushing further gives real non-zero deltas.
//   Warping caused "dancing": if a real event arrived between SetCursorPos
//   and its echo, skip_warps desynchronised → huge oscillating delta.
//
//   Mode set IMMEDIATELY in callback.
//   remote_mode=true must be stored here (not via async coordinator latency).
//   Any delay lets events slip through as LOCAL, bouncing the cursor.
//
//   AUTO return edge.
//   When being controlled by a peer, we watch a dynamically-updated
//   return_edge (set by coordinator from CursorEnter's from_edge).
//   No manual config needed on the receiving machine.

use crate::config::Config;
use crate::protocol::{NetEvent, EDGE_BOTTOM, EDGE_LEFT, EDGE_RIGHT, EDGE_TOP};
use log::{error, info};
use rdev::{grab, Event, EventType};
use std::cell::Cell;
use std::sync::{
    atomic::{AtomicBool, AtomicU8, Ordering},
    mpsc, Arc,
};

#[derive(Debug)]
pub enum CaptureMsg {
    Event(NetEvent),
    /// Our cursor left the screen — we're now controlling the remote machine.
    EnterRemote { edge: u8, pos_frac: f32 },
    /// Cursor reached the return edge — signal the coordinator to send CursorLeave
    /// back to whoever is currently controlling us.
    ReturnControl { edge: u8, pos_frac: f32 },
    /// ScrollLock pressed — unconditional release of whichever mode is active.
    ForceRelease,
}

pub fn start(
    config: Config,
    being_controlled: Arc<AtomicBool>,
    return_edge: Arc<AtomicU8>,
) -> (mpsc::Receiver<CaptureMsg>, Arc<AtomicBool>) {
    let (tx, rx) = mpsc::sync_channel::<CaptureMsg>(512);
    let remote_mode = Arc::new(AtomicBool::new(false));
    let mode_flag = Arc::clone(&remote_mode);

    std::thread::Builder::new()
        .name("capture".into())
        .spawn(move || run_grab(config, tx, mode_flag, being_controlled, return_edge))
        .expect("capture thread");

    (rx, remote_mode)
}

fn run_grab(
    config: Config,
    tx: mpsc::SyncSender<CaptureMsg>,
    mode: Arc<AtomicBool>,
    being_controlled: Arc<AtomicBool>,
    return_edge: Arc<AtomicU8>,
) {
    let (vx, vy, vw, vh) = screen_bounds();
    let threshold = config.edge_threshold as f64;
    let switch_edge = config.switch_edge.clone();

    info!(
        "capture: virtual screen ({vx},{vy}) {}×{}, switch_edge={:?}, threshold={}px",
        vw, vh, switch_edge, config.edge_threshold
    );

    // rdev::grab requires Fn (not FnMut) — Cell gives interior mutability.
    let prev_x          = Cell::new(vx + vw / 2.0);
    let prev_y          = Cell::new(vy + vh / 2.0);
    let was_remote      = Cell::new(false);
    let prev_being_ctrl = Cell::new(false);
    // Debounce: skip return-edge check for N events after entering being_ctrl.
    // inject.rs places the cursor near the return edge; without this the very
    // first injected move event fires ReturnControl instantly → CursorLeave →
    // remote_mode=false on controller → infinite enter/leave loop.
    let debounce_count  = Cell::new(0u32);

    let result = grab(move |event: Event| -> Option<Event> {
        let in_remote  = mode.load(Ordering::Relaxed);
        let being_ctrl = being_controlled.load(Ordering::Relaxed);
        let ret_edge   = return_edge.load(Ordering::Relaxed);

        // Detect remote→local transition and restore cursor visibility.
        if was_remote.get() && !in_remote {
            show_cursor();
            was_remote.set(false);
        }

        // Detect being_ctrl false→true transition: arm debounce counter.
        if being_ctrl && !prev_being_ctrl.get() {
            debounce_count.set(40);
        }
        prev_being_ctrl.set(being_ctrl);

        match &event.event_type {
            // ── Mouse movement ────────────────────────────────────────────────
            EventType::MouseMove { x, y } => {
                let (cx, cy) = (*x, *y);

                // ── Controlling remote ────────────────────────────────────────
                if in_remote {
                    // Windows: Raw Input (tray.rs WM_INPUT handler) provides
                    // true hardware deltas independent of cursor position.
                    // Just suppress here — don't try to compute deltas from
                    // LLMHF absolute coords, which are clamped to screen bounds
                    // and give zero/tiny deltas when cursor is frozen at edge.
                    #[cfg(not(windows))]
                    {
                        // Non-Windows: cursor isn't clamped the same way;
                        // use the "frozen anchor" approach.
                        // prev_x/prev_y are set at entry and NEVER updated,
                        // so cx = anchor + hardware_delta → dx = hardware_delta.
                        let dx = cx - prev_x.get();
                        let dy = cy - prev_y.get();
                        if dx != 0.0 || dy != 0.0 {
                            let _ = tx.try_send(CaptureMsg::Event(
                                NetEvent::MouseMove { dx, dy },
                            ));
                        }
                    }
                    return None;
                }

                // ── Being controlled — watch for return edge ──────────────────
                if being_ctrl {
                    let dc = debounce_count.get();
                    if dc > 0 {
                        // Still in debounce window — don't check return edge yet.
                        debounce_count.set(dc - 1);
                    } else if check_edge(ret_edge, cx, cy, vx, vy, vw, vh, threshold) {
                        let pos_frac = edge_frac(ret_edge, cx, cy, vx, vy, vw, vh);
                        let _ = tx.try_send(CaptureMsg::ReturnControl {
                            edge: ret_edge,
                            pos_frac,
                        });
                    }
                    // Don't suppress — cursor should move freely while injected.
                    prev_x.set(cx);
                    prev_y.set(cy);
                    return Some(event);
                }

                // ── Local mode — watch for switch edge ────────────────────────
                let sw_edge = switch_edge.as_u8();
                if check_edge(sw_edge, cx, cy, vx, vy, vw, vh, threshold) {
                    let pos_frac = edge_frac(sw_edge, cx, cy, vx, vy, vw, vh);
                    mode.store(true, Ordering::Relaxed);
                    was_remote.set(true);
                    hide_cursor();
                    prev_x.set(cx);
                    prev_y.set(cy);
                    let _ = tx.try_send(CaptureMsg::EnterRemote {
                        edge: sw_edge,
                        pos_frac,
                    });
                    return None;
                }

                prev_x.set(cx);
                prev_y.set(cy);
                Some(event)
            }

            // ── Mouse buttons ─────────────────────────────────────────────────
            EventType::ButtonPress(button) => {
                if in_remote {
                    let _ = tx.try_send(CaptureMsg::Event(
                        NetEvent::MouseButton { button: *button, pressed: true },
                    ));
                    return None;
                }
                Some(event)
            }
            EventType::ButtonRelease(button) => {
                if in_remote {
                    let _ = tx.try_send(CaptureMsg::Event(
                        NetEvent::MouseButton { button: *button, pressed: false },
                    ));
                    return None;
                }
                Some(event)
            }

            // ── Scroll ────────────────────────────────────────────────────────
            EventType::Wheel { delta_x, delta_y } => {
                if in_remote {
                    let _ = tx.try_send(CaptureMsg::Event(
                        NetEvent::MouseScroll { dx: *delta_x, dy: *delta_y },
                    ));
                    return None;
                }
                Some(event)
            }

            // ── Keyboard ──────────────────────────────────────────────────────
            EventType::KeyPress(key) => {
                // ScrollLock = emergency release, always intercept.
                if matches!(key, rdev::Key::ScrollLock) {
                    let currently_doing_something = in_remote || being_ctrl;
                    if currently_doing_something {
                        mode.store(false, Ordering::Relaxed);
                        show_cursor();
                        was_remote.set(false);
                        let _ = tx.try_send(CaptureMsg::ForceRelease);
                        info!("capture: force-released via ScrollLock");
                    }
                    return None;
                }
                if in_remote {
                    let _ = tx.try_send(CaptureMsg::Event(
                        NetEvent::Key { key: *key, pressed: true },
                    ));
                    return None;
                }
                Some(event)
            }
            EventType::KeyRelease(key) => {
                if matches!(key, rdev::Key::ScrollLock) {
                    return None;
                }
                if in_remote {
                    let _ = tx.try_send(CaptureMsg::Event(
                        NetEvent::Key { key: *key, pressed: false },
                    ));
                    return None;
                }
                Some(event)
            }
        }
    });

    if let Err(e) = result {
        error!("capture: rdev::grab failed: {e:?}");
        error!("macOS: grant Accessibility in System Settings → Privacy → Accessibility");
        error!("Linux/Wayland: rdev grab unsupported — X11/XWayland required");
    }
}

// ── Edge helpers ──────────────────────────────────────────────────────────────

/// Returns true if the cursor (cx, cy) is within `threshold` of the named edge.
fn check_edge(edge: u8, cx: f64, cy: f64,
              vx: f64, vy: f64, vw: f64, vh: f64, threshold: f64) -> bool {
    match edge {
        EDGE_LEFT   => cx <= vx + threshold,
        EDGE_RIGHT  => cx >= vx + vw - threshold,
        EDGE_TOP    => cy <= vy + threshold,
        EDGE_BOTTOM => cy >= vy + vh - threshold,
        _           => false,
    }
}

/// Fractional position (0.0–1.0) along the edge — used for cursor placement
/// on the remote screen.
fn edge_frac(edge: u8, cx: f64, cy: f64,
             vx: f64, vy: f64, vw: f64, vh: f64) -> f32 {
    (match edge {
        EDGE_LEFT | EDGE_RIGHT   => (cy - vy) / vh,
        EDGE_TOP  | EDGE_BOTTOM  => (cx - vx) / vw,
        _                        => 0.5,
    } as f32)
        .clamp(0.0, 1.0)
}

// ── Screen bounds ─────────────────────────────────────────────────────────────
//
// Returns (x_origin, y_origin, width, height) of the full virtual desktop.
// On Windows with multiple monitors, origin can be negative and width > primary.

fn screen_bounds() -> (f64, f64, f64, f64) {
    #[cfg(windows)]
    unsafe {
        use windows_sys::Win32::UI::WindowsAndMessaging::{
            GetSystemMetrics,
            SM_CXVIRTUALSCREEN, SM_CYVIRTUALSCREEN,
            SM_XVIRTUALSCREEN, SM_YVIRTUALSCREEN,
        };
        let x = GetSystemMetrics(SM_XVIRTUALSCREEN) as f64;
        let y = GetSystemMetrics(SM_YVIRTUALSCREEN) as f64;
        let w = GetSystemMetrics(SM_CXVIRTUALSCREEN) as f64;
        let h = GetSystemMetrics(SM_CYVIRTUALSCREEN) as f64;
        // Sanity-check: if the API returns zeros (shouldn't happen but safe), fall back.
        if w <= 0.0 || h <= 0.0 {
            let (fw, fh) = rdev::display_size().unwrap_or((1920, 1080));
            return (0.0, 0.0, fw as f64, fh as f64);
        }
        (x, y, w, h)
    }
    #[cfg(not(windows))]
    {
        let (w, h) = rdev::display_size().unwrap_or((1920, 1080));
        (0.0, 0.0, w as f64, h as f64)
    }
}

// ── Cursor visibility ─────────────────────────────────────────────────────────
//
// ShowCursor maintains a reference count. We loop until we overshoot the
// threshold so the cursor is definitely in the desired state regardless of
// where the count started.

/// Hide the local cursor (called when entering remote mode).
pub fn hide_cursor() {
    #[cfg(windows)]
    unsafe {
        use windows_sys::Win32::UI::WindowsAndMessaging::ShowCursor;
        while ShowCursor(0) >= 0 {}
    }
}

/// Show the local cursor (called when returning to local mode).
pub fn show_cursor() {
    #[cfg(windows)]
    unsafe {
        use windows_sys::Win32::UI::WindowsAndMessaging::ShowCursor;
        while ShowCursor(1) < 0 {}
    }
}
