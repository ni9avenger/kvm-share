// inject.rs — receive NetEvent from the network and replay it on this machine.
//
// Uses enigo 0.2 for cross-platform input injection:
//   Windows  → SendInput
//   macOS    → CGEventCreate / CGEventPost
//   Linux    → X11 XTest (or uinput via enigo's linux backend)
//
// Threading: enigo is not Send, so injection runs on a dedicated OS thread.
// The tokio runtime sends events to it via a std::sync::mpsc channel.

use crate::protocol::{NetEvent, EDGE_BOTTOM, EDGE_LEFT, EDGE_RIGHT, EDGE_TOP};
use enigo::{
    Axis, Button, Coordinate, Direction, Enigo, Key, Keyboard, Mouse, Settings,
};
use log::{debug, error, warn};
use rdev::Key as RdevKey;
use rdev::Button as RdevButton;
use std::sync::mpsc;

/// Start the injection thread.
/// Returns a sender — push NetEvents into it and they'll be injected locally.
pub fn start() -> mpsc::SyncSender<NetEvent> {
    let (tx, rx) = mpsc::sync_channel::<NetEvent>(512);

    std::thread::Builder::new()
        .name("inject".into())
        .spawn(move || run_inject(rx))
        .expect("failed to spawn inject thread");

    tx
}

fn run_inject(rx: mpsc::Receiver<NetEvent>) {
    let mut enigo = match Enigo::new(&Settings::default()) {
        Ok(e) => e,
        Err(e) => {
            error!("inject: failed to create Enigo: {e:?}");
            return;
        }
    };

    // Cache screen size for CursorEnter placement
    let (screen_w, screen_h) = rdev::display_size().unwrap_or((1920, 1080));

    while let Ok(event) = rx.recv() {
        if let Err(e) = apply(&mut enigo, &event, screen_w, screen_h) {
            debug!("inject: {e:?}");
        }
    }
}

fn apply(
    enigo: &mut Enigo,
    event: &NetEvent,
    screen_w: u64,
    screen_h: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    match event {
        NetEvent::MouseMove { dx, dy } => {
            enigo.move_mouse(*dx as i32, *dy as i32, Coordinate::Rel)?;
        }

        NetEvent::MouseButton { button, pressed } => {
            if let Some(btn) = rdev_button_to_enigo(button) {
                let dir = if *pressed { Direction::Press } else { Direction::Release };
                enigo.button(btn, dir)?;
            }
        }

        NetEvent::MouseScroll { dx, dy } => {
            if *dy != 0 {
                enigo.scroll(*dy as i32, Axis::Vertical)?;
            }
            if *dx != 0 {
                enigo.scroll(*dx as i32, Axis::Horizontal)?;
            }
        }

        NetEvent::Key { key, pressed } => {
            if let Some(k) = rdev_key_to_enigo(key) {
                let dir = if *pressed { Direction::Press } else { Direction::Release };
                enigo.key(k, dir)?;
            } else {
                debug!("inject: unmapped key {:?}", key);
            }
        }

        NetEvent::CursorEnter { from_edge, pos_frac } => {
            // Place cursor at the entry point on this screen.
            // Cursor enters from the *opposite* edge — e.g. server's Right edge
            // means cursor appears on our Left edge.
            let (x, y) = entry_position(*from_edge, *pos_frac, screen_w, screen_h);
            enigo.move_mouse(x, y, Coordinate::Abs)?;
        }

        NetEvent::CursorLeave { .. } | NetEvent::Ping => {}
    }
    Ok(())
}

/// Compute where to place the cursor when it enters this screen.
fn entry_position(from_edge: u8, pos_frac: f32, sw: u64, sh: u64) -> (i32, i32) {
    let sw = sw as f32;
    let sh = sh as f32;
    let frac = pos_frac.clamp(0.0, 1.0);

    // Place 80px inward from the edge so the cursor doesn't immediately
    // trigger the return-edge threshold on the receiving machine.
    const INSET: i32 = 80;
    match from_edge {
        // Cursor came from server's Right → enters our Left edge
        EDGE_RIGHT  => (INSET, (sh * frac) as i32),
        // Cursor came from server's Left  → enters our Right edge
        EDGE_LEFT   => (sw as i32 - INSET, (sh * frac) as i32),
        // Cursor came from server's Bottom → enters our Top edge
        EDGE_BOTTOM => ((sw * frac) as i32, INSET),
        // Cursor came from server's Top   → enters our Bottom edge
        EDGE_TOP    => ((sw * frac) as i32, sh as i32 - INSET),
        _           => (sw as i32 / 2, sh as i32 / 2),
    }
}

// ── Key mapping: rdev → enigo ─────────────────────────────────────────────────
//
// rdev uses OS-level key codes; enigo uses its own Key enum.
// This mapping covers the keys most users actually share across machines.
// Unknown keys are skipped with a debug log (not an error).

fn rdev_button_to_enigo(btn: &RdevButton) -> Option<Button> {
    match btn {
        RdevButton::Left    => Some(Button::Left),
        RdevButton::Right   => Some(Button::Right),
        RdevButton::Middle  => Some(Button::Middle),
        RdevButton::Unknown(n) => {
            warn!("inject: unknown mouse button {n}");
            None
        }
    }
}

fn rdev_key_to_enigo(key: &RdevKey) -> Option<Key> {
    match key {
        // ── Letters ──────────────────────────────────────────────────────────
        RdevKey::KeyA => Some(Key::Unicode('a')),
        RdevKey::KeyB => Some(Key::Unicode('b')),
        RdevKey::KeyC => Some(Key::Unicode('c')),
        RdevKey::KeyD => Some(Key::Unicode('d')),
        RdevKey::KeyE => Some(Key::Unicode('e')),
        RdevKey::KeyF => Some(Key::Unicode('f')),
        RdevKey::KeyG => Some(Key::Unicode('g')),
        RdevKey::KeyH => Some(Key::Unicode('h')),
        RdevKey::KeyI => Some(Key::Unicode('i')),
        RdevKey::KeyJ => Some(Key::Unicode('j')),
        RdevKey::KeyK => Some(Key::Unicode('k')),
        RdevKey::KeyL => Some(Key::Unicode('l')),
        RdevKey::KeyM => Some(Key::Unicode('m')),
        RdevKey::KeyN => Some(Key::Unicode('n')),
        RdevKey::KeyO => Some(Key::Unicode('o')),
        RdevKey::KeyP => Some(Key::Unicode('p')),
        RdevKey::KeyQ => Some(Key::Unicode('q')),
        RdevKey::KeyR => Some(Key::Unicode('r')),
        RdevKey::KeyS => Some(Key::Unicode('s')),
        RdevKey::KeyT => Some(Key::Unicode('t')),
        RdevKey::KeyU => Some(Key::Unicode('u')),
        RdevKey::KeyV => Some(Key::Unicode('v')),
        RdevKey::KeyW => Some(Key::Unicode('w')),
        RdevKey::KeyX => Some(Key::Unicode('x')),
        RdevKey::KeyY => Some(Key::Unicode('y')),
        RdevKey::KeyZ => Some(Key::Unicode('z')),

        // ── Numbers ──────────────────────────────────────────────────────────
        RdevKey::Num0 => Some(Key::Unicode('0')),
        RdevKey::Num1 => Some(Key::Unicode('1')),
        RdevKey::Num2 => Some(Key::Unicode('2')),
        RdevKey::Num3 => Some(Key::Unicode('3')),
        RdevKey::Num4 => Some(Key::Unicode('4')),
        RdevKey::Num5 => Some(Key::Unicode('5')),
        RdevKey::Num6 => Some(Key::Unicode('6')),
        RdevKey::Num7 => Some(Key::Unicode('7')),
        RdevKey::Num8 => Some(Key::Unicode('8')),
        RdevKey::Num9 => Some(Key::Unicode('9')),

        // ── Modifiers ────────────────────────────────────────────────────────
        RdevKey::ShiftLeft | RdevKey::ShiftRight       => Some(Key::Shift),
        RdevKey::ControlLeft | RdevKey::ControlRight   => Some(Key::Control),
        RdevKey::Alt                                    => Some(Key::Alt),
        RdevKey::AltGr                                 => Some(Key::Alt),
        RdevKey::MetaLeft | RdevKey::MetaRight         => Some(Key::Meta),
        RdevKey::CapsLock                              => Some(Key::CapsLock),

        // ── Navigation ───────────────────────────────────────────────────────
        RdevKey::UpArrow    => Some(Key::UpArrow),
        RdevKey::DownArrow  => Some(Key::DownArrow),
        RdevKey::LeftArrow  => Some(Key::LeftArrow),
        RdevKey::RightArrow => Some(Key::RightArrow),
        RdevKey::Home       => Some(Key::Home),
        RdevKey::End        => Some(Key::End),
        RdevKey::PageUp     => Some(Key::PageUp),
        RdevKey::PageDown   => Some(Key::PageDown),

        // ── Editing ──────────────────────────────────────────────────────────
        RdevKey::Return     => Some(Key::Return),
        RdevKey::Tab        => Some(Key::Tab),
        RdevKey::Space      => Some(Key::Space),
        RdevKey::Backspace  => Some(Key::Backspace),
        RdevKey::Delete     => Some(Key::Delete),
        RdevKey::Escape     => Some(Key::Escape),

        // ── Function keys ────────────────────────────────────────────────────
        RdevKey::F1  => Some(Key::F1),
        RdevKey::F2  => Some(Key::F2),
        RdevKey::F3  => Some(Key::F3),
        RdevKey::F4  => Some(Key::F4),
        RdevKey::F5  => Some(Key::F5),
        RdevKey::F6  => Some(Key::F6),
        RdevKey::F7  => Some(Key::F7),
        RdevKey::F8  => Some(Key::F8),
        RdevKey::F9  => Some(Key::F9),
        RdevKey::F10 => Some(Key::F10),
        RdevKey::F11 => Some(Key::F11),
        RdevKey::F12 => Some(Key::F12),

        // ── Punctuation / symbols ────────────────────────────────────────────
        RdevKey::Minus      => Some(Key::Unicode('-')),
        RdevKey::Equal      => Some(Key::Unicode('=')),
        RdevKey::LeftBracket  => Some(Key::Unicode('[')),
        RdevKey::RightBracket => Some(Key::Unicode(']')),
        RdevKey::BackSlash  => Some(Key::Unicode('\\')),
        RdevKey::SemiColon  => Some(Key::Unicode(';')),
        RdevKey::Quote      => Some(Key::Unicode('\'')),
        RdevKey::BackQuote  => Some(Key::Unicode('`')),
        RdevKey::Comma      => Some(Key::Unicode(',')),
        RdevKey::Dot        => Some(Key::Unicode('.')),
        RdevKey::Slash      => Some(Key::Unicode('/')),

        // ── Unknown ──────────────────────────────────────────────────────────
        RdevKey::Unknown(code) => {
            debug!("inject: unmapped key code {code}");
            None
        }
        _ => None,
    }
}
