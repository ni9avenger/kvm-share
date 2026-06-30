// protocol.rs — wire format for all events between the two machines.
//
// Transport:
//   Input events  →  UDP port 4242  (fire-and-forget, ~5–15 bytes each)
//   Clipboard     →  TCP port 4243  (length-prefixed UTF-8, reliable)
//
// Why UDP for input?
//   A dropped mouse-move packet doesn't matter — the next one arrives in <1 ms.
//   TCP would queue stale events and introduce head-of-line blocking lag.
//
// Why TCP for clipboard?
//   Clipboard must arrive intact. It's infrequent so TCP overhead is irrelevant.

use rdev::{Button, Key};
use serde::{Deserialize, Serialize};

/// Every event that travels over the UDP input channel.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NetEvent {
    // ── Mouse ────────────────────────────────────────────────────────────────
    /// Relative mouse delta. We send deltas (not absolute coords) so the
    /// remote screen resolution doesn't need to match.
    MouseMove { dx: f64, dy: f64 },
    MouseButton { button: Button, pressed: bool },
    /// Vertical scroll: dy>0 = down; horizontal: dx>0 = right
    MouseScroll { dx: i64, dy: i64 },

    // ── Keyboard ─────────────────────────────────────────────────────────────
    Key { key: Key, pressed: bool },

    // ── Control ──────────────────────────────────────────────────────────────
    /// Server → client: cursor is entering the remote screen.
    /// `from_edge`  — which edge the cursor came from (use EDGE_* constants).
    /// `pos_frac`   — 0.0–1.0 position along that edge (for cursor placement).
    CursorEnter { from_edge: u8, pos_frac: f32 },

    /// Client → server: cursor has left the remote screen; return control.
    CursorLeave { to_edge: u8, pos_frac: f32 },

    /// Keepalive — sent every 2 s when no input is flowing.
    Ping,
}

/// Edge identifiers used in CursorEnter / CursorLeave.
pub const EDGE_LEFT:   u8 = 0;
pub const EDGE_RIGHT:  u8 = 1;
pub const EDGE_TOP:    u8 = 2;
pub const EDGE_BOTTOM: u8 = 3;

/// Opposite edge (cursor entering Right → leaves Left on the remote)
pub fn opposite_edge(edge: u8) -> u8 {
    match edge {
        EDGE_LEFT   => EDGE_RIGHT,
        EDGE_RIGHT  => EDGE_LEFT,
        EDGE_TOP    => EDGE_BOTTOM,
        EDGE_BOTTOM => EDGE_TOP,
        _           => edge,
    }
}

impl NetEvent {
    /// Serialize to bytes for UDP transmission.
    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::serialize(self).unwrap_or_default()
    }

    /// Deserialize from a received UDP datagram.
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        bincode::deserialize(data).ok()
    }
}
