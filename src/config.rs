// config.rs — persisted settings, loaded at startup and saved from the tray.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// IP address of the remote machine (set via tray)
    pub peer_ip: Option<String>,
    /// UDP port for input events (default 4242)
    pub input_port: u16,
    /// TCP port for clipboard sync (default 4243)
    pub clipboard_port: u16,
    /// Which screen edge triggers the switch to remote control
    pub switch_edge: Edge,
    /// Pixels from screen edge that count as "at the edge" (2–5 works well)
    pub edge_threshold: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Edge {
    Left,
    Right,
    Top,
    Bottom,
}

impl Edge {
    /// The protocol edge constant for this edge
    pub fn as_u8(&self) -> u8 {
        match self {
            Edge::Left   => crate::protocol::EDGE_LEFT,
            Edge::Right  => crate::protocol::EDGE_RIGHT,
            Edge::Top    => crate::protocol::EDGE_TOP,
            Edge::Bottom => crate::protocol::EDGE_BOTTOM,
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            peer_ip:        None,
            input_port:     4242,
            clipboard_port: 4243,
            switch_edge:    Edge::Right,
            edge_threshold: 3,
        }
    }
}

impl Config {
    /// Path: ~/.config/kvm-share/config.json
    pub fn path() -> PathBuf {
        dirs::config_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("kvm-share")
            .join("config.json")
    }

    /// Load from disk, or return defaults if the file doesn't exist.
    pub fn load() -> Self {
        let path = Self::path();
        if path.exists() {
            std::fs::read_to_string(&path)
                .ok()
                .and_then(|s| serde_json::from_str(&s).ok())
                .unwrap_or_default()
        } else {
            Self::default()
        }
    }

    /// Persist to disk (creates parent directory if needed).
    pub fn save(&self) {
        let path = Self::path();
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if let Ok(json) = serde_json::to_string_pretty(self) {
            let _ = std::fs::write(&path, json);
        }
    }

    pub fn input_addr(&self) -> String {
        format!("0.0.0.0:{}", self.input_port)
    }

    pub fn peer_input_addr(&self) -> Option<String> {
        self.peer_ip
            .as_ref()
            .map(|ip| format!("{}:{}", ip, self.input_port))
    }

    pub fn peer_clipboard_addr(&self) -> Option<String> {
        self.peer_ip
            .as_ref()
            .map(|ip| format!("{}:{}", ip, self.clipboard_port))
    }
}
