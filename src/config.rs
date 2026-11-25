// config.rs — persisted settings, loaded at startup and saved from the tray.
//
// v0.2 uses its OWN file, config-v2.json, next to v0.1.x's config.json.
// Why: v0.1.x's save() rewrites config.json with only its five keys, so if
// both versions shared a file, rolling back and touching the tray once would
// silently delete the v0.2 pairing key. On first run v0.2 copies peer_ip,
// switch_edge and edge_threshold from config.json, and never writes it.

use crate::crypto;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

// `#[serde(default)]`: a hand-edited file missing a key falls back to that key's
// default instead of failing to parse and silently resetting the whole config.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    /// IP address of the remote machine
    pub peer_ip: Option<String>,
    /// UDP port for signed input events (v0.1.x used 4242)
    pub input_port: u16,
    /// TCP port for the control channel: handshake, pairing, liveness,
    /// clipboard (v0.1.x used 4243 for clipboard only)
    pub control_port: u16,
    /// TCP port reserved for file transfer (Phase 3)
    pub transfer_port: u16,
    /// Which screen edge triggers the switch to remote control
    pub switch_edge: Edge,
    /// Pixels from screen edge that count as "at the edge" (2–5 works well)
    pub edge_threshold: i32,
    /// Name shown to the peer; defaults to the Windows computer name
    pub machine_name: Option<String>,
    /// Set once the two PCs are paired
    pub pairing: Option<PairingRecord>,
    /// error | warn | info | debug | trace
    pub log_level: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairingRecord {
    pub peer_name: String,
    /// 32-byte key, DPAPI-encrypted for the current Windows user, hex
    pub key_protected: String,
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
            input_port:     4252,
            control_port:   4253,
            transfer_port:  4254,
            switch_edge:    Edge::Right,
            edge_threshold: 3,
            machine_name:   None,
            pairing:        None,
            log_level:      "info".into(),
        }
    }
}

impl PairingRecord {
    pub fn new(peer_name: String, key: &[u8; 32]) -> Option<Self> {
        let sealed = crypto::protect(key)?;
        Some(Self { peer_name, key_protected: crypto::to_hex(&sealed) })
    }

    /// None if the record is corrupt or was made by another Windows user.
    pub fn key(&self) -> Option<[u8; 32]> {
        let sealed = crypto::from_hex(&self.key_protected)?;
        crypto::unprotect(&sealed)?.try_into().ok()
    }
}

impl Config {
    fn dir() -> PathBuf {
        dirs::config_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("kvm-share")
    }

    /// %APPDATA%\kvm-share\config-v2.json
    pub fn path() -> PathBuf {
        Self::dir().join("config-v2.json")
    }

    /// v0.1.x file, read once for migration, never written.
    fn legacy_path() -> PathBuf {
        Self::dir().join("config.json")
    }

    /// Load from disk; on first run, seed from v0.1.x settings.
    pub fn load() -> Self {
        let path = Self::path();
        if path.exists() {
            return Self::load_from(&path);
        }
        let cfg = Self::migrate_from(&Self::legacy_path());
        cfg.save();
        cfg
    }

    fn load_from(path: &std::path::Path) -> Self {
        std::fs::read_to_string(path)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default()
    }

    fn migrate_from(legacy: &std::path::Path) -> Self {
        let mut cfg = Self::default();
        let Some(v) = std::fs::read_to_string(legacy)
            .ok()
            .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok())
        else {
            return cfg;
        };
        if let Some(ip) = v.get("peer_ip").and_then(|x| x.as_str()) {
            cfg.peer_ip = Some(ip.to_string());
        }
        if let Some(e) = v.get("switch_edge").and_then(|x| serde_json::from_value(x.clone()).ok()) {
            cfg.switch_edge = e;
        }
        if let Some(t) = v.get("edge_threshold").and_then(|x| x.as_i64()) {
            cfg.edge_threshold = t as i32;
        }
        cfg
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

    pub fn name(&self) -> String {
        self.machine_name
            .clone()
            .or_else(|| std::env::var("COMPUTERNAME").ok())
            .unwrap_or_else(|| "kvm-share".into())
    }

    pub fn peer_addr(&self) -> Option<std::net::IpAddr> {
        self.peer_ip.as_ref()?.trim().parse().ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_file(name: &str, body: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("kvm-share-test-{}-{name}", std::process::id()));
        std::fs::write(&p, body).unwrap();
        p
    }

    #[test]
    fn migrates_v01_settings_only() {
        let p = temp_file(
            "legacy.json",
            r#"{"peer_ip":"192.168.1.5","input_port":4242,"clipboard_port":4243,"switch_edge":"Top","edge_threshold":5}"#,
        );
        let c = Config::migrate_from(&p);
        assert_eq!(c.peer_ip.as_deref(), Some("192.168.1.5"));
        assert_eq!(c.switch_edge, Edge::Top);
        assert_eq!(c.edge_threshold, 5);
        // Ports are NOT carried over: v2 must not collide with v0.1.x.
        assert_eq!((c.input_port, c.control_port), (4252, 4253));
        let _ = std::fs::remove_file(p);
    }

    #[test]
    fn missing_keys_fall_back_to_defaults() {
        let p = temp_file("partial.json", r#"{"peer_ip":"10.0.0.2"}"#);
        let c = Config::load_from(&p);
        assert_eq!(c.peer_ip.as_deref(), Some("10.0.0.2"));
        assert_eq!(c.control_port, 4253);
        assert_eq!(c.log_level, "info");
        let _ = std::fs::remove_file(p);
    }

    #[test]
    fn pairing_key_round_trip() {
        let key = crypto::random_bytes::<32>();
        let rec = PairingRecord::new("HP".into(), &key).unwrap();
        assert!(!rec.key_protected.contains(&crypto::to_hex(&key)));
        assert_eq!(rec.key().unwrap(), key);
    }
}
