// tray.rs — system tray icon and menu.
//
// MUST run on the main thread (OS requirement on all platforms).
//
// Menu:
//   KVM Share
//   ─────────────────────────
//   Peer: 192.168.x.x          (current peer, or "No peer set")
//   ─────────────────────────
//   Switch edge: Right          (current edge)
//   Cycle switch edge           (click to change: Right→Left→Top→Bottom→…)
//   ─────────────────────────
//   Release: press ScrollLock   (disabled hint)
//   ─────────────────────────
//   Edit config file…           (opens JSON in Notepad / default editor)
//   Reload config               (re-reads JSON, applies new peer IP / edge)
//   ─────────────────────────
//   Quit

use crate::config::{Config, Edge};
use log::info;
use tray_icon::{
    menu::{Menu, MenuEvent, MenuItem, PredefinedMenuItem},
    TrayIconBuilder, TrayIconEvent,
};
use tokio::sync::mpsc::Sender;

const ICON_BYTES: &[u8] = include_bytes!("../assets/icon.png");

pub fn run(mut cfg: Config, peer_tx: Sender<Option<String>>) {
    let icon = load_icon();

    // ── Menu items ────────────────────────────────────────────────────────
    let title_item   = MenuItem::new("KVM Share",                    false, None);
    let peer_label   = MenuItem::new(peer_display(&cfg),             false, None);
    let edge_label   = MenuItem::new(edge_display(&cfg),             false, None);
    let cycle_edge   = MenuItem::new("Cycle switch edge",            true,  None);
    let release_hint = MenuItem::new("Release: press ScrollLock",    false, None);
    let edit_cfg     = MenuItem::new("Edit config file…",            true,  None);
    let reload_cfg   = MenuItem::new("Reload config",                true,  None);
    let quit_item    = MenuItem::new("Quit",                         true,  None);

    let tray_menu = Menu::new();
    tray_menu.append_items(&[
        &title_item,
        &PredefinedMenuItem::separator(),
        &peer_label,
        &PredefinedMenuItem::separator(),
        &edge_label,
        &cycle_edge,
        &PredefinedMenuItem::separator(),
        &release_hint,
        &PredefinedMenuItem::separator(),
        &edit_cfg,
        &reload_cfg,
        &PredefinedMenuItem::separator(),
        &quit_item,
    ]).unwrap();

    let _tray = TrayIconBuilder::new()
        .with_menu(Box::new(tray_menu))
        .with_tooltip("KVM Share — right-click to configure")
        .with_icon(icon)
        .build()
        .expect("failed to create tray icon");

    #[cfg(target_os = "linux")]
    gtk::init().expect("GTK init failed");

    let menu_channel = MenuEvent::receiver();
    info!("tray: running");

    loop {
        // ── Handle menu events ─────────────────────────────────────────────
        while let Ok(event) = menu_channel.try_recv() {
            let id = event.id();

            if id == quit_item.id() {
                info!("quit requested");
                std::process::exit(0);
            }

            if id == cycle_edge.id() {
                cfg.switch_edge = match cfg.switch_edge {
                    Edge::Right  => Edge::Left,
                    Edge::Left   => Edge::Top,
                    Edge::Top    => Edge::Bottom,
                    Edge::Bottom => Edge::Right,
                };
                cfg.save();
                edge_label.set_text(edge_display(&cfg));
                info!("switch edge → {:?}", cfg.switch_edge);
            }

            if id == edit_cfg.id() {
                open_config_in_editor();
            }

            if id == reload_cfg.id() {
                cfg = Config::load();
                peer_label.set_text(peer_display(&cfg));
                edge_label.set_text(edge_display(&cfg));
                // Notify the background runtime of the (possibly new) peer IP
                let _ = peer_tx.blocking_send(cfg.peer_ip.clone());
                info!("config reloaded: peer={:?} edge={:?}", cfg.peer_ip, cfg.switch_edge);
            }
        }

        while TrayIconEvent::receiver().try_recv().is_ok() {}

        // ── Platform message pumps ─────────────────────────────────────────
        #[cfg(target_os = "windows")]
        pump_win32();

        #[cfg(target_os = "linux")]
        while gtk::events_pending() {
            gtk::main_iteration_do(false);
        }

        std::thread::sleep(std::time::Duration::from_millis(16));
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn peer_display(cfg: &Config) -> String {
    match &cfg.peer_ip {
        Some(ip) => format!("Peer: {ip}"),
        None     => "Peer: not set".into(),
    }
}

fn edge_display(cfg: &Config) -> String {
    format!("Switch edge: {:?}", cfg.switch_edge)
}

fn load_icon() -> tray_icon::Icon {
    let img = image::load_from_memory(ICON_BYTES)
        .expect("icon load")
        .into_rgba8();
    let (w, h) = img.dimensions();
    tray_icon::Icon::from_rgba(img.into_raw(), w, h).expect("icon create")
}

/// Open the config JSON in the system's default text editor.
/// User edits the file, saves, then clicks "Reload config" in the tray.
fn open_config_in_editor() {
    let path = Config::path();

    // Ensure the file exists before opening
    if !path.exists() {
        let default = Config::default();
        default.save();
    }

    #[cfg(target_os = "windows")]
    {
        let _ = std::process::Command::new("notepad")
            .arg(&path)
            .spawn();
    }

    #[cfg(target_os = "macos")]
    {
        let _ = std::process::Command::new("open")
            .args(["-t", &path.to_string_lossy()])
            .spawn();
    }

    #[cfg(target_os = "linux")]
    {
        // Try common editors in order
        for editor in &["xdg-open", "gedit", "kate", "nano"] {
            if std::process::Command::new(editor)
                .arg(&path)
                .spawn()
                .is_ok()
            {
                break;
            }
        }
    }
}

/// Drain pending Win32 messages so the tray context menu works on Windows.
/// tray-icon creates a hidden HWND on the main thread; without pumping its
/// message queue, WM_RBUTTONUP → TrackPopupMenu never fires.
#[cfg(target_os = "windows")]
fn pump_win32() {
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        DispatchMessageW, PeekMessageW, TranslateMessage, MSG, PM_REMOVE,
    };
    unsafe {
        let mut msg: MSG = std::mem::zeroed();
        while PeekMessageW(&mut msg, 0, 0, 0, PM_REMOVE) != 0 {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }
}
