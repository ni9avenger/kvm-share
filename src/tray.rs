// tray.rs — system tray icon, menu, and (Windows) Raw Input mouse capture.
//
// MUST run on the main thread (OS requirement on all platforms).
//
// On Windows this thread does double duty:
//   1. Tray icon + context menu (via tray-icon crate + Win32 message pump)
//   2. Raw Input mouse delta capture for remote mode
//
// Why Raw Input for remote-mode mouse movement?
//   rdev's WH_MOUSE_LL hook gives LLMHF absolute screen coords. On a
//   single-monitor machine these coords are clamped to [0, screen_width-1],
//   so pushing the mouse past the right edge still gives x=1919 every event
//   → delta = 0 → cursor on remote machine never moves.
//
//   Raw Input (RegisterRawInputDevices / WM_INPUT / GetRawInputData) bypasses
//   all of that and gives lLastX/lLastY directly from the HID driver.
//   These are true relative hardware deltas, always correct regardless of
//   where the visible cursor is or whether it's clamped.

use crate::config::{Config, Edge};
use crate::debug_window;
use log::{info, warn};
use std::sync::{
    atomic::AtomicBool,
    Arc,
};
use tray_icon::{
    menu::{Menu, MenuEvent, MenuItem, PredefinedMenuItem},
    TrayIconBuilder, TrayIconEvent,
};
use tokio::sync::mpsc::Sender;

const ICON_BYTES: &[u8] = include_bytes!("../assets/icon.png");

/// Tray → coordinator.
pub enum TrayCmd {
    Reload(Config),
    PairStart,
    PairConfirm,
    PairCancel,
    Unpair,
}

/// Coordinator → tray. Pairing has no text entry on purpose: both PCs show
/// the same code and the owner confirms on each (numeric comparison), which
/// works from a plain menu until the Phase 4 settings window exists.
pub struct TrayUpdate {
    pub status: String,
    pub pairing: bool,
    pub paired: bool,
}

pub fn run(
    mut cfg: Config,
    cmd_tx: Sender<TrayCmd>,
    updates: std::sync::mpsc::Receiver<TrayUpdate>,
    remote_mode: Arc<AtomicBool>,
    raw_tx: std::sync::mpsc::SyncSender<(f64, f64)>,
) {
    let icon = load_icon();

    // ── Menu items ────────────────────────────────────────────────────────
    let title = format!("KVM Share v{}", env!("CARGO_PKG_VERSION"));
    let title_item   = MenuItem::new(title,                       false, None);
    let status_item  = MenuItem::new("Starting…",                 false, None);
    let peer_label   = MenuItem::new(peer_display(&cfg),          false, None);
    let pair_item    = MenuItem::new(pair_display(&cfg),          cfg.peer_ip.is_some(), None);
    let confirm_item = MenuItem::new("Confirm pairing (codes match)", false, None);
    let cancel_item  = MenuItem::new("Cancel pairing",            false, None);
    let unpair_item  = MenuItem::new("Unpair",                    cfg.pairing.is_some(), None);
    let edge_label   = MenuItem::new(edge_display(&cfg),          false, None);
    let cycle_edge   = MenuItem::new("Cycle switch edge (restart to apply)", true, None);
    let release_hint = MenuItem::new("Release: press ScrollLock", false, None);
    let edit_cfg     = MenuItem::new("Edit config file…",         true,  None);
    let reload_cfg   = MenuItem::new("Reload config",             true,  None);
    let logs_item    = MenuItem::new("Open log folder",           true,  None);
    let debug_item   = MenuItem::new("Debug Window",              true,  None);
    let quit_item    = MenuItem::new("Quit",                      true,  None);

    let tray_menu = Menu::new();
    tray_menu.append_items(&[
        &title_item,
        &status_item,
        &PredefinedMenuItem::separator(),
        &peer_label,
        &pair_item,
        &confirm_item,
        &cancel_item,
        &unpair_item,
        &PredefinedMenuItem::separator(),
        &edge_label,
        &cycle_edge,
        &PredefinedMenuItem::separator(),
        &release_hint,
        &PredefinedMenuItem::separator(),
        &edit_cfg,
        &reload_cfg,
        &logs_item,
        &debug_item,
        &PredefinedMenuItem::separator(),
        &quit_item,
    ]).unwrap();

    let tray = TrayIconBuilder::new()
        .with_menu(Box::new(tray_menu))
        .with_tooltip("KVM Share — right-click to configure")
        .with_icon(icon)
        .build()
        .expect("failed to create tray icon");

    #[cfg(target_os = "linux")]
    gtk::init().expect("GTK init failed");

    // ── Windows: set up Raw Input on this thread ──────────────────────────
    #[cfg(target_os = "windows")]
    {
        match win32::create_raw_input_window(remote_mode.clone(), raw_tx.clone()) {
            Some(hwnd) => {
                if win32::register_raw_input(hwnd) {
                    info!("raw input: registered successfully");
                } else {
                    warn!("raw input: RegisterRawInputDevices failed — mouse in remote mode may not work");
                }
            }
            None => {
                warn!("raw input: could not create hidden window");
            }
        }
    }

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
                pair_item.set_text(pair_display(&cfg));
                edge_label.set_text(edge_display(&cfg));
                let _ = cmd_tx.blocking_send(TrayCmd::Reload(cfg.clone()));
                info!("config reloaded: peer={:?} edge={:?}", cfg.peer_ip, cfg.switch_edge);
            }

            if id == pair_item.id() {
                let _ = cmd_tx.blocking_send(TrayCmd::PairStart);
            }
            if id == confirm_item.id() {
                let _ = cmd_tx.blocking_send(TrayCmd::PairConfirm);
                confirm_item.set_enabled(false);
            }
            if id == cancel_item.id() {
                let _ = cmd_tx.blocking_send(TrayCmd::PairCancel);
            }
            if id == unpair_item.id() {
                let _ = cmd_tx.blocking_send(TrayCmd::Unpair);
            }

            if id == logs_item.id() {
                open_log_folder();
            }

            if id == debug_item.id() {
                debug_window::init();
                debug_window::log(format!(
                    "=== KVM Share debug started ===  peer={:?}  edge={:?}",
                    cfg.peer_ip, cfg.switch_edge
                ));
            }
        }

        // ── Coordinator status → menu ──────────────────────────────────────
        if let Some(u) = updates.try_iter().last() {
            status_item.set_text(format!("Status: {}", u.status));
            let _ = tray.set_tooltip(Some(format!("KVM Share — {}", u.status)));
            confirm_item.set_enabled(u.pairing);
            cancel_item.set_enabled(u.pairing);
            pair_item.set_enabled(!u.pairing);
            unpair_item.set_enabled(u.paired && !u.pairing);
            // The coordinator may have adopted a new peer IP or saved a pairing.
            cfg = Config::load();
            peer_label.set_text(peer_display(&cfg));
            pair_item.set_text(pair_display(&cfg));
        }

        while TrayIconEvent::receiver().try_recv().is_ok() {}

        // ── Platform message pumps ─────────────────────────────────────────
        #[cfg(target_os = "windows")]
        win32::pump_messages();

        #[cfg(target_os = "linux")]
        while gtk::events_pending() {
            gtk::main_iteration_do(false);
        }

        std::thread::sleep(std::time::Duration::from_millis(8));
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

fn pair_display(cfg: &Config) -> String {
    match (&cfg.peer_ip, &cfg.pairing) {
        (Some(ip), Some(_)) => format!("Pair again with {ip}…"),
        (Some(ip), None)    => format!("Pair with {ip}…"),
        (None, _)           => "Pair… (set peer_ip in config first)".into(),
    }
}

fn open_log_folder() {
    let dir = crate::logging::log_dir();
    let _ = std::fs::create_dir_all(&dir);
    #[cfg(target_os = "windows")]
    { let _ = std::process::Command::new("explorer").arg(&dir).spawn(); }
    #[cfg(not(target_os = "windows"))]
    { let _ = std::process::Command::new("xdg-open").arg(&dir).spawn(); }
}

fn load_icon() -> tray_icon::Icon {
    let img = image::load_from_memory(ICON_BYTES)
        .expect("icon load")
        .into_rgba8();
    let (w, h) = img.dimensions();
    tray_icon::Icon::from_rgba(img.into_raw(), w, h).expect("icon create")
}

fn open_config_in_editor() {
    let path = Config::path();
    if !path.exists() {
        Config::default().save();
    }

    #[cfg(target_os = "windows")]
    { let _ = std::process::Command::new("notepad").arg(&path).spawn(); }

    #[cfg(target_os = "macos")]
    { let _ = std::process::Command::new("open").args(["-t", &path.to_string_lossy()]).spawn(); }

    #[cfg(target_os = "linux")]
    {
        for editor in &["xdg-open", "gedit", "kate", "nano"] {
            if std::process::Command::new(editor).arg(&path).spawn().is_ok() { break; }
        }
    }
}

// ── Windows: Raw Input + Win32 message pump ───────────────────────────────────
#[cfg(target_os = "windows")]
mod win32 {
    use log::debug;
    use std::sync::{atomic::{AtomicBool, Ordering}, Arc};
    use windows_sys::Win32::Foundation::{HWND, LPARAM, LRESULT, WPARAM};
    use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
    use windows_sys::Win32::UI::Input::{
        GetRawInputData, RegisterRawInputDevices,
        RAWINPUT, RAWINPUTDEVICE, RAWINPUTHEADER,
        RIDEV_INPUTSINK, RID_INPUT,
    };
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        CreateWindowExW, DefWindowProcW, DispatchMessageW, PeekMessageW,
        RegisterClassExW, TranslateMessage, HWND_MESSAGE, WS_POPUP,
        MSG, PM_REMOVE, WNDCLASSEXW,
    };

    const WM_INPUT: u32        = 0x00FF;
    const RIM_TYPEMOUSE: u32   = 0;
    /// Bit 0 of RAWMOUSE.usFlags: 1 = absolute, 0 = relative
    const MOUSE_ABSOLUTE: u16  = 1;

    type RawSink = (Arc<AtomicBool>, std::sync::mpsc::SyncSender<(f64, f64)>);

    thread_local! {
        /// Where the window procedure sends deltas. Thread-local because the
        /// window procedure always runs on the thread that created the window.
        static RAW_SINK: std::cell::RefCell<Option<RawSink>> = const { std::cell::RefCell::new(None) };
    }

    /// Create a message-only hidden window on the current thread.
    /// WM_INPUT messages from Raw Input are delivered to this window.
    ///
    /// WM_INPUT is handled in the window procedure, not in `pump_messages`:
    /// while the tray menu is open, TrackPopupMenu runs its own modal loop
    /// on this thread, and our pump never sees the messages. Deltas were
    /// lost and the cursor stuck on the peer (two-PC test, 2026-11-24).
    /// Every modal loop still dispatches to the window procedure.
    pub fn create_raw_input_window(
        remote_mode: Arc<AtomicBool>,
        raw_tx: std::sync::mpsc::SyncSender<(f64, f64)>,
    ) -> Option<HWND> {
        RAW_SINK.with(|s| *s.borrow_mut() = Some((remote_mode, raw_tx)));
        unsafe {
            let hinstance = GetModuleHandleW(std::ptr::null());
            let class_name: Vec<u16> = "KvmShareRawInput\0".encode_utf16().collect();

            let wc = WNDCLASSEXW {
                cbSize:        std::mem::size_of::<WNDCLASSEXW>() as u32,
                style:         0,
                lpfnWndProc:   Some(raw_input_wnd_proc),
                cbClsExtra:    0,
                cbWndExtra:    0,
                hInstance:     hinstance,
                hIcon:         0,
                hCursor:       0,
                hbrBackground: 0,
                lpszMenuName:  std::ptr::null(),
                lpszClassName: class_name.as_ptr(),
                hIconSm:       0,
            };
            RegisterClassExW(&wc); // OK if it fails (class already exists)

            let hwnd = CreateWindowExW(
                0,
                class_name.as_ptr(),
                std::ptr::null(),  // no title
                WS_POPUP,
                0, 0, 0, 0,        // invisible, zero size
                HWND_MESSAGE,      // message-only — never shown on screen
                0,
                hinstance,
                std::ptr::null(),
            );

            if hwnd == 0 { None } else { Some(hwnd) }
        }
    }

    /// Register hwnd for raw mouse input. RIDEV_INPUTSINK = receive even
    /// when the app is not in the foreground (critical for a KVM tool).
    pub fn register_raw_input(hwnd: HWND) -> bool {
        unsafe {
            let rid = RAWINPUTDEVICE {
                usUsagePage: 0x01, // HID_USAGE_PAGE_GENERIC
                usUsage:     0x02, // HID_USAGE_GENERIC_MOUSE
                dwFlags:     RIDEV_INPUTSINK,
                hwndTarget:  hwnd,
            };
            RegisterRawInputDevices(
                &rid,
                1,
                std::mem::size_of::<RAWINPUTDEVICE>() as u32,
            ) != 0
        }
    }

    /// Parse a WM_INPUT lParam and return (dx, dy) for relative mouse movement.
    fn read_raw_delta(lparam: isize) -> Option<(f64, f64)> {
        unsafe {
            let header_sz = std::mem::size_of::<RAWINPUTHEADER>() as u32;
            let mut sz = 0u32;

            // Query size first.
            GetRawInputData(lparam as _, RID_INPUT,
                            std::ptr::null_mut(), &mut sz, header_sz);
            if sz == 0 { return None; }

            // Read the struct.
            let mut buf = vec![0u8; sz as usize];
            let r = GetRawInputData(
                lparam as _,
                RID_INPUT,
                buf.as_mut_ptr() as *mut _,
                &mut sz,
                header_sz,
            );
            if r == u32::MAX { return None; }

            let raw = &*(buf.as_ptr() as *const RAWINPUT);
            if raw.header.dwType != RIM_TYPEMOUSE { return None; }

            let mouse = &raw.data.mouse;
            // Skip absolute-mode devices (tablets, touch).
            if mouse.usFlags & MOUSE_ABSOLUTE != 0 { return None; }

            let dx = mouse.lLastX as f64;
            let dy = mouse.lLastY as f64;
            if dx == 0.0 && dy == 0.0 { return None; }

            debug!("raw input dx={dx} dy={dy}");
            Some((dx, dy))
        }
    }

    /// Window procedure of the raw-input window: forwards remote-mode deltas,
    /// then lets DefWindowProc do the WM_INPUT cleanup Windows expects.
    unsafe extern "system" fn raw_input_wnd_proc(hwnd: HWND, msg: u32, wp: WPARAM, lp: LPARAM) -> LRESULT {
        use std::sync::atomic::AtomicU64;
        static WM_INPUT_COUNT: AtomicU64 = AtomicU64::new(0);

        if msg == WM_INPUT {
            RAW_SINK.with(|s| {
                let Some((remote_mode, raw_tx)) = &*s.borrow() else { return };
                let in_remote = remote_mode.load(Ordering::Relaxed);
                let n = WM_INPUT_COUNT.fetch_add(1, Ordering::Relaxed);

                if let Some((dx, dy)) = read_raw_delta(lp) {
                    // Log every 20th event to show data is flowing
                    if n % 20 == 0 || n < 5 {
                        crate::debug_window::log(format!(
                            "WM_INPUT #{n}  remote={in_remote}  dx={dx:.1} dy={dy:.1}"
                        ));
                    }
                    if in_remote {
                        let _ = raw_tx.try_send((dx, dy));
                    }
                } else if n < 5 {
                    // Log early failures (absolute mouse, size=0, etc.)
                    crate::debug_window::log(format!(
                        "WM_INPUT #{n}  remote={in_remote}  (no delta / absolute device)"
                    ));
                }
            });
        }
        DefWindowProcW(hwnd, msg, wp, lp)
    }

    /// Drain the Win32 message queue. WM_INPUT is handled by
    /// `raw_input_wnd_proc` when dispatched, here or in a modal loop.
    pub fn pump_messages() {
        unsafe {
            let mut msg: MSG = std::mem::zeroed();
            while PeekMessageW(&mut msg, 0, 0, 0, PM_REMOVE) != 0 {
                TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }
        }
    }
}
