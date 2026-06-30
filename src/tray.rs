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

pub fn run(
    mut cfg: Config,
    peer_tx: Sender<Option<String>>,
    remote_mode: Arc<AtomicBool>,
    raw_tx: std::sync::mpsc::SyncSender<(f64, f64)>,
) {
    let icon = load_icon();

    // ── Menu items ────────────────────────────────────────────────────────
    let title_item   = MenuItem::new("KVM Share",                 false, None);
    let peer_label   = MenuItem::new(peer_display(&cfg),          false, None);
    let edge_label   = MenuItem::new(edge_display(&cfg),          false, None);
    let cycle_edge   = MenuItem::new("Cycle switch edge",         true,  None);
    let release_hint = MenuItem::new("Release: press ScrollLock", false, None);
    let edit_cfg     = MenuItem::new("Edit config file…",         true,  None);
    let reload_cfg   = MenuItem::new("Reload config",             true,  None);
    let debug_item   = MenuItem::new("Debug Window",              true,  None);
    let quit_item    = MenuItem::new("Quit",                      true,  None);

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
        &debug_item,
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

    // ── Windows: set up Raw Input on this thread ──────────────────────────
    #[cfg(target_os = "windows")]
    {
        match win32::create_raw_input_window() {
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
                edge_label.set_text(edge_display(&cfg));
                let _ = peer_tx.blocking_send(cfg.peer_ip.clone());
                info!("config reloaded: peer={:?} edge={:?}", cfg.peer_ip, cfg.switch_edge);
            }

            if id == debug_item.id() {
                debug_window::init();
                debug_window::log(format!(
                    "=== KVM Share debug started ===  peer={:?}  edge={:?}",
                    cfg.peer_ip, cfg.switch_edge
                ));
            }
        }

        while TrayIconEvent::receiver().try_recv().is_ok() {}

        // ── Platform message pumps ─────────────────────────────────────────
        #[cfg(target_os = "windows")]
        win32::pump_messages(&remote_mode, &raw_tx);

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
    use windows_sys::Win32::Foundation::HWND;
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

    /// Create a message-only hidden window on the current thread.
    /// WM_INPUT messages from Raw Input are delivered to this window.
    pub fn create_raw_input_window() -> Option<HWND> {
        unsafe {
            let hinstance = GetModuleHandleW(std::ptr::null());
            let class_name: Vec<u16> = "KvmShareRawInput\0".encode_utf16().collect();

            let wc = WNDCLASSEXW {
                cbSize:        std::mem::size_of::<WNDCLASSEXW>() as u32,
                style:         0,
                lpfnWndProc:   Some(DefWindowProcW),
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

    /// Drain the Win32 message queue.
    /// Intercepts WM_INPUT for remote-mode mouse movement; passes everything
    /// else to DefWindowProc (handles tray icon, menu, etc.).
    pub fn pump_messages(
        remote_mode: &Arc<AtomicBool>,
        raw_tx: &std::sync::mpsc::SyncSender<(f64, f64)>,
    ) {
        use std::sync::atomic::AtomicU64;
        static WM_INPUT_COUNT: AtomicU64 = AtomicU64::new(0);

        unsafe {
            let mut msg: MSG = std::mem::zeroed();
            while PeekMessageW(&mut msg, 0, 0, 0, PM_REMOVE) != 0 {
                if msg.message == WM_INPUT {
                    let in_remote = remote_mode.load(Ordering::Relaxed);
                    let n = WM_INPUT_COUNT.fetch_add(1, Ordering::Relaxed);

                    if let Some((dx, dy)) = read_raw_delta(msg.lParam) {
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
                }
                TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }
        }
    }
}
