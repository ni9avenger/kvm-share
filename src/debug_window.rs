// debug_window.rs — floating debug log window (Windows: real Win32 window;
// other platforms: log lines are silently dropped).
//
// Usage:
//   debug_window::init();          // creates the window on a background thread
//   debug_window::log("hello");    // append a line; safe from any thread/hook

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, mpsc};

static INIT: AtomicBool = AtomicBool::new(false);
static LOG_TX: Mutex<Option<mpsc::SyncSender<String>>> = Mutex::new(None);

/// Create the debug window.  Idempotent — safe to call multiple times.
pub fn init() {
    if INIT.compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst).is_err() {
        return;
    }
    let (tx, rx) = mpsc::sync_channel::<String>(4096);
    if let Ok(mut guard) = LOG_TX.lock() {
        *guard = Some(tx);
    }
    std::thread::Builder::new()
        .name("debug-window".into())
        .spawn(move || platform_run(rx))
        .expect("debug-window thread");
}

/// Append a timestamped line.  No-op if window not yet created.
/// Uses try_lock so it never blocks (safe to call from hook callbacks).
pub fn log(msg: impl Into<String>) {
    if !INIT.load(Ordering::Relaxed) {
        return;
    }
    if let Ok(guard) = LOG_TX.try_lock() {
        if let Some(ref tx) = *guard {
            use std::time::{SystemTime, UNIX_EPOCH};
            let ms = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.subsec_millis())
                .unwrap_or(0);
            let _ = tx.try_send(format!("[{:03}] {}", ms, msg.into()));
        }
    }
}

// ── Windows implementation ────────────────────────────────────────────────────

#[cfg(windows)]
fn platform_run(rx: mpsc::Receiver<String>) {
    use std::{mem, ptr};
    use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        CreateWindowExW, DispatchMessageW, GetWindowTextLengthW,
        PeekMessageW, SendMessageW, ShowWindow, TranslateMessage,
        MSG, PM_REMOVE, SW_SHOW, WM_QUIT,
        WS_OVERLAPPEDWINDOW, WS_VSCROLL,
    };

    // Edit-control window styles (not exported as named consts by windows-sys)
    const ES_MULTILINE:   u32 = 0x0004;
    const ES_AUTOVSCROLL: u32 = 0x0040;
    const ES_READONLY:    u32 = 0x0800;

    // Edit-control messages
    const EM_SETSEL:      u32 = 0x00B1;
    const EM_REPLACESEL:  u32 = 0x00C2;
    const EM_LIMITTEXT:   u32 = 0x00C5;
    const EM_SCROLLCARET: u32 = 0x00B7; // scroll so caret is visible

    unsafe {
        let hi = GetModuleHandleW(ptr::null());
        let class: Vec<u16> = "EDIT\0".encode_utf16().collect();
        let title: Vec<u16> = "KVM Share - Debug Log\0".encode_utf16().collect();

        let hwnd = CreateWindowExW(
            0,
            class.as_ptr(),
            title.as_ptr(),
            WS_OVERLAPPEDWINDOW | WS_VSCROLL | ES_MULTILINE | ES_AUTOVSCROLL | ES_READONLY,
            50, 50, 920, 680,
            0, 0, hi, ptr::null(),
        );
        if hwnd == 0 {
            return;
        }

        ShowWindow(hwnd, SW_SHOW);
        // Allow up to 2 MB of text before wrapping
        SendMessageW(hwnd, EM_LIMITTEXT, 2_000_000, 0);

        loop {
            // Pump messages for the debug window
            let mut msg: MSG = mem::zeroed();
            while PeekMessageW(&mut msg, 0, 0, 0, PM_REMOVE) != 0 {
                if msg.message == WM_QUIT { return; }
                TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }

            // Drain incoming log lines and append them
            let mut did_append = false;
            while let Ok(line) = rx.try_recv() {
                let mut text: Vec<u16> = line.encode_utf16().collect();
                text.push('\r' as u16);
                text.push('\n' as u16);
                text.push(0u16);

                let end = GetWindowTextLengthW(hwnd).max(0) as usize;
                SendMessageW(hwnd, EM_SETSEL, end, end as isize);
                SendMessageW(hwnd, EM_REPLACESEL, 0, text.as_ptr() as isize);
                did_append = true;
            }

            // Scroll to show the caret (which is already at end after EM_REPLACESEL)
            if did_append {
                SendMessageW(hwnd, EM_SCROLLCARET, 0, 0);
            }

            std::thread::sleep(std::time::Duration::from_millis(50));
        }
    }
}

#[cfg(not(windows))]
fn platform_run(rx: mpsc::Receiver<String>) {
    while rx.recv().is_ok() {}
}
