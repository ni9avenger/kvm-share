// debug_window.rs — floating debug log window.
//
// Architecture (Windows):
//   A custom "KVMShareDbg" frame window owns a child EDIT control that fills
//   its client area.  This is the correct Win32 pattern — using EDIT directly
//   as a top-level window causes EM_SCROLLCARET to silently fail when the
//   window lacks focus.  A child EDIT has no such restriction.
//
//   WM_DESTROY → PostQuitMessage makes WM_QUIT arrive cleanly in the pump.
//
// Usage:
//   debug_window::init();   // creates / re-creates the window
//   debug_window::log("…"); // thread-safe, hook-safe

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, mpsc};

static INIT: AtomicBool = AtomicBool::new(false);
static LOG_TX: Mutex<Option<mpsc::SyncSender<String>>> = Mutex::new(None);

/// Create the debug window.  Re-creates it if previously closed.
pub fn init() {
    if INIT.compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst).is_err() {
        return;
    }
    let (tx, rx) = mpsc::sync_channel::<String>(4096);
    if let Ok(mut g) = LOG_TX.lock() { *g = Some(tx); }

    std::thread::Builder::new()
        .name("debug-window".into())
        .spawn(move || {
            platform_run(rx);
            INIT.store(false, Ordering::SeqCst);
            if let Ok(mut g) = LOG_TX.lock() { *g = None; }
        })
        .expect("debug-window thread");
}

/// Append a timestamped log line.  No-op if window not created.
/// try_lock ensures this is safe to call from WH_MOUSE_LL hook callbacks.
pub fn log(msg: impl Into<String>) {
    if !INIT.load(Ordering::Relaxed) { return; }
    if let Ok(g) = LOG_TX.try_lock() {
        if let Some(ref tx) = *g {
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

// Thread-local HWND of the child EDIT control.  Shared between the WndProc
// (which runs on the debug-window thread) and the log-drain loop.
// Defined at module level so the static extern "system" fn can access it.
#[cfg(windows)]
use std::cell::Cell;

#[cfg(windows)]
thread_local! {
    static CHILD_EDIT: Cell<isize> = const { Cell::new(0) };
}

// ── WndProc for the frame window ──────────────────────────────────────────────
// Module-level fn so it can see the module-level CHILD_EDIT thread-local.
#[cfg(windows)]
unsafe extern "system" fn frame_wnd_proc(
    hwnd: isize, msg: u32, _wp: usize, lp: isize,
) -> isize {
    use std::ptr;
    use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        CreateWindowExW, DefWindowProcW, MoveWindow, PostQuitMessage, SendMessageW,
        WS_CHILD, WS_VISIBLE, WS_VSCROLL,
    };

    const ES_MULTILINE:   u32 = 0x0004;
    const ES_AUTOVSCROLL: u32 = 0x0040;
    const ES_READONLY:    u32 = 0x0800;
    const WS_EX_CLIENTEDGE: u32 = 0x0000_0200;
    const EM_LIMITTEXT:   u32 = 0x00C5;
    const WM_CREATE:  u32 = 0x0001;
    const WM_SIZE:    u32 = 0x0005;
    const WM_DESTROY: u32 = 0x0002;

    match msg {
        WM_CREATE => {
            let hi = GetModuleHandleW(ptr::null());
            let class: Vec<u16> = "EDIT\0".encode_utf16().collect();
            let edit = CreateWindowExW(
                WS_EX_CLIENTEDGE,
                class.as_ptr(),
                ptr::null(),
                WS_CHILD | WS_VISIBLE | WS_VSCROLL
                    | ES_MULTILINE | ES_AUTOVSCROLL | ES_READONLY,
                0, 0, 10, 10,   // sized properly by the first WM_SIZE
                hwnd, 0, hi, ptr::null(),
            );
            if edit != 0 {
                SendMessageW(edit, EM_LIMITTEXT, 2_000_000, 0);
                CHILD_EDIT.with(|c| c.set(edit));
            }
            0
        }
        WM_SIZE => {
            let edit = CHILD_EDIT.with(|c| c.get());
            if edit != 0 {
                // lParam low-word = client width, high-word = client height
                let w = (lp as u32 & 0xFFFF) as i32;
                let h = ((lp as u32 >> 16) & 0xFFFF) as i32;
                MoveWindow(edit, 0, 0, w, h, 1);
            }
            0
        }
        WM_DESTROY => {
            // PostQuitMessage ensures WM_QUIT arrives in the pump below,
            // giving us a clean exit signal — no need for IsWindow polling.
            PostQuitMessage(0);
            0
        }
        _ => DefWindowProcW(hwnd, msg, _wp, lp),
    }
}

#[cfg(windows)]
fn platform_run(rx: mpsc::Receiver<String>) {
    use std::{mem, ptr};
    use windows_sys::Win32::Graphics::Gdi::HBRUSH;
    use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        CreateWindowExW, DispatchMessageW, GetWindowTextLengthW,
        PeekMessageW, RegisterClassExW, SendMessageW, ShowWindow, TranslateMessage,
        MSG, PM_REMOVE, SW_SHOW, WNDCLASSEXW,
        WS_OVERLAPPEDWINDOW,
    };

    // Edit-control messages
    const EM_SETSEL:      u32 = 0x00B1;
    const EM_REPLACESEL:  u32 = 0x00C2;
    const EM_SCROLLCARET: u32 = 0x00B7;

    // Window-class constants not exported by windows-sys 0.52
    const CS_VREDRAW:   u32 = 0x0001;
    const CS_HREDRAW:   u32 = 0x0002;
    const COLOR_WINDOW: i32 = 5;
    const WM_QUIT:      u32 = 0x0012;

    // Reset the child-edit handle for this run (in case window is being
    // re-created after a previous close).
    CHILD_EDIT.with(|c| c.set(0));

    unsafe {
        let hi = GetModuleHandleW(ptr::null());
        let class_name: Vec<u16> = "KVMShareDbg\0".encode_utf16().collect();

        // Register the frame class (silently ignore "already registered").
        let mut wc: WNDCLASSEXW = mem::zeroed();
        wc.cbSize        = mem::size_of::<WNDCLASSEXW>() as u32;
        wc.style         = CS_HREDRAW | CS_VREDRAW;
        wc.lpfnWndProc   = Some(frame_wnd_proc);
        wc.hInstance     = hi;
        wc.lpszClassName = class_name.as_ptr();
        wc.hbrBackground = (COLOR_WINDOW + 1) as HBRUSH;
        RegisterClassExW(&wc);

        let title: Vec<u16> = "KVM Share - Debug Log\0".encode_utf16().collect();
        let hwnd = CreateWindowExW(
            0,
            class_name.as_ptr(),
            title.as_ptr(),
            WS_OVERLAPPEDWINDOW,
            50, 50, 920, 680,
            0, 0, hi, ptr::null(),
        );
        if hwnd == 0 { return; }

        ShowWindow(hwnd, SW_SHOW);

        // ── Message pump + log drain ──────────────────────────────────────────
        loop {
            // Pump all pending Win32 messages for this thread.
            let mut msg: MSG = mem::zeroed();
            while PeekMessageW(&mut msg, 0, 0, 0, PM_REMOVE) != 0 {
                if msg.message == WM_QUIT { return; } // WM_DESTROY posted this
                TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }

            let edit = CHILD_EDIT.with(|c| c.get());
            if edit == 0 {
                // WM_CREATE hasn't fired yet — spin
                std::thread::sleep(std::time::Duration::from_millis(10));
                continue;
            }

            // Append any queued log lines to the child EDIT.
            let mut did_append = false;
            while let Ok(line) = rx.try_recv() {
                let mut text: Vec<u16> = line.encode_utf16().collect();
                text.push('\r' as u16);
                text.push('\n' as u16);
                text.push(0u16);

                let end = GetWindowTextLengthW(edit).max(0) as usize;
                SendMessageW(edit, EM_SETSEL, end, end as isize);
                SendMessageW(edit, EM_REPLACESEL, 0, text.as_ptr() as isize);
                did_append = true;
            }

            // After EM_REPLACESEL the caret is at the end of the new text.
            // EM_SCROLLCARET on a *child* EDIT works without focus.
            if did_append {
                let end = GetWindowTextLengthW(edit).max(0) as usize;
                SendMessageW(edit, EM_SETSEL, end, end as isize);
                SendMessageW(edit, EM_SCROLLCARET, 0, 0);
            }

            std::thread::sleep(std::time::Duration::from_millis(50));
        }
    }
}

#[cfg(not(windows))]
fn platform_run(rx: mpsc::Receiver<String>) {
    while rx.recv().is_ok() {}
}
