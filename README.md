# KVM Share

> Software keyboard, mouse & clipboard sharing for Windows — built in Rust.

Move your cursor to the edge of the screen and it crosses to the next machine, carrying your keyboard and clipboard with it. No hardware KVM switch. No cloud account. No Electron. A single 3 MB `.exe`.

---

## Quick Start

### 1. Use

Move your cursor to the configured edge. It crosses to the other machine. Move it back to the opposite edge to return. Press **Scroll Lock** at any time to force-release control.

### Firewall (both machines)

Open ports in admin PowerShell:

```powershell
New-NetFirewallRule -DisplayName "KVM Share Input"     -Direction Inbound -Protocol UDP -LocalPort 4242 -Action Allow
New-NetFirewallRule -DisplayName "KVM Share Clipboard" -Direction Inbound -Protocol TCP -LocalPort 4243 -Action Allow
```

---

## How It Works

```
Machine A (controller)                          Machine B (receiver)
──────────────────────                          ────────────────────
 tray.rs: WM_INPUT → lLastX/lLastY              inject.rs: enigo::move_mouse (relative)
          ──────────────────────── UDP 4242 ──►
 capture.rs: rdev::grab suppresses              capture.rs: watches return edge
             local events in remote mode        ◄─────────────────────────────

 clipboard.rs: arboard::get_text()
          ──────────────────────── TCP 4243 ──►  clipboard.rs: arboard::set_text()
```

### Two-channel design

**Input channel (UDP 4242)** — Mouse moves, clicks, scroll, keystrokes. UDP is intentional: a dropped packet skips one mouse event. TCP under Wi-Fi packet loss queues stale events and causes visible lag spikes. UDP drops them cleanly and moves on.

**Clipboard channel (TCP 4243)** — Clipboard sync runs on a separate TCP connection. A large paste cannot delay a keystroke. The two channels are fully independent.

### Edge detection

KVM Share reads the full virtual desktop bounds with `SM_CXVIRTUALSCREEN` / `SM_CYVIRTUALSCREEN` — not just the primary monitor. On a 3840×1080 dual-monitor setup, `rdev::display_size()` returns 1920×1080 and fires at the wrong edge. KVM Share fires correctly at x=3839.

### Return detection

When Machine B receives control, the coordinator automatically sets the return edge to the opposite of the entry edge. No configuration needed on Machine B. The fractional position along the edge is preserved — the cursor appears at the same relative height on the receiving machine.

### Anti-loop protection

The cursor is placed 80 px inward from the entry edge on arrival. A 40-event debounce prevents the return-edge check from firing during this initial placement — eliminating the enter/leave infinite loop that affects tools placing the cursor at x=2.

---

## Configuration Reference

| Key | Type | Default | Description |
|---|---|---|---|
| `peer_ip` | string | `""` | IP address of the other machine |
| `switch_edge` | string | `"Right"` | Trigger edge: `Left` / `Right` / `Top` / `Bottom` |
| `edge_threshold` | integer | `10` | Pixels from edge to trigger (raise if accidental triggers) |

---

## Building from Source

### Prerequisites

- [Rust](https://rustup.rs/) stable 1.77+
- Windows 10 or later
- Visual Studio Build Tools with C++ workload (for linking)

### Build

```sh
git clone https://github.com/your-org/kvm-share
cd kvm-share
cargo build --release
# → target/release/kvm-share.exe
```

### Optimised binary

```sh
cargo build --release --target x86_64-pc-windows-msvc
# With RUSTFLAGS="-C opt-level=z -C strip=symbols" → ~3 MB
```

### Development (with console)

Comment out `#![windows_subsystem = "windows"]` in `main.rs`, then `cargo run`.

---

## Architecture

```
main.rs
  ├── tray.rs          System tray + Win32 message pump + Raw Input (WM_INPUT)
  ├── capture.rs       rdev::grab — suppress local events while controlling remote
  ├── inject.rs        enigo — replay NetEvents as real input on this machine
  ├── net.rs           UDP listener/sender + TCP clipboard server/client
  ├── coordinator.rs   Async state machine connecting all channels
  ├── config.rs        JSON config load/save
  ├── protocol.rs      NetEvent enum + bincode serialisation
  └── debug_window.rs  Win32 EDIT-class floating log window
```

### Threading model

| Thread | Role |
|---|---|
| Main (Win32) | Tray message pump + Raw Input `WM_INPUT` handler |
| `capture` | `rdev::grab` low-level hook (must own its thread) |
| `inject` | `enigo` input injection (`!Send` — dedicated thread) |
| `tokio` runtime | Async coordinator, UDP I/O, TCP clipboard, keepalive |
| `debug-window` | Win32 EDIT window + log drain loop |

The Win32 message pump **must** be on the main thread. `tokio` runs on a background thread via `Builder::new_multi_thread()`. Cross-thread communication uses `tokio::sync::mpsc` (async) and `std::sync::mpsc` (sync boundary with hooks).

---

## Troubleshooting

**Cursor doesn't cross to the other machine**
1. Open **Debug Window** → look for `WM_INPUT #0` log lines. Absent = Raw Input registration failed.
2. Verify `peer_ip` is correct and reachable (`ping <peer_ip>`).
3. Check UDP 4242 is not blocked by Windows Firewall on the receiving machine.
4. Both machines must be running KVM Share.

**Cursor crosses but remote cursor doesn't move**
1. Debug Window: look for `RAW DELTA dx=0.0 dy=0.0` lines. If deltas are zero, file an issue with your mouse model.
2. Check `remote_mode=true` appears in `RAW DELTA` lines — if false, `EnterRemote` isn't reaching the coordinator.

**Cursor immediately snaps back (enter/leave loop)**
Fixed in current version via 80 px inset + 40-event debounce. If you still see rapid `ENTERED REMOTE MODE` / `ReturnControl` cycles, file an issue with your screen resolution and `edge_threshold`.

**Clipboard doesn't sync**
TCP 4243 must be open on both machines. Clipboard sync is best-effort — very large contents (>1 MB images) may be skipped.

**ScrollLock doesn't release**
ScrollLock is intercepted by the `rdev::grab` hook. If the hook failed to start (check Debug Window for `capture:` startup lines), restarting KVM Share clears the mode flag.

---

## Auto-start on Login

Copy `kvm-share.exe` to:
```
%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\
```

---

## Roadmap

- [ ] mDNS auto-discovery (no manual IP entry)
- [ ] In-tray peer IP configuration dialog
- [ ] Hotkey-triggered machine switching
- [ ] Three-machine chaining
- [ ] TLS/DTLS encryption
- [ ] macOS support
- [ ] Linux (X11) support

---

## Contributing

PRs welcome. Before opening one:

1. `cargo fmt` and `cargo clippy -- -D warnings`
2. Test on a real two-machine setup — edge behaviour cannot be unit-tested without hardware
3. For new platform injection: mirror the 80 px `INSET` logic in `inject.rs`

---

## Acknowledgements

- [`rdev`](https://github.com/Narsil/rdev) — cross-platform input hook + event types
- [`enigo`](https://github.com/enigo-rs/enigo) — cross-platform input injection
- [`arboard`](https://github.com/1Password/arboard) — clipboard access
- [`tray-icon`](https://github.com/tauri-apps/tray-icon) — system tray
- [`tokio`](https://tokio.rs/) — async runtime
- [`bincode`](https://github.com/bincode-org/bincode) — compact binary serialisation
- [`windows-sys`](https://github.com/microsoft/windows-rs) — Win32 FFI bindings
