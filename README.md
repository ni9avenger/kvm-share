# kvm-share

Keyboard, mouse & clipboard sharing over LAN.  
**No terminal. No lag. No external tools.**

Self-contained Rust app — no lan-mouse, no Synergy, no daemons.

---

## How it works

```
Machine A (your keyboard/mouse)          Machine B
──────────────────────────────────       ──────────────────────────────────
rdev::grab intercepts all input          enigo injects received events
→ detects cursor at screen edge          ← receives NetEvent over UDP
→ sends NetEvent over UDP port 4242      → cursor warps to entry edge
→ clipboard changes → TCP port 4243  ←→  ← clipboard sync → TCP port 4243
```

Both machines run the **same binary**. Control switches dynamically when
the cursor hits the configured edge (default: Right). Move back across the
opposite edge to return control.

---

## Quick start

### 1. Install Rust
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

### 2. Platform prerequisites

**Linux** (GTK for tray + dialog for IP prompt):
```bash
sudo apt install libgtk-3-dev zenity
# or on Fedora: sudo dnf install gtk3-devel zenity
```

**macOS** — grant **Accessibility permission** when prompted  
(System Settings → Privacy & Security → Accessibility → kvm-share ✓)

**Windows** — no prerequisites

### 3. Build
```bash
cd kvm-share
cargo build --release
# binary: target/release/kvm-share  (or .exe on Windows)
```

### 4. Open firewall ports (both machines)

| Port | Protocol | Purpose |
|------|----------|---------|
| 4242 | UDP | Keyboard / mouse events |
| 4243 | TCP | Clipboard sync |

**Windows** (admin PowerShell):
```powershell
New-NetFirewallRule -DisplayName "KVM Share Input"     -Direction Inbound -Protocol UDP -LocalPort 4242 -Action Allow
New-NetFirewallRule -DisplayName "KVM Share Clipboard" -Direction Inbound -Protocol TCP -LocalPort 4243 -Action Allow
```

**macOS**: System Settings → Network → Firewall → allow `kvm-share`

**Linux**:
```bash
sudo ufw allow 4242/udp
sudo ufw allow 4243/tcp
```

### 5. Run on both machines

```
Machine A: ./kvm-share  → right-click tray → Set peer IP → enter Machine B's IP
Machine B: ./kvm-share  → right-click tray → Set peer IP → enter Machine A's IP
```

Move cursor to the **right edge** of Machine A's screen → control switches to B.  
Move cursor to the **left edge** of Machine B's screen → control returns to A.

To change which edge triggers the switch: right-click tray → **Cycle switch edge**.

---

## Auto-start on login

**Windows**: copy `kvm-share.exe` to  
`%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\`

**macOS** (`~/Library/LaunchAgents/com.kvm-share.plist`):
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
    <key>Label</key>             <string>com.kvm-share</string>
    <key>ProgramArguments</key>  <array><string>/path/to/kvm-share</string></array>
    <key>RunAtLoad</key>         <true/>
    <key>KeepAlive</key>         <true/>
</dict></plist>
```
```bash
launchctl load ~/Library/LaunchAgents/com.kvm-share.plist
```

**Linux** (`~/.config/systemd/user/kvm-share.service`):
```ini
[Unit]
Description=KVM Share

[Service]
ExecStart=/path/to/kvm-share
Restart=on-failure

[Install]
WantedBy=default.target
```
```bash
systemctl --user enable --now kvm-share
```

---

## Config file

Auto-saved to `~/.config/kvm-share/config.json` when you set the peer IP or change edge.

```json
{
  "peer_ip": "192.168.1.20",
  "input_port": 4242,
  "clipboard_port": 4243,
  "switch_edge": "Right",
  "edge_threshold": 3
}
```

---

## Source layout

```
src/
├── main.rs        Entry point — wires all channels, runs tray on main thread
├── config.rs      Config struct, load/save JSON
├── protocol.rs    NetEvent wire format (bincode over UDP)
├── capture.rs     rdev::grab — intercepts input, detects edge switch
├── inject.rs      enigo — injects received events; rdev→enigo key map
├── net.rs         UDP input sender/receiver + TCP clipboard server/client
├── clipboard.rs   arboard — polls local clipboard, applies received content
└── tray.rs        System tray icon + menu
```

---

## Known limitations

| Platform | Limitation |
|----------|------------|
| Linux/Wayland | `rdev::grab` only works on X11. Wayland needs a compositor-specific input inhibitor protocol. Works fine on X11 / XWayland. |
| macOS | Requires Accessibility permission for `rdev::grab` to suppress events. |
| All | Mouse acceleration curves differ between machines — raw deltas are sent, so feel may vary slightly. |
