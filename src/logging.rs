// logging.rs — rolling log file + Debug Window mirror.
//
// Why not env_logger: the release build has no console (windows_subsystem =
// "windows"), so env_logger's output went nowhere and every warn!/info! from
// the network and clipboard code was lost. The v0.1.1 diagnostic build proved
// that file logs are what make field problems diagnosable.
//
// Non-blocking by design: `log()` may be called from the WH_MOUSE_LL hook
// callback, which must never wait on disk I/O. Records are formatted on the
// caller's thread and handed to a writer thread over an unbounded channel.
//
// Files: %LOCALAPPDATA%\kvm-share\logs\kvm-share.log, rolled at 2 MB, keeping
// kvm-share.1.log … kvm-share.4.log (oldest dropped). Timestamps are UTC.

use log::{Level, LevelFilter, Log, Metadata, Record};
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::sync::mpsc;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

const ROLL_BYTES: u64 = 2 * 1024 * 1024;
const KEEP: u32 = 4;

struct Logger {
    level: LevelFilter,
    tx: Mutex<mpsc::Sender<String>>,
}

impl Log for Logger {
    fn enabled(&self, m: &Metadata) -> bool {
        // Third-party crates only at warn and above; ours at the chosen level.
        if m.target().starts_with("kvm_share") {
            m.level() <= self.level
        } else {
            m.level() <= Level::Warn
        }
    }

    fn log(&self, r: &Record) {
        if !self.enabled(r.metadata()) {
            return;
        }
        let line = format!(
            "[{} {:<5} {}] {}",
            utc_now(),
            r.level(),
            r.target(),
            r.args()
        );
        crate::debug_window::log(line.clone());
        // try_lock: never block a hook callback; a dropped line is acceptable.
        if let Ok(tx) = self.tx.try_lock() {
            let _ = tx.send(line);
        }
    }

    fn flush(&self) {}
}

pub fn log_dir() -> PathBuf {
    dirs::data_local_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("kvm-share")
        .join("logs")
}

pub fn init(level: &str) {
    let level = level.parse().unwrap_or(LevelFilter::Info);
    let (tx, rx) = mpsc::channel::<String>();
    let dir = log_dir();
    let _ = std::fs::create_dir_all(&dir);
    std::thread::Builder::new()
        .name("log-writer".into())
        .spawn(move || writer(dir, rx))
        .expect("log thread");
    let logger = Box::new(Logger {
        level,
        tx: Mutex::new(tx),
    });
    if log::set_boxed_logger(logger).is_ok() {
        log::set_max_level(level.max(LevelFilter::Warn));
    }
}

fn open(dir: &std::path::Path) -> Option<(File, u64)> {
    let f = OpenOptions::new()
        .create(true)
        .append(true)
        .open(dir.join("kvm-share.log"))
        .ok()?;
    let len = f.metadata().map(|m| m.len()).unwrap_or(0);
    Some((f, len))
}

fn roll(dir: &std::path::Path) {
    let name = |i: u32| dir.join(format!("kvm-share.{i}.log"));
    let _ = std::fs::remove_file(name(KEEP));
    for i in (1..KEEP).rev() {
        let _ = std::fs::rename(name(i), name(i + 1));
    }
    let _ = std::fs::rename(dir.join("kvm-share.log"), name(1));
}

fn writer(dir: PathBuf, rx: mpsc::Receiver<String>) {
    let mut cur = open(&dir);
    for line in rx {
        if let Some((f, len)) = cur.as_mut() {
            if writeln!(f, "{line}").is_ok() {
                *len += line.len() as u64 + 1;
            }
            if *len >= ROLL_BYTES {
                drop(cur.take()); // close before renaming (Windows locks open files)
                roll(&dir);
                cur = open(&dir);
            }
        } else {
            cur = open(&dir);
        }
    }
}

/// "2026-11-24T15:31:34.841Z" without a date crate (Howard Hinnant's
/// days-to-civil algorithm).
fn utc_now() -> String {
    let d = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    format_utc(d.as_secs(), d.subsec_millis())
}

fn format_utc(secs: u64, ms: u32) -> String {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{ms:03}Z",
        rem / 3600,
        (rem / 60) % 60,
        rem % 60
    )
}

#[cfg(test)]
mod tests {
    #[test]
    fn utc_format() {
        assert_eq!(super::format_utc(0, 0), "1970-01-01T00:00:00.000Z");
        // 2026-11-24T15:31:34Z, the first diagnostic log line.
        assert_eq!(
            super::format_utc(1_795_534_294, 841),
            "2026-11-24T15:31:34.841Z"
        );
        assert_eq!(
            super::format_utc(951_782_400, 5),
            "2000-02-29T00:00:00.005Z"
        );
    }
}
