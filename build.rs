// build.rs — intentionally minimal.
//
// The console window is already suppressed by:
//   #![cfg_attr(target_os = "windows", windows_subsystem = "windows")]
// in main.rs — no winres needed.
//
// To embed a custom .exe icon later, convert assets/icon.png to assets/icon.ico
// (e.g. with ImageMagick: `magick convert icon.png icon.ico`), then add:
//   winres = "0.1" to [target.'cfg(windows)'.build-dependencies]
// and uncomment the block below.

fn main() {
    // #[cfg(target_os = "windows")]
    // {
    //     let mut res = winres::WindowsResource::new();
    //     res.set_icon("assets/icon.ico");   // must be .ico, not .png
    //     res.compile().unwrap();
    // }
}
