use std::time::{SystemTime, UNIX_EPOCH};
use time::OffsetDateTime;

fn main() {
    let now = SystemTime::now();
    let timestamp = now.duration_since(UNIX_EPOCH).expect("Time went backwards");

    let datetime =
        OffsetDateTime::from_unix_timestamp(timestamp.as_secs() as i64).expect("Invalid timestamp");

    // Only append build date if version doesn't already have one
    let pkg_version = env!("CARGO_PKG_VERSION");
    if !pkg_version.contains('-') {
        let build_date = format!(
            "{:04}{:02}{:02}",
            datetime.year(),
            datetime.month() as u8,
            datetime.day()
        );
        println!("cargo:rustc-env=BUILD_DATE={}", build_date);
    }
}
