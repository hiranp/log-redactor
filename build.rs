use std::env;
use std::fs;
use std::path::Path;
use vergen::EmitBuilder;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Generate build information
    EmitBuilder::builder()
        .build_timestamp()
        .all_build()
        .emit()?;

    // Get the output directory for generated files
    let out_dir = env::var("OUT_DIR")?;
    let dest_path = Path::new(&out_dir).join("version_gen.rs");

    // Get the package version from Cargo.toml
    let version = env!("CARGO_PKG_VERSION");

    // Create the version string with current date
    let now = chrono::Local::now();
    let build_date = now.format("%Y%m%d");

    // Generate the contents of version_gen.rs
    let contents = format!(
        "pub const VERSION: &str = \"{}-{}\";\n",
        version, build_date
    );

    // Write the generated code to the file
    fs::write(&dest_path, contents)?;

    // Tell cargo to rerun this script if Cargo.toml changes
    println!("cargo:rerun-if-changed=Cargo.toml");

    Ok(())
}
