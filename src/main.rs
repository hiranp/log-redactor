use clap::builder::PossibleValuesParser;
use clap::{Arg, Command};
use log::info;
use log_redactor::Redactor;
use std::env;
use std::path::{Path, PathBuf};

// Include the generated version file
include!(concat!(env!("OUT_DIR"), "/version_gen.rs"));

fn main() {
    let matches = Command::new("Log Redactor")
        .author("HP <null@hiranpatel.com>")
        .version(VERSION)
        .about("A tool for redacting sensitive information in files and archives. Supports various file types including text files, PDFs, and archives (ZIP, TAR, GZ, BZIP2).")
        .arg(
            Arg::new("path")
                .help("The path to a file, directory, or archive to redact")
                .required(true)
                .index(1),
        )
        .arg(
            Arg::new("interactive")
                .short('i')
                .long("interactive")
                .help("Run in interactive mode (enter 'yes' or 'no')")
                .value_name("BOOLEAN")
                .value_parser(PossibleValuesParser::new(["yes", "no"])),
        )
        .arg(
            Arg::new("secrets")
                .short('s')
                .long("secrets")
                .help("Path to the secrets file")
                .value_name("FILE"),
        )
        .arg(
            Arg::new("ignores")
                .short('g')
                .long("ignores")
                .help("Path to the ignores file")
                .value_name("FILE"),
        )
        .get_matches();

    let path = matches.get_one::<String>("path").unwrap();
    let interactive = matches
        .get_one::<String>("interactive")
        .map(|s| s == "yes")
        .unwrap_or(false);

    let current_dir = env::current_dir().unwrap();
    let default_secrets_file = current_dir.join("secrets.csv");
    let default_ignores_file = current_dir.join("ignore.csv");
    let redacted_mapping_file = current_dir.join("redacted-mapping.txt");

    let secrets_file = matches
        .get_one::<String>("secrets")
        .map(PathBuf::from)
        .unwrap_or(default_secrets_file);

    let ignores_file = matches
        .get_one::<String>("ignores")
        .map(PathBuf::from)
        .unwrap_or(default_ignores_file);

    let mut redactor = Redactor::new(
        interactive,
        secrets_file.to_str().unwrap(),
        ignores_file.to_str().unwrap(),
        redacted_mapping_file.to_str().unwrap(),
    );

    let path = Path::new(path);
    if path.is_file() {
        match std::fs::read(path) {
            Ok(content) => {
                if let Some(kind) = infer::get(&content) {
                    match kind.mime_type() {
                        "application/zip" => {
                            if let Err(e) = redactor.redact_zip(path.to_str().unwrap()) {
                                info!("Failed to redact ZIP file: {}", e);
                            }
                        }
                        "application/pdf" => {
                            if let Err(e) = redactor.redact_pdf(path.to_str().unwrap()) {
                                info!("Failed to redact PDF: {}", e);
                            }
                        }
                        "application/x-tar" => {
                            if let Err(e) = redactor.redact_tar(path.to_str().unwrap()) {
                                info!("Failed to redact TAR file: {}", e);
                            }
                        }
                        "application/gzip" => {
                            if let Err(e) = redactor.redact_tar_gz(path.to_str().unwrap()) {
                                info!("Failed to redact TAR.GZ file: {}", e);
                            }
                        }
                        _ => redactor.redact_file(path.to_str().unwrap()),
                    }
                } else {
                    // Assume it's a regular text file if type cannot be determined
                    redactor.redact_file(path.to_str().unwrap());
                    return;
                }
            }
            Err(e) => {
                eprintln!("Error reading file: {}", e);
                return;
            }
        }
    } else if path.is_dir() {
        redactor.redact_directory(path.to_str().unwrap());
    } else {
        eprintln!("Error: The provided path is neither a file nor a directory.");
    }

    info!("Redaction process completed");
}
