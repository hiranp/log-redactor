use clap::{Arg, Command};
use log::info;
use log_redactor::Redactor;
use std::env;
use std::path::{Path, PathBuf};

fn main() {
    let matches = Command::new("Redactor")
        .version("1.0")
        .author("HP <null@hiranpatel.com>")
        .about("Redacts sensitive information from files, directories, or ZIP archives")
        .arg(
            Arg::new("path")
                .help("The path to a file, directory, or ZIP archive to redact")
                .required(true)
                .index(1),
        )
        .arg(
            Arg::new("interactive")
                .short('i')
                .long("interactive")
                .help("Run in interactive mode"),
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
    let interactive = matches.contains_id("interactive");

    let current_dir = env::current_dir().unwrap();
    let default_secrets_file = current_dir.join("secrets.csv");
    let default_ignores_file = current_dir.join("ignore.csv");

    let secrets_file = matches
        .get_one::<String>("secrets")
        .map(|s| PathBuf::from(s))
        .unwrap_or(default_secrets_file);

    let ignores_file = matches
        .get_one::<String>("ignores")
        .map(|s| PathBuf::from(s))
        .unwrap_or(default_ignores_file);

    let mut redactor = Redactor::new(
        interactive,
        secrets_file.to_str().unwrap(),
        ignores_file.to_str().unwrap(),
    );

    let path = Path::new(path);
    if path.is_file() {
        if path.extension().and_then(|ext| ext.to_str()) == Some("zip") {
            redactor.redact_zip(path.to_str().unwrap());
        } else if path.extension().and_then(|ext| ext.to_str()) == Some("pdf") {
            if let Err(e) = redactor.redact_pdf(path.to_str().unwrap()) {
                info!("Failed to redact PDF: {}", e);
            }
        } else {
            redactor.redact_file(path.to_str().unwrap());
        }
    } else if path.is_dir() {
        redactor.redact_directory(path.to_str().unwrap());
    } else {
        eprintln!("Error: The provided path is neither a file nor a directory.");
    }

    info!("Redaction process completed");
}
