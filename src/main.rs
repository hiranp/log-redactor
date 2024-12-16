extern crate clap;
extern crate regex;
extern crate serde_json;

use clap::{App, Arg};
use regex::Regex;
use serde_json::json;
use std::collections::{HashMap, HashSet};
use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};

#[derive(Debug)]
pub struct Redactor {
    interactive: bool,
    secrets: HashMap<String, Vec<String>>,
    ignores: HashMap<String, Vec<String>>,
    unique_mapping: HashMap<String, String>,
    ip_counter: u32,
    counter: HashMap<String, u32>,
    patterns: HashMap<String, Regex>,
}

impl Redactor {
    pub fn new(interactive: bool) -> Self {
        let patterns = HashMap::from([
            ("email".to_string(), Regex::new(r"[\w\.-]+@[\w\.-]+\.\w+").unwrap()),
            ("ipv4".to_string(), Regex::new(r"\b(?:\d{1,3}\.){3}\d{1,3}\b").unwrap()),
            ("ipv6".to_string(), Regex::new(r"([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}").unwrap()),
            ("phone".to_string(), Regex::new(r"\b\d{3}[-.\s]?\d{3}[-.\s]?\d{4}\b").unwrap()),
            ("url".to_string(), Regex::new(r"https?:\/\/(www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_\+.~#?&//=]*)").unwrap()),
            ("api".to_string(), Regex::new(r"(token|key|api|apikey|apitoken)=[^&\s]*").unwrap()),
        ]);

        Redactor {
            interactive,
            secrets: Redactor::load_lists("secrets.csv"),
            ignores: Redactor::load_lists("ignore.csv"),
            unique_mapping: HashMap::new(),
            ip_counter: 1,
            counter: HashMap::from([
                ("email".to_string(), 1),
                ("phone".to_string(), 1),
                ("url".to_string(), 1),
            ]),
            patterns,
        }
    }

    fn load_lists(filename: &str) -> HashMap<String, Vec<String>> {
        let mut lists = HashMap::new();
        let secret_types = vec!["email", "ipv4", "ipv6", "phone", "url", "api"];
        for secret_type in secret_types {
            lists.insert(secret_type.to_string(), Vec::new());
        }

        if let Ok(file) = File::open(filename) {
            for line in io::BufReader::new(file).lines() {
                if let Ok(line) = line {
                    let mut parts = line.split(',');
                    if let (Some(secret_type), Some(value)) = (parts.next(), parts.next()) {
                        if let Some(list) = lists.get_mut(secret_type) {
                            list.push(value.to_string());
                        }
                    }
                }
            }
        }
        lists
    }

    fn save_to_file(&self, filename: &str, secret_type: &str, value: &str) {
        let mut file = OpenOptions::new()
            .append(true)
            .create(true)
            .open(filename)
            .unwrap();

        if let Ok(metadata) = file.metadata() {
            if metadata.len() > 0 {
                writeln!(file).unwrap();
            }
        }

        writeln!(file, "{},{}", secret_type, value).unwrap();
    }

    fn save_mappings(&self, filename: &str) {
        let mappings = json!(self.unique_mapping);
        let mut file = File::create(filename).unwrap();
        file.write_all(mappings.to_string().as_bytes()).unwrap();
    }

    fn redact_line(&mut self, line: String, secret_type: &str) -> String {
        let pattern = &self.patterns[secret_type];
        let ignore_set: HashSet<String> = self
            .ignores
            .get(secret_type)
            .unwrap_or(&Vec::new())
            .iter()
            .cloned()
            .collect();

        pattern.find_iter(&line).fold(line, |mut line, match_obj| {
            let value = match_obj.as_str().to_string();
            if !ignore_set.contains(&value) {
                let replacement = self.generate_unique_mapping(&value, secret_type);
                line = line.replace(&value, &replacement);
            }
            line
        })
    }

    fn generate_unique_mapping(&mut self, value: &str, secret_type: &str) -> String {
        if !self.unique_mapping.contains_key(value) {
            let mapped_value = if secret_type == "ipv4" {
                let mapped_ip = format!("240.0.0.{}", self.ip_counter);
                self.ip_counter += 1;
                mapped_ip
            } else {
                let mapped_value = format!(
                    "{}_{}",
                    secret_type.to_uppercase(),
                    self.counter[secret_type]
                );
                self.counter
                    .insert(secret_type.to_string(), self.counter[secret_type] + 1);
                mapped_value
            };
            self.unique_mapping
                .insert(value.to_string(), mapped_value.clone());
            mapped_value
        } else {
            self.unique_mapping.get(value).unwrap().clone()
        }
    }

    pub fn redact(&mut self, lines: Vec<String>) -> Vec<String> {
        lines
            .into_iter()
            .map(|line| {
                self.patterns.keys().fold(line, |line, secret_type| {
                    self.redact_line(line, secret_type)
                })
            })
            .collect()
    }

    pub fn redact_file(&mut self, file: &str) {
        let path = Path::new(file);
        if path.exists() {
            let lines: Vec<String> = io::BufReader::new(File::open(file).unwrap())
                .lines()
                .map(|line| line.unwrap())
                .collect();

            let redacted_lines = self.redact(lines);

            let mut output_file = File::create(file.to_string() + "-redacted").unwrap();
            for line in redacted_lines {
                writeln!(output_file, "{}", line).unwrap();
            }

            self.save_mappings(&(file.to_string() + "-mappings.json"));
            println!("Redacted file saved as {}-redacted", file);
        } else {
            println!("File not found: {}", file);
        }
    }

    pub fn redact_directory(&mut self, directory: &str) {
        for entry in std::fs::read_dir(directory).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            if path.is_file() {
                self.redact_file(path.to_str().unwrap());
            }
        }
    }

    pub fn extract_and_redact_zip(&mut self, zip_file: &str) {
        let extract_dir = zip_file.replace(".zip", "");
        let file = File::open(zip_file).unwrap();
        let mut archive = zip::ZipArchive::new(file).unwrap();
        archive.extract(&extract_dir).unwrap();
        self.redact_directory(&extract_dir);
    }
}

fn main() {
    let matches = App::new("Redactor")
        .version("1.0")
        .author("HP <null@hiranpatel.com")
        .about("Redacts sensitive information from files")
        .arg(
            Arg::with_name("path")
                .help("The file, directory, or zip archive to redact")
                .required(true)
                .index(1),
        )
        .arg(
            Arg::with_name("interactive")
                .short("i")
                .long("interactive")
                .help("Run in interactive mode"),
        )
        .get_matches();

    let path = matches.value_of("path").unwrap();
    let interactive = matches.is_present("interactive");

    let mut redactor = Redactor::new(interactive);

    if Path::new(path).is_dir() {
        redactor.redact_directory(path);
    } else if path.ends_with(".zip") {
        redactor.extract_and_redact_zip(path);
    } else {
        redactor.redact_file(path);
    }
}
