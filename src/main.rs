use clap::{App, Arg};
use env_logger;
use log::info; // Import logging macros
use rand::seq::SliceRandom;
use regex::Regex;
use serde_derive::{Deserialize, Serialize};
use serde_json::json; // Import for json! macro
use std::collections::HashMap;
use std::collections::HashSet; // Import for HashSet
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, BufReader, Write};
use std::path::Path;
use zip::read::ZipArchive; // Import derive macros // Initialize the logger

#[derive(Serialize, Deserialize)]
struct Secret {
    value: String,
}

#[derive(Serialize, Deserialize)]
struct Ignore {
    value: String,
}

#[derive(Default)] // Add this line
struct RedactorConfig {
    secrets: Option<HashMap<String, Vec<String>>>,
    ignores: Option<HashMap<String, Vec<String>>>,
}

impl RedactorConfig {
    fn from_files(secrets_file: &str, ignores_file: &str) -> Result<Self, std::io::Error> {
        let secrets = File::open(secrets_file)
            .ok()
            .map(|file| serde_json::from_reader(BufReader::new(file)).unwrap_or_default());

        let ignores = File::open(ignores_file)
            .ok()
            .map(|file| serde_json::from_reader(BufReader::new(file)).unwrap_or_default());

        Ok(RedactorConfig { secrets, ignores })
    }
}

struct Redactor {
    patterns: HashMap<String, Regex>,
    validators: HashMap<String, fn(&str) -> bool>,
    config: RedactorConfig,
    unique_mapping: HashMap<String, String>,
    ip_counter: u32,
    counter: HashMap<String, u32>,
    interactive: bool,
    phone_formats: Vec<String>,
}

impl Redactor {
    fn new(interactive: bool) -> Self {
        let patterns = Self::init_patterns();

        let mut validators: HashMap<String, fn(&str) -> bool> = HashMap::new();
        validators.insert("ipv4".to_string(), validate_ipv4);
        validators.insert("ipv6".to_string(), validate_ipv6);
        validators.insert("url".to_string(), validate_url);
        validators.insert("hostname".to_string(), validate_hostname);

        let config = RedactorConfig::from_files("secrets.csv", "ignore.csv").unwrap_or_default();

        let phone_formats = vec![
            "({}) {}-{:04}".to_string(),
            "{}-{}-{:04}".to_string(),
            "{}.{}.{}".to_string(),
            "{} {} {}".to_string(),
        ];

        Redactor {
            patterns,
            validators,
            config,
            unique_mapping: HashMap::new(),
            ip_counter: 1,
            counter: HashMap::new(),
            interactive,
            phone_formats,
        }
    }

    fn init_patterns() -> HashMap<String, Regex> {
        let mut patterns = HashMap::new();
        patterns.insert(
            "ipv4".to_string(),
            Regex::new(r"\b(?:\d{1,3}\.){3}\d{1,3}\b").unwrap(),
        );
        patterns.insert("ipv6".to_string(), Regex::new(r"([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}").unwrap());
        patterns.insert("url".to_string(), Regex::new(r"https?:\/\/(www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_\+.~#?&//=]*)").unwrap());
        patterns.insert("hostname".to_string(), Regex::new(r"(?=.{1,255}$)(?!-)[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?)*\.?").unwrap());
        patterns.insert(
            "phone".to_string(),
            Regex::new(r"\b\d{3}[-.\s]?\d{3}[-.\s]?\d{4}\b").unwrap(),
        );
        patterns.insert(
            "email".to_string(),
            Regex::new(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+").unwrap(),
        );
        patterns.insert(
            "api".to_string(),
            Regex::new(r"(token|key|api|apikey|apitoken)=[^&\s]*").unwrap(),
        );
        patterns
    }

    fn generate_unique_mapping(&mut self, value: &str, secret_type: &str) -> String {
        if !self.unique_mapping.contains_key(value) {
            let mapped_value = if secret_type == "ipv4" {
                let mapped_ip = format!("240.0.0.{}", self.ip_counter);
                self.ip_counter += 1;
                mapped_ip
            } else if secret_type == "phone" {
                let format = self.phone_formats.choose(&mut rand::thread_rng()).unwrap();
                let count = self.counter.entry(secret_type.to_string()).or_insert(0);
                let mapped_phone = match format.as_str() {
                    "({}) {}-{:04}" => format!("(800) 555-{:04}", count),
                    "{}-{}-{:04}" => format!("800-555-{:04}", count),
                    "{}.{}.{}" => format!("800.555.{:04}", count),
                    _ => format!("800 555 {:04}", count),
                };
                *self.counter.get_mut(secret_type).unwrap() += 1;
                mapped_phone
            } else {
                let count = self.counter.entry(secret_type.to_string()).or_insert(1);
                let mapped_value = format!("{}_{}", secret_type.to_uppercase(), count);
                *count += 1;
                mapped_value
            };
            self.unique_mapping
                .insert(value.to_string(), mapped_value.clone());
            mapped_value
        } else {
            self.unique_mapping.get(value).unwrap().clone()
        }
    }

    fn ask_user(&self, value: &str, secret_type: &str) -> bool {
        println!("Found a potential {}: {}", secret_type, value);
        println!("Would you like to redact? (yes/no/always/never)");
        let mut input = String::new();
        io::stdin().read_line(&mut input).unwrap();
        match input.trim().to_lowercase().as_str() {
            "yes" | "y" => true,
            "no" | "n" => false,
            "always" | "a" => {
                self.save_to_file("secrets.csv", secret_type, value);
                true
            }
            "never" => {
                self.save_to_file("ignore.csv", secret_type, value);
                false
            }
            _ => false,
        }
    }

    fn save_to_file(&self, filename: &str, secret_type: &str, value: &str) {
        if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(filename) {
            writeln!(file, "{},{}", secret_type, value).unwrap();
        }
    }

    fn redact_pattern(&mut self, line: &str, pattern_type: &str) -> String {
        let pattern = &self.patterns[pattern_type];
        let captures: Vec<_> = pattern.captures_iter(line).collect();

        let ignore_set: HashSet<String> = self
            .config
            .ignores
            .as_ref()
            .and_then(|ignores| ignores.get(pattern_type).cloned())
            .unwrap_or_default()
            .into_iter()
            .collect();

        let secrets_set: HashSet<String> = self
            .config
            .secrets
            .as_ref()
            .and_then(|secrets| secrets.get(pattern_type).cloned())
            .unwrap_or_default()
            .into_iter()
            .collect();

        let validator_fn = self.validators[pattern_type];
        let interactive = self.interactive;

        let mut redacted_line = line.to_string();

        for cap in captures {
            let value = cap.get(0).unwrap().as_str();

            let should_redact = if secrets_set.contains(value) {
                true
            } else if ignore_set.contains(value) {
                false
            } else {
                validator_fn(value) && (!interactive || self.ask_user(value, pattern_type))
            };

            if should_redact {
                let replacement = self.generate_unique_mapping(value, pattern_type);
                redacted_line = redacted_line.replace(value, &replacement);
            }
        }

        redacted_line
    }

    pub fn redact(&mut self, lines: Vec<String>) -> Vec<String> {
        let pattern_keys: Vec<String> = self.patterns.keys().cloned().collect();
        lines
            .into_iter()
            .map(|line| {
                let mut redacted_line = line;
                for secret_type in &pattern_keys {
                    redacted_line = self.redact_pattern(&redacted_line, secret_type);
                }
                redacted_line
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

            let extension = path
                .extension()
                .and_then(|ext| ext.to_str())
                .unwrap_or("txt");
            let file_stem = path
                .file_stem()
                .and_then(|stem| stem.to_str())
                .unwrap_or("file");

            let redacted_file_name = format!("{}-redacted.{}", file_stem, extension);
            let mut output_file = File::create(&redacted_file_name).unwrap();
            for line in redacted_lines {
                writeln!(output_file, "{}", line).unwrap();
            }

            self.save_mappings(&format!("{}-mappings.json", file_stem));
            println!("Redacted file saved as {}", redacted_file_name);
        } else {
            println!("File not found: {}", file);
        }
    }

    pub fn redact_directory(&mut self, dir: &str) {
        let path = Path::new(dir);
        if path.is_dir() {
            for entry in fs::read_dir(path).unwrap() {
                let entry = entry.unwrap();
                let path = entry.path();
                if path.is_file() {
                    self.redact_file(path.to_str().unwrap());
                }
            }
        } else {
            println!("Directory not found: {}", dir);
        }
    }

    pub fn redact_zip(&mut self, zip_file: &str) {
        let file = File::open(zip_file).unwrap();
        let mut archive = ZipArchive::new(file).unwrap();

        for i in 0..archive.len() {
            let mut file = archive.by_index(i).unwrap();
            if file.is_file() {
                let mut contents = Vec::new();
                io::copy(&mut file, &mut contents).unwrap();
                let contents = String::from_utf8(contents).unwrap();
                let redacted_contents = self.redact(vec![contents]);
                let redacted_file_name = format!("{}-redacted", file.name());
                let mut output_file = File::create(&redacted_file_name).unwrap();
                for line in redacted_contents {
                    writeln!(output_file, "{}", line).unwrap();
                }
                println!("Redacted file saved as {}", redacted_file_name);
            }
        }
    }

    pub fn redact_pdf(&mut self, file: &str) -> Result<(), Box<dyn std::error::Error>> {
        let pdf_file = PdfFile::<std::fs::File>::open(file)?;
        let mut doc = pdf_file.into_document();

        for page_num in 0..doc.num_pages() {
            let page = doc.get_page(page_num)?;
            let contents = page.contents.as_ref().unwrap_or(&vec![]);
            let mut content_data = Vec::new();

            for &content_id in contents {
                let content_stream = doc.get_object(content_id)?;
                content_data.extend_from_slice(&content_stream.data);
            }

            // Extract text from the content data
            let text = extract_text(&content_data); // Implement text extraction logic

            // Redact the text
            let redacted_text = self.redact(vec![text]);

            // Update the page content with redacted text
            // Implement logic to replace the content streams with redacted text
        }

        // Save the redacted PDF
        doc.save("redacted.pdf")?;
        Ok(())
    }

    fn save_mappings(&self, filename: &str) {
        let mappings = json!(self.unique_mapping);
        let mut file = File::create(filename).unwrap();
        file.write_all(mappings.to_string().as_bytes()).unwrap();
    }
}

// Implement a function to extract text from PDF content data
fn extract_text(data: &[u8]) -> String {
    // Implement text extraction from PDF content streams
    String::new() // Placeholder
}

fn validate_ipv4(ip: &str) -> bool {
    ip.parse::<std::net::Ipv4Addr>().is_ok()
}

fn validate_ipv6(ip: &str) -> bool {
    ip.parse::<std::net::Ipv6Addr>().is_ok()
}

fn validate_url(url_str: &str) -> bool {
    url::Url::parse(url_str).is_ok()
}

fn validate_hostname(hostname: &str) -> bool {
    let hostname_regex = Regex::new(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)$").unwrap();
    if hostname.len() > 253 {
        return false;
    }
    let labels: Vec<&str> = hostname.split('.').collect();
    if labels.last().unwrap().parse::<u32>().is_ok() {
        return false;
    }
    labels.iter().all(|label| hostname_regex.is_match(label))
}

fn main() {
    let matches = App::new("Redactor")
        .version("1.0")
        .author("HP <null@hiranpate.com>")
        .about("Redacts sensitive information from a file within a directory or zip file")
        .arg(
            Arg::with_name("file")
                .help("The file to redact")
                .required(true)
                .index(1),
        )
        .arg(
            Arg::with_name("interactive")
                .short("i")
                .long("interactive")
                .help("Run in interactive mode"),
        )
        .arg(
            Arg::with_name("directory")
                .short("d")
                .long("directory")
                .help("Redact all files in a directory"),
        )
        .arg(
            Arg::with_name("zip")
                .short("z")
                .long("zip")
                .help("Redact all files in a zip archive"),
        )
        .get_matches();

    let file = matches.value_of("file").unwrap();
    let interactive = matches.is_present("interactive");
    let is_directory = matches.is_present("directory");
    let is_zip = matches.is_present("zip");

    let mut redactor = Redactor::new(interactive);

    if is_directory {
        redactor.redact_directory(file);
    } else if is_zip {
        redactor.redact_zip(file);
    } else {
        let path = Path::new(file);
        if path.is_file() {
            if path.extension().and_then(|ext| ext.to_str()) == Some("pdf") {
                redactor.redact_pdf(file).unwrap();
            } else {
                redactor.redact_file(file);
            }
        } else {
            println!("File not found: {}", file);
        }
    }
}
