use ipnet::{Ipv4Net, Ipv6Net};
use log::{info, warn};
use lopdf::Document;
use rand::seq::SliceRandom;
use regex::Regex;
use serde_derive::{Deserialize, Serialize};
use serde_json::json;
use std::collections::HashMap;
use std::collections::HashSet;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, BufReader, Write};
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::path::Path;
use zip::read::ZipArchive;

pub mod redaction_utils;

#[derive(Serialize, Deserialize)]
struct Secret {
    value: String,
}

#[derive(Serialize, Deserialize)]
struct Ignore {
    value: String,
}

#[derive(Default)]
pub struct RedactorConfig {
    secrets: Option<HashMap<String, Vec<String>>>,
    ignores: Option<HashMap<String, Vec<String>>>,
}

impl RedactorConfig {
    pub fn from_files(secrets_file: &str, ignores_file: &str) -> Result<Self, std::io::Error> {
        let secrets = File::open(secrets_file)
            .ok()
            .map(|file| serde_json::from_reader(BufReader::new(file)).unwrap_or_default());

        let ignores = File::open(ignores_file)
            .ok()
            .map(|file| serde_json::from_reader(BufReader::new(file)).unwrap_or_default());

        Ok(RedactorConfig { secrets, ignores })
    }
}
pub struct Redactor {
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
    pub fn new(interactive: bool) -> Self {
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

    pub fn init_patterns() -> HashMap<String, Regex> {
        let mut patterns = HashMap::new();

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
            Regex::new(r"(?i)(token|key|api|apikey|apitoken)=[^&\s]*").unwrap(),
        );

        patterns
    }

    fn generate_unique_mapping(&mut self, value: &str, secret_type: &str) -> String {
        if !self.unique_mapping.contains_key(value) {
            let mapped_value = match secret_type {
                "ipv4" => {
                    let mapped_ip = generate_ipv4_address(self.ip_counter);
                    self.ip_counter += 1;
                    mapped_ip.to_string()
                }
                "ipv6" => {
                    let mapped_ip = generate_ipv6_address(self.ip_counter);
                    self.ip_counter += 1;
                    mapped_ip.to_string()
                }
                "phone" => self.generate_phone_number(),
                "hostname" => self.generate_hostname(),
                "url" => self.generate_url(),
                "email" => self.generate_email(),
                _ if secret_type.starts_with("token")
                    || secret_type.starts_with("key")
                    || secret_type.starts_with("api")
                    || secret_type.starts_with("apikey")
                    || secret_type.starts_with("apitoken") =>
                {
                    self.generate_api_key(secret_type)
                }
                _ => value.to_string(),
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
        info!("Redacting file: {}", file);
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

            if let Err(e) = self.save_mappings(&format!("{}-mappings.json", file_stem)) {
                warn!("Failed to save mappings: {}", e);
            }
            info!("File redaction complete");
            println!("Redacted file saved as {}", redacted_file_name);
        } else {
            warn!("File not found: {}", file);
        }
    }

    pub fn redact_directory(&mut self, dir: &str) {
        info!("Redacting directory: {}", dir);
        let path = Path::new(dir);
        if path.is_dir() {
            for entry in fs::read_dir(path).unwrap() {
                let entry = entry.unwrap();
                let path = entry.path();
                if path.is_file() {
                    self.redact_file(path.to_str().unwrap());
                }
            }
            info!("Directory redaction complete");
        } else {
            warn!("Directory not found: {}", dir);
        }
    }

    pub fn redact_zip(&mut self, zip_file: &str) {
        info!("Redacting ZIP archive: {}", zip_file);
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
        info!("ZIP archive redaction complete");
    }

    pub fn redact_pdf(&mut self, file: &str) -> Result<(), Box<dyn std::error::Error>> {
        info!("Redacting PDF file: {}", file);

        let mut doc = Document::load(file)?;
        let pages = doc.get_pages();

        for &page_id in pages.values() {
            // Get the content streams of the page
            let content_data = doc.get_page_content(page_id)?;
            let mut content = lopdf::content::Content::decode(&content_data)?;

            // Iterate over the operations and redact text
            for operation in &mut content.operations {
                if let Some(lopdf::Object::String(ref mut text, _)) = operation.operands.get_mut(0)
                {
                    let redacted = self.redact_string(text)?;
                    *text = redacted;
                } else if let Some(lopdf::Object::Array(ref mut elements)) =
                    operation.operands.get_mut(0)
                {
                    for elem in elements {
                        if let lopdf::Object::String(ref mut text, _) = elem {
                            let redacted = self.redact_string(text)?;
                            *text = redacted;
                        }
                    }
                }
            }

            // Encode the modified content stream
            let redacted_content = content.encode()?;
            if let Err(e) = doc.change_page_content(page_id, redacted_content) {
                warn!("Failed to change page content: {}", e);
            }
        }

        // Save the redacted PDF
        let output_path = format!(
            "{}-redacted.pdf",
            Path::new(file)
                .file_stem()
                .unwrap_or_default()
                .to_str()
                .unwrap_or("file")
        );
        doc.save(&output_path)?;

        info!("PDF redaction complete");
        println!("Redacted PDF saved as {}", output_path);

        Ok(())
    }

    // Helper method to redact a single string
    fn redact_string(&mut self, text_bytes: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        // Decode the PDF text (assuming it's encoded in standard encoding)
        let decoded_text = String::from_utf8(text_bytes.to_vec())?;

        // Redact the text
        let redacted_text = self.redact(vec![decoded_text]).join("");

        // Return the redacted text as bytes
        Ok(redacted_text.into_bytes())
    }

    fn save_mappings(&self, filename: &str) -> Result<(), std::io::Error> {
        let mappings = json!(self.unique_mapping);
        let mut file = File::create(filename)?;
        file.write_all(mappings.to_string().as_bytes())?;
        Ok(())
    }

    // Generates a new phone number in 800-555-xxxx range
    fn generate_phone_number(&mut self) -> String {
        let format = self.phone_formats.choose(&mut rand::thread_rng()).unwrap();
        let count = self.counter.entry("phone".to_string()).or_insert(0);
        let mapped_phone = match format.as_str() {
            "({}) {}-{:04}" => format!("(800) 555-{:04}", count),
            "{}-{}-{:04}" => format!("800-555-{:04}", count),
            "{}.{}.{}" => format!("800.555.{:04}", count),
            _ => format!("800 555 {:04}", count),
        };
        *self.counter.get_mut("phone").unwrap() += 1;
        mapped_phone
    }

    fn generate_hostname(&mut self) -> String {
        let hostname = format!(
            "redacted_host{}.example.com",
            self.counter.get("hostname").unwrap_or(&0)
        );
        self.counter
            .entry("hostname".to_string())
            .and_modify(|e| *e += 1)
            .or_insert(1);
        hostname
    }

    fn generate_url(&mut self) -> String {
        let url = format!(
            "https://www.example{}.com",
            self.counter.get("url").unwrap_or(&0)
        );
        self.counter
            .entry("url".to_string())
            .and_modify(|e| *e += 1)
            .or_insert(1);
        url
    }

    fn generate_email(&mut self) -> String {
        let count = self.counter.entry("email".to_string()).or_insert(0);
        let email = format!("redacted{}@example.com", count);
        *self.counter.get_mut("email").unwrap() += 1;
        email
    }

    fn generate_api_key(&mut self, prefix: &str) -> String {
        let count = self.counter.entry(prefix.to_string()).or_insert(0);
        let api_key = format!("{}_redacted_{}", prefix, count);
        *self.counter.get_mut(prefix).unwrap() += 1;
        api_key
    }
}

fn validate_ipv4(ip: &str) -> bool {
    ip.parse::<Ipv4Net>().is_ok()
}

fn validate_ipv6(ip: &str) -> bool {
    ip.parse::<Ipv6Net>().is_ok()
}

fn validate_url(url_str: &str) -> bool {
    url::Url::parse(url_str).is_ok()
}

fn validate_hostname(hostname: &str) -> bool {
    let hostname_regex = Regex::new(r"^[A-Za-z0-9-]{1,63}$").unwrap();
    if hostname.len() > 253 {
        return false;
    }
    let labels: Vec<&str> = hostname.split('.').collect();
    if labels.last().unwrap().parse::<u32>().is_ok() {
        return false;
    }
    labels.iter().all(|label| hostname_regex.is_match(label))
}

// Generates a new IPv4 address in the 240.0.0.0/4 network
fn generate_ipv4_address(counter: u32) -> Ipv4Addr {
    let octet3 = (counter >> 8) as u8;
    let octet4 = (counter & 0xFF) as u8;
    Ipv4Addr::new(240, 0, octet3, octet4)
}

// Generate a new IPv6 address in the 3fff::/20 network
fn generate_ipv6_address(counter: u32) -> Ipv6Addr {
    let mut segments = [0u16; 8];
    segments[0] = 0x3fff;
    segments[1] = (counter >> 16) as u16;
    segments[2] = (counter & 0xFFFF) as u16;
    Ipv6Addr::new(segments[0], segments[1], segments[2], 0, 0, 0, 0, 0)
}
