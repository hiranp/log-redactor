use flate2::read::GzDecoder;
use lazy_static::lazy_static;
use log::{debug, info, warn};
use lopdf::Document;
use rand::seq::SliceRandom;
use regex::Regex;
use serde_derive::{Deserialize, Serialize};
use serde_json::json;
use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufReader, Write};
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::path::{Path, PathBuf};
use tar::Archive;
use time::OffsetDateTime;
use zip::read::ZipArchive;
use globset::{Glob, GlobSet, GlobSetBuilder};

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
    secret_patterns: HashMap<String, GlobSet>,
    ignore_patterns: HashMap<String, GlobSet>,
}

impl RedactorConfig {
    pub fn from_files(secrets_file: &str, ignores_file: &str) -> Result<Self, std::io::Error> {
        let secrets = if Path::new(secrets_file).exists() {
            File::open(secrets_file)
                .ok()
                .map(|file| serde_json::from_reader(BufReader::new(file)).unwrap_or_default())
        } else {
            None
        };

        let ignores = if Path::new(ignores_file).exists() {
            File::open(ignores_file)
                .ok()
                .map(|file| serde_json::from_reader(BufReader::new(file)).unwrap_or_default())
        } else {
            None
        };

        let mut config = RedactorConfig {
            secrets,
            ignores,
            secret_patterns: HashMap::new(),
            ignore_patterns: HashMap::new(),
        };

        // Build glob patterns for secrets
        if let Some(ref secrets) = config.secrets {
            for (key, patterns) in secrets {
                let mut builder = GlobSetBuilder::new();
                for pattern in patterns {
                    if let Ok(glob) = Glob::new(pattern) {
                        builder.add(glob);
                    }
                }
                if let Ok(set) = builder.build() {
                    config.secret_patterns.insert(key.clone(), set);
                }
            }
        }

        // Build glob patterns for ignores
        if let Some(ref ignores) = config.ignores {
            for (key, patterns) in ignores {
                let mut builder = GlobSetBuilder::new();
                for pattern in patterns {
                    if let Ok(glob) = Glob::new(pattern) {
                        builder.add(glob);
                    }
                }
                if let Ok(set) = builder.build() {
                    config.ignore_patterns.insert(key.clone(), set);
                }
            }
        }

        Ok(config)
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
    redacted_mapping_file: String,
}

lazy_static! {
    static ref IPV4_REGEX: Regex = Regex::new(
        r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
    ).unwrap();
    
    static ref IPV6_REGEX: Regex = Regex::new(
        r"(?i)\b(?:[0-9a-f]{1,4}:){7}[0-9a-f]{1,4}\b|(?:[0-9a-f]{1,4}:)*(?::[0-9a-f]{1,4})*(?::(?::[0-9a-f]{1,4})*)?")
        .unwrap();
    
    static ref PHONE_REGEX: Regex = Regex::new(
        r"\b(?:\+?1[-. ]?)?\s*\(?\d{3}\)?[-. ]\d{3}[-. ]\d{4}\b"
    ).unwrap();
    
    static ref EMAIL_REGEX: Regex = Regex::new(
        r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+"
    ).unwrap();
    
    static ref URL_REGEX: Regex = Regex::new(
        r"https?://(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}(?:/[^\s]*)?"
    ).unwrap();
    
    static ref HOSTNAME_REGEX: Regex = Regex::new(
        r"(?:^|[^.])[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}"
    ).unwrap();
    
    static ref API_REGEX: Regex = Regex::new(
        r"(?i)(token|key|api|apikey|apitoken)=([^&\s]*)"
    ).unwrap();
}

impl Redactor {
    pub fn new(
        interactive: bool,
        secrets_file: &str,
        ignores_file: &str,
        redacted_mapping_file: &str,
    ) -> Self {
        let patterns = Self::init_patterns();

        let mut validators: HashMap<String, fn(&str) -> bool> = HashMap::new();
        validators.insert("ipv4".to_string(), validate_ipv4);
        validators.insert("ipv6".to_string(), validate_ipv6);
        validators.insert("url".to_string(), validate_url);
        validators.insert("hostname".to_string(), is_valid_hostname);
        validators.insert("phone".to_string(), validate_phone);
        validators.insert("email".to_string(), is_valid_email);
        validators.insert("api".to_string(), validate_api);

        let config = RedactorConfig::from_files(secrets_file, ignores_file).unwrap_or_default();

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
            redacted_mapping_file: redacted_mapping_file.to_string(),
        }
    }

    pub fn init_patterns() -> HashMap<String, Regex> {
        let mut patterns = HashMap::new();
        patterns.insert("ipv4".to_string(), IPV4_REGEX.clone());
        patterns.insert("ipv6".to_string(), IPV6_REGEX.clone());
        patterns.insert("phone".to_string(), PHONE_REGEX.clone());
        patterns.insert("email".to_string(), EMAIL_REGEX.clone());
        patterns.insert("url".to_string(), URL_REGEX.clone());
        patterns.insert("hostname".to_string(), HOSTNAME_REGEX.clone());
        patterns.insert("api".to_string(), API_REGEX.clone());
        patterns
    }

    fn generate_unique_mapping(&mut self, value: &str, secret_type: &str) -> String {
        println!(
            "Generating unique mapping for value: {}, secret_type: {}",
            value, secret_type
        );
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
            self.save_mapping_to_file(value, &mapped_value);
            mapped_value
        } else {
            self.unique_mapping.get(value).unwrap().clone()
        }
    }

    fn save_mapping_to_file(&self, original: &str, redacted: &str) {
        match OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.redacted_mapping_file)
        {
            Ok(mut file) => {
                // Use now_utc() since now_local() isn't available
                let now = OffsetDateTime::now_utc();
                if let Err(e) = writeln!(
                    file,
                    "{},{},{}",
                    now.format(
                        &time::format_description::parse(
                            "[year]-[month]-[day] [hour]:[minute]:[second]"
                        )
                        .unwrap()
                    )
                    .unwrap(),
                    original,
                    redacted
                ) {
                    warn!("Failed to write mapping to file: {}", e);
                }
            }
            Err(e) => {
                warn!("Failed to open mapping file: {}", e);
            }
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
            "never" | "r" => {
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

    fn should_ignore_value(&self, value: &str, pattern_type: &str) -> bool {
        if pattern_type == "phone" {
            // Ignore if value has no separators (likely a timestamp or ID)
            if value.chars().filter(|c| c.is_ascii_digit()).count() == value.len() {
                debug!("Ignoring numeric value without separators: {}", value);
                return true;
            }
        }
        false
    }

    fn redact_pattern(&mut self, line: &str, pattern_type: &str) -> String {
        if line.contains("redacted-") || line.contains("redacted_") {
            return line.to_string();
        }

        println!("Redacting pattern type: {}", pattern_type); // Debug line
        let pattern = &self.patterns[pattern_type];
        let captures: Vec<_> = pattern.captures_iter(line).collect();

        // Add debug logging
        debug!(
            "Pattern type: {}, Found matches: {}",
            pattern_type,
            captures.len()
        );
        
        let validator_fn = self.validators[pattern_type];
        let interactive = self.interactive;

        let mut redacted_line = line.to_string();

        for cap in captures {
            let (key_type, value) = if pattern_type == "api" {
                // Extract the actual key type from the match
                let key_type = cap.get(1).map_or("api", |m| m.as_str());
                (key_type, cap.get(0).unwrap().as_str())
            } else {
                (pattern_type, cap.get(0).unwrap().as_str())
            };

            // Pass pattern_type to should_ignore_value
            if self.should_ignore_value(value, pattern_type) {
                continue;
            }

            // First check if it matches any secret patterns
            let should_redact = if self.config.secret_patterns
                .get(pattern_type)
                .map_or(false, |patterns| patterns.is_match(value))
            {
                true
            } else if self.config.ignore_patterns
                .get(pattern_type)
                .map_or(false, |patterns| patterns.is_match(value))
            {
                false
            } else {
                // Only validate and ask user if no pattern matches
                validator_fn(value) && (!interactive || self.ask_user(value, key_type))
            };

            if should_redact {
                let replacement = self.generate_unique_mapping(value, key_type);
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
        if !path.exists() {
            warn!("File not found: {}", file);
            return;
        }

        let content = match fs::read(path) {
            Ok(content) => content,
            Err(e) => {
                warn!("Failed to read file: {}", e);
                return;
            }
        };

        // Use infer to detect file type
        let kind = infer::get(&content);

        if let Some(k) = kind {
            match k.mime_type() {
                // Handle archives
                "application/zip" => {
                    info!("Detected ZIP archive");
                    if let Err(e) = self.redact_zip(file) {
                        warn!("Failed to process ZIP file: {}", e);
                    }
                    return;
                }
                "application/x-tar" => {
                    info!("Detected TAR archive");
                    if let Err(e) = self.redact_tar(file) {
                        warn!("Failed to process TAR file: {}", e);
                    }
                    return;
                }
                "application/gzip" => {
                    info!("Detected GZIP archive");
                    if let Err(e) = self.redact_tar_gz(file) {
                        warn!("Failed to process GZIP file: {}", e);
                    }
                    return;
                }
                "application/x-bzip2" => {
                    info!("Detected BZIP2 archive");
                    if let Err(e) = self.redact_bzip2(file) {
                        warn!("Failed to process BZIP2 file: {}", e);
                    }
                    return;
                }
                // Handle other binary types
                mime if mime.starts_with("image/")
                    || mime.starts_with("video/")
                    || mime.starts_with("audio/") =>
                {
                    warn!("Unsupported binary file type: {}", mime);
                    return;
                }
                _ => (), // Continue processing other types
            }
        }

        // Handle all text-based files
        match String::from_utf8(content.clone()) {
            Ok(text_content) => {
                self.process_text_file(path, &text_content);
            }
            Err(_) => warn!("File appears to be binary and is not supported"),
        }
    }

    pub fn redact_bzip2(&mut self, bzip2_file: &str) -> Result<(), std::io::Error> {
        info!("Redacting BZIP2 archive: {}", bzip2_file);
        let file = File::open(bzip2_file)?;
        let decoder = bzip2::read::BzDecoder::new(file);
        let mut archive = Archive::new(decoder);

        // Create output directory
        let output_dir = format!("{}-redacted", bzip2_file.trim_end_matches(".bz2"));
        fs::create_dir_all(&output_dir)?;

        // Extract all files
        archive.unpack(&output_dir)?;
        info!("Extracted BZIP2 archive to: {}", output_dir);

        // Process each file in the extracted directory
        self.redact_directory(&output_dir);

        info!("BZIP2 archive redaction complete");
        Ok(())
    }

    fn process_text_file(&mut self, file_path: &Path, text_content: &str) {
        let lines: Vec<String> = text_content.lines().map(|line| line.to_string()).collect();
        let redacted_lines = self.redact(lines);

        let extension = file_path
            .extension()
            .and_then(|ext| ext.to_str())
            .unwrap_or("txt");
        let file_stem = file_path
            .file_stem()
            .and_then(|stem| stem.to_str())
            .unwrap_or("file");

        let redacted_file_name = format!("{}-redacted.{}", file_stem, extension);

        // Write redacted content
        if let Ok(mut output_file) = File::create(&redacted_file_name) {
            for line in redacted_lines {
                if let Err(e) = writeln!(output_file, "{}", line) {
                    warn!("Failed to write redacted line: {}", e);
                }
            }
            info!("Created redacted file: {}", redacted_file_name);
        }
    }

    pub fn redact_directory(&mut self, dir: &str) {
        info!("Redacting directory: {}", dir);
        let path = Path::new(dir);
        
        if !path.is_dir() {
            warn!("Directory not found: {}", dir);
            return;
        }

        // Collect all files recursively
        match collect_files(path) {
            Ok(files) => {
                info!("Found {} files to process", files.len());
                for file_path in files {
                    info!("Processing file: {}", file_path.display());
                    if let Some(path_str) = file_path.to_str() {
                        self.redact_file(path_str);
                    }
                }
                info!("Directory redaction complete");
            }
            Err(e) => {
                warn!("Error walking directory {}: {}", dir, e);
            }
        }
    }

    pub fn redact_zip(&mut self, zip_file: &str) -> Result<(), std::io::Error> {
        info!("Redacting ZIP archive: {}", zip_file);
        let file = File::open(zip_file)?;
        let mut archive = ZipArchive::new(file)?;

        // Create output directory
        let output_dir = format!("{}-redacted", zip_file.trim_end_matches(".zip"));
        fs::create_dir_all(&output_dir)?;

        for i in 0..archive.len() {
            let mut file = archive.by_index(i)?;
            let outpath = Path::new(&output_dir).join(file.name());

            if file.is_dir() {
                fs::create_dir_all(&outpath)?;
            } else {
                if let Some(p) = outpath.parent() {
                    if !p.exists() {
                        fs::create_dir_all(p)?;
                    }
                }
                let mut outfile = File::create(&outpath)?;
                io::copy(&mut file, &mut outfile)?;
            }
        }

        info!("Extracted ZIP archive to: {}", output_dir);

        // Then process each file in the extracted directory
        self.redact_directory(&output_dir);

        info!("ZIP archive redaction complete");
        Ok(())
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

    #[allow(dead_code)]
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
        println!("Generating phone number with count: {}", count);
        let mapped_phone = match format.as_str() {
            "({}) {}-{:04}" => format!("(800) 555-{:04}", count),
            "{}-{}-{:04}" => format!("800-555-{:04}", count),
            "{}.{}.{}" => format!("800.555.{:04}", count),
            "{} {} {}" => format!("800 555 {:04}", count),
            _ => format!("800 555 {:04}", count),
        };
        *self.counter.get_mut("phone").unwrap() += 1;
        mapped_phone
    }

    fn generate_hostname(&mut self) -> String {
        let count = self.counter.entry("hostname".to_string()).or_insert(0);
        let hostname = format!("redacted-host-{:03}.example.com", count);
        *count += 1;
        hostname
    }

    fn generate_url(&mut self) -> String {
        let count = self.counter.entry("url".to_string()).or_insert(0);
        let url = format!("https://redacted-url-{:03}.example.com", count);
        *count += 1;
        url
    }

    fn generate_email(&mut self) -> String {
        let count = self.counter.entry("email".to_string()).or_insert(0);
        println!("Generating email with count: {}", count);
        let email = format!("redacted{}@example.com", count);
        *self.counter.get_mut("email").unwrap() += 1;
        email
    }

    fn generate_api_key(&mut self, key_type: &str) -> String {
        let count = {
            let counter = self.counter.entry(format!("{}_key", key_type)).or_insert(0);
            let current = *counter;
            *counter += 1;
            debug!("Counter for {}: {}", key_type, current);
            current
        };

        let redacted = format!("{}=redacted_{:03}", key_type, count);
        debug!("Generated redacted key: {}", redacted);
        redacted
    }

    pub fn redact_tar(&mut self, tar_file: &str) -> Result<(), std::io::Error> {
        info!("Redacting TAR archive: {}", tar_file);
        let file = File::open(tar_file)?;
        let mut archive = Archive::new(file);

        // Create output directory
        let output_dir = format!("{}-redacted", tar_file.trim_end_matches(".tar"));
        fs::create_dir_all(&output_dir)?;

        // First extract all files
        archive.unpack(&output_dir)?;
        info!("Extracted TAR archive to: {}", output_dir);

        // Then process each file in the extracted directory
        self.redact_directory(&output_dir);

        info!("TAR archive redaction complete");
        Ok(())
    }

    pub fn redact_tar_gz(&mut self, tar_gz_file: &str) -> Result<(), std::io::Error> {
        info!("Redacting TAR.GZ archive: {}", tar_gz_file);
        let file = File::open(tar_gz_file)?;
        let gz = GzDecoder::new(file);
        let mut archive = Archive::new(gz);

        // Create output directory - handle both .tar.gz and .tgz extensions
        let base_name = tar_gz_file
            .trim_end_matches(".tar.gz")
            .trim_end_matches(".tgz");
        let output_dir = format!("{}-redacted", base_name);
        fs::create_dir_all(&output_dir)?;

        // First extract all files
        archive.unpack(&output_dir)?;
        info!("Extracted TAR.GZ archive to: {}", output_dir);

        // Then process each file in the extracted directory
        self.redact_directory(&output_dir);

        info!("TAR.GZ archive redaction complete");
        Ok(())
    }
}

// Helper function to collect all files recursively
fn collect_files(dir: &Path) -> io::Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    
    if dir.is_dir() {
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            
            if path.is_dir() {
                // Recursively collect files from subdirectories
                files.extend(collect_files(&path)?);
            } else if path.is_file() {
                // Skip already redacted files
                if !path.to_string_lossy().contains("-redacted") {
                    files.push(path);
                }
            }
        }
    }
    
    Ok(files)
}

pub fn validate_ipv4(ip: &str) -> bool {
    // Split the IP address into octets
    let parts: Vec<&str> = ip.split('.').collect();

    if parts.len() != 4 {
        return false;
    }

    // Parse each octet, allowing for leading zeros
    for part in parts {
        // Remove leading zeros
        let trimmed = part.trim_start_matches('0');
        let octet = if trimmed.is_empty() {
            0
        } else {
            match trimmed.parse::<u8>() {
                Ok(num) => num,
                Err(_) => return false,
            }
        };

        // Verify the original representation
        if octet.to_string() != trimmed && part != "0" {
            return false;
        }
    }

    true
}

pub fn validate_ipv6(ip: &str) -> bool {
    ip.parse::<Ipv6Addr>().is_ok()
}

pub fn validate_url(url_str: &str) -> bool {
    url::Url::parse(url_str).is_ok()
}

pub fn validate_hostname(hostname: &str) -> bool {
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

// hostname-validator: https://docs.rs/crate/hostname-validator/latest [orginal failed security audit]
// REFS: https://tools.ietf.org/html/rfc1123
// A hostname is valid if the following condition are true:
pub fn is_valid_hostname(hostname: &str) -> bool {
    fn is_valid_char(byte: u8) -> bool {
        byte.is_ascii_lowercase()
            || byte.is_ascii_uppercase()
            || byte.is_ascii_digit()
            || byte == b'-'
            || byte == b'.'
    }

    !(hostname.bytes().any(|byte| !is_valid_char(byte))
        || hostname.split('.').any(|label| {
            label.is_empty() || label.len() > 63 || label.starts_with('-') || label.ends_with('-')
        })
        || hostname.is_empty()
        || hostname.len() > 253)
}

// Generates a new IPv4 address in the 240.0.0.0/4 network
fn generate_ipv4_address(counter: u32) -> Ipv4Addr {
    let octet3 = (counter >> 8) as u8;
    let octet4 = (counter & 0xFF) as u8;
    Ipv4Addr::new(240, 0, octet3, octet4)
}

// Generate a new IPv6 address in the fd00::/8 network (unique local address)
fn generate_ipv6_address(counter: u32) -> Ipv6Addr {
    let mut segments = [0u16; 8];
    segments[0] = 0xfd00; // Using fd00::/8 for unique local addresses
    segments[1] = (counter >> 16) as u16;
    segments[2] = counter as u16;
    // Keep the remaining segments as 0 to maintain structure
    Ipv6Addr::new(
        segments[0],
        segments[1],
        segments[2],
        segments[3],
        segments[4],
        segments[5],
        segments[6],
        segments[7],
    )
}

// Validates formats: XXX-XXX-XXXX, (XXX) XXX-XXXX, XXX.XXX.XXXX, XXX XXX XXXX
pub fn validate_phone(phone: &str) -> bool {
    PHONE_REGEX.is_match(phone)
}

pub fn validate_email(email: &str) -> bool {
    EMAIL_REGEX.is_match(email)
}
#[allow(dead_code)]
pub fn is_valid_email(email: &str) -> bool {
    email_address::EmailAddress::is_valid(email)
}

pub fn validate_api(api: &str) -> bool {
    if api.ends_with('=') {
        return false;
    }
    API_REGEX.is_match(api)
}
