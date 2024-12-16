use clap::{App, Arg};
use rand::seq::SliceRandom;
use regex::Regex;
use serde_json::json;
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{self, BufRead, Write};
use std::path::Path;

pub struct Redactor {
    patterns: HashMap<String, Regex>,
    validators: HashMap<String, Box<dyn Fn(&str) -> bool>>,
    secrets: HashMap<String, Vec<String>>,
    ignores: HashMap<String, Vec<String>>,
    unique_mapping: HashMap<String, String>,
    ip_counter: u32,
    counter: HashMap<String, u32>,
    interactive: bool,
    phone_formats: Vec<String>,
}

impl Redactor {
    pub fn new(interactive: bool) -> Self {
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

        let mut validators = HashMap::new();
        validators.insert(
            "ipv4".to_string(),
            Box::new(|x: &str| Redactor::is_valid_ipv4(x)) as Box<dyn Fn(&str) -> bool>,
        );
        validators.insert(
            "ipv6".to_string(),
            Box::new(|x: &str| Redactor::is_valid_ipv6(x)) as Box<dyn Fn(&str) -> bool>,
        );
        validators.insert(
            "url".to_string(),
            Box::new(|x: &str| Redactor::is_valid_url(x)) as Box<dyn Fn(&str) -> bool>,
        );
        validators.insert(
            "hostname".to_string(),
            Box::new(|x: &str| Redactor::is_valid_hostname(x)) as Box<dyn Fn(&str) -> bool>,
        );

        let phone_formats = vec![
            "({}) {}-{:04}".to_string(),
            "{}-{}-{:04}".to_string(),
            "{}.{}.{}".to_string(),
            "{} {} {}".to_string(),
        ];

        Redactor {
            patterns,
            validators,
            secrets: Redactor::load_lists("secrets.csv"),
            ignores: Redactor::load_lists("ignore.csv"),
            unique_mapping: HashMap::new(),
            ip_counter: 1,
            counter: HashMap::new(),
            interactive,
            phone_formats,
        }
    }

    fn load_lists(filename: &str) -> HashMap<String, Vec<String>> {
        let mut lists = HashMap::new();
        if let Ok(file) = File::open(filename) {
            for line in io::BufReader::new(file).lines() {
                if let Ok(line) = line {
                    let parts: Vec<&str> = line.split(',').collect();
                    if parts.len() == 2 {
                        lists
                            .entry(parts[0].to_string())
                            .or_insert_with(Vec::new)
                            .push(parts[1].to_string());
                    }
                }
            }
        }
        lists
    }

    fn is_valid_ipv4(ip: &str) -> bool {
        ip.parse::<std::net::Ipv4Addr>().is_ok()
    }

    fn is_valid_ipv6(ip: &str) -> bool {
        ip.parse::<std::net::Ipv6Addr>().is_ok()
    }

    fn is_valid_url(url: &str) -> bool {
        url::Url::parse(url).is_ok()
    }

    fn is_valid_hostname(hostname: &str) -> bool {
        let hostname_regex = Regex::new(r"(?!-)[a-z0-9-]{1,63}(?<!-)$").unwrap();
        if hostname.len() > 253 {
            return false;
        }
        let labels: Vec<&str> = hostname.split('.').collect();
        if labels.last().unwrap().parse::<u32>().is_ok() {
            return false;
        }
        labels.iter().all(|label| hostname_regex.is_match(label))
    }

    fn generate_unique_mapping(&mut self, value: &str, secret_type: &str) -> String {
        if !self.unique_mapping.contains_key(value) {
            let mapped_value = if secret_type == "ipv4" {
                let mapped_ip = format!("240.0.0.{}", self.ip_counter);
                self.ip_counter += 1;
                mapped_ip
            } else if secret_type == "phone" {
                let format = self.phone_formats.choose(&mut rand::thread_rng()).unwrap();
                let mapped_phone = format!(
                    format,
                    "800",
                    "555",
                    self.counter.entry(secret_type.to_string()).or_insert(0)
                );
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
        let mut file = File::create(filename).unwrap();
        writeln!(file, "{},{}", secret_type, value).unwrap();
    }

    fn redact_pattern(&mut self, line: String, pattern_type: &str) -> String {
        let pattern = self.patterns.get(pattern_type).unwrap();
        let ignore_set: HashSet<_> = self
            .ignores
            .get(pattern_type)
            .unwrap_or(&vec![])
            .iter()
            .cloned()
            .collect();

        let mut redacted_line = line.clone();
        for cap in pattern.captures_iter(&line) {
            let value = cap.get(0).unwrap().as_str();
            if !ignore_set.contains(value) {
                if let Some(validator) = self.validators.get(pattern_type) {
                    if !validator(value) {
                        continue;
                    }
                }
                if self.interactive && !self.ask_user(value, pattern_type) {
                    continue;
                }
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
                pattern_keys.iter().fold(line, |line, secret_type| {
                    self.redact_pattern(line, secret_type)
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

            // Determine the original file extension
            let extension = path
                .extension()
                .and_then(|ext| ext.to_str())
                .unwrap_or("txt");
            let file_stem = path
                .file_stem()
                .and_then(|stem| stem.to_str())
                .unwrap_or("file");

            // Create the redacted file name
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

    fn save_mappings(&self, filename: &str) {
        let mappings = json!(self.unique_mapping);
        let mut file = File::create(filename).unwrap();
        file.write_all(mappings.to_string().as_bytes()).unwrap();
    }
}

fn main() {
    let matches = App::new("Redactor")
        .version("1.0")
        .author("HP <null@hiranpate.com>")
        .about("Redacts sensitive information from files")
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
        .get_matches();

    let file = matches.value_of("file").unwrap();
    let interactive = matches.is_present("interactive");

    let mut redactor = Redactor::new(interactive);
    redactor.redact_file(file);
}
