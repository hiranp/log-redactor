use log_redactor::Redactor;
use std::fs::File;
use std::io::{self, BufRead};
use std::net::Ipv4Addr;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};

// Global variable to switch between sample_log_file and test_sample
static USE_SAMPLE_LOG_FILE: AtomicBool = AtomicBool::new(false);
static SAMPLE_LOG_FILE: &str = "../samples/sample.log";

fn read_lines<P>(filename: P) -> io::Result<Vec<String>>
where
    P: AsRef<Path>,
{
    let file = File::open(filename)?;
    let buf = io::BufReader::new(file);
    buf.lines().collect()
}

fn sample_log_file() -> Vec<String> {
    let lines = match read_lines(SAMPLE_LOG_FILE) {
        Ok(lines) => lines,
        Err(e) => {
            eprintln!("Failed to read sample log file: {}", e);
            std::process::exit(1);
        }
    };
    let mut redactor = Redactor::new(
        false,
        "dummy_secrets.csv",
        "dummy_ignores.csv",
        "dummy_mapping.txt",
    );
    let redacted_lines = redactor.redact(lines);

    for line in &redacted_lines {
        println!("{}", line);
    }

    redacted_lines
}

fn test_sample() -> Vec<String> {
    let log_data = r#"
# Sample Log File

# IPv4 Examples
192.168.1.1
10.0.0.255
172.16.254.1
192.168.0.1
10.1.1.1
192.0.2.0
203.0.113.0
255.255.255.255
127.0.0.1
8.8.8.8

# IPv6 Examples
2001:0db8:85a3:0000:0000:8a2e:0370:7334
fe80::1ff:fe23:4567:890a
::1
2001:db8::ff00:42:8329
2001:db8:85a3::8a2e:370:7334
2001:db8:0:1234:0:567:8:1
2001:0db8::0000:0000:0000:0000:0000
::ffff:192.168.1.1
2001:db8:0:0:0:0:2:1
::a00:1

# Hostname Examples
example.com
subdomain.example.com
my-hostname.org
test.example.co.uk
example123.net
test-site.com
sub.domain.example
hostname-with-dash.com
example-123.net

# Phone Examples
(800) 555-0100
(800) 555-0101
123-456-7890
333.444.5555
999 888 7777
(555) 555-5555

# Email Examples
john.doe@example.com
jane.doe@example.com
admin@example.com
user@example.com
contact@example.com
eisenhower@army.us.mil

# URL Examples
https://www.example.com
http://example.org
https://example.net/path/to/resource?query=1&value=2
http://localhost:8080/test
https://subdomain.example.com/path

# API Key Examples
apikey=1234567890abcdef
token=abcdef1234567890
key=abcdef1234567890
apitoken=abcdef1234567890
"#;

    log_data.lines().map(|line| line.to_string()).collect()
}

fn get_log_lines() -> Vec<String> {
    if USE_SAMPLE_LOG_FILE.load(Ordering::Relaxed) {
        sample_log_file()
    } else {
        test_sample()
    }
}

fn print_redaction_result(pattern_type: &str, original: &str, redacted: &str) {
    println!("----------------------------------------");
    println!("Pattern Type: {}", pattern_type);
    println!("Original: {}", original);
    println!("Redacted: {}", redacted);
    println!("----------------------------------------");
}

#[test]
fn test_redact_ipv4() {
    let mut redactor = Redactor::new(
        false,
        "dummy_secrets.csv",
        "dummy_ignores.csv",
        "dummy_mapping.txt",
    );
    let log_lines = get_log_lines();
    let redacted_lines = redactor.redact(log_lines);

    println!("\nIPv4 Redaction Results:");
    println!("=======================");

    let ipv4_addresses = vec![
        "192.168.1.1",
        "10.0.0.255",
        "172.16.254.1",
        "192.168.0.1",
        "10.1.1.1",
        "192.0.2.0",
        "203.0.113.0",
        "255.255.255.255",
        "127.0.0.1",
        "8.8.8.8",
    ];

    let mut redacted_ips = Vec::new();

    for line in redacted_lines {
        for ip in &ipv4_addresses {
            if line.contains(ip) {
                print_redaction_result("IPv4", ip, &line);
            }
            assert!(!line.contains(ip));
        }

        for word in line.split_whitespace() {
            if let Ok(ip) = word.parse::<Ipv4Addr>() {
                if ip.octets()[0] >= 240 {
                    redacted_ips.push(ip);
                }
            }
        }
    }

    println!("\nRedacted IPs: {:?}", redacted_ips);
}

#[test]
fn test_redact_ipv6() {
    let mut redactor = Redactor::new(
        false,
        "dummy_secrets.csv",
        "dummy_ignores.csv",
        "dummy_mapping.txt",
    );
    let log_lines = get_log_lines();
    let redacted_lines = redactor.redact(log_lines);

    println!("\nIPv6 Redaction Results:");
    println!("=======================");

    let ipv6_addresses = vec![
        "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
        "fe80::1ff:fe23:4567:890a",
        "::1",
        "2001:db8::ff00:42:8329",
        "2001:db8:85a3::8a2e:370:7334",
        "2001:db8:0:1234:0:567:8:1",
        "2001:0db8::0000:0000:0000:0000:0000",
        "::ffff:192.168.1.1",
        "2001:db8:0:0:0:0:2:1",
        "::a00:1",
    ];

    for line in redacted_lines {
        for ip in &ipv6_addresses {
            if line.contains(ip) {
                print_redaction_result("IPv6", ip, &line);
            }
            assert!(!line.contains(ip));
        }
    }
}

#[test]
fn test_redact_hostname() {
    let mut redactor = Redactor::new(
        false,
        "dummy_secrets.csv",
        "dummy_ignores.csv",
        "dummy_mapping.txt",
    );
    let log_lines = get_log_lines();
    let redacted_lines = redactor.redact(log_lines);

    println!("\nHostname Redaction Results:");
    println!("===========================");

    let hostnames = vec![
        "example.com",
        "subdomain.example.com",
        "my-hostname.org",
        "test.example.co.uk",
        "example123.net",
        "test-site.com",
        "sub.domain.example",
        "hostname-with-dash.com",
        "example-123.net",
    ];

    let mut redacted_hostnames = Vec::new();

    for line in redacted_lines {
        for hostname in &hostnames {
            if line.contains(hostname) {
                print_redaction_result("Hostname", hostname, &line);
            }
            assert!(!line.contains(hostname));
        }

        for word in line.split_whitespace() {
            if word.starts_with("redacted_host") {
                redacted_hostnames.push(word.to_string());
            }
        }
    }

    println!("\nRedacted Hostnames: {:?}", redacted_hostnames);
}

#[test]
fn test_redact_phone_direct() {
    let mut redactor = Redactor::new(
        false,
        "dummy_secrets.csv",
        "dummy_ignores.csv",
        "dummy_mapping.txt",
    );
    let lines = vec![
        "Call me at 123-456-7890".to_string(),
        "My number is 333.444.5555".to_string(),
        "Reach me at 999 888 7777".to_string(),
    ];
    let redacted_lines = redactor.redact(lines);

    println!("\nPhone Redaction Results:");
    println!("========================");

    for line in redacted_lines {
        if line.contains("123-456-7890") {
            print_redaction_result("Phone", "123-456-7890", &line);
        }
        if line.contains("333.444.5555") {
            print_redaction_result("Phone", "333.444.5555", &line);
        }
        if line.contains("999 888 7777") {
            print_redaction_result("Phone", "999 888 7777", &line);
        }
        assert!(!line.contains("123-456-7890"));
        assert!(!line.contains("333.444.5555"));
        assert!(!line.contains("999 888 7777"));
    }
}

#[test]
fn test_redact_phone() {
    let mut redactor = Redactor::new(
        false,
        "dummy_secrets.csv",
        "dummy_ignores.csv",
        "dummy_mapping.txt",
    );
    let log_lines = get_log_lines();
    let redacted_lines = redactor.redact(log_lines);

    println!("\nPhone Redaction Results:");
    println!("========================");

    let phone_numbers = vec![
        "(800) 555-0100",
        "(800) 555-0101",
        "123-456-7890",
        "333.444.5555",
        "999 888 7777",
        "(555) 555-5555",
    ];

    let mut redacted_phones = Vec::new();

    for line in redacted_lines {
        for phone in &phone_numbers {
            if line.contains(phone) {
                print_redaction_result("Phone", phone, &line);
            }
            assert!(!line.contains(phone));
        }

        for word in line.split_whitespace() {
            if word.starts_with("800") {
                redacted_phones.push(word.to_string());
            }
        }
    }

    println!("\nRedacted Phones: {:?}", redacted_phones);
}

#[test]
fn test_redact_email() {
    let mut redactor = Redactor::new(
        false,
        "dummy_secrets.csv",
        "dummy_ignores.csv",
        "dummy_mapping.txt",
    );
    let log_lines = get_log_lines();
    let redacted_lines = redactor.redact(log_lines);

    println!("\nEmail Redaction Results:");
    println!("========================");

    let emails = vec![
        "john.doe@example.com",
        "jane.doe@example.com",
        "admin@example.com",
        "user@example.com",
        "contact@example.com",
    ];

    let mut redacted_emails = Vec::new();

    for line in redacted_lines {
        for email in &emails {
            if line.contains(email) {
                print_redaction_result("Email", email, &line);
            }
            assert!(!line.contains(email));
        }

        for word in line.split_whitespace() {
            if word.contains("@example.com") {
                redacted_emails.push(word.to_string());
            }
        }
    }

    println!("\nRedacted Emails: {:?}", redacted_emails);
}

#[test]
fn test_redact_url() {
    let mut redactor = Redactor::new(
        false,
        "dummy_secrets.csv",
        "dummy_ignores.csv",
        "dummy_mapping.txt",
    );
    let log_lines = get_log_lines();
    let redacted_lines = redactor.redact(log_lines);

    println!("\nURL Redaction Results:");
    println!("======================");

    let urls = vec![
        "https://www.example.com",
        "http://example.org",
        "https://example.net/path/to/resource?query=1&value=2",
        "http://localhost:8080/test",
        "https://subdomain.example.com/path",
    ];

    let mut redacted_urls = Vec::new();

    for line in redacted_lines {
        for url in &urls {
            if line.contains(url) {
                print_redaction_result("URL", url, &line);
            }
            assert!(!line.contains(url));
        }

        for word in line.split_whitespace() {
            if word.starts_with("https://www.example") {
                redacted_urls.push(word.to_string());
            }
        }
    }

    println!("\nRedacted URLs: {:?}", redacted_urls);
}

#[test]
fn test_redact_api_key() {
    let mut redactor = Redactor::new(
        false,
        "dummy_secrets.csv",
        "dummy_ignores.csv",
        "dummy_mapping.txt",
    );
    let log_lines = get_log_lines();
    let redacted_lines = redactor.redact(log_lines);

    println!("\nAPI Key Redaction Results:");
    println!("==========================");

    let api_keys = vec![
        "apikey=1234567890abcdef",
        "token=abcdef1234567890",
        "key=abcdef1234567890",
        "apitoken=abcdef1234567890",
    ];

    let mut redacted_api_keys = Vec::new();

    for line in redacted_lines {
        for api_key in &api_keys {
            if line.contains(api_key) {
                print_redaction_result("API Key", api_key, &line);
            }
            assert!(!line.contains(api_key));
        }

        for word in line.split_whitespace() {
            if word.contains("_redacted_") {
                redacted_api_keys.push(word.to_string());
            }
        }
    }

    println!("\nRedacted API Keys: {:?}", redacted_api_keys);
}

#[test]
fn test_redact_zip() {
    let mut redactor = Redactor::new(
        false,
        "dummy_secrets.csv",
        "dummy_ignores.csv",
        "dummy_mapping.txt",
    );
    redactor.redact_zip("samples/sample.zip");

    // Add assertions to verify the redacted content in the ZIP file
    // For example, you can extract the redacted ZIP and check the contents
}
