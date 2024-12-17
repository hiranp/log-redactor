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
    let mut redactor = Redactor::new(false);
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

#[test]
fn test_redact_ipv4() {
    let mut redactor = Redactor::new(false);
    let redacted_lines = redactor.redact(get_log_lines());

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
        println!("Line: {}", line);
        for ip in &ipv4_addresses {
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

    println!("Redacted IPs: {:?}", redacted_ips);
}

#[test]
fn test_redact_ipv6() {
    let mut redactor = Redactor::new(false);
    let redacted_lines = redactor.redact(get_log_lines());

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
        println!("Line: {}", line);
        for ip in &ipv6_addresses {
            assert!(!line.contains(ip));
        }
    }
}

#[test]
fn test_redact_hostname() {
    let mut redactor = Redactor::new(false);
    let redacted_lines = redactor.redact(get_log_lines());

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
        println!("Line: {}", line);
        for hostname in &hostnames {
            assert!(!line.contains(hostname));
        }

        for word in line.split_whitespace() {
            if word.starts_with("redacted_host") {
                redacted_hostnames.push(word.to_string());
            }
        }
    }

    println!("Redacted Hostnames: {:?}", redacted_hostnames);
}

#[test]
fn test_redact_phone() {
    let mut redactor = Redactor::new(false);
    let redacted_lines = redactor.redact(get_log_lines());

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
        println!("Line: {}", line);
        for phone in &phone_numbers {
            assert!(!line.contains(phone));
        }

        for word in line.split_whitespace() {
            if word.starts_with("800") {
                redacted_phones.push(word.to_string());
            }
        }
    }

    println!("Redacted Phones: {:?}", redacted_phones);
}

#[test]
fn test_redact_email() {
    let mut redactor = Redactor::new(false);
    let redacted_lines = redactor.redact(get_log_lines());

    let emails = vec![
        "john.doe@example.com",
        "jane.doe@example.com",
        "admin@example.com",
        "user@example.com",
        "contact@example.com",
    ];

    let mut redacted_emails = Vec::new();

    for line in redacted_lines {
        println!("Line: {}", line);
        for email in &emails {
            assert!(!line.contains(email));
        }

        for word in line.split_whitespace() {
            if word.contains("@example.com") {
                redacted_emails.push(word.to_string());
            }
        }
    }

    println!("Redacted Emails: {:?}", redacted_emails);
}

#[test]
fn test_redact_url() {
    let mut redactor = Redactor::new(false);
    let redacted_lines = redactor.redact(get_log_lines());

    let urls = vec![
        "https://www.example.com",
        "http://example.org",
        "https://example.net/path/to/resource?query=1&value=2",
        "http://localhost:8080/test",
        "https://subdomain.example.com/path",
    ];

    let mut redacted_urls = Vec::new();

    for line in redacted_lines {
        println!("Line: {}", line);
        for url in &urls {
            assert!(!line.contains(url));
        }

        for word in line.split_whitespace() {
            if word.starts_with("https://www.example") {
                redacted_urls.push(word.to_string());
            }
        }
    }

    println!("Redacted URLs: {:?}", redacted_urls);
}

#[test]
fn test_redact_api_key() {
    let mut redactor = Redactor::new(false);
    let redacted_lines = redactor.redact(get_log_lines());

    let api_keys = vec![
        "apikey=1234567890abcdef",
        "token=abcdef1234567890",
        "key=abcdef1234567890",
        "apitoken=abcdef1234567890",
    ];

    let mut redacted_api_keys = Vec::new();

    for line in redacted_lines {
        println!("Line: {}", line);
        for api_key in &api_keys {
            assert!(!line.contains(api_key));
        }

        for word in line.split_whitespace() {
            if word.contains("_redacted_") {
                redacted_api_keys.push(word.to_string());
            }
        }
    }

    println!("Redacted API Keys: {:?}", redacted_api_keys);
}

#[test]
fn test_redact_zip() {
    let mut redactor = Redactor::new(false);
    redactor.redact_zip("samples/sample.zip");

    // Add assertions to verify the redacted content in the ZIP file
    // For example, you can extract the redacted ZIP and check the contents
}
