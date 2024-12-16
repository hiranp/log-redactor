use crate::Redactor;
use std::fs::File;
use std::io::{self, BufRead};
use std::path::Path;

fn read_lines<P>(filename: P) -> io::Result<Vec<String>>
where
    P: AsRef<Path>,
{
    let file = File::open(filename)?;
    let buf = io::BufReader::new(file);
    buf.lines().collect()
}

fn sample_log_file() -> Vec<String> {
    read_lines("samples/sample.log").unwrap()
}

fn test_sample() -> Vec<String> {
    vec![
        // ...existing sample log data...
    ]
}

#[test]
fn test_redact_ipv4() {
    let mut redactor = Redactor::new(false);
    let redacted_lines = redactor.redact(test_sample());

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

    for line in redacted_lines {
        for ip in &ipv4_addresses {
            assert!(!line.contains(ip));
        }
    }
}

#[test]
fn test_redact_ipv6() {
    let mut redactor = Redactor::new(false);
    let redacted_lines = redactor.redact(test_sample());

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
            assert!(!line.contains(ip));
        }
    }
}

#[test]
fn test_redact_hostname() {
    let mut redactor = Redactor::new(false);
    let redacted_lines = redactor.redact(test_sample());

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

    for line in redacted_lines {
        for hostname in &hostnames {
            assert!(!line.contains(hostname));
        }
    }
}

#[test]
fn test_redact_phone() {
    let mut redactor = Redactor::new(false);
    let redacted_lines = redactor.redact(test_sample());

    let phone_numbers = vec![
        "(800) 555-0100",
        "(800) 555-0101",
        "123-456-7890",
        "333.444.5555",
        "999 888 7777",
        "(555) 555-5555",
    ];

    for line in redacted_lines {
        for phone in &phone_numbers {
            assert!(!line.contains(phone));
        }
    }
}

#[test]
fn test_redact_email() {
    let mut redactor = Redactor::new(false);
    let redacted_lines = redactor.redact(test_sample());

    let emails = vec![
        "john.doe@example.com",
        "jane.doe@example.com",
        "admin@example.com",
        "user@example.com",
        "contact@example.com",
    ];

    for line in redacted_lines {
        for email in &emails {
            assert!(!line.contains(email));
        }
    }
}

#[test]
fn test_redact_url() {
    let mut redactor = Redactor::new(false);
    let redacted_lines = redactor.redact(test_sample());

    let urls = vec![
        "https://www.example.com",
        "http://example.org",
        "https://example.net/path/to/resource?query=1&value=2",
        "http://localhost:8080/test",
        "https://subdomain.example.com/path",
    ];

    for line in redacted_lines {
        for url in &urls {
            assert!(!line.contains(url));
        }
    }
}

#[test]
fn test_redact_api_key() {
    let mut redactor = Redactor::new(false);
    let redacted_lines = redactor.redact(test_sample());

    let api_keys = vec![
        "apikey=1234567890abcdef",
        "token=abcdef1234567890",
        "key=abcdef1234567890",
        "apitoken=abcdef1234567890",
    ];

    for line in redacted_lines {
        for api_key in &api_keys {
            assert!(!line.contains(api_key));
        }
    }
}
