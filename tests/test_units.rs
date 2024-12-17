use log_redactor::{
    validate_api, validate_email, validate_hostname, validate_ipv4, validate_ipv6, validate_phone,
    validate_url, Redactor,
};

#[cfg(test)]
mod tests {
    use super::*;

    // Common helper function for printing test results
    fn print_test_result(
        test_name: &str,
        input: &str,
        is_valid: bool,
        expected: bool,
        redacted: Option<String>,
    ) {
        println!("----------------------------------------");
        println!("Test: {} ", test_name);
        println!("Input: {}", input);
        println!("Result: {} (Expected: {})", is_valid, expected);
        if let Some(red) = redacted {
            println!("Redacted: {}", red);
        }
        println!("----------------------------------------");
    }

    // Common function to run validation tests
    fn run_validation_test(
        test_name: &str,
        test_cases: Vec<(&str, bool)>,
        validator: fn(&str) -> bool,
        should_redact: bool,
    ) {
        println!("\nRunning {} Validation Tests:", test_name);
        println!("{}=", "=".repeat(test_name.len() + 21));

        let mut redactor = if should_redact {
            Some(Redactor::new(false, "secrets.csv", "ignore.csv"))
        } else {
            None
        };

        for (input, expected) in test_cases {
            let is_valid = validator(input);
            let redacted = if is_valid && should_redact {
                let redacted_lines = redactor.as_mut().unwrap().redact(vec![input.to_string()]);
                Some(redacted_lines[0].to_string())
            } else {
                None
            };
            print_test_result(test_name, input, is_valid, expected, redacted);
            assert_eq!(is_valid, expected, "Failed for {}: {}", test_name, input);
        }
    }

    #[test]
    fn test_validate_phone() {
        let test_cases = vec![
            ("123-456-7890", true),
            ("(123) 456-7890", true),
            ("123.456.7890", true),
            ("123 456 7890", true),
            ("123-456-789", false),
            ("123-456-78901", false),
        ];
        run_validation_test("Phone", test_cases, validate_phone, true);
    }

    #[test]
    fn test_validate_email() {
        let test_cases = vec![
            ("user@example.com", true),
            ("user.name@example.co.uk", true),
            ("george.washington@whitehouse.gov", true),
            ("eisenhower@army.us.mil", true),
            ("maverick@topgun.us.af.mil", true),
            ("user.name+tag+sorting@example.com", true),
            ("Simon Johnston <johnstonsk@gmail.com>", false),
            ("McLovin <mclovin@hawaii.gov>", false),
            ("invalid.email@", false),
            ("@invalid.com", false),
        ];
        run_validation_test("Email", test_cases, validate_email, true);
    }

    #[test]
    fn test_validate_api() {
        let test_cases = vec![
            ("apikey=abc123def456", true),
            ("token=xyz789", true),
            ("key=f32342351235wqer32145340", true),
            ("invalid-key", false),
            ("apikey=", false),
        ];
        run_validation_test("API Key", test_cases, validate_api, true);
    }

    #[test]
    fn test_api_key_redaction() {
        let mut redactor = Redactor::new(false, "secrets.csv", "ignore.csv");
        let test_cases = vec![
            ("key=f32342351235wqer32145340", "key=redacted_0"),
            ("token=abcdef1234567890", "token=redacted_0"),
            ("apikey=secretvalue123", "apikey=redacted_0"),
        ];

        for (input, expected) in test_cases {
            let result = redactor.redact(vec![input.to_string()]);
            assert_eq!(result[0], expected, "Failed on input: {}", input);
        }
    }

    #[test]
    fn test_validate_ipv4() {
        let test_cases = vec![
            ("10.1.0.110", true),
            ("192.168.1.1", true),
            ("172.16.254.1", true),
            ("256.1.2.3", false),
            ("1.2.3.4.5", false),
            ("192.168.001.1", true),
            ("0.0.0.0", true),
            ("00.00.00.00", false),
        ];
        run_validation_test("IPv4", test_cases, validate_ipv4, true);
    }

    #[test]
    fn test_validate_hostname() {
        let test_cases = vec![
            ("www.example.com", true),
            ("subdomain.example.com", true),
            ("example.com", true),
            ("server1.us.mil", true),
            ("invalid_hostname", false),
            ("www.example.com/path", false),
            ("www.example.com:8080", false),
        ];
        run_validation_test("Hostname", test_cases, validate_hostname, true);
    }

    #[test]
    fn test_validate_url() {
        let test_cases = vec![
            ("http://www.example.com", true),
            ("https://www.example.com", true),
            ("ftp://ftp.example.com", true),
            ("www.example.com", false),
            ("https://www.whitehouse.gov/path", true),
            ("http://www.example.com/path", true),
            ("http://www.example.com:8080", true),
            ("http://www.example.com:8080/path", true),
            ("http://www.example.com:8080/path?query=1", true),
            ("http://www.example.com:8080/path?query=1#fragment", true),
        ];
        run_validation_test("URL", test_cases, validate_url, true);
    }

    #[test]
    fn test_validate_ipv6() {
        let test_cases = vec![
            ("2001:0db8:85a3:0000:0000:8a2e:0370:7334", true),
            ("2001:db8:85a3:0:0:8a2e:370:7334", true),
            ("2001:db8:85a3::8a2e:370:7334", true),
            ("2001:db8:85a3::8a2e:370:7334:1", true), // This is actually valid
            ("2001:db8:85a3::8a2e:370:7334::", false),
            ("::1", true),     // Loopback address is valid
            ("fe80::1", true), // Link-local address is valid
            ("2001:db8::1:0:0:1", true),
            ("2001:db8::1::1", false), // Multiple :: is invalid
            ("2001:db8:85a3:0:0:8a2e:370g:7334", false), // Invalid hex digit
            ("not:a:valid:ipv6:address", false),
        ];
        run_validation_test("IPv6", test_cases, validate_ipv6, true);
    }

    #[test]
    fn test_sample_log_redaction() {
        use std::fs::File;
        use std::io::{BufRead, BufReader};
        // Delete the sample_redacted.log file if it exists
        std::fs::remove_file("samples/sample_redacted.log").ok();

        // Initialize the redactor with paths to secrets and ignores
        let mut redactor = Redactor::new(false, "samples/secret.csv", "samples/ignore.csv");

        // Open the sample.log file
        let file = File::open("samples/sample.log").expect("Failed to open sample.log");
        let reader = BufReader::new(file);

        // Read lines from the log file
        let lines: Vec<String> = reader
            .lines()
            .map(|line| line.expect("Failed to read line"))
            .collect();

        // Redact the lines
        let redacted_lines = redactor.redact(lines);

        // Assert that known secrets are redacted (replace with actual secret values)
        for line in &redacted_lines {
            assert!(
                !line.contains("your_secret_value"),
                "Secret value was not redacted"
            );
            // Add more assertions as needed
        }

        // Optionally, write redacted output to a file for manual inspection
        std::fs::write("samples/sample_redacted.log", redacted_lines.join("\n"))
            .expect("Failed to write redacted log");
    }

    #[test]
    fn test_process_tar_file() {
        // Test processing of tar files
    }

    #[test]
    fn test_process_tar_gz_file() {
        // Test processing of tar.gz files
    }
}
