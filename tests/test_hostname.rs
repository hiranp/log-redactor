use log_redactor::{validate_hostname, Redactor};

#[cfg(test)]
mod tests {
    use super::*;

    // Helper function for validation tests with printing
    fn run_validation_test(
        test_name: &str,
        test_cases: Vec<(&str, bool)>,
        validator: fn(&str) -> bool,
    ) {
        println!("\nRunning {} Validation Tests", test_name);
        println!("{}=", "=".repeat(test_name.len() + 21));

        for (input, expected) in test_cases {
            let is_valid = validator(input);

            // Print input and validation result
            println!("Input    : {}", input);
            println!("Is Valid : {}", is_valid);
            println!("Expected : {}\n", expected);

            // Assertion
            assert_eq!(
                is_valid, expected,
                "Validation failed for input '{}': expected {}, got {}",
                input, expected, is_valid
            );
        }
    }

    #[test]
    fn test_hostname_validation() {
        let test_cases = vec![
            ("server1.example.com", true),
            ("sub.domain.example.com", true),
            ("web-1.company.net", true),
            ("invalid..hostname", false),
            ("no_dots", false),
            ("ends-with-dash-.com", false),
            ("-starts-with-dash.com", false),
            ("", false),
        ];
        run_validation_test("Hostname", test_cases, validate_hostname);
    }

    #[test]
    fn test_hostname_redaction() {
        let mut redactor = Redactor::new(
            false,
            "samples/secrets.json",
            "samples/ignore.json",
            "samples/redacted-mapping.txt",
        );

        let test_cases = vec![
            ("server1.example.com", "redacted-host-000.example.com"),
            ("db1.internal.net", "redacted-host-001.example.com"),
            ("web-01.company.com", "redacted-host-002.example.com"),
            ("cache.service.local", "redacted-host-003.example.com"),
        ];

        for (input, expected) in test_cases {
            let redacted = redactor.redact(vec![input.to_string()])[0].clone();
            assert_eq!(
                redacted, expected,
                "Redaction failed for input '{}'. Expected '{}', got '{}'",
                input, expected, redacted
            );
        }
    }
}
