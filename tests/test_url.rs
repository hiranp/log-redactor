use log_redactor::{validate_url, Redactor};

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
    fn test_url_validation() {
        let test_cases = vec![
            ("https://example.com", true),
            ("http://sub.domain.com/path", true),
            ("https://api.service.com/v1/users", true),
            ("not-a-url", false),
            ("http:/missing-domain", false),
            ("ftp:/invalid-url", false),
            ("", false),
        ];
        run_validation_test("URL", test_cases, validate_url);
    }

    #[test]
    fn test_url_redaction() {
        let mut redactor = Redactor::new(
            false,
            "samples/secrets.json",
            "samples/ignore.json",
            "samples/redacted-mapping.txt",
        );

        let test_cases = vec![
            (
                "https://api.internal.com",
                "https://redacted-url-000.example.com",
            ),
            (
                "http://admin.service.net",
                "https://redacted-url-001.example.com",
            ),
            (
                "https://secret.company.org",
                "https://redacted-url-002.example.com",
            ),
            (
                "http://public.system.com",
                "https://redacted-url-003.example.com",
            ),
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
