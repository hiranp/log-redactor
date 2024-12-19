use log_redactor::{validate_api, Redactor};

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
    fn test_api_validation() {
        let test_cases = vec![
            ("api_key=abc123xyz", true),
            ("token=secret123", true),
            ("apikey=test-key-789", true),
            ("invalid-key-format", false),
            ("api_key=", false),
            ("token", false),
            ("", false),
        ];
        run_validation_test("API Key", test_cases, validate_api);
    }

    #[test]
    fn test_api_redaction() {
        let mut redactor = Redactor::new(
            false,
            "samples/secrets.json",
            "samples/ignore.json",
            "samples/redacted-mapping.txt",
        );

        let test_cases = vec![
            ("api_key=secret123", "api_key=redacted_000"),
            ("token=live_xyz789", "token=redacted_000"),
            ("apikey=test-456", "apikey=redacted_000"),
            ("key=prod-abc", "key=redacted_001"),
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
