use log_redactor::{validate_email, Redactor};

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
    fn test_email_validation() {
        let test_cases = vec![
            ("user@example.com", true),
            ("first.last@company.com", true),
            ("user+tag@domain.com", true),
            ("invalid@email", false),
            ("@nodomain.com", false),
            ("noat.domain.com", false),
            ("spaces in@email.com", false),
            ("", false),
        ];
        run_validation_test("Email", test_cases, validate_email);
    }

    #[test]
    fn test_email_redaction() {
        let mut redactor = Redactor::new(
            false,
            "samples/secrets.json",
            "samples/ignore.json",
            "samples/redacted-mapping.txt",
        );

        let test_cases = vec![
            ("user@example.com", "redacted0@example.com"),
            ("admin@company.net", "redacted1@example.com"),
            ("support@service.org", "redacted2@example.com"),
            ("noreply@system.com", "redacted3@example.com"),
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
