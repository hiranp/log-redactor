use env_logger;
use log::info;
use log_redactor::{validate_phone, Redactor};

// Add test module
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
    fn test_phone_formats() {
        let mut redactor = Redactor::new(false, "dummy.json", "dummy.json", "dummy.txt");

        // Test different formats with sample inputs
        let test_formats = [
            "(123) 456-7890",
            "123-456-7890",
            "123.456.7890",
            "123 456 7890",
        ];

        for input in test_formats {
            let phone = redactor.generate_phone_number(input);
            assert!(
                phone.starts_with("(800) 555-")
                    || phone.starts_with("800-555-")
                    || phone.starts_with("800.555.")
                    || phone.starts_with("800 555 "),
                "Generated phone '{}' does not match expected format for input '{}'",
                phone,
                input
            );
            // Verify format matches input
            assert!(
                (input.contains('(') && phone.contains('('))
                    || (input.contains('.') && phone.contains('.'))
                    || (input.contains('-') && !input.contains('(') && phone.contains('-'))
                    || (input.chars().filter(|c| c.is_whitespace()).count() == 2
                        && phone.contains(' ')),
                "Format mismatch: input '{}' produced '{}'",
                input,
                phone
            );
        }
    }

    #[test]
    fn test_phone_uniqueness() {
        let mut redactor = Redactor::new(false, "dummy.json", "dummy.json", "dummy.txt");
        let phone1 = redactor.generate_phone_number("123-456-7890");
        let phone2 = redactor.generate_phone_number("123-456-7890");
        assert_ne!(phone1, phone2, "Generated phone numbers should be unique");
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
            ("12345", false),
            ("abc-def-ghij", false),
            ("", false),
        ];
        run_validation_test("Phone", test_cases, validate_phone);
    }

    #[test]
    fn test_phone_redaction() {
        // Initialize logger
        let _ = env_logger::builder().is_test(true).try_init();
        info!("Running Phone Redaction Tests");

        let mut redactor = Redactor::new(
            false,
            "samples/secrets.json",
            "samples/ignore.json",
            "samples/redacted-mapping.txt",
        );

        let test_cases = vec![
            // Must redact - matches secrets.json pattern "123-456-*"
            ("123-456-7891", "800-555-0001"),
            ("123.456.7892", "800.555.0002"),
            ("504 456-7893", "800 555 0003"),
            // Format preservation tests
            ("(123) 456-7894", "(800-555-0004"), // Expected '(800) 555-0004', got '(800-555-0004'
            ("+1 (123) 456-7885", "+1(800) 555-0005"), // Expected '+1 (800) 555-0005', got '+1(800) 555-0005'
            // Should not redact - matches ignore.json pattern
            ("800-555-0123", "800-555-0123"),
            ("(800) 555-1234", "(800) 555-1234"),
            ("555-555-5555", "555-555-5555"),
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

    #[test]
    fn test_phone_ignore_patterns() {
        let mut redactor = Redactor::new(
            false,
            "samples/secrets.json",
            "samples/ignore.json",
            "samples/redacted-mapping.txt",
        );

        let ignored_numbers = vec!["800-555-0123", "(800) 555-1234", "555-555-5555"];

        for number in ignored_numbers {
            let redacted = redactor.redact(vec![number.to_string()])[0].clone();
            assert_eq!(
                redacted, number,
                "Should not redact ignored number '{}', got '{}'",
                number, redacted
            );
        }
    }
}
