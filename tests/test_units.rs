use log_redactor::{
    validate_api, validate_email, validate_hostname, validate_ipv4, validate_phone, Redactor,
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
            Some(Redactor::new(false))
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
        let mut redactor = Redactor::new(false);
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
}
