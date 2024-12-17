use log_redactor::{validate_api, validate_email, validate_phone};

// Add unit tests for new validators
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_phone() {
        assert!(validate_phone("123-456-7890"));
        assert!(validate_phone("(123) 456-7890"));
        assert!(validate_phone("123.456.7890"));
        assert!(validate_phone("123 456 7890"));
        assert!(!validate_phone("123-456-789")); // Too short
        assert!(!validate_phone("123-456-78901")); // Too long
    }

    #[test]
    fn test_validate_email() {
        assert!(validate_email("user@example.com"));
        assert!(validate_email("user.name@example.co.uk"));
        assert!(!validate_email("invalid.email@"));
        assert!(!validate_email("@invalid.com"));
    }

    #[test]
    fn test_validate_api() {
        assert!(validate_api("apikey=abc123def456"));
        assert!(validate_api("token=xyz789"));
        assert!(!validate_api("invalid-key"));
        assert!(!validate_api("apikey="));
    }
}
