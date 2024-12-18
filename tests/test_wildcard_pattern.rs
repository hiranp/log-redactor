use log_redactor::Redactor;

use std::fs::File;
use std::io::Write;
use tempfile::tempdir;

#[test]
fn test_wildcard_patterns() {
    let temp_dir = tempdir().unwrap();

    // Create temporary secrets file with wildcard patterns
    let secrets_path = temp_dir.path().join("secrets.json");
    let secrets_content = r#"{
        "hostname": ["test*.example.com", "*-internal.local"],
        "email": ["admin*@company.com", "*@internal.domain"],
        "url": ["https://*.secret.com/*", "*.internal-api.*"]
    }"#;
    File::create(&secrets_path)
        .unwrap()
        .write_all(secrets_content.as_bytes())
        .unwrap();

    // Create temporary ignores file with wildcard patterns
    let ignores_path = temp_dir.path().join("ignores.json");
    let ignores_content = r#"{
        "hostname": ["public*.example.com"],
        "email": ["noreply@*"],
        "url": ["https://public.*"]
    }"#;
    File::create(&ignores_path)
        .unwrap()
        .write_all(ignores_content.as_bytes())
        .unwrap();

    let mapping_path = temp_dir.path().join("mapping.csv");
    let mut redactor = Redactor::new(
        false,
        secrets_path.to_str().unwrap(),
        ignores_path.to_str().unwrap(),
        mapping_path.to_str().unwrap(),
    );

    // Test cases for hostnames
    let test_cases = vec![
        // Format: (input, should_be_redacted)
        ("test1.example.com", true),    // Matches test*.example.com
        ("test-srv.example.com", true), // Matches test*.example.com
        ("public1.example.com", false), // Matches ignore pattern
        ("app-internal.local", true),   // Matches *-internal.local
        ("random.domain", false),       // No match
    ];

    for (input, should_be_redacted) in test_cases {
        let result = redactor.redact(vec![input.to_string()]);
        let was_redacted = result[0] != input;
        assert_eq!(
            was_redacted, should_be_redacted,
            "Failed for hostname '{}': expected redacted={}, got redacted={}",
            input, should_be_redacted, was_redacted
        );
    }

    // Test cases for emails
    let email_cases = vec![
        ("admin@company.com", true),    // Matches admin*@company.com
        ("admin123@company.com", true), // Matches admin*@company.com
        ("user@internal.domain", true), // Matches *@internal.domain
        ("noreply@company.com", false), // Matches ignore pattern
        ("random@email.com", false),    // No match
    ];

    for (input, should_be_redacted) in email_cases {
        let result = redactor.redact(vec![input.to_string()]);
        let was_redacted = result[0] != input;
        assert_eq!(
            was_redacted, should_be_redacted,
            "Failed for email '{}': expected redacted={}, got redacted={}",
            input, should_be_redacted, was_redacted
        );
    }

    // Test cases for URLs
    let url_cases = vec![
        ("https://api.secret.com/v1", true), // Matches https://*.secret.com/*
        ("https://test.internal-api.com", true), // Matches *.internal-api.*
        ("https://public.domain.com", false), // Matches ignore pattern
        ("https://random.com", false),       // No match
    ];

    for (input, should_be_redacted) in url_cases {
        let result = redactor.redact(vec![input.to_string()]);
        let was_redacted = result[0] != input;
        assert_eq!(
            was_redacted, should_be_redacted,
            "Failed for URL '{}': expected redacted={}, got redacted={}",
            input, should_be_redacted, was_redacted
        );
    }
}

#[test]
fn test_complex_wildcard_patterns() {
    let temp_dir = tempdir().unwrap();

    // Test more complex wildcard patterns
    let secrets_path = temp_dir.path().join("secrets.json");
    let secrets_content = r#"{
        "hostname": ["*.prod.*", "srv-*-[0-9]*"],
        "email": ["team-*@*.com", "*-admin@*"],
        "api": ["api_key=prod-*", "secret_*=*"]
    }"#;
    File::create(&secrets_path)
        .unwrap()
        .write_all(secrets_content.as_bytes())
        .unwrap();

    let ignores_path = temp_dir.path().join("ignores.json");
    let mapping_path = temp_dir.path().join("mapping.csv");

    let mut redactor = Redactor::new(
        false,
        secrets_path.to_str().unwrap(),
        ignores_path.to_str().unwrap(),
        mapping_path.to_str().unwrap(),
    );

    // Test complex hostname patterns
    let complex_cases = vec![
        ("app.prod.company.com", true),      // Matches *.prod.*
        ("srv-web-001", true),               // Matches srv-*-[0-9]*
        ("srv-db-002.local", true),          // Matches srv-*-[0-9]*
        ("test.staging.company.com", false), // No match
    ];

    for (input, should_be_redacted) in complex_cases {
        let result = redactor.redact(vec![input.to_string()]);
        let was_redacted = result[0] != input;
        assert_eq!(
            was_redacted, should_be_redacted,
            "Failed for complex pattern '{}': expected redacted={}, got redacted={}",
            input, should_be_redacted, was_redacted
        );
    }

    // Test email patterns with multiple wildcards
    let complex_email_cases = vec![
        ("team-dev@company.com", true),      // Matches team-*@*.com
        ("security-admin@domain.org", true), // Matches *-admin@*
        ("regular.user@company.com", false), // No match
    ];

    for (input, should_be_redacted) in complex_email_cases {
        let result = redactor.redact(vec![input.to_string()]);
        let was_redacted = result[0] != input;
        assert_eq!(
            was_redacted, should_be_redacted,
            "Failed for complex email '{}': expected redacted={}, got redacted={}",
            input, should_be_redacted, was_redacted
        );
    }

    // Test API key patterns
    let api_cases = vec![
        ("api_key=prod-123456", true), // Matches api_key=prod-*
        ("secret_token=abc123", true), // Matches secret_*=*
        ("api_key=dev-123456", false), // No match
    ];

    for (input, should_be_redacted) in api_cases {
        let result = redactor.redact(vec![input.to_string()]);
        let was_redacted = result[0] != input;
        assert_eq!(
            was_redacted, should_be_redacted,
            "Failed for API key '{}': expected redacted={}, got redacted={}",
            input, should_be_redacted, was_redacted
        );
    }
}
