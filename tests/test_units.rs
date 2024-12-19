use log_redactor::{
    validate_api, validate_email, validate_hostname, validate_ipv4, validate_ipv6, validate_phone,
    validate_url, Redactor,
};

/// NOTE: The tests in this file are meant to be run with `cargo test -- --nocapture`
/// This will allow the tests to print output to the console.

// Validation Tests
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

    // Helper function for redaction tests with printing
    fn run_redaction_test(test_name: &str, test_cases: Vec<(&str, &str)>, redactor: &mut Redactor) {
        println!("\nRunning {} Redaction Tests", test_name);
        println!("{}=", "=".repeat(test_name.len() + 20));

        for (input, expected) in test_cases {
            let redacted_lines = redactor.redact(vec![input.to_string()]);
            let redacted = &redacted_lines[0];

            // Print input and redacted output for comparison
            println!("Input    : {}", input);
            println!("Redacted : {}\n", redacted);

            // Assertion
            assert_eq!(
                redacted, expected,
                "Redaction failed for input '{}'. Expected '{}', got '{}'",
                input, expected, redacted
            );
        }
    }

    // Validation Tests
    #[test]
    fn test_phone_number_generation() {
        let mut redactor = Redactor::new(false, "dummy.json", "dummy.json", "dummy.txt");
        let phone1 = redactor.generate_phone_number();
        let phone2 = redactor.generate_phone_number();

        assert!(validate_phone(&phone1));
        assert!(validate_phone(&phone2));
        assert_ne!(phone1, phone2);
    }

    #[test]
    fn test_phone_validation() {
        assert!(validate_phone("(800) 555-0123"));
        assert!(validate_phone("800-555-0123"));
        assert!(validate_phone("800.555.0123"));
        assert!(validate_phone("800 555 0123"));

        assert!(!validate_phone("123456789")); // too short
        assert!(!validate_phone("abcd-efg-hijk")); // invalid chars
        assert!(!validate_phone("")); // empty
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
            ("Richard Nixon <r.nixon@whitehouse.gov>", true),
            ("McLovin <mclovin@hawaii.gov>", true),
            ("invalid.email@", false),
            ("@invalid.com", false),
        ];
        run_validation_test("Email", test_cases, validate_email);
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
        run_validation_test("IPv4", test_cases, validate_ipv4);
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
        run_validation_test("Hostname", test_cases, validate_hostname);
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
        run_validation_test("URL", test_cases, validate_url);
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
        run_validation_test("IPv6", test_cases, validate_ipv6);
    }

    #[test]
    fn test_validate_api_key() {
        let test_cases = vec![
            ("token=abcdef1234567890", true),
            ("apikey=secretvalue123", true),
            ("key=f3234235.1235wqer32145340", true),
            ("invalid-key", false),
            ("apikey=", false),
        ];
        run_validation_test("API Key", test_cases, validate_api);
    }

    // Redaction Tests ========================================
    #[test]
    fn test_api_key_redaction() {
        let mut redactor = Redactor::new(
            false,
            "samples/secrets.json",
            "samples/ignore.json",
            "samples/redacted-mapping.txt",
        );
        let test_cases = vec![
            ("token=abcdef1234567890", "token=redacted_000"),
            ("apikey=secretvalue123", "apikey=redacted_000"),
            ("key=f3234235.1235wqer32145340", "key=redacted_000"),
            ("invalid-key", "invalid-key"),
            ("apikey=", "apikey="),
        ];
        run_redaction_test("API Key", test_cases, &mut redactor);
    }

    #[test]
    fn test_sample_log_redaction() {
        use std::env;
        use std::fs;
        use tempfile::tempdir;

        // Create temporary directory
        let temp_dir = tempdir().expect("Failed to create temp directory");
        let temp_path = temp_dir.path();

        // Create sample files in temp directory
        let sample_log = temp_path.join("sample.log");
        let sample_content = r#"# Sample Log File
    
# IPv4 Examples
192.168.1.1
10.0.0.255

# Email Examples
user@example.com
admin@company.com

# Phone Numbers
(123) 456-7890
800-555-0123

# Mixed Examples - Complex Log Entries
[2023-12-17T10:15:23Z] INFO user@company.com accessed https://api.example.com/v1/users from 192.168.1.100
[2023-12-17T10:15:24Z] WARN Failed login attempt from 2001:0db8:85a3:0000:0000:8a2e:0370:7334
[2023-12-17T10:15:25Z] ERROR API key violation - key=ab12cd34ef56gh78 host=backend-prod-01.example.com
[2023-12-17T10:15:26Z] DEBUG Call from (555) 123-4567 to support system uuid=123e4567-e89b-12d3-a456-426614174000

# Customer Service Logs
timestamp=1703062427 level=INFO agent="Sarah Smith" phone="(800) 555-0123" case_id=CS123456
timestamp=1703062428 level=INFO agent="John Doe" email=john.doe@support.example.com ticket=HD987654
timestamp=1703062429 level=WARN ip_address=10.20.30.40 failed_auth=true user_agent="Mozilla/5.0"

# System Monitoring
[2023-12-17 10:20:00] host=db-primary-01.internal status=UP ip=172.16.0.100 load=0.75
[2023-12-17 10:20:01] host=cache-redis-02.internal status=WARN ip=172.16.0.101 memory=85%
[2023-12-17 10:20:02] host=app-server-03.internal status=DOWN ip=172.16.0.102 error="Connection refused"

# API Gateway Logs
method=POST path=/api/v1/users ip=203.0.113.100 api_key=pk_live_abcdef123456 response_time=235ms
method=GET path=/api/v1/orders ip=2001:db8::1234 token=sk_test_98765432xyz response_time=189ms
method=PUT path=/api/v1/products ip=198.51.100.50 auth=Bearer_Token_xyz789 response_time=150ms

# Social Media Integration
platform=twitter handle=@techcompany followers=50000 last_post="2023-12-17T10:25:00Z"
platform=linkedin profile="https://linkedin.com/company/tech-example" employees=1000
platform=facebook page="fb.com/techexample" likes=25000 admin_email=social@example.com

# Security Events
event=login src_ip=10.0.0.100 user=admin@internal.com status=success mfa=true timestamp=1703062430
event=firewall_block src_ip=192.0.2.100 dst_ip=10.0.0.50 port=443 reason="Invalid certificate"
event=ssh_attempt user=root src_ip=2001:db8:1234:5678::1 status=blocked timestamp=1703062431

"#;
        fs::write(&sample_log, sample_content).expect("Failed to write sample log");

        // Create secrets.json
        let secrets_file = temp_path.join("secrets.json");
        fs::write(&secrets_file, "ipv4,192.168.1.1\nemail,user@example.com")
            .expect("Failed to write secrets");

        // Create ignore.json
        let ignore_file = temp_path.join("ignore.json");
        fs::write(&ignore_file, "phone,800-555-0123").expect("Failed to write ignores");

        // Create mapping file path
        let mapping_file = temp_path.join("redacted-mapping.txt");

        // Get current working directory for redacted file location
        let current_dir = env::current_dir().expect("Failed to get current directory");
        let expected_redacted_path = current_dir.join("sample-redacted.log");

        // Initialize redactor with temp files
        let mut redactor = Redactor::new(
            false,
            secrets_file.to_str().unwrap(),
            ignore_file.to_str().unwrap(),
            mapping_file.to_str().unwrap(),
        );

        // Redact the sample log
        redactor.redact_file(sample_log.to_str().unwrap());

        // Verify redacted file exists and contains expected content
        // show the path
        println!("Redacted Path: {:?}", expected_redacted_path);
        // Verify redacted file exists in current directory
        assert!(
            expected_redacted_path.exists(),
            "Redacted file should exist at {:?}",
            expected_redacted_path
        );

        // Read and verify redacted content
        let redacted_content =
            fs::read_to_string(expected_redacted_path).expect("Failed to read redacted file");

        assert!(
            redacted_content.contains("240.0.0."),
            "Should contain redacted IPv4"
        );
        assert!(
            !redacted_content.contains("192.168.1.1"),
            "Should not contain original IPv4"
        );
        assert!(
            redacted_content.contains("redacted"),
            "Should contain redaction markers"
        );
        assert!(
            redacted_content.contains("800-555-0123"),
            "Should preserve ignored phone number"
        );

        // Temp directory and contents are automatically cleaned up when temp_dir is dropped
    }

    #[test]
    fn test_sample_static_log_redaction() {
        use std::fs::File;
        use std::io::{BufRead, BufReader};

        // Delete the sample_redacted.log file if it exists
        std::fs::remove_file("samples/sample_redacted.log").ok();

        // Initialize the redactor with paths to secrets and ignores
        let mut redactor = Redactor::new(
            false,
            "samples/secret.json",
            "samples/ignore.json",
            "samples/redacted-mapping.txt",
        );

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
    fn test_simple_sample_log_redaction() {
        use std::env;
        use std::fs;
        use tempfile::tempdir;

        // Create temporary directory
        let temp_dir = tempdir().expect("Failed to create temp directory");
        let temp_path = temp_dir.path();

        // Create all files in temp directory
        let sample_log = temp_path.join("sample.log");
        let secrets_file = temp_path.join("secrets.json");
        let ignore_file = temp_path.join("ignore.json");
        let mapping_file = temp_path.join("redacted-mapping.txt");

        // Get current working directory for redacted file location
        let current_dir = env::current_dir().expect("Failed to get current directory");
        let expected_redacted_path = current_dir.join("sample-redacted.log");

        // Write sample log content
        let sample_content = r#"# Sample Log File
        
    # IPv4 Examples
    192.168.1.1
    10.0.0.255
    
    # Email Examples
    user@example.com
    admin@company.com
    
    # Phone Numbers
    (123) 456-7890
    800-555-0123"#;
        fs::write(&sample_log, sample_content).expect("Failed to write sample log");

        // Write secrets and ignores
        fs::write(&secrets_file, "ipv4,192.168.1.1\nemail,user@example.com")
            .expect("Failed to write secrets");
        fs::write(&ignore_file, "phone,800-555-0123").expect("Failed to write ignores");

        // Initialize redactor with temp files
        let mut redactor = Redactor::new(
            false,
            secrets_file.to_str().unwrap(),
            ignore_file.to_str().unwrap(),
            mapping_file.to_str().unwrap(),
        );

        // Redact the sample log
        redactor.redact_file(sample_log.to_str().unwrap());

        // Verify redacted file exists and read content
        assert!(
            expected_redacted_path.exists(),
            "Redacted file should exist at {:?}",
            expected_redacted_path
        );

        let redacted_content =
            fs::read_to_string(&expected_redacted_path).expect("Failed to read redacted file");

        // Verify redaction results
        assert!(
            !redacted_content.contains("192.168.1.1"),
            "Should not contain original IPv4"
        );
        assert!(
            !redacted_content.contains("user@example.com"),
            "Should not contain original email"
        );
        assert!(
            redacted_content.contains("800-555-0123"),
            "Should preserve ignored phone number"
        );
        assert!(
            redacted_content.contains("redacted"),
            "Should contain redaction markers"
        );

        // Temp directory and contents are automatically cleaned up when temp_dir is dropped
    }

    #[test]
    fn test_process_tar_file() {
        use std::fs::File;
        use std::io::{BufRead, BufReader};
        use tempfile::tempdir;

        // Create a temporary directory
        let temp_dir = tempdir().expect("Failed to create temp dir");
        let temp_dir_path = temp_dir.path().to_str().unwrap();

        // Initialize the redactor with paths to secrets and ignores
        let mut redactor = Redactor::new(
            false,
            "samples/secrets.json",
            "samples/ignore.json",
            &format!("{}/redacted-mapping.txt", temp_dir_path),
        );

        // Copy the sample.tar file to the temporary directory
        let sample_tar_path = format!("{}/sample.tar", temp_dir_path);
        std::fs::copy("samples/sample.tar", &sample_tar_path).expect("Failed to copy sample.tar");

        // Call redact_tar to process the tar file
        redactor
            .redact_tar(&sample_tar_path)
            .expect("Failed to redact tar file");

        // Verify that the redacted files are created in the temporary directory
        let redacted_dir_path = format!("{}-redacted", sample_tar_path.trim_end_matches(".tar"));
        assert!(
            std::path::Path::new(&redacted_dir_path).exists(),
            "Redacted directory not found"
        );

        // Read and verify the redacted files
        for entry in
            std::fs::read_dir(&redacted_dir_path).expect("Failed to read redacted directory")
        {
            let entry = entry.expect("Failed to read entry");
            let path = entry.path();
            if path.is_file() {
                let file = File::open(&path).expect("Failed to open redacted file");
                let reader = BufReader::new(file);
                for line in reader.lines() {
                    let line = line.expect("Failed to read line");
                    // Add assertions to verify redaction
                    assert!(line.contains("redacted"), "Line not redacted: {}", line);
                }
            }
        }
    }

    #[test]
    fn test_process_tar_gz_file() {
        // Test processing of tar.gz files
    }
}
