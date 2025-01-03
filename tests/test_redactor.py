import os
import sys
import urllib.parse

import pytest
import rtoml

# Add the parent directory to the sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from log_redactor.redactor import Redactor


@pytest.fixture
def sample_log_file():
    with open("samples/sample.log") as file:
        return file.readlines()

@pytest.fixture
def test_sample():
    return """
    # Sample Log File

    # IPv4 Examples
    192.168.1.1
    10.0.0.255
    172.16.254.1
    192.168.0.1
    10.1.1.1
    192.0.2.0
    203.0.113.0
    255.255.255.255
    127.0.0.1
    8.8.8.8

    # IPv6 Examples
    2001:0db8:85a3:0000:0000:8a2e:0370:7334
    fe80::1ff:fe23:4567:890a
    ::1
    2001:db8::ff00:42:8329
    2001:db8:85a3::8a2e:370:7334
    2001:db8:0:1234:0:567:8:1
    2001:0db8::0000:0000:0000:0000:0000
    ::ffff:192.168.1.1
    2001:db8:0:0:0:0:2:1
    ::a00:1

    # Hostname Examples
    example.com
    subdomain.example.com
    my-hostname.org
    test.example.co.uk
    example123.net
    test-site.com
    sub.domain.example
    hostname-with-dash.com
    example-123.net

    # Phone Examples
    # US phone number can be formatted in a few ways, including: (XXX) XXX-XXXX, XXX-XXX-XXXX, +1 XXX-XXX-XXXX, and +1 202 555 1234.
    (888) 555-9900
    (333) 444-5555
    444-555-6666
    +1 202 555 1234
    +1 800 575 0101
    123-456-7890
    333.444.5555  # Invalid phone number

    # Email Examples
    john.doe@example.com
    jane.doe@example.com
    admin@example.com
    user@example.com
    contact@example.com

    # URL Examples
    https://www.example.com
    http://example.org
    https://example.net/path/to/resource?query=1&value=2
    http://localhost:8080/test
    https://subdomain.example.com/path

    # API Key Examples
    apikey=1234567890abcdef
    token=abcdef1234567890
    key=abcdef1234567890
    apitoken=abcdef1234567890
    """.strip().split('\n')

@pytest.fixture
def sample_secrets_toml():
    return """
[ipv4]
patterns = [
    "192.168.1.*",
    "10.10.*.*"
]

[email]
patterns = [
    "*@internal.company.com",
    "admin*@*"
]
"""

@pytest.fixture
def sample_ignore_toml():
    return """
[ipv4]
patterns = [
    "127.0.0.1",
    "10.0.0.*"
]

[email]
patterns = [
    "public@example.com",
    "*@public.com"
]
"""

@pytest.fixture
def sample_secrets_csv():
    return """ipv4,192.168.1.*
ipv4,10.10.*.*
email,*@internal.company.com
email,admin*@*"""

@pytest.fixture
def sample_ignore_csv():
    return """ipv4,127.0.0.1
ipv4,10.0.0.*
email,public@example.com
email,*@public.com"""

def test_load_toml_config(tmp_path, sample_secrets_toml, sample_ignore_toml):
    # Create temporary TOML files
    secrets_path = tmp_path / "samples" / "secrets.toml"
    ignore_path = tmp_path / "samples" / "ignore.toml"

    os.makedirs(secrets_path.parent, exist_ok=True)
    secrets_path.write_text(sample_secrets_toml)
    ignore_path.write_text(sample_ignore_toml)

    redactor = Redactor()
    assert "ipv4" in redactor.secrets
    assert "email" in redactor.secrets
    assert "192.168.1.*" in redactor.secrets["ipv4"]["patterns"]

def test_load_csv_config(tmp_path, sample_secrets_csv, sample_ignore_csv):
    # Create temporary CSV files
    secrets_path = tmp_path / "samples" / "secrets.csv"
    ignore_path = tmp_path / "samples" / "ignore.csv"

    os.makedirs(secrets_path.parent, exist_ok=True)
    secrets_path.write_text(sample_secrets_csv)
    ignore_path.write_text(sample_ignore_csv)

    redactor = Redactor()
    assert "ipv4" in redactor.secrets
    assert "email" in redactor.secrets
    assert "192.168.1.*" in redactor.secrets["ipv4"]["patterns"]

def test_config_format_precedence(tmp_path, sample_secrets_toml, sample_secrets_csv):
    # Test that TOML takes precedence over CSV when both exist
    secrets_toml_path = tmp_path / "samples" / "secrets.toml"
    secrets_csv_path = tmp_path / "samples" / "secrets.csv"

    os.makedirs(secrets_toml_path.parent, exist_ok=True)
    secrets_toml_path.write_text(sample_secrets_toml)
    secrets_csv_path.write_text(sample_secrets_csv)

    redactor = Redactor()
    # Verify TOML config was loaded instead of CSV
    assert "patterns" in redactor.secrets["ipv4"]
    assert "192.168.1.*" in redactor.secrets["ipv4"]["patterns"]

def test_save_to_file(tmp_path):
    """Test saving patterns to both TOML and CSV formats"""
    # Create a redactor with samples dir in tmp_path
    samples_dir = tmp_path / "samples"
    os.makedirs(samples_dir, exist_ok=True)

    # Pass the config_path to Redactor
    redactor = Redactor(config_path=str(samples_dir))

    # Override the default samples directory for testing
    original_dir = os.getcwd()
    os.chdir(tmp_path)

    try:
        # Test saving to TOML
        redactor._save_to_file("secret", "ipv4", "192.168.1.*", "toml")
        toml_path = samples_dir / "secrets.toml"
        assert toml_path.exists()
        with open(toml_path) as f:
            config = rtoml.load(f)
            assert "ipv4" in config
            assert "192.168.1.*" in config["ipv4"]["patterns"]

        # Test saving to CSV
        redactor._save_to_file("ignore", "ipv4", "127.0.0.1", "csv")
        csv_path = samples_dir / "ignores.csv"
        assert csv_path.exists()
        with open(csv_path) as f:
            content = f.read()
            assert "ipv4,127.0.0.1" in content

    finally:
        # Restore original working directory
        os.chdir(original_dir)

def test_save_mappings(tmp_path):
    """Test saving mappings in both TOML and CSV formats"""
    redactor = Redactor()
    redactor.unique_mapping = {
        "192.168.1.1": "10.0.0.1",
        "test@example.com": "redacted.user001@example.com"
    }

    # Test TOML format
    toml_path = tmp_path / "mappings.toml"
    redactor.save_mappings(str(toml_path), "toml")
    assert toml_path.exists()
    with open(toml_path) as f:
        data = rtoml.load(f)
        assert "mappings" in data
        assert data["mappings"]["192.168.1.1"] == "10.0.0.1"

    # Test CSV format
    csv_path = tmp_path / "mappings.csv"
    redactor.save_mappings(str(csv_path), "csv")
    assert csv_path.exists()
    with open(csv_path) as f:
        lines = f.readlines()
        assert "192.168.1.1,10.0.0.1\n" in lines
        assert "test@example.com,redacted.user001@example.com\n" in lines

def test_wildcard_pattern_matching():
    redactor = Redactor()
    assert redactor._matches_pattern("test@internal.company.com", "*@internal.company.com")
    assert redactor._matches_pattern("192.168.1.100", "192.168.1.*")
    assert redactor._matches_pattern("admin123@example.com", "admin*@*")
    assert not redactor._matches_pattern("test@example.com", "*@internal.company.com")

def test_redaction_precedence():
    redactor = Redactor()
    # Test value in both secrets and ignore
    value = "192.168.1.100"
    assert redactor.should_redact_value(value, "ipv4") == True

    # Test value only in ignore
    value = "127.0.0.1"
    assert redactor.should_redact_value(value, "ipv4") == False

    # Test value only in secrets
    value = "10.10.0.1"
    assert redactor.should_redact_value(value, "ipv4") == True

    # Test value in neither list
    value = "8.8.8.8"
    assert redactor.should_redact_value(value, "ipv4") == False

def test_validation_rules():
    redactor = Redactor()
    # Test invalid IP
    assert redactor.should_redact_value("256.256.256.256", "ipv4") == False

    # Test invalid email
    assert redactor.should_redact_value("not.an.email", "email") == False

    # Test invalid URL
    assert redactor.should_redact_value("not_a_url", "url") == False

@pytest.fixture
def test_simple_values():
    return {
        'hostname': [
            ('example.com', 'redacted_host001'),
            ('test.example.com', 'redacted_host002')  # Updated expectation for second value
        ],
        'email': [
            ('user@example.com', 'redacted.user001@example.com'),
            ('admin@test.com', 'redacted.user002@example.com')  # Updated expectation
        ],
        'url': [
            ('https://api.example.com', 'https://redacted.url001'),
            ('http://test.com/api', 'https://redacted.url002')  # Updated expectation
        ],
        'ipv4': [
            ('10.8.0.1', '240.0.0.0'),
            ('230.0.0.1', '240.0.0.1')  # Updated expectation
        ],
        'ipv6': [
            ('2001:0db8::ff00:42:8329', '3fff::0000'),
            ('fe80::1ff:fe23:4567:890a', '3fff::0001')  # Updated expectation
        ],
        'phone': [
            ('(800) 555-9900', '(800) 555-0000'),
            ('+1 202 555 1234', '(800) 555-0001')  # Updated expectation
        ],
        'api_key': [
            ('apikey=1234567890abcdef', 'apikey=redacted_api_key001'),
            ('token=abcdef1234567890', 'token=redacted_api_key002')  # Updated expectation
        ]
    }

def test_simple_redactions(test_simple_values, capsys):
    redactor = Redactor()

    for redact_type, test_cases in test_simple_values.items():
        print(f"\nTesting {redact_type} redactions:")
        counter = 1

        for original, expected in test_cases:
            # Test direct value redaction
            redacted = redactor._generate_unique_mapping(original, redact_type)
            print(f"\nInput:    {original}")
            print(f"Redacted: {redacted}")
            print(f"Expected: {expected}")

            # Verify the counter in the redacted value
            expected_suffix = f"{counter:03d}"
            if redact_type == 'ipv4':
                assert redacted.startswith('240.0.'), f"Expected IPv4 to start with 240.0., got: {redacted}"
            elif redact_type == 'ipv6':
                assert redacted.startswith('3fff:'), f"Expected IPv6 to start with 3fff:, got: {redacted}"
            elif redact_type == 'phone':
                assert redacted.startswith('(800) 555-'), f"Expected phone to start with (800) 555-, got: {redacted}"
                expected_suffix = f"{counter:04d}"
            elif redact_type == 'email':
                assert redacted.startswith('redacted.'), f"Expected email to start with redacted., got: {redacted}"
            else:
                assert redacted.endswith(expected_suffix), f"Expected suffix '{expected_suffix}', got: {redacted}"

            # Test in-context redaction
            test_line = f"Found value {original} in text"
            redacted_line = redactor._redact_pattern(test_line, redact_type)
            print(f"Original line: {test_line}")
            print(f"Redacted line: {redacted_line}")

            assert original not in redacted_line, "Original value found in redacted line"
            counter += 1

    # Print mappings for debugging
    print("\nFinal Mappings:")
    for original, redacted in redactor.unique_mapping.items():
        print(f"{original} -> {redacted}")

@pytest.fixture
def valid_ipv4():
    return [
        "192.168.1.1",
        "10.0.0.255",
        "172.16.254.1",
        "192.168.0.1",
        "10.1.1.1",
        "192.0.2.0",
        "203.0.113.0",
        "255.255.255.255",
        "127.0.0.1",
        "8.8.8.8"
    ]

@pytest.fixture
def valid_ipv6():
    return [
        "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
        "fe80::1ff:fe23:4567:890a",
        "::1",
        "2001:db8::ff00:42:8329",
        "2001:db8:85a3::8a2e:370:7334",
        "2001:db8:0:1234:0:567:8:1",
        "2001:0db8::0000:0000:0000:0000:0000",
        "::ffff:192.168.1.1",
        "2001:db8:0:0:0:0:2:1",
        "::a00:1"
    ]

def test_redact_ipv4(valid_ipv4, capsys):
    """Test IPv4 validation and redaction"""
    redactor = Redactor()
    print("\nTesting IPv4 Addresses:")

    for ip in valid_ipv4:
        redacted = redactor._generate_unique_mapping(ip, 'ipv4')
        print(f"\nInput:    {ip}")
        print(f"Redacted: {redacted}")
        assert ip not in redacted, f"Original IP found in redacted value: {ip}"
        assert redacted.startswith("240.0"), f"Redacted IPv4 should start with 10., got: {redacted}"

    print("\nFinal IPv4 Mappings:")
    for original, redacted in redactor.unique_mapping.items():
        print(f"{original} -> {redacted}")

def test_redact_ipv6(valid_ipv6, capsys):
    """Test IPv6 validation and redaction"""
    redactor = Redactor()
    print("\nTesting IPv6 Addresses:")

    for ip in valid_ipv6:
        redacted = redactor._generate_unique_mapping(ip, 'ipv6')
        print(f"\nInput:    {ip}")
        print(f"Redacted: {redacted}")
        assert ip not in redacted, f"Original IP found in redacted value: {ip}"
        assert redacted.startswith("3fff:"), f"Redacted IPv6 should start with 3fff:, got: {redacted}"

    print("\nFinal IPv6 Mappings:")
    for original, redacted in redactor.unique_mapping.items():
        print(f"{original} -> {redacted}")

@pytest.fixture
def test_hostnames():
    return [
        "example.com",
        "subdomain.example.com",
        "my-hostname.org",
        "test.example.co.uk",
        "example123.net",
        "test-site.com",
        "sub.domain.example",
        "hostname-with-dash.com",
        "example-123.net"
    ]

def test_redact_hostname(test_hostnames, capsys):
    redactor = Redactor()
    expected_counter = 1

    for hostname in test_hostnames:
        # Test single hostname
        redacted = redactor._generate_unique_mapping(hostname, 'hostname')
        print(f"\nTesting hostname: {hostname}")
        print(f"Redacted as: {redacted}")

        # Verify redaction
        assert hostname not in redacted, f"Hostname {hostname} was not redacted"
        assert redacted.startswith("redacted_host"), f"Expected redacted_host prefix, got: {redacted}"
        assert redacted.endswith(f"{expected_counter:03d}"), f"Expected suffix '{expected_counter:03d}', got: {redacted}"

        # Test in a line of text
        test_line = f"Server {hostname} is responding"
        redacted_line = redactor._redact_pattern(test_line, "hostname")
        print(f"Original line: {test_line}")
        print(f"Redacted line: {redacted_line}")

        assert hostname not in redacted_line, f"Hostname {hostname} found in redacted line"
        expected_counter += 1

    # Show final mapping
    print("\nFinal hostname mappings:")
    for original, redacted in redactor.unique_mapping.items():
        print(f"{original} -> {redacted}")

@pytest.fixture
def test_phones():
    return [
        "(888) 555-9900",    # Standard US format
        "(333) 444-5555",    # Standard US format
        "444-555-6666",      # Basic format
        "+1 202 555 1234",   # International format
        "+1 800 575 0101",   # Toll free format
        "123-456-7890"       # Basic format
    ]

@pytest.fixture
def invalid_phones():
    return [
        "333.444.5555",      # Invalid separator
        "1234567890",        # No separators
        "(123) 45-6789",     # Wrong grouping
        "123-45-6789",       # Wrong grouping
        "+invalid",          # Non-numeric
        "(800)",            # Incomplete
    ]

def test_redact_phone(test_phones, invalid_phones, capsys):
    redactor = Redactor()
    print("\nTesting Valid Phone Numbers:")

    for phone in test_phones:
        redacted = redactor._generate_unique_mapping(phone, 'phone')
        print(f"\nInput:    {phone}")
        print(f"Redacted: {redacted}")

        # Verify redaction
        assert phone not in redacted, f"Phone {phone} was not redacted"
        assert redacted.startswith("(800) 555-"), f"Expected (800) 555- prefix, got: {redacted}"

        # Extract and verify suffix is 4 digits between 0000-9999
        suffix = redacted.split('-')[1]
        assert len(suffix) == 4, f"Expected 4-digit suffix, got: {suffix}"
        assert suffix.isdigit(), f"Expected numeric suffix, got: {suffix}"
        assert 0 <= int(suffix) <= 9999, f"Suffix {suffix} out of range (0000-9999)"

        print(f"Verified redaction format: {redacted} (suffix: {suffix})")

        # Test in context
        test_line = f"Contact support at {phone}"
        redacted_line = redactor._redact_pattern(test_line, "phone")
        print(f"Original: {test_line}")
        print(f"Redacted: {redacted_line}")

    print("\nTesting Invalid Phone Numbers:")
    for phone in invalid_phones:
        print(f"\nTesting invalid: {phone}")
        assert not redactor.should_redact_value(phone, "phone"), f"Incorrectly validated invalid phone: {phone}"

    print("\nFinal Phone Mappings:")
    for original, redacted in redactor.unique_mapping.items():
        print(f"{original} -> {redacted}")

def test_redact_email(test_sample, capsys):
    redactor = Redactor()
    redacted_lines = redactor.redact(test_sample)

    # Capture the standard output
    captured = capsys.readouterr()
    print("Redacted Lines:\n" + "\n".join(captured))
    # Check that email addresses are redacted
    for line in redacted_lines:
        assert not any(email in line for email in [
            "john.doe@example.com", "jane.doe@example.com", "admin@example.com",
            "user@example.com", "contact@example.com"
        ])


def test_redact_url(capsys):
    redactor = Redactor()
    test_urls = [
        ("https://api.example.com", "https://redacted.url001"),
        ("http://subdomain.example.com:8080/path", "http://redacted.url001:8080/path"),
        ("https://example.com/api/v1?key=value", "https://redacted.url001/api/v1?key=value"),
    ]

    for original, expected_base in test_urls:
        redacted = redactor._generate_unique_mapping(original, "url")
        print(f"\nTesting URL: {original}")
        print(f"Redacted as: {redacted}")

        # Parse both URLs
        original_parts = urllib.parse.urlparse(original)
        redacted_parts = urllib.parse.urlparse(redacted)

        # Verify schema
        assert redacted_parts.scheme == original_parts.scheme

        # Verify redacted domain
        assert "redacted.url" in redacted_parts.netloc

        # Verify path preserved exactly
        if original_parts.path:
            assert redacted_parts.path == original_parts.path

        # Verify query preserved exactly
        if original_parts.query:
            assert redacted_parts.query == original_parts.query

        # Verify port preserved if present
        if original_parts.port:
            assert str(original_parts.port) in redacted_parts.netloc

def test_redact_api_key(capsys):
    """Test API key redaction with various formats."""
    redactor = Redactor()

    test_cases = [
        # (input, expected_prefix)
        ("apikey=1234567890abcdef", "apikey=redacted_api_key"),
        ("token=abcdef1234567890", "token=redacted_api_key"),
        ("key=987654321xyz", "key=redacted_api_key"),
        ("apitoken=abc123def456", "apitoken=redacted_api_key")
    ]

    redacted_keys = []
    for api_key, expected_prefix in test_cases:
        redacted = redactor._generate_unique_mapping(api_key, 'api_key')
        redacted_keys.append(redacted)
        print(f"\nTesting API key: {api_key}")
        print(f"Redacted as: {redacted}")

        # Check format
        assert redacted.startswith(expected_prefix), \
            f"API key not properly redacted. Expected prefix '{expected_prefix}', got: {redacted}"

        # Check counter
        counter = int(redacted.split('key')[-1])
        assert 1 <= counter <= 999, f"Counter out of range in redacted value: {redacted}"

    # Verify uniqueness
    assert len(set(redacted_keys)) == len(test_cases), "Each API key should have a unique redaction"

    # Print summary
    if capsys.readouterr().out:
        print("\nRedacted keys:")
        for original, redacted in zip([t[0] for t in test_cases], redacted_keys):
            print(f"{original} -> {redacted}")

@pytest.fixture
def valid_api_keys():
    return [
        "apikey=1234567890abcdef",
        "token=abcdef1234567890",
        "key=987654321xyz",
        "apitoken=abc123def456"
    ]

@pytest.fixture
def invalid_api_keys():
    return [
        "notakey=1234",
        "api_key_without_equals",
        "key=",
        "=value"
    ]

def test_api_key_validation(valid_api_keys, invalid_api_keys, capsys):
    """Test API key validation and redaction"""
    redactor = Redactor()
    print("\nTesting Valid API Keys:")

    for key in valid_api_keys:
        redacted = redactor._generate_unique_mapping(key, 'api_key')
        print(f"\nInput:    {key}")
        print(f"Redacted: {redacted}")
        assert redactor.should_redact_value(key, "api_key"), f"Failed to redact valid key: {key}"
        assert key not in redacted, f"Original key found in redacted value: {key}"

    print("\nTesting Invalid API Keys:")
    for key in invalid_api_keys:
        print(f"\nTesting invalid key: {key}")
        assert not redactor.should_redact_value(key, "api_key"), f"Incorrectly redacted invalid key: {key}"

    print("\nFinal API Key Mappings:")
    for original, redacted in redactor.unique_mapping.items():
        print(f"{original} -> {redacted}")
