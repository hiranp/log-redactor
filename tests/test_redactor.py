import os
import re
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
def redactor():
    return Redactor()
def test_simple_redactions(redactor, capsys):
    # Capture stdout
    captured = capsys.readouterr()
    output = captured.out.strip().split('\n')

    redacted_value = redactor._generate_unique_mapping("example.com", "hostname")
    # Check that the redacted value ends with '001'
    assert redacted_value.endswith('001'), f"Expected hostname to end with '001', but got {redacted_value}"

    redacted_value = redactor._generate_unique_mapping("bad.name@company.com", "email")
    print(f"Redacted email: {redacted_value}")
    assert redacted_value.split('@')[0].endswith('001'), f"Expected email domain to end with '001', but got {redacted_value}"

    redacted_value = redactor._generate_unique_mapping("https://www.example.com", "url")
    assert '001' in redacted_value, f"Expected URL to end with '001', but got {redacted_value}"

    redacted_value = redactor._generate_unique_mapping("apikey=1234567890abcdef", "api_key")
    assert redacted_value.endswith('001'), f"Expected API URL to end with '001', but got {redacted_value}"

    redacted_value = redactor._generate_unique_mapping("800-335-0100", "phone")
    assert '0000' in redacted_value, f"Expected phone number to end with '001', but got {redacted_value}"

    # Print full redacted output for debugging
    print("\nFull redacted output:")
    print('\n'.join(output))

def test_simple_redactions_std(redactor, capsys):
    # Test hostname redaction
    hostname = redactor._generate_unique_mapping('example.com', 'hostname')
    print(f"Redacted hostname: {hostname}")

    # Test email redaction
    email = redactor._generate_unique_mapping('user@example.com', 'email')
    print(f"Redacted email: {email}")

    # Test API URL redaction
    api = redactor._generate_unique_mapping('https://api.example.com', 'api')
    print(f"Redacted API URL: {api}")

    # Capture stdout
    captured = capsys.readouterr()
    output = captured.out.strip().split('\n')

    # Verify output contains redacted values
    assert len(output) == 3, f"Expected 3 redacted values, got {len(output)}"
    assert "redacted_host001" in output[0]
    assert "redacted.user001" in output[1]
    assert "redacted.url001" in output[2]

    # Print full redacted output for debugging
    print("\nFull redacted output:")
    print('\n'.join(output))

def test_redact_ipv4(test_sample, capsys):
    redactor = Redactor()
    redacted_lines = redactor.redact(test_sample)

    # Capture the standard output
    captured = capsys.readouterr()

    # Check that IPv4 addresses are redacted
    for line in redacted_lines:
        assert not any(ip in line for ip in [
            "192.168.1.1", "10.0.0.255", "172.16.254.1", "192.168.0.1",
            "10.1.1.1", "192.0.2.0", "203.0.113.0", "255.255.255.255",
            "127.0.0.1", "8.8.8.8"
        ])

    # Print the redacted lines
    print("Redacted Lines:\n" + "\n".join(redacted_lines))
    captured = capsys.readouterr()
    print(captured.out)

def test_redact_ipv6(test_sample, capsys):
    redactor = Redactor()
    redacted_lines = redactor.redact(test_sample)

    # Capture the standard output
    captured = capsys.readouterr()

    # Print the redacted lines for debugging
    print("Redacted Lines:\n" + "\n".join(redacted_lines))

    # Check that IPv6 addresses are redacted
    for line in redacted_lines:
        if any(ip in line for ip in [
            "2001:0db8:85a3:0000:0000:8a2e:0370:7334", "fe80::1ff:fe23:4567:890a",
            "::1", "2001:db8::ff00:42:8329", "2001:db8:85a3::8a2e:370:7334",
            "2001:db8:0:1234:0:567:8:1", "2001:0db8::0000:0000:0000:0000:0000",
            "::ffff:192.168.1.1", "2001:db8:0:0:0:0:2:1", "::a00:1"
        ]):
            print(f"Failed to redact IPv6 address in line: {line}")
            raise AssertionError()

    # Check that redacted IPv6 addresses follow the expected pattern
    for line in redacted_lines:
        if re.search(r"3fff:[0-9a-fA-F:]*", line) is None:
            print(f"Redacted IPv6 address does not match expected pattern in line: {line}")
            raise AssertionError()

def test_redact_hostname(test_sample, capsys):
    redactor = Redactor()
    redacted_lines = redactor.redact(test_sample)

    # Capture the standard output
    captured = capsys.readouterr()

    # Print the redacted lines for debugging
    print("Redacted Lines:\n" + "\n".join(captured))

    # Check that hostnames are redacted
    for line in redacted_lines:
        assert not any(hostname in line for hostname in [
            "example.com", "subdomain.example.com", "my-hostname.org",
            "test.example.co.uk", "example123.net", "test-site.com",
            "sub.domain.example", "hostname-with-dash.com", "example-123.net"
        ])

    # Check that redacted hostnames follow the expected pattern
    for line in redacted_lines:
        assert not re.search(r"\bexample\.com\b", line)
        assert not re.search(r"\bsubdomain\.example\.com\b", line)
        assert not re.search(r"\bmy-hostname\.org\b", line)
        assert not re.search(r"\btest\.example\.co\.uk\b", line)
        assert not re.search(r"\bexample123\.net\b", line)
        assert not re.search(r"\btest-site\.com\b", line)
        assert not re.search(r"\bsub\.domain\.example\b", line)
        assert not re.search(r"\bhostname-with-dash\.com\b", line)
        assert not re.search(r"\bexample-123\.net\b", line)

def test_redact_phone(test_sample, capsys):
    redactor = Redactor()
    redacted_lines = redactor.redact(test_sample)

    # Valid phone numbers that should be redacted
    valid_phones = [
        "(888) 555-9900",
        "(333) 444-5555",
        "444-555-6666",
        "+1 202 555 1234",
        "+1 800 575 0101",
        "123-456-7890"
    ]

    # Check valid phones are redacted
    for line in redacted_lines:
        # Skip comment lines
        if line.strip().startswith("#"):
            continue

        # Check each valid phone format
        for phone in valid_phones:
            if phone in line:
                assert phone not in line, f"Phone {phone} was not redacted in line: {line}"
                assert "(800) 555-" in line, f"Expected redacted format not found in line: {line}"

    # Verify redacted format matches expectation
    redacted_pattern = re.compile(r'\(800\) 555-\d{4}')
    for line in redacted_lines:
        if "(800) 555-" in line:
            matches = redacted_pattern.findall(line)
            assert all(redacted_pattern.match(match) for match in matches), \
                f"Invalid redacted phone format in line: {line}"

    # Optional: Print redacted content for debugging
    if capsys.readouterr().out:
        print("\nRedacted lines:")
        for line in redacted_lines:
            if "(800) 555-" in line:
                print(line.strip())

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


def test_redact_url():
    redactor = Redactor()
    REDACTED_URL_BASE = "redacted.url"
    test_urls = [
        "https://api.example.com",
        "http://subdomain.example.com:8080/path",
        "https://example.com/api/v1?key=value",
        "ftp://files.example.com"  # Invalid URL
    ]

    redacted_urls = []
    for url in test_urls:
        if not re.match(r'https?://', url):
            print(f"\nSkipping invalid URL: {url}")
            continue

        redacted = redactor._generate_unique_mapping(url, "url")
        redacted_urls.append(redacted)
        print(f"\nTesting URL: {url}")
        print(f"Redacted as: {redacted}")

        # Check basic URL structure
        assert redacted.startswith("https://") or redacted.startswith("http://"), f"URL should start with https:// or http://: {redacted}"
        assert REDACTED_URL_BASE in redacted, f"URL should contain {REDACTED_URL_BASE}: {redacted}"

        # Check that original URL components are replaced
        original_parts = urllib.parse.urlparse(url)
        redacted_parts = urllib.parse.urlparse(redacted)

        # The hostname should be redacted
        assert original_parts.netloc not in redacted_parts.netloc

        # Path and query should be preserved if present
        if original_parts.path:
            assert redacted_parts.path == original_parts.path
        if original_parts.query:
            assert redacted_parts.query == original_parts.query

    # Verify each URL gets a unique redaction
    assert len(set(redacted_urls)) == len(redacted_urls), "Each URL should have a unique redaction"

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

def test_api_key_validation():
    """Test API key validation logic"""
    redactor = Redactor()

    valid_keys = [
        "apikey=1234567890abcdef",
        "token=abcdef1234567890",
        "key=987654321xyz",
        "apitoken=abc123def456"
    ]

    invalid_keys = [
        "notakey=1234",
        "api_key_without_equals",
        "key=",
        "=value"
    ]

    for key in valid_keys:
        assert redactor.should_redact_value(key, "api_key"), f"Should redact valid key: {key}"

    for key in invalid_keys:
        assert not redactor.should_redact_value(key, "api_key"), f"Should not redact invalid key: {key}"
