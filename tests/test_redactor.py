import os
import sys

import pytest

# Add the parent directory to the sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from log_redactor.redactor import Redactor


@pytest.fixture
def sample_log_file():
    with open("samples/sample.log") as file:
        return file.readlines()

@pytest.fixture
def sample_log():
    return [
        "# Sample Log File\n",
        "\n",
        "# IPv4 Examples\n",
        "192.168.1.1\n",
        "10.0.0.255\n",
        "172.16.254.1\n",
        "192.168.0.1\n",
        "10.1.1.1\n",
        "192.0.2.0\n",
        "203.0.113.0\n",
        "255.255.255.255\n",
        "127.0.0.1\n",
        "8.8.8.8\n",
        "\n",
        "# IPv6 Examples\n",
        "2001:0db8:85a3:0000:0000:8a2e:0370:7334\n",
        "fe80::1ff:fe23:4567:890a\n",
        "::1\n",
        "2001:db8::ff00:42:8329\n",
        "2001:db8:85a3::8a2e:370:7334\n",
        "2001:db8:0:1234:0:567:8:1\n",
        "2001:0db8::0000:0000:0000:0000:0000\n",
        "::ffff:192.168.1.1\n",
        "2001:db8:0:0:0:0:2:1\n",
        "::a00:1\n",
        "\n",
        "# Hostname Examples\n",
        "example.com\n",
        "subdomain.example.com\n",
        "my-hostname.org\n",
        "test.example.co.uk\n",
        "example123.net\n",
        "test-site.com\n",
        "sub.domain.example\n",
        "hostname-with-dash.com\n",
        "example-123.net\n",
        "\n",
        "# Phone Examples\n",
        "(800) 555-0100\n",
        "(800) 555-0101\n",
        "(123) 456-7890\n",
        "(555) 555-5555\n",
        "\n",
        "# Email Examples\n",
        "john.doe@example.com\n",
        "jane.doe@example.com\n",
        "admin@example.com\n",
        "user@example.com\n",
        "contact@example.com\n",
        "\n",
        "# URL Examples\n",
        "https://www.example.com\n",
        "http://example.org\n",
        "https://example.net/path/to/resource?query=1&value=2\n",
        "http://localhost:8080/test\n",
        "https://subdomain.example.com/path\n",
        "\n",
        "# API Key Examples\n",
        "apikey=1234567890abcdef\n",
        "token=abcdef1234567890\n",
        "key=abcdef1234567890\n",
        "apitoken=abcdef1234567890\n",
    ]

def test_redact_ipv4(sample_log, capsys):
    redactor = Redactor()
    redacted_lines = redactor.redact(sample_log)

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
    print("".join(redacted_lines))
    captured = capsys.readouterr()
    print(captured.out)

def test_redact_ipv6(sample_log, capsys):
    redactor = Redactor()
    redacted_lines = redactor.redact(sample_log)

    # Capture the standard output
    captured = capsys.readouterr()

    # Print the redacted lines for debugging
    print("Redacted Lines:")
    print("".join(redacted_lines))

    # Check that IPv6 addresses are redacted
    for line in redacted_lines:
        assert not any(ip in line for ip in [
            "2001:0db8:85a3:0000:0000:8a2e:0370:7334", "fe80::1ff:fe23:4567:890a",
            "::1", "2001:db8::ff00:42:8329", "2001:db8:85a3::8a2e:370:7334",
            "2001:db8:0:1234:0:567:8:1", "2001:0db8::0000:0000:0000:0000:0000",
            "::ffff:192.168.1.1", "2001:db8:0:0:0:0:2:1", "::a00:1"
        ])

def test_redact_hostname(sample_log, capsys):
    redactor = Redactor()
    redacted_lines = redactor.redact(sample_log)

    # Capture the standard output
    captured = capsys.readouterr()

    # Check that hostnames are redacted
    for line in redacted_lines:
        assert not any(hostname in line for hostname in [
            "example.com", "subdomain.example.com", "my-hostname.org",
            "test.example.co.uk", "example123.net", "test-site.com",
            "sub.domain.example", "hostname-with-dash.com", "example-123.net"
        ])

def test_redact_phone(sample_log, capsys):
    redactor = Redactor()
    redacted_lines = redactor.redact(sample_log)

    # Capture the standard output
    captured = capsys.readouterr()

    # Check that phone numbers are redacted
    for line in redacted_lines:
        assert not any(phone in line for phone in [
            "(800) 555-0100", "(800) 555-0101", "(123) 456-7890", "(555) 555-5555"
        ])

def test_redact_email(sample_log, capsys):
    redactor = Redactor()
    redacted_lines = redactor.redact(sample_log)

    # Capture the standard output
    captured = capsys.readouterr()

    # Check that email addresses are redacted
    for line in redacted_lines:
        assert not any(email in line for email in [
            "john.doe@example.com", "jane.doe@example.com", "admin@example.com",
            "user@example.com", "contact@example.com"
        ])

def test_redact_url(sample_log, capsys):
    redactor = Redactor()
    redacted_lines = redactor.redact(sample_log)

    # Capture the standard output
    captured = capsys.readouterr()

    # Check that URLs are redacted
    for line in redacted_lines:
        assert not any(url in line for url in [
            "https://www.example.com", "http://example.org",
            "https://example.net/path/to/resource?query=1&value=2",
            "http://localhost:8080/test", "https://subdomain.example.com/path"
        ])

def test_redact_api_key(sample_log, capsys):
    redactor = Redactor()
    redacted_lines = redactor.redact(sample_log)

    # Capture the standard output
    captured = capsys.readouterr()

    # Check that API keys are redacted
    for line in redacted_lines:
        assert not any(api_key in line for api_key in [
            "apikey=1234567890abcdef", "token=abcdef1234567890",
            "key=abcdef1234567890", "apitoken=abcdef1234567890"
        ])
