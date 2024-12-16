import os
import re
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
    (800) 555-0100
    (800) 555-0101
    123-456-7890
    333.444.5555
    999 888 7777
    (555) 555-5555

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
            assert False

    # Check that redacted IPv6 addresses follow the expected pattern
    for line in redacted_lines:
        if re.search(r"3fff:[0-9a-fA-F:]*", line) is None:
            print(f"Redacted IPv6 address does not match expected pattern in line: {line}")
            assert False

def test_redact_hostname(test_sample, capsys):
    redactor = Redactor()
    redacted_lines = redactor.redact(test_sample)

    # Capture the standard output
    captured = capsys.readouterr()

    # Print the redacted lines for debugging
    print("Redacted Lines:\n" + "\n".join(redacted_lines))

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

    # Capture the standard output
    captured = capsys.readouterr()

    # Print the redacted lines for debugging
    print("Redacted Lines:\n" + "\n".join(redacted_lines))

    # Check that phone numbers are redacted
    for line in redacted_lines:
        if any(phone in line for phone in [
             "(888) 555-9900", "(800) 575-0101", "123-456-7890", "333.444.5555", "999 888 7777", "(555) 555-5555"
        ]):
            print(f"Failed to redact phone number in line: {line}")
            assert False

    # Check that redacted phone numbers follow the expected pattern
    for line in redacted_lines:
        if re.search(r"\(800\) 555-01\d{2}", line) is None:
            print(f"Redacted phone number does not match expected pattern in line: {line}")
            assert False

def test_redact_email(test_sample, capsys):
    redactor = Redactor()
    redacted_lines = redactor.redact(test_sample)

    # Capture the standard output
    captured = capsys.readouterr()

    # Check that email addresses are redacted
    for line in redacted_lines:
        assert not any(email in line for email in [
            "john.doe@example.com", "jane.doe@example.com", "admin@example.com",
            "user@example.com", "contact@example.com"
        ])

def test_redact_url(test_sample, capsys):
    redactor = Redactor()
    redacted_lines = redactor.redact(test_sample)

    # Capture the standard output
    captured = capsys.readouterr()

    # Check that URLs are redacted
    for line in redacted_lines:
        assert not any(url in line for url in [
            "https://www.example.com", "http://example.org",
            "https://example.net/path/to/resource?query=1&value=2",
            "http://localhost:8080/test", "https://subdomain.example.com/path"
        ])

def test_redact_api_key(test_sample, capsys):
    redactor = Redactor()
    redacted_lines = redactor.redact(test_sample)

    # Capture the standard output
    captured = capsys.readouterr()

    # Check that API keys are redacted
    for line in redacted_lines:
        assert not any(api_key in line for api_key in [
            "apikey=1234567890abcdef", "token=abcdef1234567890",
            "key=abcdef1234567890", "apitoken=abcdef1234567890"
        ])

    # Check that redacted API keys follow the expected pattern
    for line in redacted_lines:
        if re.search(r"apikey=redacted_api_key\d+", line) is None:
            print(f"Redacted API key does not match expected pattern in line: {line}")
            assert False
        if re.search(r"token=redacted_api_key\d+", line) is None:
            print(f"Redacted API key does not match expected pattern in line: {line}")
            assert False
        if re.search(r"key=redacted_api_key\d+", line) is None:
            print(f"Redacted API key does not match expected pattern in line: {line}")
            assert False
        if re.search(r"apitoken=redacted_api_key\d+", line) is None:
            print(f"Redacted API key does not match expected pattern in line: {line}")
            assert False
