
import os
import sys

import pytest

# Add the parent directory to the sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from log_redactor.redactor import Redactor


@pytest.fixture
def sample_log():
    with open("samples/sample.log") as file:
        return file.readlines()

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

    # Check that IPv6 addresses are redacted
    for line in redacted_lines:
        assert not any(ip in line for ip in [
            "2001:0db8:85a3:0000:0000:8a2e:0370:7334", "fe80::1ff:fe23:4567:890a",
            "::1", "2001:db8::ff00:42:8329", "2001:db8:85a3::8a2e:370:7334",
            "2001:db8:0:1234:0:567:8:1", "2001:0db8::0000:0000:0000:0000:0000",
            "::ffff:192.168.1.1", "2001:db8:0:0:0:0:2:1", "::a00:1"
        ])

    # Print the redacted lines
    print("".join(redacted_lines))
    captured = capsys.readouterr()
    print(captured.out)

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
            "http://localhost:8080/test", "https://subdomain.example.com/path",
            "https://example.co.uk", "http://192.168.1.1/login",
            "https://www.example.com/file?type=test#fragment",
            "ftp://example.com", "https://www.example.com:80"
        ])

    # Print the redacted lines
    print("".join(redacted_lines))
    captured = capsys.readouterr()
    print(captured.out)

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

    # Print the redacted lines
    print("".join(redacted_lines))
    captured = capsys.readouterr()
    print(captured.out)

if __name__ == "__main__":
    pytest.main()
