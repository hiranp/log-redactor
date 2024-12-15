import argparse
import ipaddress
import os
import re
import zipfile
from typing import ClassVar


class Redactor:
    # Common regex patterns for email, IP, and phone number, and API tokens
    # HOSTNAME_PATTERN = r"([a-zA-Z0-9]+(-[a-zA-Z0-9]+)*\.)+[a-zA-Z]{2,}"
    ipv4_pattern=r"^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
    ipv6_pattern=r"(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))"
    phone_number_pattern = r"^\\+?\\d{1,4}?[-.\\s]?\\(?\\d{1,3}?\\)?[-.\\s]?\\d{1,4}[-.\\s]?\\d{1,4}[-.\\s]?\\d{1,9}$"
    EMAIL_PATTERN = r"[\w\.-]+@[\w\.-]+\.\w+"
    IPV4_PATTERN = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
    PHONE_PATTERN = r"\b\d{3}[-.\s]?\d{3}[-.\s]?\d{4}\b"
    URL_PATTERN = r"https?:\/\/(www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_\+.~#?&//=]*)"
    HOSTNAME_PATTERN = r"(?!-)[a-z0-9-]{1,63}(?<!-)$"
    API_TOKEN_PATTERNS: ClassVar[list[str]] = [
        r"token=[^&\s]*",
        r"key=[^&\s]*",
        r"api=[^&\s]*",
        r"apikey=[^&\s]*",
        r"apitoken=[^&\s]*"
    ]

    def __init__(self, interactive=False):
        self.interactive = interactive
        self.secrets = self.get_lists("secrets.csv")
        self.ignores = self.get_lists("ignore.csv")

        # Pre-compile all regex patterns
        self.email_regex = re.compile(self.EMAIL_PATTERN)
        self.ipv4_regex = re.compile(self.IPV4_PATTERN)
        self.ipv6_regex = re.compile(self.IPV6_PATTERN)
        self.url_regex = re.compile(self.URL_PATTERN)
        self.hostname_regex = re.compile(self.HOSTNAME_PATTERN, re.IGNORECASE)
        self.phone_regex = re.compile(self.PHONE_PATTERN)
        self.api_token_regexes = [re.compile(pattern) for pattern in self.API_TOKEN_PATTERNS]

    def get_file_lines(self, file):
        with open(file) as f:
            return f.readlines()

    def add_to_secrets(self, value, secret_type):
        with open("secrets.csv", "a") as f:
            if f.tell() != 0:
                f.write("\n")
            f.write(f"{secret_type},{value}")

    def add_to_ignore(self, value, secret_type):
        with open("ignore.csv", "a") as f:
            if f.tell() != 0:
                f.write("\n")
            f.write(f"{secret_type},{value}")

    def ask_user(self, value, secret_type):
        print(f"Found a potential {secret_type}: {value}")
        print("Would you like to redact? (yes/no/always/never)")
        while True:
            answer = input().lower()
            if answer in ["yes", "y"]:
                return True
            elif answer in ["no", "n"]:
                return False
            elif answer in ["always", "a"]:
                self.add_to_secrets(value, secret_type)
                return True
            elif answer == "never":
                self.add_to_ignore(value, secret_type)
                return False

    def get_lists(self, filename):
        with open(filename) as f:
            lines = f.readlines()
        lists = {"email": [], "ip": [], "phone": [], "name": [], "api": []}
        for line in lines:
            secret_type, value = line.strip().split(",")
            lists[secret_type].append(value)
        return lists

    def redactor(self, line, secret_array, ignore_array, secret_type, pattern=None):
        for value in secret_array:
            if value in line:
                return (
                    re.sub(re.escape(value), f"{secret_type.upper()}_REDACTED", line),
                    secret_array,
                    ignore_array,
                )
        if self.interactive and pattern:
            value = re.search(pattern, line)
            if value:
                value = value.group(0)
                if value not in ignore_array and self.ask_user(value, secret_type):
                    secret_array.append(value)
                    return (
                        re.sub(re.escape(value), f"{secret_type.upper()}_REDACTED", line),
                        secret_array,
                        ignore_array,
                    )
                else:
                    ignore_array.append(value)
        return line, secret_array, ignore_array

    def processor(self, line, secret_array, ignore_array, secret_type):
        token_array = ["token=", "key=", "api=", "apikey=", "apitoken="]
        for value in secret_array:
            if value in line:
                return (
                    re.sub(re.escape(value), f"{secret_type.upper()}_REDACTED", line),
                    secret_array,
                    ignore_array,
                )
        if self.interactive:
            for token in token_array:
                if token in line:
                    value = re.search(re.escape(token) + r"[^&\s]*", line)
                    if value:
                        value = value.group(0).replace(token, "")
                        if value not in ignore_array and self.ask_user(value, secret_type):
                            secret_array.append(value)
                            return (
                                re.sub(
                                    re.escape(value),
                                    f"{token}{secret_type.upper()}_REDACTED",
                                    line,
                                ),
                                secret_array,
                                ignore_array,
                            )
                        else:
                            ignore_array.append(value)
        return line, secret_array, ignore_array

    def parse(self, lines):
        stripped_lines = []
        for line in lines:
            line = self.redact_email(line)
            line = self.redact_ip(line)
            line = self.redact_url(line)
            line = self.redact_phone(line)
            line = self.redact_name(line)
            line = self.redact_api(line)
            stripped_lines.append(line)
        return stripped_lines

    def is_valid_ipv4(ip):
        try:
            ipaddress.IPv4Address(ip)
            return True
        except ipaddress.AddressValueError:
            return False

    def is_valid_hostname(hostname):
        if hostname[-1] == ".":
            # strip exactly one dot from the right, if present
            hostname = hostname[:-1]
        if len(hostname) > 253:
            return False

        labels = hostname.split(".")

        # the TLD must be not all-numeric
        if re.match(r"[0-9]+$", labels[-1]):
            return False

        return all(hostname_regex.match(label) for label in labels)

    def redact_ip(self, line):
            """Redact both IPv4 and IPv6 addresses"""
            # Check IPv4
            ipv4_matches = self.ipv4_regex.finditer(line)
            for match in ipv4_matches:
                ip = match.group(0)
                if self.is_valid_ip(ip):
                    line = line.replace(ip, "IP_REDACTED")

            # Check IPv6
            ipv6_matches = self.ipv6_regex.finditer(line)
            for match in ipv6_matches:
                ip = match.group(0)
                if self.is_valid_ip(ip):
                    line = line.replace(ip, "IP_REDACTED")

            return line

    def redact_url(self, line):
        """Redact URLs and hostnames"""
        # Check URLs
        url_matches = self.url_regex.finditer(line)
        for match in url_matches:
            url = match.group(0)
            if self.is_valid_url(url):
                line = line.replace(url, "URL_REDACTED")

        # Check hostnames
        hostname_matches = self.hostname_regex.finditer(line)
        for match in hostname_matches:
            hostname = match.group(0)
            if self.is_valid_hostname(hostname):
                line = line.replace(hostname, "HOSTNAME_REDACTED")

    def redact_email(self, line):
        return self.redact(line, "email", r"[\w\.-]+@[\w\.-]+\.\w+")

    def redact_phone(self, line):
        return self.redact(line, "phone", r"\b\d{3}[-.\s]?\d{3}[-.\s]?\d{4}\b")

    def redact_name(self, line):
        return self.redact(line, "name")

    def redact_api(self, line):
        return self.redact_api_keys(line)

    def redact(self, line, secret_type, pattern=None):
        secret_set = set(self.secrets[secret_type])
        ignore_set = set(self.ignores[secret_type])

        # Use the appropriate pre-compiled regex based on secret_type
        regex = None
        if secret_type == "email":
            regex = self.email_regex
        elif secret_type == "ip":
            regex = self.ipv4_regex
        elif secret_type == "phone":
            regex = self.phone_regex

        for value in secret_set:
            if value in line:
                return re.sub(re.escape(value), f"{secret_type.upper()}_REDACTED", line)

        if self.interactive and regex:
            value = regex.search(line)
            if value:
                value = value.group(0)
                if value not in ignore_set and self.ask_user(value, secret_type):
                    self.secrets[secret_type].append(value)
                    return re.sub(re.escape(value), f"{secret_type.upper()}_REDACTED", line)
                else:
                    self.ignores[secret_type].append(value)
        return line

    def redact_api_keys(self, line):
        secret_set = set(self.secrets["api"])
        ignore_set = set(self.ignores["api"])

        for value in secret_set:
            if value in line:
                return re.sub(re.escape(value), "API_REDACTED", line)

        if self.interactive:
            for regex in self.api_token_regexes:
                value = regex.search(line)
                if value:
                    token = value.group(0)
                    value = token.split('=', 1)[1]
                    if value not in ignore_set and self.ask_user(value, "api"):
                        self.secrets["api"].append(value)
                        return line.replace(token, f"{token.split('=')[0]}=API_REDACTED")
                    else:
                        self.ignores["api"].append(value)
        return line

    def redact_file(self, file):
        lines = self.get_file_lines(file)
        stripped_lines = self.parse(lines)
        with open(file + "-redacted", "w") as f:
            for line in stripped_lines:
                f.write(line)
        print(f"Redacted file saved as {file}-redacted")

    def extract_and_redact_zip(self, zip_file):
        with zipfile.ZipFile(zip_file, 'r') as zip_ref:
            extract_dir = zip_file.replace('.zip', '')
            zip_ref.extractall(extract_dir)
            print(f"Extracted {zip_file} to {extract_dir}")
            for root, _, files in os.walk(extract_dir):
                for file in files:
                    file_path = os.path.join(root, file)
                    self.redact_file(file_path)


def main():
    parser = argparse.ArgumentParser(
        description="Redact sensitive information from a file or a zip archive."
    )
    parser.add_argument("file", help="The file or zip archive to redact")
    parser.add_argument(
        "-i", "--interactive", action="store_true", help="Run in interactive mode"
    )
    args = parser.parse_args()

    redactor = Redactor(interactive=args.interactive)

    if args.file.endswith('.zip'):
        redactor.extract_and_redact_zip(args.file)
    else:
        redactor.redact_file(args.file)


if __name__ == "__main__":
    main()
