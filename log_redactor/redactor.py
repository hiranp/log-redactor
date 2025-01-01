import argparse
import ipaddress
import os
import pathlib
import re
import tarfile
import zipfile
from typing import ClassVar

from log_redactor.IPv4Generator import IPv4Generator
from log_redactor.IPv6Generator import IPv6Generator

try:
    import urllib.parse
except ImportError:
    print("Please install the urllib library using 'pip install urllib'")
    exit()

try:
    import ipaddress
except ImportError:
    print("Please install the ipaddress library using 'pip install ipaddress'")
    exit()

try:
    import rtoml
except ImportError:
    print("Please install the rtoml library using 'pip install rtoml'")
    exit()

try:
    from emval import validate_email
except ImportError:
    print("Please install the emval library using 'pip install emval'")
    exit()

PDF_SUPPORT = True
try:
    import fitz  # PyMuPDF
except ImportError:
    PDF_SUPPORT = False
    print("PyMuPDF library not installed. PDF redaction will be disabled.")
    print("Please install it using 'pip install --upgrade pymupdf'")

# Global variables for redacted patterns
REDACTED_EMAIL_BASE = "redacted.user"
REDACTED_EMAIL_DOMAIN = "@example.com"
REDACTED_PHONE_BASE = "(800) 555-0"
REDACTED_PHONE_RANGE_START = 0
REDACTED_PHONE_RANGE_END = 999
REDACTED_HOST_BASE = "redacted_host"
REDACTED_URL_BASE = "redacted.url"
REDACTED_API_KEY_BASE = "redacted_api_key"

class Redactor:
    """Class to redact sensitive information such as IPs, HOSTs, URLs, IPs, EMAILs, and API keys."""

    PATTERNS: ClassVar[dict] = {
        "ipv4": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
        "ipv6": re.compile(r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|\b(?:[0-9a-fA-F]{1,4}:){1,7}:|::(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}\b"),
        "hostname": re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b"),
        "phone": re.compile(r"\(\d{3}\) \d{3}-\d{4}|\d{3}-\d{3}-\d{4}|\d{3}\.\d{3}\.\d{4}|\d{3} \d{3} \d{4}"),
        "email": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"),
        "url": re.compile(r"https?://[^\s/$.?#].[^\s]*"),
        "api_key": re.compile(r"\b(?:apikey|token|key|apitoken)=\w+\b")
    }


    VALIDATORS: ClassVar[dict] = {
        "ipv4": lambda x: Redactor.is_valid_ipv4(x),
        "ipv6": lambda x: Redactor.is_valid_ipv6(x),
        "url": lambda x: Redactor.is_valid_url(x),
        "hostname": lambda x: Redactor.is_valid_hostname(x),
        "phone": lambda x: Redactor.PATTERNS["phone"].match(x) is not None,
        "email": lambda x: Redactor.is_valid_email(x)
    }

    def __init__(self, interactive: bool = False):
        self.interactive = interactive
        self.secrets = self._load_config("secrets")
        self.ignores = self._load_config("ignore")
        self.unique_mapping = {}
        self.counter = {
            "ipv4": 0,
            "ipv6": 0,
            "hostname": 1,
            "phone": REDACTED_PHONE_RANGE_START,
            "email": 1,
            "url": 1,
            "api_key": 1
        }
        self.ipv4_generator = IPv4Generator()
        self.ipv6_generator = IPv6Generator()

    def _load_config(self, config_type: str) -> dict[str, list[str]]:
        """Load configuration from TOML file in samples directory."""
        config_path = os.path.join("samples", f"{config_type}.toml")
        if not os.path.exists(config_path):
            print(f"Warning: Configuration file {config_path} not found")
            return {key: [] for key in self.PATTERNS}

        try:
            with open(config_path) as config_file:
                config = rtoml.load(config_file)
                return config
        except Exception as e:
            print(f"Error reading TOML file {config_path}: {e}")
            return {key: [] for key in self.PATTERNS}

    def _matches_pattern(self, value: str, pattern: str) -> bool:
        """Check if value matches a pattern, supporting wildcards."""
        # Convert wildcard pattern to regex
        regex_pattern = pattern.replace(".", "\\.").replace("*", ".*")
        return bool(re.match(f"^{regex_pattern}$", value))

    def _matches_any_pattern(self, value: str, pattern_type: str, patterns: dict) -> bool:
        """Check if value matches any pattern in the given config."""
        if pattern_type not in patterns:
            return False
        return any(self._matches_pattern(value, pattern)
            for pattern in patterns[pattern_type]["patterns"])

    def should_redact_value(self, value: str, pattern_type: str) -> bool:
        """
        Determine if a value should be redacted based on validation rules and patterns.

        Returns:
            bool: True if the value should be redacted, False otherwise
        """
        # First check if value is valid according to core validation rules
        validator = self.VALIDATORS.get(pattern_type)
        if validator and not validator(value):
            return False

        # Check if value appears in both lists
        is_secret = self._matches_any_pattern(value, pattern_type, self.secrets)
        is_ignored = self._matches_any_pattern(value, pattern_type, self.ignores)

        if is_secret and is_ignored:
            print(f"Warning: {value} matches both secret and ignore patterns. Using secret pattern.")
            return True

        # Check if value appears in ignore list
        if is_ignored:
            return False

        # Check if value appears in secrets list
        if is_secret:
            return True

        # If in interactive mode and no patterns matched, ask user
        if self.interactive:
            return self._ask_user(value, pattern_type)

        return False

    def _load_lists(self, filename: str) -> dict[str, list[str]]:
        """Load secrets or ignore lists from a file."""
        lists = {key: [] for key in self.PATTERNS}
        try:
            with open(filename) as f:
                for line in f:
                    secret_type, value = line.strip().split(",")
                    lists[secret_type].append(value)
        except FileNotFoundError:
            pass
        return lists

    def _save_to_file(self, filename: str, secret_type: str, value: str):
        """Save a value to a secrets or ignore list."""
        with open(filename, "a") as f:
            if f.tell() != 0:
                f.write("\n")
            f.write(f"{secret_type},{value}")

    # def save_mappings(self, filename: str):
    #     """Save unique mappings to a file."""
    #     with open(filename, "w") as f:
    #         json.dump(self.unique_mapping, f, indent=4)

    def save_mapping(mapping, file_path):
        """
        Save the mapping to a .toml file.

        :param mapping: Dictionary to save.
        :param file_path: Path to the .toml file.
        """
        with open(file_path, 'w') as toml_file:
            rtoml.dump(mapping, toml_file)

    def _ask_user(self, value: str, secret_type: str) -> bool:
        """Prompt the user to decide whether to redact a value."""
        print(f"Found a potential {secret_type}: {value}")
        print("Would you like to redact? (yes/no/always/never)")
        while True:
            answer = input().lower()
            if answer in ["yes", "y"]:
                return True
            elif answer in ["no", "n"]:
                return False
            elif answer in ["always", "a"]:
                self._save_to_file("secrets.csv", secret_type, value)
                return True
            elif answer == "never":
                self._save_to_file("ignore.csv", secret_type, value)
                return False

    @staticmethod
    def is_valid_ipv4(ip: str) -> bool:
        try:
            ipaddress.IPv4Address(ip)
            return True
        except ipaddress.AddressValueError:
            return False

    @staticmethod
    def is_valid_ipv6(ip: str) -> bool:
        try:
            ipaddress.IPv6Address(ip)
            return True
        except ipaddress.AddressValueError:
            return False

    @staticmethod
    def is_valid_url(url: str) -> bool:
        try:
            result = urllib.parse.urlparse(url)
            return all([result.scheme, result.netloc])
        except ValueError:
            return False

    @staticmethod
    def is_valid_email(email: str) -> bool:
        try:
            validate_email(
                email,
                allow_quoted_local=True,
                deliverable_address=False,
            )
            return True
        except SyntaxError:
            return False

    @staticmethod
    def is_valid_hostname(hostname: str) -> bool:
        if hostname[-1] == ".":
            hostname = hostname[:-1]
        if len(hostname) > 253:
            return False

        labels = hostname.split(".")
        if re.match(r"[0-9]+$", labels[-1]):
            return False

        hostname_regex = re.compile(r"(?!-)[a-z0-9-]{1,63}(?<!-)$", re.IGNORECASE)
        return all(hostname_regex.match(label) for label in labels)

    def _generate_unique_email(self) -> str:
        """Generate a unique redacted email address."""
        email = f"{REDACTED_EMAIL_BASE}{self.email_counter:03}{REDACTED_EMAIL_DOMAIN}"
        self.email_counter += 1
        return email

    def _generate_unique_phone(self) -> str:
        """Generate a unique redacted phone number."""
        if self.phone_counter > REDACTED_PHONE_RANGE_END:
            raise ValueError("No more phone numbers available in the specified range.")
        phone = f"{REDACTED_PHONE_BASE}{str(self.phone_counter).zfill(2)}"
        self.phone_counter += 1
        return phone

    def _generate_unique_hostname(self) -> str:
        """Generate a unique redacted hostname."""
        hostname = f"{REDACTED_HOST_BASE}{self.counter:03['hostname']}"
        self.counter['hostname'] += 1
        return hostname

    def _generate_unique_url(self, value: str) -> str:
        """Generate a unique redacted URL, keeping the first part of the original URL."""
        parsed_url = urllib.parse.urlparse(value)
        scheme = parsed_url.scheme
        url = f"{scheme}://{REDACTED_URL_BASE}{self.counter['url']:03}"
        self.counter['url'] += 1
        return url

    def _generate_unique_api_key(self, value: str) -> str:
        """Generate a unique redacted API key, keeping the first part of the original key."""
        key_type = re.sub(r'\W+', '', value.split('=')[0])  # Remove non-alphanumeric characters
        api_key = f"{key_type}=redacted_api_key{self.counter['api_key']:03}"
        self.counter['api_key'] += 1
        return api_key

    def _generate_unique_mapping(self, value: str, pattern_type: str) -> str:
        """Generate a unique mapping for the given value based on its pattern type."""
        if pattern_type == "ipv4":
            mapped_ip = f"240.0.0.{self.counter[pattern_type]}"
            self.unique_mapping[value] = mapped_ip
            self.counter[pattern_type] += 1
        elif pattern_type == "ipv6":
            self.unique_mapping[value] = self.ipv6_generator.generate_unique_ipv6()
        elif pattern_type == "phone":
            mapped_phone = f"{REDACTED_PHONE_BASE}{self.counter[pattern_type]:02d}"
            self.unique_mapping[value] = mapped_phone
            self.counter[pattern_type] += 1
            if self.counter[pattern_type] > REDACTED_PHONE_RANGE_END:
                self.counter[pattern_type] = REDACTED_PHONE_RANGE_START
        elif pattern_type == "url":
            self.unique_mapping[value] = self._generate_unique_url(value)
        elif pattern_type == "api_key":
            self.unique_mapping[value] = self._generate_unique_api_key(value)
        elif pattern_type == "email":
            self.unique_mapping[value] = self._generate_unique_email()
        else:
            self.unique_mapping[value] = self._generate_unique_hostname()

        return self.unique_mapping[value]


    def _redact_pattern(self, line: str, pattern_type: str) -> str:
        """Unified redaction method for all patterns"""
        pattern = self.PATTERNS.get(pattern_type)
        if not pattern:
            return line

        def replace_match(match):
            value = match.group(0)
            if self.should_redact_value(value, pattern_type):
                return self._generate_unique_mapping(value, pattern_type)
            return value

        return pattern.sub(replace_match, line)

    def redact(self, lines: list) -> list:
        """Redact sensitive information from the given lines."""
        redacted_lines = []
        for line in lines:
            for pattern_type in self.PATTERNS:
                line = self._redact_pattern(line, pattern_type)
            redacted_lines.append(line)
        return redacted_lines

    def redact_file(self, file: str):
        """Redact a file in place."""
        try:
            extension = pathlib.Path(file).suffix or ".txt"
            with open(file) as f:
                lines = f.readlines()
            redacted_lines = self.redact(lines)
            with open(file + "-redacted" + extension, "w") as f:
                f.writelines(redacted_lines)
            self.save_mappings(file + "-mappings.toml")
            print(f"Redacted file saved as {file}-redacted")
        except FileNotFoundError:
            print(f"File not found: {file}")
        except Exception as e:
            print(f"An error occurred while redacting the file: {e}")

    def redact_directory(self, directory: str):
        """Redact all files in a directory."""
        for root, _, files in os.walk(directory):
            for file in files:
                file_path = os.path.join(root, file)
                self.redact_file(file_path)

    def extract_and_redact_zip(self, zip_file: str):
        """Extract and redact all files in a ZIP archive."""
        try:
            with zipfile.ZipFile(zip_file, 'r') as zip_ref:
                extract_dir = zip_file.replace('.zip', '')
                zip_ref.extractall(extract_dir)
                print(f"Extracted {zip_file} to {extract_dir}")
                self.redact_directory(extract_dir)
        except FileNotFoundError:
            print(f"ZIP file not found: {zip_file}")
        except zipfile.BadZipFile:
            print(f"Invalid ZIP file: {zip_file}")
        except Exception as e:
            print(f"An error occurred while extracting the ZIP file: {e}")

    def extract_and_redact_archive(self, archive_path: str):
        """Extract and redact files from various archive formats."""
        base_name = os.path.splitext(archive_path)[0]
        if base_name.endswith('.tar'):
            base_name = os.path.splitext(base_name)[0]

        extract_dir = f"{base_name}-redacted"

        try:
            if archive_path.endswith('.tar.gz') or archive_path.endswith('.tgz'):
                with tarfile.open(archive_path, 'r:gz') as tar:
                    tar.extractall(extract_dir)
            elif archive_path.endswith('.tar'):
                with tarfile.open(archive_path, 'r') as tar:
                    tar.extractall(extract_dir)
            elif archive_path.endswith('.gz'):
                import gzip
                with gzip.open(archive_path, 'rb') as gz:
                    output_path = os.path.join(extract_dir, os.path.basename(base_name))
                    os.makedirs(extract_dir, exist_ok=True)
                    with open(output_path, 'wb') as out:
                        out.write(gz.read())
            else:
                print(f"Unsupported archive format: {archive_path}")
                return

            print(f"Extracted {archive_path} to {extract_dir}")
            self.redact_directory(extract_dir)

        except Exception as e:
            print(f"Error processing archive {archive_path}: {e}")

    def redact_pdf(self, pdf_file: str):
        """Redact sensitive information from a PDF file."""
        if not PDF_SUPPORT:
            print("PDF redaction is not supported. Please install the PyMuPDF library.")
            return

        try:
            doc = fitz.open(pdf_file)
            for page_num in range(len(doc)):
                page = doc.load_page(page_num)
                text = page.get_text("text")
                redacted_text = self.redact([text])[0]
                if text != redacted_text:
                    areas = page.search_for(text)
                    for area in areas:
                        page.add_redact_annot(area, fill=(0, 0, 0))
                    page.apply_redactions()
            redacted_pdf_file = pdf_file.replace(".pdf", "-redacted.pdf")
            doc.save(redacted_pdf_file)
            self.save_mappings(pdf_file.replace(".pdf", "-mappings.toml"))
            print(f"Redacted PDF saved as {redacted_pdf_file}")
        except Exception as e:
            print(f"An error occurred while redacting the PDF file: {e}")

def main():
    parser = argparse.ArgumentParser(
        description="Redact sensitive information from a file, directory, or archive."
    )
    parser.add_argument("path", help="The file, directory, or archive to redact")
    parser.add_argument(
        "-i", "--interactive", action="store_true", help="Run in interactive mode"
    )
    args = parser.parse_args()

    redactor = Redactor(interactive=args.interactive)

    if os.path.isdir(args.path):
        redactor.redact_directory(args.path)
    elif any(args.path.endswith(ext) for ext in ['.zip', '.tar', '.gz', '.tar.gz', '.tgz']):
        if args.path.endswith('.zip'):
            redactor.extract_and_redact_zip(args.path)
        else:
            redactor.extract_and_redact_archive(args.path)
    elif args.path.endswith('.pdf'):
        redactor.redact_pdf(args.path)
    else:
        redactor.redact_file(args.path)

if __name__ == "__main__":
    main()

# TODO: Add more patterns and validators
# [x] https://github.com/bnkc/emval - Email Validator
