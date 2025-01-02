import argparse
import ipaddress
import os
import pathlib
import re
import tarfile
import zipfile
from re import IGNORECASE, Pattern
from typing import ClassVar, Optional

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
    print("Please install the PyMuPDF library using 'pip install pymupdf'")

# Global variables for redacted patterns
REDACTED_EMAIL_BASE = "redacted.user"
REDACTED_EMAIL_DOMAIN = "@example.com"
REDACTED_PHONE_BASE = "(800) 555-"
REDACTED_PHONE_RANGE_START = 0000
REDACTED_PHONE_RANGE_END = 9999
REDACTED_HOST_BASE = "redacted_host"
REDACTED_URL_BASE = "redacted.url"
REDACTED_API_KEY_BASE = "redacted_api_key"

class Redactor:
    """Class to redact sensitive information such as IPs, HOSTs, URLs, IPs, EMAILs, and API keys."""

    PATTERNS: ClassVar[dict] = {
        "ipv4": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
        "ipv6": re.compile(r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|\b(?:[0-9a-fA-F]{1,4}:){1,7}:|::(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}\b"),
        "hostname": re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b"),
        "phone": re.compile(
            r"(?<!\d)"  # Negative lookbehind for digit
            r"(?:"
            r"\(\d{3}\)\s?\d{3}-\d{4}|"          # (XXX)XXX-XXXX or (XXX) XXX-XXXX
            r"\+?1[\s-]?\d{3}[\s-]\d{3}[\s-]\d{4}|"  # +1 XXX-XXX-XXXX or +1 XXX XXX XXXX
            r"\d{3}[-\s]\d{3}[-\s]\d{4}"         # XXX-XXX-XXXX or XXX XXX XXXX
            r")"
            r"(?!\d)"  # Negative lookahead for digit
        ),
        "email": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"),
        "url": re.compile(r"https?://[^\s/$.?#].[^\s]*"),
        "api_key": re.compile(r"\b(?:apikey|token|key|apitoken)=\w+\b")
    }

    # Hostname pattern components
    HOSTNAME_PATTERN: ClassVar[re.Pattern] = re.compile(
        r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    )

    # API key pattern - matches key/value pairs like apikey=xyz, token=abc, key=123
    API_KEY_PATTERN: ClassVar[Pattern] = compile(
        r"\b(?:apikey|token|key|apitoken)=\w+\b",
        IGNORECASE
    )

    VALID_PHONE_PATTERNS: ClassVar[list] = [
        re.compile(r"^\(\d{3}\)\s?\d{3}-\d{4}$"),      # (XXX)XXX-XXXX or (XXX) XXX-XXXX
        re.compile(r"^\+?1[\s-]?\d{3}[\s-]\d{3}[\s-]\d{4}$"),  # +1 XXX-XXX-XXXX or +1 XXX XXX XXXX
        re.compile(r"^\d{3}[-\s]\d{3}[-\s]\d{4}$")    # XXX-XXX-XXXX or XXX XXX XXXX
    ]

    VALIDATORS: ClassVar[dict] = {
        "ipv4": lambda x: Redactor.is_valid_ipv4(x),
        "ipv6": lambda x: Redactor.is_valid_ipv6(x),
        "url": lambda x: Redactor.is_valid_url(x),
        "hostname": lambda x: Redactor.is_valid_hostname(x),
        "phone": lambda x: Redactor.is_valid_phone(x),
        "email": lambda x: Redactor.is_valid_email(x),
        "api_key": lambda x: Redactor.is_valid_api_key(x)  # Add API key validator
    }

    def __init__(self, interactive: bool = False, config_path: Optional[str] = None, config_format: str = "toml"):
        """
        Initialize redactor with configuration options.
        Args:
            interactive: Whether to run in interactive mode
            config_path: Path to configuration directory (default: current working directory)
            config_format: Format of config files ("toml" or "csv")
        """
        self.interactive = interactive
        self.config_path = config_path or os.getcwd()
        self.config_format = config_format
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
        """
        Load configuration from file in specified format.

        Args:
            config_type: Type of config ("secrets" or "ignore")
        """
        config = {key: {"patterns": []} for key in self.PATTERNS}

        # Build file paths for both formats
        paths = {
            "toml": os.path.join(self.config_path, f"{config_type}.toml"),
            "csv": os.path.join(self.config_path, f"{config_type}.csv")
        }

        # Try loading specified format first
        if os.path.exists(paths[self.config_format]):
            try:
                if self.config_format == "toml":
                    with open(paths[self.config_format]) as f:
                        return rtoml.load(f)
                else:  # csv format
                    with open(paths[self.config_format]) as f:
                        for line in f:
                            if line.strip():
                                pattern_type, value = line.strip().split(",", 1)
                                if pattern_type in config:
                                    if "patterns" not in config[pattern_type]:
                                        config[pattern_type]["patterns"] = []
                                    config[pattern_type]["patterns"].append(value)
                    return config
            except Exception as e:
                print(f"Error reading {self.config_format} file {paths[self.config_format]}: {e}")

        return config

    def _save_pattern(self, config_type: str, pattern_type: str, value: str, save_format: str = "toml"):
        """Save a pattern to either TOML or CSV configuration file. Defined by config_type."""
        if save_format == "toml":
            file_path = os.path.join(self.config_path, f"{config_type}.toml")
            config = self._load_config(config_type)
            if pattern_type not in config:
                config[pattern_type] = {"patterns": []}
            if value not in config[pattern_type]["patterns"]:
                config[pattern_type]["patterns"].append(value)
            os.makedirs(os.path.dirname(file_path), exist_ok=True)
            with open(file_path, "w") as f:
                rtoml.dump(config, f)
        else:  # csv format
            file_path = os.path.join(self.config_path, f"{config_type}.csv")
            os.makedirs(os.path.dirname(file_path), exist_okay=True)
            with open(file_path, "a") as f:
                f.write(f"{pattern_type},{value}\n")

    def _save_to_file(self, config_type: str, pattern_type: str, value: str, format_type: str = "toml") -> None:
        """
        Save a pattern to either TOML or CSV configuration file.

        Args:
            config_type: Type of config ("secret" or "ignore")
            pattern_type: Type of pattern (e.g., "ipv4", "email")
            value: Pattern value to save
            format_type: File format ("toml" or "csv")
        """

        if format_type == "toml":
            file_path = os.path.join(self.config_path, f"{config_type}s.toml")
            config = self._load_config(f"{config_type}s")
            if pattern_type not in config:
                config[pattern_type] = {"patterns": []}
            if value not in config[pattern_type]["patterns"]:
                config[pattern_type]["patterns"].append(value)
            with open(file_path, "w") as f:
                rtoml.dump(config, f)
        else:  # csv format
            file_path = os.path.join(self.config_path, f"{config_type}s.csv")
            with open(file_path, "a") as f:
                f.write(f"{pattern_type},{value}\n")

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

    def _ask_user(self, value: str, pattern_type: str) -> bool:
        """Prompt the user to decide whether to redact a value."""
        print(f"\nFound a potential {pattern_type}: {value}")
        print("Options:")
        print("1. yes/y - Redact this occurrence only")
        print("2. no/n  - Don't redact this occurrence")
        print("3. always/a [toml|csv] - Always redact (save to secrets)")
        print("4. never/n [toml|csv] - Never redact (save to ignore)")

        while True:
            answer = input("Your choice: ").lower().strip()
            parts = answer.split()

            if answer in ["yes", "y"]:
                return True
            elif answer in ["no", "n"]:
                return False
            elif len(parts) == 2 and parts[0] in ["always", "a"]:
                format_type = parts[1] if parts[1] in ["toml", "csv"] else "toml"
                self._save_pattern("secrets", pattern_type, value, format_type)
                return True
            elif len(parts) == 2 and parts[0] == "never":
                format_type = parts[1] if parts[1] in ["toml", "csv"] else "toml"
                self._save_pattern("ignore", pattern_type, value, format_type)
                return False
            else:
                print("Invalid choice. Please try again.")

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

    @staticmethod
    def is_valid_phone(phone: str) -> bool:
        """Validate phone number format using pre-compiled patterns."""
        return any(pattern.match(phone) for pattern in Redactor.VALID_PHONE_PATTERNS)

    @staticmethod
    def is_valid_api_key(self, key: str) -> bool:
        """Validate API key using precompiled patterns."""
        return any(pattern.match(key) for pattern in self.API_KEY_PATTERNS)

    def _generate_unique_email(self) -> str:
        """Generate a unique redacted email address."""
        email = f"{REDACTED_EMAIL_BASE}{self.counter['email']:03}{REDACTED_EMAIL_DOMAIN}"
        self.counter['email'] += 1
        return email

    def _generate_unique_phone(self) -> str:
        """Generate a unique redacted phone number."""
        if self.counter['phone'] > REDACTED_PHONE_RANGE_END:
            self.counter['phone'] = REDACTED_PHONE_RANGE_START
        phone = f"{REDACTED_PHONE_BASE}{str(self.counter['phone']).zfill(4)}"
        self.counter['phone'] += 1
        return phone

    def _generate_unique_hostname(self) -> str:
        """Generate a unique redacted hostname."""
        hostname = f"{REDACTED_HOST_BASE}{self.counter['hostname']:03}"
        self.counter['hostname'] += 1
        return hostname

    def _generate_unique_url(self, value: str) -> str:
        """Generate a unique redacted URL, keeping the structure of the original URL."""
        parsed_url = urllib.parse.urlparse(value)
        scheme = parsed_url.scheme
        netloc = f"{REDACTED_URL_BASE}{self.counter['url']:03}"
        if parsed_url.port:
            netloc += f":{parsed_url.port}"

        path = parsed_url.path
        query = parsed_url.query
        redacted_url = f"{scheme}://{netloc}{path}"
        if query:
            redacted_url += f"?{query}"
        self.counter['url'] += 1
        return redacted_url


    def _generate_unique_api_key(self, value: str) -> str:
        """Generate a unique redacted API key, keeping the first part of the original key."""
        key_type = re.sub(r'\W+', '', value.split('=')[0])  # Remove non-alphanumeric characters
        api_key = f"{key_type}=redacted_api_key{self.counter['api_key']:03}"
        self.counter['api_key'] += 1
        return api_key

    def _generate_unique_mapping(self, value: str, pattern_type: str) -> str:
        """Generate a unique mapping for the given value based on its pattern type."""
        if value in self.unique_mapping:
            return self.unique_mapping[value]

        redacted_value = None
        if pattern_type == "ipv4":
            redacted_value = self.ipv4_generator.generate_unique_ipv4()
        elif pattern_type == "ipv6":
            redacted_value = self.ipv6_generator.generate_unique_ipv6()
        elif pattern_type == "phone":
            redacted_value = self._generate_unique_phone()
        elif pattern_type == "email":
            redacted_value = self._generate_unique_email()
        elif pattern_type == "url":
            redacted_value = self._generate_unique_url(value)
        elif pattern_type == "api_key":
            redacted_value = self._generate_unique_api_key(value)
        elif pattern_type == "hostname":
            redacted_value = self._generate_unique_hostname()

        if redacted_value:
            self.unique_mapping[value] = redacted_value
            return redacted_value

        return value

    def _redact_pattern(self, line: str, pattern_type: str) -> str:
        """Unified redaction method for all patterns"""
        pattern = self.PATTERNS.get(pattern_type)
        if not pattern:
            return line

        def replace_match(match):
            value = match.group(0)
            if self.should_redact_value(value, pattern_type):
                if pattern_type == "hostname":
                    return self._generate_unique_hostname()
                return self._generate_unique_mapping(value, pattern_type)
            return value

        return pattern.sub(replace_match, line)

        return pattern.sub(replace_match, line)

    def redact(self, lines: list) -> list:
        """Redact sensitive information from the given lines."""
        redacted_lines = []
        for line in lines:
            for pattern_type in self.PATTERNS:
                line = self._redact_pattern(line, pattern_type)
            redacted_lines.append(line)
        return redacted_lines

    def _is_binary_file(self, file_path: str) -> bool:
        """Check if file is binary by reading first chunk.
        TODO: Improve binary file detection."""
        chunk_size = 8192
        try:
            with open(file_path, 'rb') as f:
                chunk = f.read(chunk_size)
                return b'\0' in chunk  # Binary files typically contain null bytes
        except Exception:
            return False

    # def save_mappings_json(self, filename: str):
    #     """Save unique mappings to a file."""
    #     with open(filename, "w") as f:
    #         json.dump(self.unique_mapping, f, indent=4)

    def save_mappings(self, file_path: str, format_type: str = "toml") -> None:
        """
        Save the mapping to a file in specified format.

        Args:
            file_path: Path to the output file
            format_type: File format ("toml" or "csv"), defaults to "toml"
        """
        os.makedirs(os.path.dirname(file_path), exist_ok=True)

        if format_type == "toml":
            with open(file_path, 'w') as f:
                rtoml.dump({"mappings": self.unique_mapping}, f)
        else:  # csv format
            with open(file_path, 'w') as f:
                for original, redacted in self.unique_mapping.items():
                    f.write(f"{original},{redacted}\n")

    def redact_file(self, file: str, mapping_format: str = "toml"):
        """
        Redact a file in place.

        Args:
            file: Path to file to redact
            mapping_format: Format for saving mappings ("toml" or "csv")
        """
        try:
            if self._is_binary_file(file):
                print(f"Skipping binary file: {file}")
                return

            extension = pathlib.Path(file).suffix
            if not extension:
                extension = ".txt"

            with open(file) as f:
                lines = f.readlines()
            redacted_lines = self.redact(lines)
            with open(file + "-redacted" + extension, "w") as f:
                f.writelines(redacted_lines)

            # Save mappings in specified format
            mapping_ext = ".toml" if mapping_format == "toml" else ".csv"
            self.save_mappings(file + "-mappings" + mapping_ext, mapping_format)

            print(f"Redacted file saved as {file}-redacted{extension}")
            print(f"Mappings saved as {file}-mappings{mapping_ext}")
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
                    os.makedirs(extract_dir, exist_okay=True)
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
        description="""
        Redact sensitive information from files, directories, or archives.
        Supports multiple file formats including text, ZIP, TAR, GZ, and PDF.
        Can be configured using either TOML or CSV configuration files.
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument("path",
                        help="File, directory, or archive to redact")

    parser.add_argument("-i", "--interactive",
                        action="store_true",
                        help="Run in interactive mode, prompting for decisions")

    parser.add_argument("-c", "--config-path",
                        help="Path to directory containing config files (default: current directory)")

    parser.add_argument("--config-format",
                        choices=["toml", "csv"],
                        default="toml",
                        help="Configuration file format (default: toml)")

    parser.add_argument("-m", "--mapping-format",
                        choices=["toml", "csv"],
                        default="toml",
                        help="Mapping output file format (default: toml)")

    parser.add_argument("-v", "--verbose",
                        action="store_true",
                        help="Increase output verbosity")

    args = parser.parse_args()

    redactor = Redactor(
        interactive=args.interactive,
        config_path=args.config_path,
        config_format=args.config_format
    )

    if args.verbose:
        print(f"Using config path: {args.config_path or os.getcwd()}")
        print(f"Using config format: {args.config_format}")
        print(f"Using mapping format: {args.mapping_format}")

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
