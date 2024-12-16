import argparse
import ipaddress
import json
import os
import pathlib
import re
import zipfile
from typing import ClassVar

try:
    import urllib.parse
except ImportError:
    print("Please install the urllib library using 'pip install urllib'")
    exit()

PDF_SUPPORT = True
try:
    import fitz  # PyMuPDF
except ImportError:
    PDF_SUPPORT = False
    print("PyMuPDF library not installed. PDF redaction will be disabled.")
    print("Please install it using 'pip install --upgrade pymupdf'")

class Redactor:
    """Class to redact sensitive information such as IPs, HOSTs, URLs, IPs, EMAILs, and API keys."""

    PATTERNS: ClassVar[dict] = {
        "ipv4": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
        "ipv6": re.compile(r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|\b(?:[0-9a-fA-F]{1,4}:){1,7}:\b|\b(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}\b|\b(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}\b|\b(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}\b|\b(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}\b|\b(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}\b|\b[0-9a-fA-F]{1,4}:(?::[0-9a-fA-F]{1,4}){1,6}\b|\b:(?::[0-9a-fA-F]{1,4}){1,7}\b|\b::(?:[0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4}\b|\b::(?:[0-9a-fA-F]{1,4}:){0,6}\b"),
        "url": re.compile(r"https?:\/\/(www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_\+.~#?&//=]*)"),
        "hostname": re.compile(r"(?=.{1,255}$)(?!-)[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?)*\.?"),
        "phone": re.compile(r"\b\d{3}[-.\s]?\d{3}[-.\s]?\d{4}\b"),
        "email": re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+"),
        "api": re.compile(r"(token|key|api|apikey|apitoken)=[^&\s]*")
    }

    VALIDATORS: ClassVar[dict] = {
        "ipv4": lambda x: Redactor.is_valid_ipv4(x),
        "ipv6": lambda x: Redactor.is_valid_ipv6(x),
        "url": lambda x: Redactor.is_valid_url(x),
        "hostname": lambda x: Redactor.is_valid_hostname(x)
    }

    def __init__(self, interactive: bool = False):
        self.interactive = interactive
        self.secrets = self._load_lists("secrets.csv")
        self.ignores = self._load_lists("ignore.csv")
        self.unique_mapping = {}
        self.ip_counter = 1
        self.counter = {key: 1 for key in self.PATTERNS.keys()}

    def _load_lists(self, filename: str) -> dict[str, list[str]]:
        """Load secrets or ignore lists from a file."""
        lists = {key: [] for key in self.PATTERNS.keys()}
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

    def save_mappings(self, filename: str):
        """Save unique mappings to a file."""
        with open(filename, "w") as f:
            json.dump(self.unique_mapping, f, indent=4)

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

    def _generate_unique_mapping(self, value: str, secret_type: str) -> str:
        """Generate a unique mapping for redacted values."""
        if value not in self.unique_mapping:
            if secret_type == "ipv4":
                mapped_ip = f"240.0.0.{self.ip_counter}"
                self.unique_mapping[value] = mapped_ip
                self.ip_counter += 1
            else:
                mapped_value = f"{secret_type.upper()}_{self.counter[secret_type]}"
                self.unique_mapping[value] = mapped_value
                self.counter[secret_type] += 1
        return self.unique_mapping[value]

    def _redact_pattern(self, line: str, pattern_type: str) -> str:
        """Unified redaction method for all patterns"""
        pattern = self.PATTERNS.get(pattern_type)
        if not pattern:
            return line

        matches = pattern.finditer(line)
        ignore_set = set(self.ignores.get(pattern_type, []))

        for match in matches:
            value = match.group(0)
            if value not in ignore_set:
                # Validate if validator exists
                validator = self.VALIDATORS.get(pattern_type)
                if validator and not validator(value):
                    continue
                replacement = self._generate_unique_mapping(value, pattern_type)
                line = re.sub(re.escape(value), replacement, line)

        return line

    def redact(self, lines: list[str]) -> list[str]:
        """Redact sensitive information from a list of lines."""
        redacted_lines = []
        for line in lines:
            for pattern_type in self.PATTERNS.keys():
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
            self.save_mappings(file + "-mappings.json")
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
            self.save_mappings(pdf_file.replace(".pdf", "-mappings.json"))
            print(f"Redacted PDF saved as {redacted_pdf_file}")
        except Exception as e:
            print(f"An error occurred while redacting the PDF file: {e}")

def main():
    parser = argparse.ArgumentParser(
        description="Redact sensitive information from a file, directory, or a zip archive."
    )
    parser.add_argument("path", help="The file, directory, or zip archive to redact")
    parser.add_argument(
        "-i", "--interactive", action="store_true", help="Run in interactive mode"
    )
    args = parser.parse_args()

    redactor = Redactor(interactive=args.interactive)

    if os.path.isdir(args.path):
        redactor.redact_directory(args.path)
    elif args.path.endswith('.zip'):
        redactor.extract_and_redact_zip(args.path)
    elif args.path.endswith('.pdf'):
        redactor.redact_pdf(args.path)
    else:
        redactor.redact_file(args.path)

if __name__ == "__main__":
    main()
