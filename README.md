# log-redactor

[![Release](https://img.shields.io/github/v/release/hiranp/log-redactor)](https://img.shields.io/github/v/release/hiranp/log-redactor)
[![Build status](https://img.shields.io/github/actions/workflow/status/hiranp/log-redactor/main.yml?branch=main)](https://github.com/hiranp/log-redactor/actions/workflows/main.yml?query=branch%3Amain)
[![codecov](https://codecov.io/gh/hiranp/log-redactor/branch/main/graph/badge.svg)](https://codecov.io/gh/hiranp/log-redactor)
[![Commit activity](https://img.shields.io/github/commit-activity/m/hiranp/log-redactor)](https://img.shields.io/github/commit-activity/m/hiranp/log-redactor)
[![License](https://img.shields.io/github/license/hiranp/log-redactor)](https://img.shields.io/github/license/hiranp/log-redactor)

Utility to redact/mask key parts of logs and other files that need to be shared. It can redact email addresses, IP addresses, phone numbers, names, URLs, and API keys. It can also redact custom patterns if interactive mode is enabled. The script reads from `secrets.csv` and `ignore.csv` to keep track of sensitive information and patterns to ignore.

- **GitHub repository**: <https://github.com/hiranp/log-redactor/>
- **Documentation**: <https://hiranp.github.io/log-redactor/>

## Features

Support for redacting the following types of data:

- IPv4 and IPv6 addresses
- URLs
- Hostnames
- Phone Numbers
- Email Addresses
- API Keys

## Usage

1. **Basic Redaction**: Run `python3 redactor.py <path>` where `<path>` is the file, directory, or zip archive you want to redact.
2. **Interactive Mode**: Run `python3 redactor.py <path> -i` to redact interactively.
3. **PDF Redaction**: Ensure `PyMuPDF` is installed. Run `python3 redactor.py <path>` where `<path>` is a PDF file.

The redacted file is saved as `<original-filename>-redacted.<extension>`.

## How it works

The script uses a list of regular expressions to find sensitive data in the file. It then replaces the sensitive data with a redacted version of itself. For example, `102.23.5.1` becomes `240.0.0.1`.

### Interactive Mode

In interactive mode, the script will ask you to confirm each redaction. You can choose to always redact that data, never redact that data, or redact/not redact just that instance of the data. If you are not in interactive mode, the script will always try to redact the data.

## Installation

1. Clone the repository:

    ```sh
    git clone https://github.com/hiranp/log-redactor.git
    cd log-redactor
    ```

2. Install the required dependencies:

    ```sh
    pip install -r requirements.txt
    ```

3. (Optional) Install `PyMuPDF` for PDF redaction:

    ```sh
    pip install pymupdf
    ```

## TODO

- [ ] Add support for redacting social security numbers
- [ ] Add support for incorporating custom patterns
- [ ] Add support for incorporating ML models to redact data more accurately
- [ ] Add support for redacting data in multiple files at once

## Credits

Inspired by [PyRedactKit](https://github.com/brootware/PyRedactKit)
