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
3. **PDF Redaction**: Ensure `PyMuPDF` is installed. Run `python3 redactor.py <path>` where `<path>` is a PDF file. [Note: PDF redaction is experimental and may not work as expected.]

The redacted file is saved as `<original-filename>-redacted.<extension>`.

## How it works

The script uses a list of regular expressions to find sensitive data in the file. It then replaces the sensitive data with a redacted version of itself. For example, `102.23.5.1` becomes `240.0.0.1`.

Based on Wikipedia's [Reserved IP addresses](https://en.wikipedia.org/wiki/Reserved_IP_addresses) page, the script uses the following reserved IP addresses for redaction:
For IP4 addresses, the script uses 240.0.0.0/4 as the redacted IP address.
For IP6 addresses, the script uses 3fff::/20 as the redacted IP address.

For numbers, the script uses (800) 555‑0100 through (800) 555‑0199 range. See <https://en.wikipedia.org/wiki/555_(telephone_number)> for more information.

For email addresses, the script uses `redacted.user@example.com` as the redacted email address. See <https://en.wikipedia.org/wiki/Example.com> for more information.

### `secrets.csv` and `ignore.csv`

The script reads from `secrets.csv` and `ignore.csv` to manage sensitive information that should be redacted or ignored during the redaction process.

#### `secrets.csv`

This file contains patterns of sensitive information that should always be redacted. Each line in the file specifies a type of sensitive information (e.g., `ipv4`, `email`, etc.) and the corresponding value to be redacted.

Example:

```csv
ipv4,192.168.1.1
email,john.doe@example.com
phone,123-456-7890
hostname,example.com
url,https://www.example.com
api,apikey=1234567890abcdef
```

#### `ignore.csv`

This file contains patterns of information that should be ignored during the redaction process. Each line in the file specifies a type of information T(e.g., ipv4, email, etc.) and the corresponding value to be ignored.

Example:

```csv
ipv4,127.0.0.1
email,admin@example.com
phone,555-555-5555
hostname,localhost
url,http://localhost
api,apikey=ignorethisapikey
```

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

- [ ] Complete rust implementation
- [ ] Improve redaction of pdf files
- [ ] Add support for redacting names
- [ ] Add support for incorporating custom patterns
- [ ] Add support for incorporating ML models to redact data more accurately
- [ ] Add support for redacting data in multiple files at once
- [ ] Add support for redacting social security numbers
- [ ] Possibly add [phonenumbers](https://pypi.org/project/phonenumbers/) library to redact phone numbers more accurately

## Credits

Inspired by [PyRedactKit](https://github.com/brootware/PyRedactKit)
