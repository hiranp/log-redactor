# log-redactor

[![Release](https://img.shields.io/github/v/release/hiranp/log-redactor)](https://img.shields.io/github/v/release/hiranp/log-redactor)
[![Build status](https://img.shields.io/github/actions/workflow/status/hiranp/log-redactor/CI?branch=main)](https://github.com/hiranp/log-redactor/actions?query=branch%3Amain)
[![codecov](https://codecov.io/gh/hiranp/log-redactor/branch/main/graph/badge.svg)](https://codecov.io/gh/hiranp/log-redactor)
[![Commit activity](https://img.shields.io/github/commit-activity/m/hiranp/log-redactor)](https://img.shields.io/github/commit-activity/m/hiranp/log-redactor)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

Utility to redact/mask key parts of logs and other files that need to be shared with breaking orignal log structure.  It can redact IPV4 and IPV6 addresses, hostnames, URLs, email addresses, phone numbers, names, and API keys. It can also redact custom patterns if interactive mode is enabled. The script reads from `secrets.csv` and `ignore.csv` to keep track of sensitive information and patterns to ignore.

The underlying redaction logic is implemented in both Python and Rust. The Python implementation is more feature-rich and supports redacting data from a variety of file types, including PDFs. The Rust implementation is faster and can redact data from tar, tar.gz, tgz, zip, and PDF files.

Unique features of the script include:

- The **redaction output** conforms to original data types (e.g., IP addresses are redacted to valid IP addresses) to ensure the entire log remains valid and usable
- Keeps track of redacted data in redacted-mapping.txt for future reference
- Redaction of sensitive data from a variety of file types, including PDFs
- Interactive mode to confirm redaction of sensitive data
- Support for custom patterns in `secrets.csv` and `ignore.csv`
- Support for redacting data from tar, tar.gz, tgz, zip, and PDF files

**GitHub repository**: <https://github.com/hiranp/log-redactor/>
**Documentation**: <https://github.com/hiranp/log-redactor/blob/main/docs/index.md>

## Features

Support for redacting the following types of data:

- IPv4 and IPv6 addresses
- URLs
- Hostnames
- Phone Numbers
- Email Addresses
- API Keys

## Python Usage

1. **Basic Redaction**: Run `python3 redactor.py <path>` where `<path>` is the file, directory, or (tar, gzip, or zip) archive you want to redact.
2. **Interactive Mode**: Run `python3 redactor.py <path> -i` to redact interactively.
3. **PDF Redaction**: Ensure `PyMuPDF` is installed. Run `python3 redactor.py <path>` where `<path>` is a PDF file. [Note: PDF redaction is experimental and may not work as expected.]

The redacted file is saved as `<original-filename>-redacted.<extension>`.

## Rust Usage

1. **Basic Redaction**: Run `cargo run --release -- <path>` where `<path>` is the file, directory, or archive (tar, tar.gz, tgz, zip, or pdf) you want to redact.
2. **Interactive Mode**: Run `cargo run --release -- <path> -i yes` to redact interactively. Enter 'yes' or 'no' when prompted.
3. **Specify Secrets File**: Use the `-s` or `--secrets` flag to specify the path to the secrets file. Example: `cargo run --release -- <path> -s /path/to/secrets.csv`
4. **Specify Ignores File**: Use the `-g` or `--ignores` flag to specify the path to the ignores file. Example: `cargo run --release -- <path> -g /path/to/ignore.csv`

### Examples

- **Redact a directory**:

  ```sh
  cargo run --release -- /path/to/directory
    ```

- **Redact a file**:

  ```sh
  cargo run --release -- /path/to/file.txt (tar.gz, tgz, zip, pdf)
  ```

- **Redact interactively**:

  ```sh
    cargo run --release -- /path/to/file.txt -i yes
    ```

- **Redact a file with custom secrets and ignores**:

    ```sh
    cargo run --release -- /path/to/file.txt -s /path/to/secrets.csv -g /path/to/ignore.csv
    ```

- **More help**:

  ```sh
  cargo run --release -- --help
  ```

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

- [x] Complete rust implementation
- [ ] Use third-party libraries to validate strings before redacting
  - [ ] Use [garde](https://docs.rs/garde/latest/garde/)
  - [ ] Use validators from [validators](https://docs.rs/validators/latest/validators/)
  - [ ] Use [phonenumbers](https://pypi.org/project/phonenumbers/) to validate phone numbers
- [ ] Improve redaction of pdf files
- [ ] Add support for incorporating custom patterns
- [ ] Add support for incorporating ML models to redact data more accurately
- [ ] Add support for redacting data in multiple files at once
- [ ] Add support for redacting social security numbers

## Credits

Inspired by [PyRedactKit](https://github.com/brootware/PyRedactKit)
