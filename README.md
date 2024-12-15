# log-redactor

[![Release](https://img.shields.io/github/v/release/hiranp/log-redactor)](https://img.shields.io/github/v/release/hiranp/log-redactor)
[![Build status](https://img.shields.io/github/actions/workflow/status/hiranp/log-redactor/main.yml?branch=main)](https://github.com/hiranp/log-redactor/actions/workflows/main.yml?query=branch%3Amain)
[![codecov](https://codecov.io/gh/hiranp/log-redactor/branch/main/graph/badge.svg)](https://codecov.io/gh/hiranp/log-redactor)
[![Commit activity](https://img.shields.io/github/commit-activity/m/hiranp/log-redactor)](https://img.shields.io/github/commit-activity/m/hiranp/log-redactor)
[![License](https://img.shields.io/github/license/hiranp/log-redactor)](https://img.shields.io/github/license/hiranp/log-redactor)

Utility to redact / mask key parts of logs and other files that need to be shared
It can redact email addresses, IP addresses, phone numbers, names, and API keys.
It can also redact custom patterns if interactive mode is enabled.
The script reads from secrets.csv and ignore.csv to keep track of sensitive information and patterns to ignore.

- **Github repository**: <https://github.com/hiranp/log-redactor/>
- **Documentation** <https://hiranp.github.io/log-redactor/>

## Features

Support for redacting the following types of data:

- IP 4 and 6 addresses
- URLs
- Names
- Phone Numbers
- Email Addresses
- API Keys  

## Usage

1. Run `python3 redact.py file` where `file` is the file you want to redact. If you want to redact interactively, run `python3 redact.py file -i` instead.
2. The redacted file is saved as `file-redacted`

## How it works

The script uses a list of regular expressions to find sensitive data in the file. It then replaces the sensitive data with a redacted version of itself. For example, `123-456-7890` becomes `XXX-XXX-XXXX`.

### Interactive Mode

In interactive mode, the script will ask you to confirm each redaction. You can choose to always redact that data, never redact that data, or redact/not redact just that instance of the data. If you are not in interactive mode, the script will always try to redact the data.
