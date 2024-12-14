# redact
A semi-intelligent automated script for redacting sensitive data from files

## Usage
1. Run `python3 redact.py file` where `file` is the file you want to redact. If you want to redact interactively, run `python3 redact.py file -i` instead.
2. The redacted file is saved as `file-redacted`

## How it works

The script uses a list of regular expressions to find sensitive data in the file. It then replaces the sensitive data with a redacted version of itself. For example, `123-456-7890` becomes `XXX-XXX-XXXX`.

### Interactive Mode

In interactive mode, the script will ask you to confirm each redaction. You can choose to always redact that data, never redact that data, or redact/not redact just that instance of the data. If you are not in interactive mode, the script will always try to redact the data.

### Redacted Data Types

- Names
- Phone Numbers
- Email Addresses
- IP Addresses
- API Keys
