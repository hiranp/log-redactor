# This script redacts sensitive information from a file.
# It can redact email addresses, IP addresses, phone numbers, names, and API keys.
# It can also redact custom patterns if interactive mode is enabled.
# The script reads from secrets.csv and ignore.csv to keep track of sensitive information and patterns to ignore.
# AUTHOR: HP

import argparse
import re


class Redactor:
    def __init__(self):
        pass


# This function takes a file and returns a list of all the lines in the file.
def get_file_lines(file):
    with open(file) as f:
        return f.readlines()


def addToSecrets(value, type):
    with open("secrets.csv", "a") as f:
        if f.tell() != 0:
            f.write("\n")
        f.write(f"{type},{value}")


def addToIgnore(value, type):
    with open("ignore.csv", "a") as f:
        if f.tell() != 0:
            f.write("\n")
        f.write(f"{type},{value}")


def askUser(value, type):
    print(f"Found a potential {type}: {value}")
    print("Would you like to redact? (yes/no/always/never)")
    while True:
        answer = input().lower()
        if answer in ["yes", "y"]:
            return True
        elif answer in ["no", "n"]:
            return False
        elif answer in ["always", "a"]:
            addToSecrets(value, type)
            return True
        elif answer == "never":
            addToIgnore(value, type)
            return False


def getLists(filename):
    with open(filename) as f:
        lines = f.readlines()
    lists = {"email": [], "ip": [], "phone": [], "name": [], "api": []}
    for line in lines:
        type, value = line.strip().split(",")
        lists[type].append(value)
    return lists


def redactor(line, secretArray, ignoreArray, type, interactive, pattern=None):
    for value in secretArray:
        if value in line:
            return (
                re.sub(re.escape(value), f"{type.upper()}_REDACTED", line),
                secretArray,
                ignoreArray,
            )
    if interactive and pattern:
        value = re.search(pattern, line)
        if value:
            value = value.group(0)
            if value not in ignoreArray and askUser(value, type):
                secretArray.append(value)
                return (
                    re.sub(re.escape(value), f"{type.upper()}_REDACTED", line),
                    secretArray,
                    ignoreArray,
                )
            else:
                ignoreArray.append(value)
    return line, secretArray, ignoreArray


def redactorAPI(line, secretArray, ignoreArray, type, interactive):
    apiStrings = ["token=", "key=", "api=", "apikey=", "apitoken="]
    for value in secretArray:
        if value in line:
            return (
                re.sub(re.escape(value), f"{type.upper()}_REDACTED", line),
                secretArray,
                ignoreArray,
            )
    if interactive:
        for apiString in apiStrings:
            if apiString in line:
                value = re.search(re.escape(apiString) + r"[^&\s]*", line)
                if value:
                    value = value.group(0).replace(apiString, "")
                    if value not in ignoreArray and askUser(value, type):
                        secretArray.append(value)
                        return (
                            re.sub(
                                re.escape(value),
                                f"{apiString}{type.upper()}_REDACTED",
                                line,
                            ),
                            secretArray,
                            ignoreArray,
                        )
                    else:
                        ignoreArray.append(value)
    return line, secretArray, ignoreArray


def parse(lines, interactive):
    secrets = getLists("secrets.csv")
    ignores = getLists("ignore.csv")
    stripped_lines = []
    for line in lines:
        line, secrets["email"], ignores["email"] = redactor(
            line,
            secrets["email"],
            ignores["email"],
            "email",
            interactive,
            r"[\w\.-]+@[\w\.-]+\.\w+",
        )
        line, secrets["ip"], ignores["ip"] = redactor(
            line,
            secrets["ip"],
            ignores["ip"],
            "ip",
            interactive,
            r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
        )
        line, secrets["phone"], ignores["phone"] = redactor(
            line,
            secrets["phone"],
            ignores["phone"],
            "phone",
            interactive,
            r"\b\d{3}[-.\s]?\d{3}[-.\s]?\d{4}\b",
        )
        line, secrets["name"], ignores["name"] = redactor(
            line, secrets["name"], ignores["name"], "name", interactive
        )
        line, secrets["api"], ignores["api"] = redactorAPI(
            line, secrets["api"], ignores["api"], "api", interactive
        )
        stripped_lines.append(line)
    return stripped_lines


def main():
    parser = argparse.ArgumentParser(
        description="Redact sensitive information from a file."
    )
    parser.add_argument("file", help="The file to redact")
    parser.add_argument(
        "-i", "--interactive", action="store_true", help="Run in interactive mode"
    )
    args = parser.parse_args()

    print(f"Redacting {args.file}")
    if args.interactive:
        print("Running in interactive mode")
    lines = get_file_lines(args.file)
    stripped_lines = parse(lines, args.interactive)
    with open(args.file + "-redacted", "w") as f:
        for line in stripped_lines:
            f.write(line)
    print(f"Redacted file saved as {args.file}-redacted")


if __name__ == "__main__":
    main()
