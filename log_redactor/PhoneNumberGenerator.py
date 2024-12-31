import random
import re


class IncrementalPhoneNumberGenerator:
    def __init__(self):
        # Define the base area code and central office code
        self.area_code = "800"
        self.central_office_code = "555"
        self.subscriber_start = 100  # Start of the subscriber range
        self.subscriber_end = 199    # End of the subscriber range
        self.current_subscriber = self.subscriber_start  # Initialize the counter
        # Predefined formats for phone numbers
        self.FORMATS = [
            "({}) {}-{:04d}",  # (800) 555-0100
            "{}-{}-{:04d}",    # 800-555-0100
            "{}.{}.{}",        # 800.555.0100
            "{} {} {}",        # 800 555 0100
        ]
        # Custom regex for validation
        self.phone_regex = re.compile(r"""
            \b                       # Word boundary
            (?:\(\d{3}\) |\d{3}[-.\s]?) # Area code with or without parentheses
            \d{3}[-.\s]?             # Central office code
            \d{4}                    # Subscriber number
            \b                       # Word boundary
        """, re.VERBOSE)

    def generate_phone_number(self) -> str:
        """Generate a phone number using incremental logic."""
        # Validate range exhaustion
        if self.current_subscriber > self.subscriber_end:
            raise ValueError("No more numbers available in the defined range.")

        # Select a format and generate the phone number
        fmt = random.choice(self.FORMATS)
        phone_number = fmt.format(self.area_code, self.central_office_code, self.current_subscriber)

        # Increment the subscriber number
        self.current_subscriber += 1

        # Validate the generated number against the regex
        if not self.phone_regex.match(phone_number):
            raise ValueError(f"Generated phone number {phone_number} does not match the regex.")

        return phone_number


# Example Usage
if __name__ == "__main__":
    phone_gen = IncrementalPhoneNumberGenerator()
    for _ in range(10):  # Generate 10 phone numbers
        print(phone_gen.generate_phone_number())
