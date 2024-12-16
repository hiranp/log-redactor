import ipaddress

class IPv4Generator:
    def __init__(self):
        # Define the base of the 240.0.0.0/4 range
        self.base_ipv4 = ipaddress.IPv4Address("240.0.0.0")
        # Calculate the total number of addresses in the 240.0.0.0/4 range (2^(32 - 4))
        self.max_addresses = 2 ** (32 - 4)
        self.ipv4_counter = 0

    def generate_unique_ipv4(self) -> str:
        """Generate a unique IPv4 address within the 240.0.0.0/4 range."""
        if self.ipv4_counter >= self.max_addresses:
            raise ValueError("No more IPv4 addresses available in the 240.0.0.0/4 range.")

        # Generate the next IPv4 address
        mapped_ipv4 = self.base_ipv4 + self.ipv4_counter
        self.ipv4_counter += 1
        return str(mapped_ipv4)

# Example usage
if __name__ == "__main__":
    ipv4_gen = IPv4Generator()
    for _ in range(10):  # Generate 10 IPv4 addresses for demonstration
        print(ipv4_gen.generate_unique_ipv4())