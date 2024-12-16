import ipaddress


class IPv6Generator:
    def __init__(self):
        # Start at the base of the 3fff::/20 range
        self.base_ipv6 = ipaddress.IPv6Address("3fff::")
        self.ipv6_counter = 0
        # Calculate the total number of addresses in the 3fff::/20 range (2^(128 - 20))
        self.max_addresses = 2 ** (128 - 20)

    def generate_unique_ipv6(self) -> str:
        """Generate a unique IPv6 address within the 3fff::/20 range."""
        if self.ipv6_counter >= self.max_addresses:
            raise ValueError("No more IPv6 addresses available in the 3fff::/20 range.")

        # Generate the next IPv6 address
        mapped_ipv6 = self.base_ipv6 + self.ipv6_counter
        self.ipv6_counter += 1
        return str(mapped_ipv6)

# Example usage
if __name__ == "__main__":
    ipv6_gen = IPv6Generator()
    for _ in range(10):  # Generate 10 IPv6 addresses for demonstration
        print(ipv6_gen.generate_unique_ipv6())
