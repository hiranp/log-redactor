use std::net::Ipv4Addr;

pub struct IPv4Generator {
    base_ipv4: Ipv4Addr,
    ipv4_counter: u32,
    max_addresses: u32,
}

impl IPv4Generator {
    pub fn new() -> Self {
        IPv4Generator {
            base_ipv4: Ipv4Addr::new(240, 0, 0, 0),
            ipv4_counter: 0,
            max_addresses: 2u32.pow(28), // 240.0.0.0/4 range
        }
    }

    pub fn generate_unique_ipv4(&mut self) -> Result<String, String> {
        if self.ipv4_counter >= self.max_addresses {
            return Err("No more IPv4 addresses available in the 240.0.0.0/4 range.".to_string());
        }
        let mapped_ipv4 = self.base_ipv4.octets();
        let new_ip = Ipv4Addr::new(
            mapped_ipv4[0],
            mapped_ipv4[1],
            mapped_ipv4[2],
            mapped_ipv4[3] + self.ipv4_counter as u8,
        );
        self.ipv4_counter += 1;
        Ok(new_ip.to_string())
    }
}
