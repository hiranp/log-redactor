pub struct IncrementalPhoneNumberGenerator {
    area_code: String,
    exchange_code: String,
    subscriber_end: u32,
    current_subscriber: u32,
}

impl IncrementalPhoneNumberGenerator {
    pub fn new(
        area_code: &str,
        exchange_code: &str,
        subscriber_start: u32,
        subscriber_end: u32,
    ) -> Self {
        IncrementalPhoneNumberGenerator {
            area_code: area_code.to_string(),
            exchange_code: exchange_code.to_string(),
            subscriber_end,
            current_subscriber: subscriber_start,
        }
    }

    pub fn generate(&mut self) -> Option<String> {
        if self.current_subscriber > self.subscriber_end {
            return None;
        }

        let phone_number = format!(
            "({}) {}-{:04}",
            self.area_code, self.exchange_code, self.current_subscriber
        );

        self.current_subscriber += 1;
        Some(phone_number)
    }
}

// Example usage
fn main() {
    let mut generator = IncrementalPhoneNumberGenerator::new("800", "555", 1000, 1010);
    while let Some(phone_number) = generator.generate() {
        println!("{}", phone_number);
    }
}
