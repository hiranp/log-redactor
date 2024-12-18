use lazy_static::lazy_static;

lazy_static! {
    pub static ref FULL_VERSION: String = {
        let pkg_version = env!("CARGO_PKG_VERSION");
        if pkg_version.contains('-') {
            pkg_version.to_string()
        } else {
            format!("{}-{}", pkg_version, env!("BUILD_DATE"))
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_format() {
        let version = FULL_VERSION.as_str();
        println!("Full version string: {}", version);

        let parts: Vec<&str> = version.split('-').collect();
        assert_eq!(parts.len(), 2, "Version should have version and date parts");

        let version_part = parts[0];
        let date_part = parts[1];

        println!("Version part: {}", version_part);
        println!("Date part: {}", date_part);

        // Verify date part is 8 digits
        assert_eq!(date_part.len(), 8, "Date should be 8 digits");
        assert!(date_part.parse::<u64>().is_ok(), "Date should be numeric");

        // Check version components
        let version_components: Vec<&str> = version_part.split('.').collect();
        assert_eq!(
            version_components.len(),
            3,
            "Version should have major.minor.patch"
        );

        for component in version_components {
            assert!(
                component.parse::<u32>().is_ok(),
                "Version components should be numeric"
            );
        }
    }
}
