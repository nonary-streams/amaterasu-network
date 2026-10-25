const NO_HARDWARE_ADDRESS: &str = "00:00:00:00:00:00";

pub(super) fn mac() -> &'static str {
    static ADDRESS: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    ADDRESS.get_or_init(|| hardware_address().unwrap_or_else(|| NO_HARDWARE_ADDRESS.into()))
}

/// Best-effort MAC of the first physical network interface, for Wake-on-LAN.
/// Virtual, loopback and unreadable interfaces yield `None` (all zeros).
#[cfg(target_os = "linux")]
fn hardware_address() -> Option<String> {
    let mut names: Vec<_> = std::fs::read_dir("/sys/class/net")
        .ok()?
        .filter_map(|entry| entry.ok()?.file_name().into_string().ok())
        .collect();
    names.sort();
    names.into_iter().find_map(|name| {
        let base = std::path::Path::new("/sys/class/net").join(&name);
        // Physical interfaces expose a backing `device`; bridges, veths and
        // tunnels do not.
        base.join("device").exists().then_some(())?;
        let address = std::fs::read_to_string(base.join("address")).ok()?;
        valid_hardware_address(address.trim())
    })
}

#[cfg(not(target_os = "linux"))]
fn hardware_address() -> Option<String> {
    None
}

#[cfg(any(target_os = "linux", test))]
fn valid_hardware_address(text: &str) -> Option<String> {
    let octets: Vec<_> = text.split(':').collect();
    let well_formed = octets.len() == 6
        && octets
            .iter()
            .all(|octet| octet.len() == 2 && octet.bytes().all(|byte| byte.is_ascii_hexdigit()));
    (well_formed && text != NO_HARDWARE_ADDRESS).then(|| text.to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn hardware_address_is_validated() {
        assert_eq!(
            valid_hardware_address("AA:bb:0c:0D:ee:ff").as_deref(),
            Some("aa:bb:0c:0d:ee:ff")
        );
        for text in [
            "",
            "00:00:00:00:00:00",
            "aa:bb:cc:dd:ee",
            "aa:bb:cc:dd:ee:g0",
        ] {
            assert!(valid_hardware_address(text).is_none());
        }
    }
}
