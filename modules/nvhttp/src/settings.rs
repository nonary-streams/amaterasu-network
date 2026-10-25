use crate::launch::StreamingConfig;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

const FALLBACK_HOSTNAME: &str = "Amaterasu";
const HOSTNAME_BUFFER_LENGTH: usize = 256;
pub const DEFAULT_PORT: u16 = 47_989;
pub const MIN_PORT: u16 = 1_029;
pub const MAX_PORT: u16 = 65_514;
pub const HTTPS_PORT_OFFSET: u16 = 5;

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum AddressFamily {
    #[default]
    Ipv4,
    Both,
}

#[derive(Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Settings {
    pub enabled: bool,
    pub http_bind: SocketAddr,
    pub https_bind: SocketAddr,
    pub address_family: Option<AddressFamily>,
    pub bind_address: Option<String>,
    pub allow_remote: bool,
    pub hostname: String,
    pub streaming: Option<StreamingConfig>,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            enabled: false,
            http_bind: SocketAddr::from(([127, 0, 0, 1], 47989)),
            https_bind: SocketAddr::from(([127, 0, 0, 1], 47984)),
            address_family: None,
            bind_address: None,
            allow_remote: false,
            hostname: default_hostname(),
            streaming: None,
        }
    }
}

impl Settings {
    pub fn validate(&self) -> Result<(), &'static str> {
        let http_binds = self.resolved_http_binds()?;
        let https_binds = self.resolved_https_binds()?;
        validate_configured_hostname(&self.hostname)?;
        validate_hostname(&effective_hostname(&self.hostname))?;
        if http_binds
            .iter()
            .any(|http| http.port() != 0 && https_binds.iter().any(|https| https == http))
        {
            return Err("listener_addresses_conflict");
        }
        if let Some(streaming) = &self.streaming {
            streaming.validate()?;
        }
        Ok(())
    }

    #[cfg(test)]
    pub fn resolved_http_bind(&self) -> Result<SocketAddr, &'static str> {
        self.resolved_http_binds()?
            .into_iter()
            .next()
            .ok_or("invalid_bind_address")
    }

    #[cfg(test)]
    pub fn resolved_https_bind(&self) -> Result<SocketAddr, &'static str> {
        self.resolved_https_binds()?
            .into_iter()
            .next()
            .ok_or("invalid_bind_address")
    }

    pub fn resolved_http_binds(&self) -> Result<Vec<SocketAddr>, &'static str> {
        self.resolved_http_binds_with(self.address_family, self.bind_address.as_deref())
    }

    pub fn resolved_https_binds(&self) -> Result<Vec<SocketAddr>, &'static str> {
        self.resolved_https_binds_with(self.address_family, self.bind_address.as_deref())
    }

    pub fn resolved_http_binds_with(
        &self,
        address_family: Option<AddressFamily>,
        bind_address: Option<&str>,
    ) -> Result<Vec<SocketAddr>, &'static str> {
        self.resolve_binds(self.http_bind, address_family, bind_address)
    }

    pub fn resolved_https_binds_with(
        &self,
        address_family: Option<AddressFamily>,
        bind_address: Option<&str>,
    ) -> Result<Vec<SocketAddr>, &'static str> {
        self.resolve_binds(self.https_bind, address_family, bind_address)
    }

    pub fn validate_network_policy(
        &self,
        address_family: Option<AddressFamily>,
        bind_address: Option<&str>,
    ) -> Result<(), &'static str> {
        let http_binds = self.resolve_binds(self.http_bind, address_family, bind_address)?;
        let https_binds = self.resolve_binds(self.https_bind, address_family, bind_address)?;
        if http_binds
            .iter()
            .any(|http| http.port() != 0 && https_binds.iter().any(|https| https == http))
        {
            return Err("listener_addresses_conflict");
        }
        Ok(())
    }

    pub fn effective_address_family(
        &self,
        address_family: Option<AddressFamily>,
        bind_address: Option<&str>,
        legacy_ip: IpAddr,
    ) -> AddressFamily {
        address_family.unwrap_or_else(|| {
            let ip = bind_address
                .and_then(|address| address.trim().parse::<IpAddr>().ok())
                .unwrap_or(legacy_ip);
            if ip.is_ipv4() {
                AddressFamily::Ipv4
            } else {
                AddressFamily::Both
            }
        })
    }

    fn resolve_binds(
        &self,
        legacy: SocketAddr,
        address_family: Option<AddressFamily>,
        bind_address: Option<&str>,
    ) -> Result<Vec<SocketAddr>, &'static str> {
        let family = self.effective_address_family(address_family, bind_address, legacy.ip());
        let addresses = match bind_address {
            Some(address) if !address.trim().is_empty() => vec![
                address
                    .trim()
                    .parse::<IpAddr>()
                    .map_err(|_| "invalid_bind_address")?,
            ],
            None if address_family.is_none() => vec![legacy.ip()],
            Some(_) if address_family.is_none() => match (family, self.allow_remote) {
                (AddressFamily::Ipv4, true) => vec![IpAddr::V4(Ipv4Addr::UNSPECIFIED)],
                (AddressFamily::Ipv4, false) => vec![legacy.ip()],
                (AddressFamily::Both, true) => vec![
                    IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                    IpAddr::V6(Ipv6Addr::UNSPECIFIED),
                ],
                (AddressFamily::Both, false) => vec![
                    IpAddr::V4(Ipv4Addr::LOCALHOST),
                    IpAddr::V6(Ipv6Addr::LOCALHOST),
                ],
            },
            _ => match (family, self.allow_remote) {
                (AddressFamily::Ipv4, true) => vec![IpAddr::V4(Ipv4Addr::UNSPECIFIED)],
                (AddressFamily::Ipv4, false) => vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
                (AddressFamily::Both, true) => vec![
                    IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                    IpAddr::V6(Ipv6Addr::UNSPECIFIED),
                ],
                (AddressFamily::Both, false) => vec![
                    IpAddr::V4(Ipv4Addr::LOCALHOST),
                    IpAddr::V6(Ipv6Addr::LOCALHOST),
                ],
            },
        };
        addresses
            .into_iter()
            .map(|ip| {
                if !family.supports(ip) {
                    return Err("address_family_mismatch");
                }
                if invalid_configured_bind(ip) || (!self.allow_remote && !ip.is_loopback()) {
                    return Err(if !self.allow_remote && !ip.is_loopback() {
                        "remote_binding_requires_allow_remote"
                    } else {
                        "invalid_bind_address"
                    });
                }
                Ok(SocketAddr::new(ip, legacy.port()))
            })
            .collect()
    }
}

impl AddressFamily {
    fn supports(self, address: IpAddr) -> bool {
        matches!(self, Self::Both) || address.is_ipv4()
    }
}

fn invalid_configured_bind(address: IpAddr) -> bool {
    address.is_multicast()
        || address == IpAddr::V4(Ipv4Addr::BROADCAST)
        || matches!(address, IpAddr::V6(address) if address.to_ipv4_mapped().is_some())
}

/// Returns the configured hostname, or the machine hostname when the setting is blank.
pub fn effective_hostname(configured: &str) -> String {
    if configured.is_empty() {
        default_hostname()
    } else {
        configured.to_owned()
    }
}

fn default_hostname() -> String {
    hostname_or_fallback(system_hostname())
}

fn hostname_or_fallback(hostname: Option<String>) -> String {
    hostname
        .filter(|hostname| validate_hostname(hostname).is_ok())
        .unwrap_or_else(|| FALLBACK_HOSTNAME.into())
}

#[cfg(unix)]
fn system_hostname() -> Option<String> {
    use std::ffi::{CStr, c_char};

    unsafe extern "C" {
        fn gethostname(name: *mut c_char, length: usize) -> i32;
    }

    // Reserve the final byte for a terminator if the platform fills the buffer.
    let mut buffer = [0 as c_char; HOSTNAME_BUFFER_LENGTH];
    // SAFETY: `buffer` is process-owned and writable for `HOSTNAME_BUFFER_LENGTH`
    // bytes. The synchronous POSIX call may write at most the provided length and
    // does not retain the pointer after returning.
    let result = unsafe { gethostname(buffer.as_mut_ptr(), HOSTNAME_BUFFER_LENGTH - 1) };
    if result != 0 {
        return None;
    }

    // SAFETY: the buffer remains owned and alive here. It was zero-initialized
    // and its final byte was excluded from the OS write, so it contains a NUL
    // terminator and the returned CStr borrow cannot outlive this buffer.
    let hostname = unsafe { CStr::from_ptr(buffer.as_ptr()) }
        .to_string_lossy()
        .into_owned();
    (!hostname.is_empty()).then_some(hostname)
}

#[cfg(windows)]
fn system_hostname() -> Option<String> {
    #[link(name = "Kernel32")]
    unsafe extern "system" {
        #[link_name = "GetComputerNameW"]
        fn get_computer_name(buffer: *mut u16, length: *mut u32) -> i32;
    }

    let mut buffer = [0_u16; HOSTNAME_BUFFER_LENGTH];
    let mut length = HOSTNAME_BUFFER_LENGTH as u32;
    // SAFETY: `buffer` is process-owned and remains alive for this synchronous
    // call. The Win32 function receives its writable code-unit capacity and does
    // not retain the pointer after returning.
    let result = unsafe { get_computer_name(buffer.as_mut_ptr(), &mut length) };
    if result == 0 || length == 0 || length as usize > buffer.len() {
        return None;
    }
    String::from_utf16(&buffer[..length as usize]).ok()
}

#[cfg(not(any(unix, windows)))]
fn system_hostname() -> Option<String> {
    None
}

pub(crate) fn validate_configured_hostname(hostname: &str) -> Result<(), &'static str> {
    if hostname.len() > 128 || hostname.chars().any(char::is_control) {
        Err("invalid_hostname")
    } else {
        Ok(())
    }
}

pub fn validate_hostname(hostname: &str) -> Result<(), &'static str> {
    if hostname.is_empty() {
        Err("invalid_hostname")
    } else {
        validate_configured_hostname(hostname)
    }
}

pub fn validate_port(port: u16) -> Result<(), &'static str> {
    if (MIN_PORT..=MAX_PORT).contains(&port) {
        Ok(())
    } else {
        Err("invalid_port")
    }
}

pub fn https_port(port: u16) -> u16 {
    port - HTTPS_PORT_OFFSET
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn defaults_bind_nothing_and_remote_opt_in_is_explicit() {
        let settings: Settings = serde_json::from_str("{}").unwrap();
        assert!(!settings.enabled);
        settings.validate().unwrap();
        assert_eq!(settings.hostname, default_hostname());
        assert!(settings.address_family.is_none());
        assert!(settings.bind_address.is_none());
        assert_eq!(
            settings.resolved_http_binds().unwrap(),
            vec!["127.0.0.1:47989".parse().unwrap()]
        );
        let mut settings: Settings =
            serde_json::from_str(r#"{"http_bind":"0.0.0.0:47989"}"#).unwrap();
        assert!(settings.validate().is_err());
        settings.allow_remote = true;
        settings.validate().unwrap();
        assert_eq!(
            settings.resolved_http_bind().unwrap().ip(),
            IpAddr::V4(Ipv4Addr::UNSPECIFIED)
        );
    }

    #[test]
    fn bind_address_and_family_resolve_and_validate_without_weakening_remote_opt_in() {
        let settings: Settings = serde_json::from_value(serde_json::json!({
            "address_family": "both",
            "bind_address": " ::1 ",
            "http_bind": "127.0.0.1:47989",
            "https_bind": "127.0.0.1:47984"
        }))
        .unwrap();
        settings.validate().unwrap();
        assert_eq!(
            settings.resolved_http_bind().unwrap(),
            "[::1]:47989".parse().unwrap()
        );
        assert_eq!(
            settings.resolved_https_bind().unwrap(),
            "[::1]:47984".parse().unwrap()
        );

        let mismatch: Settings = serde_json::from_value(serde_json::json!({
            "address_family": "ipv4",
            "bind_address": "::1"
        }))
        .unwrap();
        assert_eq!(mismatch.validate(), Err("address_family_mismatch"));

        let remote: Settings = serde_json::from_value(serde_json::json!({
            "bind_address": "192.0.2.10"
        }))
        .unwrap();
        assert_eq!(
            remote.validate(),
            Err("remote_binding_requires_allow_remote")
        );

        let malformed: Settings = serde_json::from_value(serde_json::json!({
            "bind_address": "stream.example"
        }))
        .unwrap();
        assert_eq!(malformed.validate(), Err("invalid_bind_address"));

        let collapsed: Settings = serde_json::from_value(serde_json::json!({
            "allow_remote": true,
            "bind_address": "192.0.2.10",
            "http_bind": "127.0.0.1:49000",
            "https_bind": "192.0.2.11:49000"
        }))
        .unwrap();
        assert_eq!(collapsed.validate(), Err("listener_addresses_conflict"));
    }

    #[test]
    fn both_family_empty_bind_uses_ipv6_wildcard_when_remote_access_is_enabled() {
        let settings: Settings = serde_json::from_value(serde_json::json!({
            "address_family": "both",
            "bind_address": "",
            "allow_remote": true
        }))
        .unwrap();
        assert_eq!(
            settings.resolved_http_binds().unwrap(),
            vec![
                "0.0.0.0:47989".parse().unwrap(),
                "[::]:47989".parse().unwrap()
            ]
        );
    }

    #[test]
    fn both_family_without_remote_access_resolves_to_both_loopback_addresses() {
        let settings: Settings = serde_json::from_value(serde_json::json!({
            "address_family": "both",
            "bind_address": "",
            "http_bind": "127.0.0.1:47989"
        }))
        .unwrap();
        assert_eq!(
            settings.resolved_http_binds().unwrap(),
            vec![
                "127.0.0.1:47989".parse().unwrap(),
                "[::1]:47989".parse().unwrap()
            ]
        );
    }

    #[test]
    fn explicit_address_family_without_bind_address_uses_family_defaults() {
        let cases = [
            (
                AddressFamily::Ipv4,
                false,
                vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
            ),
            (
                AddressFamily::Ipv4,
                true,
                vec![IpAddr::V4(Ipv4Addr::UNSPECIFIED)],
            ),
            (
                AddressFamily::Both,
                false,
                vec![
                    IpAddr::V4(Ipv4Addr::LOCALHOST),
                    IpAddr::V6(Ipv6Addr::LOCALHOST),
                ],
            ),
            (
                AddressFamily::Both,
                true,
                vec![
                    IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                    IpAddr::V6(Ipv6Addr::UNSPECIFIED),
                ],
            ),
        ];

        for (address_family, allow_remote, expected_ips) in cases {
            let settings = Settings {
                address_family: Some(address_family),
                allow_remote,
                ..Settings::default()
            };

            for resolved_binds in [
                settings.resolved_http_binds().unwrap(),
                settings.resolved_https_binds().unwrap(),
            ] {
                assert_eq!(
                    resolved_binds
                        .into_iter()
                        .map(|address| address.ip())
                        .collect::<Vec<_>>(),
                    expected_ips
                );
            }
        }
    }

    #[test]
    fn explicit_ipv4_family_uses_family_defaults_for_empty_binds_over_legacy_ipv6() {
        for allow_remote in [false, true] {
            for bind_address in [None, Some(""), Some(" \t ")] {
                let settings = Settings {
                    address_family: Some(AddressFamily::Ipv4),
                    bind_address: bind_address.map(str::to_owned),
                    allow_remote,
                    http_bind: "[::1]:47989".parse().unwrap(),
                    https_bind: "[::1]:47984".parse().unwrap(),
                    ..Settings::default()
                };
                let expected_ip = if allow_remote {
                    IpAddr::V4(Ipv4Addr::UNSPECIFIED)
                } else {
                    IpAddr::V4(Ipv4Addr::LOCALHOST)
                };

                settings.validate().unwrap();
                assert_eq!(settings.bind_address.as_deref(), bind_address);
                assert_eq!(
                    settings
                        .resolved_http_binds()
                        .unwrap()
                        .into_iter()
                        .map(|address| address.ip())
                        .collect::<Vec<_>>(),
                    vec![expected_ip]
                );
                assert_eq!(
                    settings
                        .resolved_https_binds()
                        .unwrap()
                        .into_iter()
                        .map(|address| address.ip())
                        .collect::<Vec<_>>(),
                    vec![expected_ip]
                );
            }
        }
    }

    #[test]
    fn empty_hostname_uses_the_machine_default_and_nonempty_values_are_preserved() {
        let machine_hostname = default_hostname();
        assert!(!machine_hostname.is_empty());

        let empty = Settings {
            hostname: String::new(),
            ..Settings::default()
        };
        empty.validate().unwrap();
        assert_eq!(effective_hostname(&empty.hostname), machine_hostname);

        let configured = "  Living Room & Games  ";
        assert_eq!(effective_hostname(configured), configured);
        validate_configured_hostname("").unwrap();
        validate_hostname(machine_hostname.as_str()).unwrap();
    }

    #[test]
    fn configured_hostname_bounds_remain_enforced() {
        assert!(validate_configured_hostname(&"x".repeat(129)).is_err());
        assert!(validate_configured_hostname("host\nname").is_err());
        assert!(validate_hostname("").is_err());
    }

    #[test]
    fn unavailable_or_invalid_machine_hostname_uses_the_documented_fallback() {
        assert_eq!(hostname_or_fallback(None), FALLBACK_HOSTNAME);
        assert_eq!(
            hostname_or_fallback(Some("host\nname".into())),
            FALLBACK_HOSTNAME
        );
    }

    #[test]
    fn port_range_preserves_https_and_rtsp_offset_bounds() {
        assert!(validate_port(MIN_PORT).is_ok());
        assert_eq!(https_port(MIN_PORT), 1_024);
        assert!(validate_port(MAX_PORT).is_ok());
        assert_eq!(u32::from(MAX_PORT) + 21, 65_535);
        assert!(validate_port(MIN_PORT - 1).is_err());
        assert!(validate_port(MAX_PORT + 1).is_err());
    }

    #[test]
    fn streaming_requires_the_complete_trusted_capture_and_profile_contract() {
        let settings: Settings = serde_json::from_value(serde_json::json!({
            "streaming": {
                "capture": {
                    "capture_provider": "dxgi",
                    "output": "display-one",
                    "encoder": 0,
                    "audio_endpoint": "default"
                },
                "profile": {
                    "max_width": 1920,
                    "max_height": 1080,
                    "max_fps": 60,
                    "bitrate_kbps": 10000,
                    "max_reference_frames": 1,
                    "packet_size": 1024,
                    "fec_percentage": 20,
                    "min_parity_shards": 2,
                    "max_fec_blocks": 1,
                    "packet_ms": 10,
                    "audio_bitrate": 128000,
                    "encrypt_video": true,
                    "encrypt_audio": true,
                    "permit_legacy_audio_iv_wrap": false
                }
            }
        }))
        .unwrap();
        settings.validate().unwrap();
        assert!(settings.streaming.is_some());

        let unsupported = serde_json::json!({
            "streaming": {
                "enabled": true,
                "capture": {},
                "profile": {}
            }
        });
        assert!(serde_json::from_value::<Settings>(unsupported).is_err());
    }
}
