use amaterasu_network_policy::{valid_peer, validate_local_bind};
use serde::Deserialize;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

pub type ControlResult<T> = Result<T, &'static str>;
pub const DEFAULT_PING_TIMEOUT_MS: i64 = 10_000;
pub const MAX_PING_TIMEOUT_MS: i64 = i32::MAX as i64;

fn default_ping_timeout_ms() -> i64 {
    DEFAULT_PING_TIMEOUT_MS
}

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Settings {
    pub enabled: bool,
    pub allow_remote: bool,
    pub allowed_principals: Vec<String>,
}

impl Settings {
    pub fn validate(&self) -> ControlResult<()> {
        if self.allowed_principals.len() > 16
            || self
                .allowed_principals
                .iter()
                .any(|owner| !valid_name(owner))
        {
            return Err("invalid_settings");
        }
        Ok(())
    }
}

#[derive(Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Open {
    pub peer_ip: IpAddr,
    #[serde(default)]
    pub peer_port: Option<u16>,
    #[serde(default)]
    pub local_bind: Option<SocketAddr>,
    pub connect_data: u32,
    pub key_hex: String,
    #[serde(default = "default_ping_timeout_ms")]
    pub ping_timeout_ms: i64,
    #[serde(default)]
    pub operation_id: Option<String>,
}

impl Open {
    pub fn validate(&self, allow_remote: bool) -> ControlResult<[u8; 16]> {
        if !valid_peer(self.peer_ip) || self.peer_port == Some(0) {
            return Err("invalid_peer");
        }
        if !allow_remote && !self.peer_ip.is_loopback() {
            return Err("remote_disabled");
        }
        validate_ping_timeout_ms(self.ping_timeout_ms)?;
        if let Some(local) = self.local_bind {
            validate_local_bind(local.ip(), self.peer_ip, allow_remote)?;
        }
        if self
            .operation_id
            .as_deref()
            .is_some_and(|id| !valid_name(id))
        {
            return Err("invalid_operation_id");
        }
        parse_key(&self.key_hex)
    }

    pub fn local(&self) -> SocketAddr {
        self.local_bind.unwrap_or_else(|| {
            let loopback = self.peer_ip.is_loopback();
            let address = match self.peer_ip {
                IpAddr::V4(_) => IpAddr::V4(if loopback {
                    Ipv4Addr::LOCALHOST
                } else {
                    Ipv4Addr::UNSPECIFIED
                }),
                IpAddr::V6(_) => IpAddr::V6(if loopback {
                    Ipv6Addr::LOCALHOST
                } else {
                    Ipv6Addr::UNSPECIFIED
                }),
            };
            SocketAddr::new(address, 0)
        })
    }
}

pub fn validate_ping_timeout_ms(value: i64) -> ControlResult<u64> {
    if !(0..=MAX_PING_TIMEOUT_MS).contains(&value) {
        return Err("invalid_ping_timeout");
    }
    Ok(value as u64)
}

pub fn valid_name(name: &str) -> bool {
    !name.is_empty() && name.len() <= 128 && !name.chars().any(char::is_control)
}

pub fn parse_key(value: &str) -> ControlResult<[u8; 16]> {
    if value.len() != 32 {
        return Err("invalid_key");
    }
    let mut key = [0; 16];
    for (output, pair) in key.iter_mut().zip(value.as_bytes().as_chunks::<2>().0) {
        let high = (pair[0] as char).to_digit(16).ok_or("invalid_key")?;
        let low = (pair[1] as char).to_digit(16).ok_or("invalid_key")?;
        *output = ((high << 4) | low) as u8;
    }
    Ok(key)
}

#[derive(Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum Operation {
    Open(Open),
    Lookup { operation_id: String },
    Close { stream: u64 },
    Status { stream: Option<u64> },
}
