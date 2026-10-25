use std::collections::BTreeMap;

pub const MAX_TARGET: usize = 12_288;
const MAX_FIELDS: usize = 24;

pub struct Query {
    pub path: String,
    fields: BTreeMap<String, String>,
}

impl Query {
    pub fn parse(target: &str) -> Result<Self, &'static str> {
        if target.len() > MAX_TARGET || !target.starts_with('/') || target.contains('#') {
            return Err("invalid request target");
        }
        let (path, query) = target.split_once('?').unwrap_or((target, ""));
        if !path
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte == b'/')
        {
            return Err("invalid route");
        }
        let mut fields = BTreeMap::new();
        if !query.is_empty() {
            for field in query.split('&') {
                if fields.len() >= MAX_FIELDS {
                    return Err("too many query fields");
                }
                let (name, value) = field
                    .split_once('=')
                    .ok_or("query field requires a value")?;
                let name = decode(name)?;
                let value = decode(value)?;
                if name.is_empty()
                    || name.len() > 64
                    || !name
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
                {
                    return Err("invalid query field name");
                }
                if fields.insert(name, value).is_some() {
                    return Err("duplicate query field");
                }
            }
        }
        Ok(Self {
            path: path.into(),
            fields,
        })
    }

    pub fn get(&self, name: &str) -> Option<&str> {
        self.fields.get(name).map(String::as_str)
    }

    pub fn required(&self, name: &str) -> Result<&str, &'static str> {
        self.get(name)
            .filter(|value| !value.is_empty())
            .ok_or("missing query field")
    }

    pub fn client_id(&self) -> Result<&str, &'static str> {
        let id = self.required("uniqueid")?;
        if id.len() > 64
            || !id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._-:/".contains(&byte))
        {
            return Err("invalid client identifier");
        }
        Ok(id)
    }

    pub fn require_only(&self, allowed: &[&str]) -> Result<(), &'static str> {
        if self
            .fields
            .keys()
            .all(|name| allowed.contains(&name.as_str()))
        {
            Ok(())
        } else {
            Err("unsupported query field")
        }
    }
}

fn decode(value: &str) -> Result<String, &'static str> {
    let input = value.as_bytes();
    let mut output = Vec::with_capacity(input.len());
    let mut index = 0;
    while index < input.len() {
        let byte = match input[index] {
            b'%' => {
                let digits = input
                    .get(index + 1..index + 3)
                    .ok_or("truncated percent escape")?;
                index += 2;
                hex_digit(digits[0])? * 16 + hex_digit(digits[1])?
            }
            b'+' => b' ',
            byte => byte,
        };
        if byte.is_ascii_control() {
            return Err("query contains control characters");
        }
        output.push(byte);
        index += 1;
    }
    let decoded = String::from_utf8(output).map_err(|_| "query is not UTF-8")?;
    if decoded.chars().any(char::is_control) {
        return Err("query contains control characters");
    }
    Ok(decoded)
}

fn hex_digit(byte: u8) -> Result<u8, &'static str> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err("invalid hexadecimal value"),
    }
}

pub fn hex_bytes(value: &str, maximum: usize) -> Result<Vec<u8>, &'static str> {
    if value.is_empty() || !value.len().is_multiple_of(2) || value.len() > maximum * 2 {
        return Err("invalid hexadecimal length");
    }
    value
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| Ok(hex_digit(pair[0])? * 16 + hex_digit(pair[1])?))
        .collect()
}
