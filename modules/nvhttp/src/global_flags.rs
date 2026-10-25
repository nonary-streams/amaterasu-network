//! Parsing and resolving legacy global configuration flags.

/// The effective switches represented by the legacy `flags` string.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct GlobalFlags {
    pub pin_stdin: bool,
    pub fresh_state: bool,
    pub force_video_header_replace: bool,
}

/// A parsed legacy flag string, including unknown characters that callers can warn about.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ParsedGlobalFlags {
    pub flags: GlobalFlags,
    pub upnp_toggle: bool,
    pub unknown: Vec<char>,
}

impl ParsedGlobalFlags {
    /// Applies the `p` flag after the separately configured UPnP value, matching the
    /// legacy configuration order.
    pub fn effective_upnp(&self, configured_upnp: bool) -> bool {
        configured_upnp ^ self.upnp_toggle
    }
}

/// Parses a legacy config-file value. Known characters toggle their switch, so repeated
/// characters cancel. Unknown characters are retained for a warning and do not prevent
/// the remaining known flags from applying.
pub fn parse_legacy_flags(value: &str) -> ParsedGlobalFlags {
    let mut parsed = ParsedGlobalFlags::default();
    for character in value.chars() {
        match character {
            '0' => parsed.flags.pin_stdin = !parsed.flags.pin_stdin,
            '1' => parsed.flags.fresh_state = !parsed.flags.fresh_state,
            '2' => {
                parsed.flags.force_video_header_replace = !parsed.flags.force_video_header_replace;
            }
            'p' => parsed.upnp_toggle = !parsed.upnp_toggle,
            unknown => parsed.unknown.push(unknown),
        }
    }
    parsed
}

/// Validates a value submitted by a settings editor. Legacy files use
/// [`parse_legacy_flags`] so unknown characters can be warned about and ignored.
pub fn parse_editor_flags(value: &str) -> Result<ParsedGlobalFlags, char> {
    let parsed = parse_legacy_flags(value);
    parsed.unknown.first().copied().map_or(Ok(parsed), Err)
}

#[cfg(test)]
mod tests {
    use super::{GlobalFlags, parse_editor_flags, parse_legacy_flags};

    #[test]
    fn known_characters_toggle_and_duplicates_cancel() {
        let parsed = parse_legacy_flags("001122pp");
        assert_eq!(parsed.flags, GlobalFlags::default());
        assert!(!parsed.upnp_toggle);
        assert!(parsed.unknown.is_empty());

        let parsed = parse_legacy_flags("012p");
        assert_eq!(
            parsed.flags,
            GlobalFlags {
                pin_stdin: true,
                fresh_state: true,
                force_video_header_replace: true,
            }
        );
        assert!(parsed.upnp_toggle);
    }

    #[test]
    fn upnp_flag_toggles_the_previously_configured_value() {
        let parsed = parse_legacy_flags("p");
        assert!(parsed.effective_upnp(false));
        assert!(!parsed.effective_upnp(true));
    }

    #[test]
    fn legacy_unknown_characters_are_reported_without_dropping_known_flags() {
        let parsed = parse_legacy_flags("0x2?");
        assert!(parsed.flags.pin_stdin);
        assert!(parsed.flags.force_video_header_replace);
        assert_eq!(parsed.unknown, ['x', '?']);
    }

    #[test]
    fn editor_input_rejects_the_first_unknown_character() {
        assert!(parse_editor_flags("02p").is_ok());
        assert_eq!(parse_editor_flags("0?2"), Err('?'));
    }
}
