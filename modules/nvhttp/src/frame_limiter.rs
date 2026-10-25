//! Nullable canonical frame-limiter settings and their effective defaults.
use serde::{Deserialize, Serialize};
#[cfg(windows)]
use std::path::Path;

const MAX_FRAME_LIMITER_FPS: f64 = 1_000.0;
const FRAME_LIMITER_FPS_SCALE: f64 = 1_000.0;
const MAX_FPS_SCALE_ERROR_MILLIHZ: f64 = 0.000_001;

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct FrameLimiterSettings {
    pub frame_limiter_enable: Option<bool>,
    /// Persisted as decimal Hz; launch adapters convert it to exact millihertz.
    pub frame_limiter_fps_limit: Option<f64>,
    pub frame_limiter_provider: Option<String>,
    pub frame_limiter_disable_vsync: Option<bool>,
    pub frame_limiter_auto_virtual_framegen: Option<String>,
    pub rtss_frame_limit_type: Option<String>,
    pub rtss_allow_virtual_display_override: Option<bool>,
    pub rtss_install_path: Option<String>,
    pub mangohud_limiter_method: Option<String>,
    pub mangohud_preset: Option<String>,
    pub mangohud_always_show_graph: Option<bool>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct EffectiveFrameLimiterSettings {
    pub frame_limiter_enable: bool,
    pub frame_limiter_fps_limit_millihz: u32,
    pub frame_limiter_provider: String,
    pub frame_limiter_disable_vsync: bool,
    pub frame_limiter_auto_virtual_framegen: String,
    pub rtss_frame_limit_type: String,
    pub rtss_allow_virtual_display_override: bool,
    pub rtss_install_path: String,
    pub mangohud_limiter_method: String,
    pub mangohud_preset: String,
    pub mangohud_always_show_graph: bool,
}

impl FrameLimiterSettings {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self
            .frame_limiter_fps_limit
            .is_some_and(|fps| !valid_fps_limit(fps))
        {
            return Err("invalid_frame_limiter_fps_limit");
        }

        if self
            .frame_limiter_provider
            .as_deref()
            .is_some_and(|provider| !valid_provider(provider))
        {
            return Err("invalid_frame_limiter_provider");
        }

        if self
            .frame_limiter_auto_virtual_framegen
            .as_deref()
            .is_some_and(|mode| !matches!(mode, "enabled" | "vrr" | "legacy" | "disabled"))
        {
            return Err("invalid_frame_limiter_auto_virtual_framegen");
        }

        if self.rtss_frame_limit_type.as_deref().is_some_and(|mode| {
            !matches!(
                mode,
                "async" | "front edge sync" | "back edge sync" | "nvidia reflex"
            )
        }) {
            return Err("invalid_rtss_frame_limit_type");
        }

        if self
            .mangohud_limiter_method
            .as_deref()
            .is_some_and(|method| !matches!(method, "early" | "late"))
        {
            return Err("invalid_mangohud_limiter_method");
        }

        if self
            .mangohud_preset
            .as_deref()
            .is_some_and(|preset| !matches!(preset, "custom" | "1" | "2" | "3" | "4"))
        {
            return Err("invalid_mangohud_preset");
        }

        self.validate_platform_fields()?;
        Ok(())
    }

    pub fn effective(&self) -> EffectiveFrameLimiterSettings {
        EffectiveFrameLimiterSettings {
            frame_limiter_enable: self.frame_limiter_enable.unwrap_or(false),
            frame_limiter_fps_limit_millihz: self
                .frame_limiter_fps_limit
                .map(fps_limit_to_millihz)
                .unwrap_or(0),
            frame_limiter_provider: self
                .frame_limiter_provider
                .clone()
                .unwrap_or_else(|| "auto".into()),
            frame_limiter_disable_vsync: self.frame_limiter_disable_vsync.unwrap_or(false),
            frame_limiter_auto_virtual_framegen: self
                .frame_limiter_auto_virtual_framegen
                .clone()
                .unwrap_or_else(|| "enabled".into()),
            rtss_frame_limit_type: self
                .rtss_frame_limit_type
                .clone()
                .unwrap_or_else(|| "async".into()),
            rtss_allow_virtual_display_override: self
                .rtss_allow_virtual_display_override
                .unwrap_or(false),
            rtss_install_path: self.rtss_install_path.clone().unwrap_or_default(),
            mangohud_limiter_method: self
                .mangohud_limiter_method
                .clone()
                .unwrap_or_else(|| "late".into()),
            mangohud_preset: self
                .mangohud_preset
                .clone()
                .unwrap_or_else(|| "custom".into()),
            mangohud_always_show_graph: self.mangohud_always_show_graph.unwrap_or(false),
        }
    }

    fn validate_platform_fields(&self) -> Result<(), &'static str> {
        #[cfg(windows)]
        {
            if self.mangohud_limiter_method.is_some()
                || self.mangohud_preset.is_some()
                || self.mangohud_always_show_graph.is_some()
            {
                return Err("unsupported_frame_limiter_setting");
            }
            if self
                .rtss_install_path
                .as_deref()
                .is_some_and(|path| !path.is_empty() && !Path::new(path).is_absolute())
            {
                return Err("invalid_rtss_install_path");
            }
        }

        #[cfg(target_os = "linux")]
        if self.has_windows_only_fields() {
            return Err("unsupported_frame_limiter_setting");
        }

        #[cfg(target_os = "macos")]
        if self.has_windows_only_fields() || self.has_linux_only_fields() {
            return Err("unsupported_frame_limiter_setting");
        }

        #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
        if self.has_windows_only_fields() || self.has_linux_only_fields() {
            return Err("unsupported_frame_limiter_setting");
        }

        Ok(())
    }

    #[cfg(not(windows))]
    fn has_windows_only_fields(&self) -> bool {
        self.frame_limiter_disable_vsync.is_some()
            || self.frame_limiter_auto_virtual_framegen.is_some()
            || self.rtss_frame_limit_type.is_some()
            || self.rtss_allow_virtual_display_override.is_some()
            || self.rtss_install_path.is_some()
    }

    #[cfg(any(target_os = "macos", not(any(windows, target_os = "linux"))))]
    fn has_linux_only_fields(&self) -> bool {
        self.mangohud_limiter_method.is_some()
            || self.mangohud_preset.is_some()
            || self.mangohud_always_show_graph.is_some()
    }
}

fn valid_fps_limit(fps: f64) -> bool {
    if !fps.is_finite() || !(0.0..=MAX_FRAME_LIMITER_FPS).contains(&fps) {
        return false;
    }

    let millihz = fps * FRAME_LIMITER_FPS_SCALE;
    (millihz - millihz.round()).abs() <= MAX_FPS_SCALE_ERROR_MILLIHZ
}

fn fps_limit_to_millihz(fps: f64) -> u32 {
    (fps * FRAME_LIMITER_FPS_SCALE).round() as u32
}

fn valid_provider(provider: &str) -> bool {
    #[cfg(windows)]
    {
        matches!(provider, "auto" | "rtss" | "nvidia-control-panel" | "none")
    }
    #[cfg(target_os = "linux")]
    {
        matches!(
            provider,
            "auto" | "mangohud" | "proton" | "mangohud-proton" | "none"
        )
    }
    #[cfg(target_os = "macos")]
    {
        provider == "auto"
    }
    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
    {
        provider == "auto"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    fn with_provider(provider: &str) -> FrameLimiterSettings {
        FrameLimiterSettings {
            frame_limiter_provider: Some(provider.into()),
            ..FrameLimiterSettings::default()
        }
    }

    #[test]
    fn nullable_fields_round_trip_and_effective_defaults_do_not_mutate_them() {
        let settings: FrameLimiterSettings = serde_json::from_value(json!({})).unwrap();
        assert!(settings.validate().is_ok());

        let persisted = serde_json::to_value(&settings).unwrap();
        let expected_null_fields = json!({
            "frame_limiter_enable": null,
            "frame_limiter_fps_limit": null,
            "frame_limiter_provider": null,
            "frame_limiter_disable_vsync": null,
            "frame_limiter_auto_virtual_framegen": null,
            "rtss_frame_limit_type": null,
            "rtss_allow_virtual_display_override": null,
            "rtss_install_path": null,
            "mangohud_limiter_method": null,
            "mangohud_preset": null,
            "mangohud_always_show_graph": null,
        });
        assert_eq!(persisted, expected_null_fields);

        let effective = settings.effective();
        assert!(!effective.frame_limiter_enable);
        assert_eq!(effective.frame_limiter_fps_limit_millihz, 0);
        assert_eq!(effective.frame_limiter_provider, "auto");
        assert!(!effective.frame_limiter_disable_vsync);
        assert_eq!(effective.frame_limiter_auto_virtual_framegen, "enabled");
        assert_eq!(effective.rtss_frame_limit_type, "async");
        assert!(!effective.rtss_allow_virtual_display_override);
        assert_eq!(effective.rtss_install_path, "");
        assert_eq!(effective.mangohud_limiter_method, "late");
        assert_eq!(effective.mangohud_preset, "custom");
        assert!(!effective.mangohud_always_show_graph);
        assert_eq!(serde_json::to_value(&settings).unwrap(), persisted);
    }

    #[test]
    fn explicit_false_and_zero_remain_durable_and_effective() {
        let settings = FrameLimiterSettings {
            frame_limiter_enable: Some(false),
            frame_limiter_fps_limit: Some(0.0),
            #[cfg(windows)]
            frame_limiter_disable_vsync: Some(false),
            ..FrameLimiterSettings::default()
        };

        #[cfg(any(windows, target_os = "linux"))]
        assert!(settings.validate().is_ok());
        #[cfg(not(any(windows, target_os = "linux")))]
        assert_eq!(
            settings.validate(),
            Err("unsupported_frame_limiter_setting")
        );
        let persisted = serde_json::to_value(&settings).unwrap();
        assert_eq!(persisted["frame_limiter_enable"], false);
        assert_eq!(persisted["frame_limiter_fps_limit"], 0.0);
        #[cfg(windows)]
        assert_eq!(persisted["frame_limiter_disable_vsync"], false);
        #[cfg(not(windows))]
        assert!(persisted["frame_limiter_disable_vsync"].is_null());
        let effective = settings.effective();
        assert!(!effective.frame_limiter_enable);
        assert_eq!(effective.frame_limiter_fps_limit_millihz, 0);
        assert!(!effective.frame_limiter_disable_vsync);
    }

    #[test]
    fn persisted_decimal_fps_converts_to_exact_millihertz_and_checks_precision() {
        for (fps, expected_millihz) in [
            (0.0, 0),
            (59.94, 59_940),
            (143.997, 143_997),
            (1000.0, 1_000_000),
        ] {
            let settings: FrameLimiterSettings =
                serde_json::from_value(json!({"frame_limiter_fps_limit": fps})).unwrap();

            assert!(settings.validate().is_ok());
            assert_eq!(
                settings.effective().frame_limiter_fps_limit_millihz,
                expected_millihz
            );
            assert_eq!(
                serde_json::to_value(&settings).unwrap()["frame_limiter_fps_limit"],
                fps
            );
        }

        for invalid_fps in [-0.001, 1000.001, 59.9999] {
            let settings: FrameLimiterSettings = serde_json::from_value(json!({
                "frame_limiter_fps_limit": invalid_fps
            }))
            .unwrap();
            assert_eq!(settings.validate(), Err("invalid_frame_limiter_fps_limit"));
        }

        let non_numeric: Result<FrameLimiterSettings, _> = serde_json::from_value(json!({
            "frame_limiter_fps_limit": "60"
        }));
        assert!(non_numeric.is_err());
    }

    #[test]
    fn provider_values_follow_the_target_platform() {
        assert!(with_provider("auto").validate().is_ok());
        #[cfg(windows)]
        let (valid, invalid): (&[&str], &str) =
            (&["rtss", "nvidia-control-panel", "none"], "mangohud");
        #[cfg(target_os = "linux")]
        let (valid, invalid): (&[&str], &str) =
            (&["mangohud", "proton", "mangohud-proton", "none"], "rtss");
        #[cfg(target_os = "macos")]
        let (valid, invalid): (&[&str], &str) = (&[], "rtss");
        #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
        let (valid, invalid): (&[&str], &str) = (&[], "rtss");

        for provider in valid {
            assert!(with_provider(provider).validate().is_ok());
        }
        assert_eq!(
            with_provider(invalid).validate(),
            Err("invalid_frame_limiter_provider")
        );
    }

    #[test]
    fn platform_specific_enums_and_fields_are_validated() {
        let mut settings = FrameLimiterSettings::default();
        #[cfg(windows)]
        {
            settings.frame_limiter_auto_virtual_framegen = Some("vrr".into());
            settings.rtss_frame_limit_type = Some("nvidia reflex".into());
            assert!(settings.validate().is_ok());
            settings.frame_limiter_auto_virtual_framegen = Some("auto".into());
            assert_eq!(
                settings.validate(),
                Err("invalid_frame_limiter_auto_virtual_framegen")
            );
            settings.frame_limiter_auto_virtual_framegen = None;
            settings.rtss_frame_limit_type = Some("sync".into());
            assert_eq!(settings.validate(), Err("invalid_rtss_frame_limit_type"));
            settings.rtss_frame_limit_type = None;
            settings.mangohud_preset = Some("custom".into());
            assert_eq!(
                settings.validate(),
                Err("unsupported_frame_limiter_setting")
            );
        }
        #[cfg(target_os = "linux")]
        {
            settings.mangohud_limiter_method = Some("early".into());
            settings.mangohud_preset = Some("4".into());
            assert!(settings.validate().is_ok());
            settings.mangohud_limiter_method = Some("middle".into());
            assert_eq!(settings.validate(), Err("invalid_mangohud_limiter_method"));
            settings.mangohud_limiter_method = Some("late".into());
            settings.mangohud_preset = Some("5".into());
            assert_eq!(settings.validate(), Err("invalid_mangohud_preset"));
            settings.mangohud_preset = None;
            settings.rtss_frame_limit_type = Some("async".into());
            assert_eq!(
                settings.validate(),
                Err("unsupported_frame_limiter_setting")
            );
        }
        #[cfg(target_os = "macos")]
        {
            settings.frame_limiter_disable_vsync = Some(false);
            assert_eq!(
                settings.validate(),
                Err("unsupported_frame_limiter_setting")
            );
        }
    }

    #[cfg(windows)]
    #[test]
    fn rtss_install_path_must_be_absolute_or_empty() {
        let mut settings = FrameLimiterSettings {
            rtss_install_path: Some(String::new()),
            ..FrameLimiterSettings::default()
        };
        assert!(settings.validate().is_ok());

        settings.rtss_install_path = Some(r"C:\Program Files\RTSS".into());
        assert!(settings.validate().is_ok());

        settings.rtss_install_path = Some("relative\\RTSS".into());
        assert_eq!(settings.validate(), Err("invalid_rtss_install_path"));
    }

    #[test]
    fn known_string_fields_are_strictly_typed() {
        let malformed: Result<FrameLimiterSettings, _> = serde_json::from_value(Value::Null);
        assert!(malformed.is_err());
        let malformed: Result<FrameLimiterSettings, _> = serde_json::from_value(json!({
            "frame_limiter_provider": false
        }));
        assert!(malformed.is_err());
    }
}
