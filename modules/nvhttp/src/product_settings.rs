//! Caller-scoped NVHTTP product settings persisted by the configuration service.
use crate::{
    frame_limiter::FrameLimiterSettings,
    launch::CaptureMode,
    preparation::{
        LegacyPreparationStep, PreparationStep, validate_legacy_preparation, validate_preparation,
    },
    settings::{self, AddressFamily, Settings},
};
use amaterasu_module_sdk::{
    Command, EncoderBackend, ModuleResult, NvencSettings, Response, RuntimeClient,
    SoftwareEncoderOptions,
};
use serde_json::{Value, json};
use std::collections::VecDeque;
use std::time::{Duration, Instant};

const CONFIGURATION_SERVICE: &str = "amaterasu.configuration/1";
const LEGACY_SETTINGS_VERSION: u64 = 1;
const PORT_SETTINGS_VERSION: u64 = 2;
const NETWORK_SETTINGS_VERSION: u64 = 3;
const OUTPUT_SETTINGS_VERSION: u64 = 4;
const STREAM_AUDIO_SETTINGS_VERSION: u64 = 5;
const CAPTURE_SETTINGS_VERSION: u64 = 6;
const VIDEO_BATCH_SETTINGS_VERSION: u64 = 7;
const MAX_BITRATE_SETTINGS_VERSION: u64 = 8;
const MINIMUM_FPS_SETTINGS_VERSION: u64 = 9;
const AUDIO_SINK_SETTINGS_VERSION: u64 = 10;
const WGC_PACING_SMOOTHING_SETTINGS_VERSION: u64 = 11;
const EXTERNAL_IP_SETTINGS_VERSION: u64 = 12;
const PING_TIMEOUT_SETTINGS_VERSION: u64 = 13;
const AUDIO_SINK_CAPTURE_ONLY_SETTINGS_VERSION: u64 = 14;
const VIRTUAL_SINK_SETTINGS_VERSION: u64 = 15;
const GLOBAL_PREPARATION_SETTINGS_VERSION: u64 = 16;
const GLOBAL_RAW_PREPARATION_SETTINGS_VERSION: u64 = 17;
const FRAME_LIMITER_SETTINGS_VERSION: u64 = 17;
const ENCRYPTION_MODE_SETTINGS_VERSION: u64 = 17;
const DISPLAY_POLICY_SETTINGS_VERSION: u64 = 18;
// The Linux Desktop profile requests video encryption. The default LAN policy
// permits that choice while still allowing other profiles to negotiate it.
#[cfg(target_os = "linux")]
const DEFAULT_LAN_ENCRYPTION_MODE: u8 = 1;
#[cfg(not(target_os = "linux"))]
const DEFAULT_LAN_ENCRYPTION_MODE: u8 = 0;
const DEFAULT_WAN_ENCRYPTION_MODE: u8 = 1;
const SOFTWARE_ENCODER_SETTINGS_VERSION: u64 = 19;
const MIN_THREADS_SETTINGS_VERSION: u64 = 20;
const UPNP_SETTINGS_VERSION: u64 = 21;
const QP_SETTINGS_VERSION: u64 = 22;
const FEC_SETTINGS_VERSION: u64 = 23;
const NVENC_SETTINGS_VERSION: u64 = 24;
const STEAM_AUDIO_DRIVER_SETTINGS_VERSION: u64 = 25;
const FULL_DISPLAY_POLICY_SETTINGS_VERSION: u64 = 26;
const LEGACY_PERMANENT_MONITOR_COUNT_KEY: &str = "dd_vdd_static_monitor_count";
const SETTINGS_VERSION: u64 = FULL_DISPLAY_POLICY_SETTINGS_VERSION;
const LEGACY_DISPLAY_POLICY_KEYS: [&str; 8] = [
    "dd_mode_remapping",
    "dd_resolution_option",
    "dd_manual_resolution",
    "dd_refresh_rate_option",
    "dd_manual_refresh_rate",
    "dd_hdr_option",
    "dd_configuration_option",
    "dd_hdr_request_override",
];
const DISPLAY_POLICY_KEYS: [&str; 30] = [
    "adapter_name",
    "adapter_pnp_id",
    "virtual_display_mode",
    "virtual_display_layout",
    "dd_mode_remapping",
    "dd_resolution_option",
    "dd_manual_resolution",
    "dd_refresh_rate_option",
    "dd_manual_refresh_rate",
    "dd_hdr_option",
    "dd_configuration_option",
    "dd_hdr_request_override",
    "dd_config_revert_delay",
    "dd_config_revert_on_disconnect",
    "dd_paused_virtual_display_timeout_secs",
    "dd_always_restore_from_golden",
    "dd_display_helper_engine",
    "dd_snapshot_restore_hotkey",
    "dd_snapshot_restore_hotkey_modifiers",
    "dd_use_sunshine_virtual_display_driver",
    "dd_activate_virtual_display",
    "dd_virtual_display_scale",
    "dd_virtual_display_permanent_count",
    "virtual_display_outputs",
    "dd_snapshot_exclude_devices",
    "dd_wa_dummy_plug_hdr10",
    "dd_wa_hdr_toggle",
    "dd_wa_hdr_toggle_delay",
    "vulkan_hdr_layer",
    "wayland_hdr_compatibility",
];
const DEFAULT_MINIMUM_FPS_TARGET: f64 = 20.0;
const DEFAULT_FEC_PERCENTAGE: u8 = 20;
const DEFAULT_PING_TIMEOUT_MS: u32 = 10_000;
const MAX_OUTPUT_NAME_BYTES: usize = 512;
const MAX_QUEUED_ADMIN_REQUESTS: usize = 32;
const CONFIGURATION_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_RETRY_DELAY: Duration = Duration::from_secs(30);

#[derive(Clone, Debug)]
// Keeping the complete bounded update together preserves typed CAS semantics.
#[allow(clippy::large_enum_variant)]
pub(crate) enum AdminAction {
    Get,
    Update {
        hostname: String,
        port: u16,
        address_family: FieldUpdate<AddressFamily>,
        bind_address: FieldUpdate<String>,
        output_name: FieldUpdate<String>,
        audio_sink: FieldUpdate<String>,
        virtual_sink: FieldUpdate<String>,
        audio_sink_capture_only: FieldUpdate<bool>,
        install_steam_audio_drivers: FieldUpdate<bool>,
        nvenc_spatial_aq: FieldUpdate<bool>,
        external_ip: FieldUpdate<String>,
        stream_audio: FieldUpdate<bool>,
        capture: FieldUpdate<CaptureMode>,
        video_max_batch_size_kb: FieldUpdate<u8>,
        max_bitrate: FieldUpdate<i32>,
        minimum_fps_target: FieldUpdate<f64>,
        wgc_pacing_smoothing: FieldUpdate<bool>,
        software_encoder: SoftwareEncoderUpdate,
        nvenc_settings: NvencSettingsUpdate,
        qp: FieldUpdate<i32>,
        fec_percentage: FieldUpdate<i32>,
        ping_timeout_ms: FieldUpdate<i32>,
        global_preparation: FieldUpdate<Vec<PreparationStep>>,
        legacy_global_preparation: FieldUpdate<Vec<LegacyPreparationStep>>,
        frame_limiter: FrameLimiterUpdate,
        display_policy: DisplayPolicyUpdate,
        encryption_modes: EncryptionModeUpdate,
        upnp: FieldUpdate<bool>,
        expected_revision: u64,
        require_listener_apply: bool,
    },
}

#[derive(Clone, Debug, Default)]
pub(crate) struct NvencSettingsUpdate {
    pub(crate) nvenc_preset: FieldUpdate<i32>,
    pub(crate) nvenc_h264_cavlc: FieldUpdate<bool>,
    pub(crate) nvenc_twopass: FieldUpdate<String>,
    pub(crate) nvenc_vbv_increase: FieldUpdate<i32>,
    pub(crate) nvenc_split_encode: FieldUpdate<String>,
    pub(crate) nvenc_realtime_hags: FieldUpdate<bool>,
    pub(crate) nvenc_opengl_vulkan_on_dxgi: FieldUpdate<bool>,
    pub(crate) nvenc_latency_over_power: FieldUpdate<bool>,
    pub(crate) vaapi_strict_rc_buffer: FieldUpdate<bool>,
}

const NVENC_SETTINGS_KEYS: [&str; 9] = [
    "nvenc_preset",
    "nvenc_h264_cavlc",
    "nvenc_twopass",
    "nvenc_vbv_increase",
    "nvenc_split_encode",
    "nvenc_realtime_hags",
    "nvenc_opengl_vulkan_on_dxgi",
    "nvenc_latency_over_power",
    "vaapi_strict_rc_buffer",
];

fn nvenc_settings_values(settings: &NvencSettings) -> serde_json::Map<String, Value> {
    serde_json::to_value(settings)
        .expect("NVENC settings serialize")
        .as_object()
        .expect("NVENC settings are an object")
        .iter()
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect()
}

fn parse_nvenc_settings(
    values: &serde_json::Map<String, Value>,
    version: u64,
) -> Result<NvencSettings, SettingFailure> {
    if version < NVENC_SETTINGS_VERSION {
        return Ok(NvencSettings::default());
    }
    let settings = serde_json::from_value::<NvencSettings>(Value::Object(
        NVENC_SETTINGS_KEYS
            .iter()
            .map(|key| ((*key).to_owned(), values[*key].clone()))
            .collect(),
    ))
    .map_err(|_| invalid_state("persisted NVENC settings are invalid"))?;
    settings
        .validate()
        .map_err(|_| invalid_state("persisted NVENC settings are invalid"))?;
    Ok(settings)
}

fn update_nvenc_settings(
    update: NvencSettingsUpdate,
    current: &NvencSettings,
) -> Result<NvencSettings, &'static str> {
    let defaults = NvencSettings::default();
    let parse_twopass = |setting: String| match setting.as_str() {
        "disabled" => Some(amaterasu_module_sdk::NvencTwoPass::Disabled),
        "quarter_res" => Some(amaterasu_module_sdk::NvencTwoPass::QuarterRes),
        "full_res" => Some(amaterasu_module_sdk::NvencTwoPass::FullRes),
        _ => None,
    };
    let parse_split = |setting: String| match setting.as_str() {
        "auto" | "driver_decides" => Some(amaterasu_module_sdk::NvencSplitEncode::Auto),
        "enabled" => Some(amaterasu_module_sdk::NvencSplitEncode::Enabled),
        "disabled" => Some(amaterasu_module_sdk::NvencSplitEncode::Disabled),
        _ => None,
    };
    let settings = NvencSettings {
        nvenc_preset: u8::try_from(apply_settings_update(
            update.nvenc_preset,
            i32::from(current.nvenc_preset),
            i32::from(defaults.nvenc_preset),
        ))
        .map_err(|_| "invalid_nvenc_settings")?,
        nvenc_h264_cavlc: apply_settings_update(
            update.nvenc_h264_cavlc,
            current.nvenc_h264_cavlc,
            defaults.nvenc_h264_cavlc,
        ),
        nvenc_twopass: match update.nvenc_twopass {
            FieldUpdate::Omitted => current.nvenc_twopass,
            FieldUpdate::Null => defaults.nvenc_twopass,
            FieldUpdate::Value(value) => parse_twopass(value).ok_or("invalid_nvenc_settings")?,
        },
        nvenc_vbv_increase: u32::try_from(apply_settings_update(
            update.nvenc_vbv_increase,
            current.nvenc_vbv_increase as i32,
            defaults.nvenc_vbv_increase as i32,
        ))
        .map_err(|_| "invalid_nvenc_settings")?,
        nvenc_split_encode: match update.nvenc_split_encode {
            FieldUpdate::Omitted => current.nvenc_split_encode,
            FieldUpdate::Null => defaults.nvenc_split_encode,
            FieldUpdate::Value(value) => parse_split(value).ok_or("invalid_nvenc_settings")?,
        },
        nvenc_realtime_hags: apply_settings_update(
            update.nvenc_realtime_hags,
            current.nvenc_realtime_hags,
            defaults.nvenc_realtime_hags,
        ),
        nvenc_opengl_vulkan_on_dxgi: apply_settings_update(
            update.nvenc_opengl_vulkan_on_dxgi,
            current.nvenc_opengl_vulkan_on_dxgi,
            defaults.nvenc_opengl_vulkan_on_dxgi,
        ),
        nvenc_latency_over_power: apply_settings_update(
            update.nvenc_latency_over_power,
            current.nvenc_latency_over_power,
            defaults.nvenc_latency_over_power,
        ),
        vaapi_strict_rc_buffer: apply_settings_update(
            update.vaapi_strict_rc_buffer,
            current.vaapi_strict_rc_buffer,
            defaults.vaapi_strict_rc_buffer,
        ),
    };
    settings.validate()?;
    Ok(settings)
}

#[derive(Clone, Debug, Default)]
pub(crate) struct SoftwareEncoderUpdate {
    pub(crate) sw_preset: FieldUpdate<String>,
    pub(crate) sw_tune: FieldUpdate<String>,
    pub(crate) encoder: FieldUpdate<EncoderBackend>,
    pub(crate) min_threads: FieldUpdate<i32>,
}

fn apply_software_encoder_update(
    update: SoftwareEncoderUpdate,
    current: &SoftwareEncoderOptions,
) -> Result<SoftwareEncoderOptions, &'static str> {
    let options = SoftwareEncoderOptions {
        sw_preset: apply_field_update(update.sw_preset, current.sw_preset.clone()),
        sw_tune: apply_field_update(update.sw_tune, current.sw_tune.clone()),
        encoder: apply_field_update(update.encoder, current.encoder),
        min_threads: apply_field_update(update.min_threads, current.min_threads),
    };
    options.validate()?;
    Ok(options)
}

#[derive(Clone, Debug, Default)]
pub(crate) struct DisplayPolicyUpdate {
    pub(crate) dd_mode_remapping: FieldUpdate<Value>,
    pub(crate) dd_resolution_option: FieldUpdate<String>,
    pub(crate) dd_manual_resolution: FieldUpdate<String>,
    pub(crate) dd_refresh_rate_option: FieldUpdate<String>,
    pub(crate) dd_manual_refresh_rate: FieldUpdate<String>,
    pub(crate) dd_hdr_option: FieldUpdate<String>,
    pub(crate) dd_configuration_option: FieldUpdate<String>,
    pub(crate) dd_hdr_request_override: FieldUpdate<String>,
    /// Sparse update for the extended display/capture policy object. Existing
    /// flat fields above remain accepted for older settings clients.
    pub(crate) additional: FieldUpdate<Value>,
}

pub(crate) fn empty_display_policy() -> Value {
    let mut policy = serde_json::Map::new();
    for key in DISPLAY_POLICY_KEYS {
        policy.insert(key.into(), Value::Null);
    }
    Value::Object(policy)
}

fn sparse_display_policy(policy: &Value) -> Value {
    Value::Object(
        policy
            .as_object()
            .expect("display policy object")
            .iter()
            .filter(|(_, value)| !value.is_null())
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect(),
    )
}

fn apply_display_policy_update(
    update: DisplayPolicyUpdate,
    current: &Value,
) -> Result<Value, &'static str> {
    let mut policy = current.clone();
    let fields = policy.as_object_mut().expect("display policy object");
    macro_rules! apply {
        ($name:ident) => {
            match update.$name {
                FieldUpdate::Omitted => {}
                FieldUpdate::Null => {
                    fields.insert(stringify!($name).into(), Value::Null);
                }
                FieldUpdate::Value(value) => {
                    fields.insert(stringify!($name).into(), json!(value));
                }
            }
        };
    }
    apply!(dd_mode_remapping);
    apply!(dd_resolution_option);
    apply!(dd_manual_resolution);
    apply!(dd_refresh_rate_option);
    apply!(dd_manual_refresh_rate);
    apply!(dd_hdr_option);
    apply!(dd_configuration_option);
    apply!(dd_hdr_request_override);
    match update.additional {
        FieldUpdate::Omitted => {}
        FieldUpdate::Null => {
            for key in DISPLAY_POLICY_KEYS {
                fields.insert(key.into(), Value::Null);
            }
        }
        FieldUpdate::Value(value) => {
            let additional = value.as_object().ok_or("invalid_display_policy")?;
            for (key, value) in additional {
                if !DISPLAY_POLICY_KEYS.contains(&key.as_str()) {
                    return Err("invalid_display_policy");
                }
                fields.insert(key.clone(), value.clone());
            }
        }
    }
    validate_display_policy_values(&policy)?;
    Ok(policy)
}

fn valid_manual_resolution(value: &str) -> bool {
    if value.is_empty() {
        return true;
    }
    if value.len() > 32 {
        return false;
    }
    let Some((width, height)) = value
        .replace('×', "x")
        .split_once('x')
        .map(|(width, height)| (width.to_owned(), height.to_owned()))
    else {
        return false;
    };
    [width.as_str(), height.as_str()].iter().all(|part| {
        !part.is_empty()
            && part.bytes().all(|byte| byte.is_ascii_digit())
            && part.parse::<u32>().is_ok_and(|size| size > 0)
    })
}

fn valid_manual_refresh(value: &str) -> bool {
    if value.is_empty() {
        return true;
    }
    let mut parts = value.split('.');
    let whole = parts.next().unwrap_or_default();
    let fractional = parts.next();
    if parts.next().is_some()
        || whole.is_empty()
        || !whole.bytes().all(|byte| byte.is_ascii_digit())
        || fractional.is_some_and(|fraction| {
            fraction.is_empty() || !fraction.bytes().all(|byte| byte.is_ascii_digit())
        })
    {
        return false;
    }
    let whole = whole.trim_start_matches('0');
    let whole = if whole.is_empty() { "0" } else { whole };
    let fraction = fractional.unwrap_or_default().trim_end_matches('0');
    if fraction.is_empty() {
        return whole
            .parse::<u32>()
            .is_ok_and(|rate| rate > 0 && rate <= 1000);
    }
    if fraction.len() > 31 {
        return false;
    }
    let Ok(numerator) = format!("{whole}{fraction}").parse::<u128>() else {
        return false;
    };
    let Some(denominator) = 10_u128.checked_pow(fraction.len() as u32) else {
        return false;
    };
    let mut a = numerator;
    let mut b = denominator;
    while b != 0 {
        (a, b) = (b, a % b);
    }
    let numerator = numerator / a;
    let denominator = denominator / a;
    numerator > 0
        && numerator <= u32::MAX as u128
        && denominator <= u32::MAX as u128
        && numerator <= 1000 * denominator
}

fn valid_bounded_text(value: &Value, maximum_bytes: usize) -> bool {
    value
        .as_str()
        .is_some_and(|text| text.len() <= maximum_bytes && !text.chars().any(char::is_control))
}

fn valid_string_list(value: &Value, maximum_count: usize, maximum_item_bytes: usize) -> bool {
    value.as_array().is_some_and(|items| {
        items.len() <= maximum_count
            && items.iter().all(|item| {
                item.as_str().is_some_and(|text| {
                    !text.is_empty()
                        && text.len() <= maximum_item_bytes
                        && !text.chars().any(char::is_control)
                })
            })
    })
}

fn valid_snapshot_hotkey(value: &Value) -> bool {
    let Some(raw) = value.as_str() else {
        return false;
    };
    let raw = raw.trim();
    if raw.is_empty()
        || matches!(
            raw.to_ascii_lowercase().as_str(),
            "disabled" | "none" | "off"
        )
    {
        return raw.len() <= 64;
    }
    let normalized = raw.to_ascii_lowercase();
    let key = normalized.strip_prefix("vk_").unwrap_or(&normalized);
    if let Some(hex) = key.strip_prefix("0x") {
        return !hex.is_empty()
            && hex.len() <= 2
            && u8::from_str_radix(hex, 16).is_ok_and(|code| code != 0);
    }
    if let Some(function) = key.strip_prefix('f')
        && let Ok(number) = function.parse::<u8>()
    {
        return (1..=24).contains(&number);
    }
    key.len() == 1 && key.as_bytes()[0].is_ascii_alphanumeric()
}

fn valid_snapshot_modifiers(value: &Value) -> bool {
    let Some(raw) = value.as_str() else {
        return false;
    };
    if raw.len() > 128 || raw.chars().any(char::is_control) {
        return false;
    }
    raw.split(['+', '|', ',', ';'])
        .filter(|part| !part.trim().is_empty())
        .all(|part| {
            matches!(
                part.trim().to_ascii_lowercase().as_str(),
                "ctrl"
                    | "control"
                    | "alt"
                    | "shift"
                    | "win"
                    | "windows"
                    | "meta"
                    | "none"
                    | "off"
                    | "disabled"
                    | "default"
            )
        })
}

fn valid_display_remapping(value: &Value) -> bool {
    value.as_object().is_some_and(|groups| {
        groups.iter().all(|(kind, entries)| {
            matches!(
                kind.as_str(),
                "mixed" | "resolution_only" | "refresh_rate_only"
            ) && entries.as_array().is_some_and(|rules| {
                rules.len() <= 128 && rules.iter().all(|rule| valid_display_rule(kind, rule))
            })
        })
    })
}

fn valid_display_rule(kind: &str, rule: &Value) -> bool {
    let Some(fields) = rule.as_object() else {
        return false;
    };
    if !fields.iter().all(|(name, value)| {
        matches!(
            name.as_str(),
            "requested_resolution" | "requested_fps" | "final_resolution" | "final_refresh_rate"
        ) && value
            .as_str()
            .is_some_and(|text| text.len() <= 64 && !text.chars().any(char::is_control))
    }) {
        return false;
    }
    let field = |name: &str| fields.get(name).and_then(Value::as_str).unwrap_or("");
    let requested_resolution = field("requested_resolution");
    let requested_fps = field("requested_fps");
    let final_resolution = field("final_resolution");
    let final_refresh_rate = field("final_refresh_rate");
    let uses_resolution = kind != "refresh_rate_only";
    let uses_refresh = kind != "resolution_only";
    if (!uses_resolution && (!requested_resolution.is_empty() || !final_resolution.is_empty()))
        || (!uses_refresh && (!requested_fps.is_empty() || !final_refresh_rate.is_empty()))
        || (uses_resolution
            && (!valid_manual_resolution(requested_resolution)
                || !valid_manual_resolution(final_resolution)))
        || (uses_refresh
            && (!requested_fps.is_empty()
                && !requested_fps.bytes().all(|byte| byte.is_ascii_digit())
                || (!requested_fps.is_empty()
                    && !requested_fps.parse::<u32>().is_ok_and(|fps| fps > 0))
                || !valid_manual_refresh(final_refresh_rate)))
    {
        return false;
    }
    (uses_resolution && !final_resolution.is_empty())
        || (uses_refresh && !final_refresh_rate.is_empty())
}

pub(crate) fn validate_display_policy_values(policy: &Value) -> Result<(), &'static str> {
    let fields = policy.as_object().ok_or("invalid_display_policy")?;
    if fields.len() != DISPLAY_POLICY_KEYS.len()
        || DISPLAY_POLICY_KEYS
            .iter()
            .any(|key| !fields.contains_key(*key))
    {
        return Err("invalid_display_policy");
    }
    let valid_choice = |key: &str, choices: &[&str]| {
        fields[key].is_null()
            || fields[key]
                .as_str()
                .is_some_and(|value| choices.contains(&value))
    };
    if !valid_choice("dd_resolution_option", &["auto", "disabled", "manual"])
        || !valid_choice(
            "dd_refresh_rate_option",
            &["auto", "disabled", "manual", "prefer_highest"],
        )
        || !valid_choice("dd_hdr_option", &["auto", "disabled"])
        || !valid_choice(
            "dd_configuration_option",
            &[
                "disabled",
                "verify_only",
                "ensure_active",
                "ensure_primary",
                "ensure_only_display",
            ],
        )
        || !valid_choice(
            "dd_hdr_request_override",
            &["auto", "force_on", "force_off"],
        )
        || (!fields["dd_manual_resolution"].is_null()
            && !fields["dd_manual_resolution"]
                .as_str()
                .is_some_and(valid_manual_resolution))
        || (!fields["dd_manual_refresh_rate"].is_null()
            && !fields["dd_manual_refresh_rate"]
                .as_str()
                .is_some_and(valid_manual_refresh))
        || (!fields["dd_mode_remapping"].is_null()
            && !valid_display_remapping(&fields["dd_mode_remapping"]))
        || (!fields["adapter_name"].is_null() && !valid_bounded_text(&fields["adapter_name"], 1024))
        || (!fields["adapter_pnp_id"].is_null()
            && !valid_bounded_text(&fields["adapter_pnp_id"], 256))
        || (fields["adapter_pnp_id"]
            .as_str()
            .is_some_and(|id| !id.is_empty())
            && fields["adapter_name"].as_str().is_none_or(str::is_empty))
        || !valid_choice(
            "virtual_display_mode",
            &["disabled", "per_client", "shared"],
        )
        || !valid_choice(
            "virtual_display_layout",
            &[
                "exclusive",
                "extended",
                "extended_primary",
                "extended_isolated",
                "extended_primary_isolated",
            ],
        )
        || !valid_choice("dd_display_helper_engine", &["auto", "v2", "legacy"])
        || (!fields["dd_config_revert_delay"].is_null()
            && !fields["dd_config_revert_delay"]
                .as_u64()
                .is_some_and(|value| value <= i32::MAX as u64))
        || (!fields["dd_paused_virtual_display_timeout_secs"].is_null()
            && !fields["dd_paused_virtual_display_timeout_secs"]
                .as_u64()
                .is_some_and(|value| value <= i32::MAX as u64))
        || (!fields["dd_snapshot_restore_hotkey"].is_null()
            && !valid_snapshot_hotkey(&fields["dd_snapshot_restore_hotkey"]))
        || (!fields["dd_snapshot_restore_hotkey_modifiers"].is_null()
            && !valid_snapshot_modifiers(&fields["dd_snapshot_restore_hotkey_modifiers"]))
        || (!fields["dd_virtual_display_scale"].is_null()
            && !fields["dd_virtual_display_scale"]
                .as_i64()
                .is_some_and(|scale| {
                    matches!(
                        scale,
                        -1 | 0
                            | 100
                            | 125
                            | 150
                            | 175
                            | 200
                            | 225
                            | 250
                            | 300
                            | 350
                            | 400
                            | 450
                            | 500
                    )
                }))
        || (!fields["dd_virtual_display_permanent_count"].is_null()
            && !fields["dd_virtual_display_permanent_count"]
                .as_u64()
                .is_some_and(|value| value <= 4))
        || (!fields["virtual_display_outputs"].is_null()
            && !valid_string_list(&fields["virtual_display_outputs"], 32, 512))
        || (!fields["dd_snapshot_exclude_devices"].is_null()
            && !valid_string_list(&fields["dd_snapshot_exclude_devices"], 256, 1024))
        || (!fields["dd_config_revert_on_disconnect"].is_null()
            && !fields["dd_config_revert_on_disconnect"].is_boolean())
        || (!fields["dd_always_restore_from_golden"].is_null()
            && !fields["dd_always_restore_from_golden"].is_boolean())
        || (!fields["dd_use_sunshine_virtual_display_driver"].is_null()
            && !fields["dd_use_sunshine_virtual_display_driver"].is_boolean())
        || (!fields["dd_activate_virtual_display"].is_null()
            && !fields["dd_activate_virtual_display"].is_boolean())
        || (!fields["dd_wa_dummy_plug_hdr10"].is_null()
            && !fields["dd_wa_dummy_plug_hdr10"].is_boolean())
        || (!fields["dd_wa_hdr_toggle"].is_null() && !fields["dd_wa_hdr_toggle"].is_boolean())
        || (!fields["dd_wa_hdr_toggle_delay"].is_null()
            && !fields["dd_wa_hdr_toggle_delay"]
                .as_u64()
                .is_some_and(|value| value <= 3000))
        || (!fields["vulkan_hdr_layer"].is_null() && !fields["vulkan_hdr_layer"].is_boolean())
        || (!fields["wayland_hdr_compatibility"].is_null()
            && !fields["wayland_hdr_compatibility"].is_boolean())
    {
        return Err("invalid_display_policy");
    }
    Ok(())
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub enum FieldUpdate<T> {
    #[default]
    Omitted,
    Null,
    Value(T),
}

fn apply_settings_update<T>(update: FieldUpdate<T>, current: T, default: T) -> T {
    match update {
        FieldUpdate::Omitted => current,
        FieldUpdate::Null => default,
        FieldUpdate::Value(value) => value,
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NetworkTarget {
    pub port: u16,
    pub address_family: Option<AddressFamily>,
    pub bind_address: Option<String>,
}

impl From<u16> for NetworkTarget {
    fn from(port: u16) -> Self {
        Self {
            port,
            address_family: None,
            bind_address: None,
        }
    }
}

impl From<&NetworkTarget> for NetworkTarget {
    fn from(target: &NetworkTarget) -> Self {
        target.clone()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeSettings {
    pub hostname: String,
    pub port: u16,
    pub address_family: Option<AddressFamily>,
    pub bind_address: Option<String>,
}

struct AdminRequest {
    request: u64,
    deadline: Instant,
    action: AdminAction,
}

struct PendingCall {
    operation_id: String,
    payload: Value,
    timeout_ms: u64,
    parent: Option<u64>,
    purpose: Purpose,
    state: CallState,
}

enum Purpose {
    Load { followup: Option<Followup> },
    Update(Box<UpdatePurpose>),
}

struct UpdatePurpose {
    request: u64,
    hostname: String,
    target: NetworkTarget,
    output_name: Option<String>,
    audio_sink: Option<String>,
    virtual_sink: Option<String>,
    audio_sink_capture_only: bool,
    install_steam_audio_drivers: bool,
    nvenc_spatial_aq: bool,
    external_ip: Option<String>,
    stream_audio: bool,
    capture: CaptureMode,
    video_max_batch_size_kb: Option<u8>,
    max_bitrate: Option<i32>,
    qp: Option<i32>,
    fec_percentage: Option<u8>,
    minimum_fps_target: Option<f64>,
    wgc_pacing_smoothing: Option<bool>,
    software_encoder: SoftwareEncoderOptions,
    nvenc_settings: NvencSettings,
    ping_timeout_ms: Option<i32>,
    global_preparation: Vec<PreparationStep>,
    legacy_global_preparation: Vec<LegacyPreparationStep>,
    frame_limiter: FrameLimiterSettings,
    display_policy: Value,
    lan_encryption_mode: u8,
    wan_encryption_mode: u8,
    upnp: bool,
    expected_revision: u64,
    require_listener_apply: bool,
}

enum Followup {
    Conflict { request: u64, revision: Option<u64> },
    Unknown { request: u64, reason: String },
}

enum CallState {
    Submitting,
    Waiting { child: u64 },
    Releasing { child: u64, outcome: CallOutcome },
}

enum CallOutcome {
    Payload(Value),
    Failure { code: String, message: String },
}

#[derive(Debug)]
struct ProductDocument {
    revision: u64,
    hostname: Option<String>,
    port: Option<u16>,
    address_family: Option<AddressFamily>,
    bind_address: Option<String>,
    output_name: Option<String>,
    audio_sink: Option<String>,
    virtual_sink: Option<String>,
    audio_sink_capture_only: bool,
    install_steam_audio_drivers: bool,
    nvenc_spatial_aq: bool,
    external_ip: Option<String>,
    stream_audio: bool,
    capture: CaptureMode,
    video_max_batch_size_kb: Option<u8>,
    max_bitrate: Option<i32>,
    qp: Option<i32>,
    fec_percentage: Option<u8>,
    minimum_fps_target: Option<f64>,
    wgc_pacing_smoothing: Option<bool>,
    software_encoder: SoftwareEncoderOptions,
    nvenc_settings: NvencSettings,
    ping_timeout_ms: Option<i32>,
    global_preparation: Vec<PreparationStep>,
    legacy_global_preparation: Vec<LegacyPreparationStep>,
    frame_limiter: FrameLimiterSettings,
    display_policy: Value,
    lan_encryption_mode: u8,
    wan_encryption_mode: u8,
    upnp: bool,
}

#[derive(Clone)]
struct ProductStreamingSettings {
    audio_sink: Option<String>,
    virtual_sink: Option<String>,
    audio_sink_capture_only: bool,
    install_steam_audio_drivers: bool,
    nvenc_spatial_aq: bool,
    external_ip: Option<String>,
    stream_audio: bool,
    capture: CaptureMode,
    video_max_batch_size_kb: Option<u8>,
    max_bitrate: Option<i32>,
    qp: Option<i32>,
    fec_percentage: Option<u8>,
    minimum_fps_target: Option<f64>,
    wgc_pacing_smoothing: Option<bool>,
    software_encoder: SoftwareEncoderOptions,
    nvenc_settings: NvencSettings,
    ping_timeout_ms: Option<i32>,
    global_preparation: Vec<PreparationStep>,
    legacy_global_preparation: Vec<LegacyPreparationStep>,
    frame_limiter: FrameLimiterSettings,
    display_policy: Value,
    lan_encryption_mode: u8,
    wan_encryption_mode: u8,
    upnp: bool,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct FrameLimiterUpdate {
    pub(crate) frame_limiter_enable: FieldUpdate<bool>,
    pub(crate) frame_limiter_fps_limit: FieldUpdate<f64>,
    pub(crate) frame_limiter_provider: FieldUpdate<String>,
    pub(crate) frame_limiter_disable_vsync: FieldUpdate<bool>,
    pub(crate) frame_limiter_auto_virtual_framegen: FieldUpdate<String>,
    pub(crate) rtss_frame_limit_type: FieldUpdate<String>,
    pub(crate) rtss_allow_virtual_display_override: FieldUpdate<bool>,
    pub(crate) rtss_install_path: FieldUpdate<String>,
    pub(crate) mangohud_limiter_method: FieldUpdate<String>,
    pub(crate) mangohud_preset: FieldUpdate<String>,
    pub(crate) mangohud_always_show_graph: FieldUpdate<bool>,
    pub(crate) rtss_disable_vsync_ullm: FieldUpdate<bool>,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct EncryptionModeUpdate {
    pub(crate) lan_encryption_mode: FieldUpdate<i64>,
    pub(crate) wan_encryption_mode: FieldUpdate<i64>,
}

/// Maintains the last confirmed product hostname and serializes its CAS writes.
pub struct ProductSettings {
    bootstrap_settings: Settings,
    bootstrap_hostname: String,
    bootstrap_port: u16,
    bootstrap_fec_percentage: u8,
    bootstrap_address_family: Option<AddressFamily>,
    bootstrap_bind_address: Option<String>,
    bootstrap_http_ip: std::net::IpAddr,
    hostname: String,
    configured_hostname: String,
    port: u16,
    configured_address_family: Option<AddressFamily>,
    configured_bind_address: Option<String>,
    configured_output_name: Option<String>,
    configured_audio_sink: Option<String>,
    configured_virtual_sink: Option<String>,
    audio_sink_capture_only: bool,
    install_steam_audio_drivers: bool,
    nvenc_spatial_aq: bool,
    configured_external_ip: Option<String>,
    configured_capture: CaptureMode,
    configured_video_max_batch_size_kb: Option<u8>,
    configured_max_bitrate: Option<i32>,
    configured_qp: Option<i32>,
    configured_fec_percentage: Option<u8>,
    configured_minimum_fps_target: Option<f64>,
    configured_wgc_pacing_smoothing: Option<bool>,
    configured_software_encoder: SoftwareEncoderOptions,
    configured_nvenc_settings: NvencSettings,
    configured_ping_timeout_ms: Option<i32>,
    configured_global_preparation: Vec<PreparationStep>,
    configured_legacy_global_preparation: Vec<LegacyPreparationStep>,
    configured_frame_limiter: FrameLimiterSettings,
    configured_display_policy: Value,
    lan_encryption_mode: u8,
    wan_encryption_mode: u8,
    configured_upnp: bool,
    upnp_status: String,
    upnp_error: Option<String>,
    stream_audio: bool,
    active_http_port: Option<u16>,
    active_https_port: Option<u16>,
    active_rtsp_base_port: Option<u16>,
    active_http_addresses: Option<Vec<String>>,
    active_https_addresses: Option<Vec<String>>,
    active_rtsp_addresses: Option<Vec<String>>,
    active_http_target: Option<NetworkTarget>,
    active_rtsp_target: Option<NetworkTarget>,
    revision: u64,
    loaded: bool,
    last_error: Option<String>,
    listener_error: Option<String>,
    rtsp_listener_error: Option<String>,
    queued: VecDeque<AdminRequest>,
    completions: VecDeque<Completion>,
    pending: Option<PendingCall>,
    sequence: u64,
    next_retry: Instant,
    retry_delay: Duration,
}

struct Completion {
    request: u64,
    payload: Value,
    required_http_target: Option<NetworkTarget>,
    required_rtsp_target: Option<NetworkTarget>,
}

impl ProductSettings {
    #[cfg(test)]
    pub fn new(bootstrap_hostname: String, bootstrap_port: u16) -> Self {
        Self::with_bootstrap_listener(
            bootstrap_hostname,
            bootstrap_port,
            None,
            None,
            std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            false,
            Settings::default(),
        )
    }

    pub fn with_bootstrap_settings(bootstrap_hostname: String, settings: &Settings) -> Self {
        Self::with_bootstrap_listener(
            bootstrap_hostname,
            settings.http_bind.port(),
            settings.address_family,
            settings.bind_address.clone(),
            settings.http_bind.ip(),
            settings.allow_remote,
            settings.clone(),
        )
    }

    fn with_bootstrap_listener(
        bootstrap_hostname: String,
        bootstrap_port: u16,
        bootstrap_address_family: Option<AddressFamily>,
        bootstrap_bind_address: Option<String>,
        bootstrap_http_ip: std::net::IpAddr,
        bootstrap_allow_remote: bool,
        mut bootstrap_settings: Settings,
    ) -> Self {
        let bootstrap_fec_percentage = bootstrap_settings
            .streaming
            .as_ref()
            .map_or(DEFAULT_FEC_PERCENTAGE, |streaming| {
                streaming.profile.fec_percentage
            });
        let bootstrap_port = if settings::validate_port(bootstrap_port).is_ok() {
            bootstrap_port
        } else {
            settings::DEFAULT_PORT
        };
        bootstrap_settings.http_bind.set_port(bootstrap_port);
        bootstrap_settings
            .https_bind
            .set_port(settings::https_port(bootstrap_port));
        bootstrap_settings.address_family = bootstrap_address_family;
        bootstrap_settings.bind_address = bootstrap_bind_address.clone();
        bootstrap_settings.allow_remote = bootstrap_allow_remote;
        Self {
            bootstrap_settings,
            hostname: bootstrap_hostname.clone(),
            configured_hostname: String::new(),
            bootstrap_hostname,
            bootstrap_port,
            bootstrap_fec_percentage,
            bootstrap_address_family,
            bootstrap_bind_address,
            bootstrap_http_ip,
            port: bootstrap_port,
            configured_address_family: None,
            configured_bind_address: None,
            configured_output_name: None,
            configured_audio_sink: None,
            configured_virtual_sink: None,
            audio_sink_capture_only: false,
            install_steam_audio_drivers: true,
            nvenc_spatial_aq: false,
            configured_external_ip: None,
            configured_capture: CaptureMode::Auto,
            configured_video_max_batch_size_kb: None,
            configured_max_bitrate: None,
            configured_qp: None,
            configured_fec_percentage: None,
            configured_minimum_fps_target: None,
            configured_wgc_pacing_smoothing: None,
            configured_software_encoder: SoftwareEncoderOptions::default(),
            configured_nvenc_settings: NvencSettings::default(),
            configured_ping_timeout_ms: None,
            configured_global_preparation: Vec::new(),
            configured_legacy_global_preparation: Vec::new(),
            configured_frame_limiter: FrameLimiterSettings::default(),
            configured_display_policy: empty_display_policy(),
            lan_encryption_mode: DEFAULT_LAN_ENCRYPTION_MODE,
            wan_encryption_mode: DEFAULT_WAN_ENCRYPTION_MODE,
            configured_upnp: false,
            upnp_status: "disabled".into(),
            upnp_error: None,
            stream_audio: true,
            active_http_port: None,
            active_https_port: None,
            active_rtsp_base_port: None,
            active_http_addresses: None,
            active_https_addresses: None,
            active_rtsp_addresses: None,
            active_http_target: None,
            active_rtsp_target: None,
            revision: 0,
            loaded: false,
            last_error: None,
            listener_error: None,
            rtsp_listener_error: None,
            queued: VecDeque::new(),
            completions: VecDeque::new(),
            pending: None,
            sequence: 0,
            next_retry: Instant::now(),
            retry_delay: Duration::from_secs(1),
        }
    }

    pub fn hostname(&self) -> &str {
        &self.hostname
    }

    pub fn configured_hostname(&self) -> &str {
        &self.configured_hostname
    }

    pub fn configured_output_name(&self) -> Option<&str> {
        self.configured_output_name.as_deref()
    }

    pub fn configured_audio_sink(&self) -> Option<&str> {
        self.configured_audio_sink.as_deref()
    }

    pub fn configured_virtual_sink(&self) -> Option<&str> {
        self.configured_virtual_sink.as_deref()
    }

    pub fn global_preparation(&self) -> &[PreparationStep] {
        &self.configured_global_preparation
    }

    pub fn legacy_global_preparation(&self) -> &[LegacyPreparationStep] {
        &self.configured_legacy_global_preparation
    }

    pub fn configured_frame_limiter(&self) -> &FrameLimiterSettings {
        &self.configured_frame_limiter
    }

    pub fn lan_encryption_mode(&self) -> u8 {
        self.lan_encryption_mode
    }

    pub fn wan_encryption_mode(&self) -> u8 {
        self.wan_encryption_mode
    }

    pub fn audio_sink_capture_only(&self) -> bool {
        self.audio_sink_capture_only
    }

    pub fn install_steam_audio_drivers(&self) -> bool {
        self.install_steam_audio_drivers
    }

    pub fn effective_audio_sink(&self) -> &str {
        self.configured_audio_sink.as_deref().unwrap_or_else(|| {
            self.bootstrap_settings
                .streaming
                .as_ref()
                .map_or("", |streaming| streaming.capture.audio_endpoint.as_str())
        })
    }

    pub fn configured_capture(&self) -> CaptureMode {
        self.configured_capture
    }

    pub fn configured_video_max_batch_size_kb(&self) -> Option<u8> {
        self.configured_video_max_batch_size_kb
    }

    pub fn effective_video_max_batch_size_kb(&self) -> u8 {
        self.configured_video_max_batch_size_kb
            .map(effective_video_max_batch_size_kb)
            .unwrap_or(64)
    }

    pub fn video_batch_size_fallback(&self) -> bool {
        self.configured_video_max_batch_size_kb
            .is_some_and(video_batch_size_fallback)
    }

    pub fn configured_max_bitrate(&self) -> Option<i32> {
        self.configured_max_bitrate
    }

    pub fn effective_max_bitrate_kbps(&self) -> Option<u32> {
        self.configured_max_bitrate
            .filter(|value| *value > 0)
            .map(|value| value as u32)
    }

    pub fn effective_qp(&self) -> i32 {
        self.configured_qp.unwrap_or(28)
    }

    pub fn configured_fec_percentage(&self) -> Option<u8> {
        self.configured_fec_percentage
    }

    pub fn effective_fec_percentage(&self) -> u8 {
        self.configured_fec_percentage
            .unwrap_or(self.bootstrap_fec_percentage)
    }

    pub fn configured_minimum_fps_target(&self) -> Option<f64> {
        self.configured_minimum_fps_target
    }

    pub fn effective_minimum_fps_target(&self) -> f64 {
        self.configured_minimum_fps_target
            .unwrap_or(DEFAULT_MINIMUM_FPS_TARGET)
    }

    pub fn software_encoder_options(&self) -> &SoftwareEncoderOptions {
        &self.configured_software_encoder
    }

    pub fn nvenc_settings(&self) -> &NvencSettings {
        &self.configured_nvenc_settings
    }

    pub fn nvenc_spatial_aq(&self) -> bool {
        self.nvenc_spatial_aq
    }

    pub fn configured_wgc_pacing_smoothing(&self) -> Option<bool> {
        self.configured_wgc_pacing_smoothing
    }

    pub fn effective_wgc_pacing_smoothing(&self) -> bool {
        self.configured_wgc_pacing_smoothing.unwrap_or(true)
    }

    pub fn configured_ping_timeout_ms(&self) -> Option<i32> {
        self.configured_ping_timeout_ms
    }

    pub fn effective_ping_timeout_ms(&self) -> u32 {
        self.configured_ping_timeout_ms
            .map_or(DEFAULT_PING_TIMEOUT_MS, |value| value as u32)
    }

    pub fn stream_audio(&self) -> bool {
        self.stream_audio
    }

    pub fn effective_output_name(&self) -> Option<&str> {
        self.configured_output_name.as_deref().or_else(|| {
            self.bootstrap_settings
                .streaming
                .as_ref()
                .map(|streaming| streaming.capture.output.as_str())
        })
    }

    pub fn capture_provider(&self) -> Option<&'static str> {
        self.bootstrap_settings.streaming.as_ref().map(|streaming| {
            let (provider, _) = self
                .configured_capture
                .resolve(streaming.capture.capture_provider);
            match provider {
                crate::launch::CaptureProvider::Dxgi => "dxgi",
                crate::launch::CaptureProvider::Wgc => "wgc",
                crate::launch::CaptureProvider::PipeWire => "pipewire",
                crate::launch::CaptureProvider::X11 => "x11",
                crate::launch::CaptureProvider::Kms => "kms",
            }
        })
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn upnp_enabled(&self) -> bool {
        self.configured_upnp
    }

    pub(crate) fn set_upnp_runtime_status(
        &mut self,
        status: impl Into<String>,
        error: Option<String>,
    ) {
        self.upnp_status = status.into();
        self.upnp_error = error;
    }

    pub(crate) fn active_rtsp_base_port(&self) -> Option<u16> {
        self.active_rtsp_base_port
    }

    pub(crate) fn active_rtsp_addresses(&self) -> Option<&[String]> {
        self.active_rtsp_addresses.as_deref()
    }

    pub fn http_target(&self) -> NetworkTarget {
        NetworkTarget {
            port: self.port,
            address_family: self
                .configured_address_family
                .or(self.bootstrap_address_family),
            bind_address: self
                .configured_bind_address
                .clone()
                .or_else(|| self.bootstrap_bind_address.clone()),
        }
    }

    /// `None` values deliberately pass through to RTSP's own startup binds.
    pub fn rtsp_target(&self) -> NetworkTarget {
        NetworkTarget {
            port: self.port,
            address_family: self.configured_address_family,
            bind_address: self.configured_bind_address.clone(),
        }
    }

    pub fn effective_address_family(&self) -> AddressFamily {
        if let Some(addresses) = &self.active_http_addresses {
            let has_v6 = addresses
                .iter()
                .filter_map(|address| address.parse::<std::net::SocketAddr>().ok())
                .any(|address| address.is_ipv6());
            return if has_v6 {
                AddressFamily::Both
            } else {
                AddressFamily::Ipv4
            };
        }
        let target = self.http_target();
        self.bootstrap_settings.effective_address_family(
            target.address_family,
            target.bind_address.as_deref(),
            self.bootstrap_http_ip,
        )
    }

    pub fn effective_bind_address(&self) -> String {
        self.active_http_addresses
            .as_ref()
            .and_then(|addresses| addresses.first())
            .and_then(|address| address.parse::<std::net::SocketAddr>().ok())
            .map(|address| address.ip().to_string())
            .or_else(|| {
                self.http_target()
                    .bind_address
                    .filter(|address| !address.trim().is_empty())
            })
            .unwrap_or_else(|| self.bootstrap_http_ip.to_string())
    }

    pub fn loaded(&self) -> bool {
        self.loaded
    }

    #[cfg(test)]
    pub(crate) fn rtsp_listener_error(&self) -> Option<&str> {
        self.rtsp_listener_error.as_deref()
    }

    pub fn set_active_http_state(
        &mut self,
        target: Option<NetworkTarget>,
        http_addresses: Option<Vec<String>>,
        https_addresses: Option<Vec<String>>,
    ) {
        self.active_http_target = target;
        self.set_active_http_addresses(http_addresses, https_addresses);
    }

    pub fn set_active_http_addresses(
        &mut self,
        http_addresses: Option<Vec<String>>,
        https_addresses: Option<Vec<String>>,
    ) {
        self.active_http_addresses = http_addresses;
        self.active_https_addresses = https_addresses;
        self.active_http_port = self
            .active_http_addresses
            .as_ref()
            .and_then(|addresses| addresses.first())
            .and_then(|address| address.parse::<std::net::SocketAddr>().ok())
            .map(|address| address.port());
        self.active_https_port = self
            .active_https_addresses
            .as_ref()
            .and_then(|addresses| addresses.first())
            .and_then(|address| address.parse::<std::net::SocketAddr>().ok())
            .map(|address| address.port());
    }

    pub fn set_active_http_target(&mut self, target: NetworkTarget) {
        self.active_http_target = Some(target);
    }

    pub fn set_active_rtsp_state(
        &mut self,
        target: Option<NetworkTarget>,
        port: Option<u16>,
        addresses: Option<Vec<String>>,
    ) {
        self.active_rtsp_target = target;
        self.active_rtsp_base_port = port;
        self.active_rtsp_addresses = addresses;
    }

    pub fn rtsp_completion_request(&self, target: impl Into<NetworkTarget>) -> Option<u64> {
        let target = target.into();
        self.completions
            .iter()
            .find(|completion| completion.required_rtsp_target.as_ref() == Some(&target))
            .map(|completion| completion.request)
    }

    #[cfg(test)]
    pub(crate) fn rtsp_completion_payload(&self, request: u64) -> Option<&Value> {
        self.completions
            .iter()
            .find(|completion| completion.request == request)
            .map(|completion| &completion.payload)
    }

    pub fn listeners_need_application(&self) -> bool {
        if !self.loaded || self.active_http_target.as_ref() == Some(&self.http_target()) {
            return false;
        }
        let bootstrap_target = NetworkTarget {
            port: self.bootstrap_port,
            address_family: self.bootstrap_address_family,
            bind_address: self.bootstrap_bind_address.clone(),
        };
        self.active_http_target.is_some() || self.http_target() != bootstrap_target
    }

    #[cfg(test)]
    fn port_needs_application(&self) -> bool {
        self.listeners_need_application()
    }

    #[cfg(test)]
    pub fn set_active_ports(&mut self, http_port: Option<u16>, https_port: Option<u16>) {
        self.active_http_port = http_port;
        self.active_https_port = https_port;
        if let Some(port) = http_port {
            let mut target = self.http_target();
            target.port = port;
            self.active_http_target = Some(target);
        }
    }

    #[cfg(test)]
    pub(crate) fn set_active_rtsp_base_port(&mut self, port: Option<u16>) {
        self.active_rtsp_base_port = port;
        self.active_rtsp_target = port.map(|port| {
            let mut target = self.rtsp_target();
            target.port = port;
            target
        });
    }

    #[cfg(test)]
    fn record_port_apply_failure(&mut self, port: u16, message: String) {
        let mut target = self.http_target();
        target.port = port;
        self.record_listener_apply_failure(&target, message);
    }

    pub fn record_listener_apply_failure(&mut self, target: &NetworkTarget, message: String) {
        self.listener_error = Some(message.clone());
        if let Some(completion) = self
            .completions
            .iter_mut()
            .find(|completion| completion.required_http_target.as_ref() == Some(target))
        {
            completion.payload = json!({
                "ok":false,
                "code":"listener_apply_failed",
                "message":format!("settings were persisted but listener rebinding failed: {message}"),
                "persisted":true,
            });
            completion.required_http_target = None;
        }
    }

    pub fn record_listener_apply_success(&mut self) {
        self.listener_error = None;
    }

    pub fn record_rtsp_apply_failure(&mut self, target: impl Into<NetworkTarget>, message: String) {
        let target = target.into();
        self.rtsp_listener_error = Some(message.clone());
        let hostname = self.hostname.clone();
        let revision = self.revision;
        let address_family = self.effective_address_family();
        let bind_address = self.effective_bind_address();
        let configured_address_family = self.configured_address_family;
        let configured_bind_address = self.configured_bind_address.clone();
        if let Some(completion) = self
            .completions
            .iter_mut()
            .find(|completion| completion.required_rtsp_target.as_ref() == Some(&target))
        {
            completion.payload = json!({
                "ok":false,
                "code":"listener_apply_pending",
                "message":format!("settings were persisted but RTSP/UDP listeners are not active: {message}"),
                "persisted":true,
                "hostname":hostname,
                "revision":revision,
                "address_family":address_family,
                "bind_address":bind_address,
                "configured_address_family":configured_address_family,
                "configured_bind_address":configured_bind_address,
            });
            completion.required_rtsp_target = None;
        }
    }

    pub fn record_rtsp_apply_success(&mut self) {
        self.rtsp_listener_error = None;
    }

    pub fn record_listener_disabled(&mut self) {
        if self.listeners_need_application() {
            self.listener_error =
                Some("NVHTTP listener is disabled; stored port will apply when enabled".into());
        }
    }

    pub fn revision(&self) -> Option<u64> {
        self.loaded.then_some(self.revision)
    }

    pub fn display_policy_snapshot(&self) -> Option<(u64, Value)> {
        self.loaded.then(|| {
            (
                self.revision,
                sparse_display_policy(&self.configured_display_policy),
            )
        })
    }

    pub fn last_error(&self) -> Option<&str> {
        self.listener_error
            .as_deref()
            .or(self.rtsp_listener_error.as_deref())
            .or(self.last_error.as_deref())
    }

    pub fn enqueue(
        &mut self,
        request: u64,
        remaining_ms: u64,
        action: AdminAction,
    ) -> Result<(), &'static str> {
        let active_admin = self.pending.as_ref().is_some_and(|pending| {
            matches!(&pending.purpose, Purpose::Update { .. })
                || matches!(&pending.purpose, Purpose::Load { followup: Some(_) })
        });
        if self.queued.len() + self.completions.len() + usize::from(active_admin)
            >= MAX_QUEUED_ADMIN_REQUESTS
        {
            return Err("settings request capacity exhausted");
        }
        let timeout = Duration::from_millis(remaining_ms.min(30_000));
        self.queued.push_back(AdminRequest {
            request,
            deadline: Instant::now() + timeout,
            action,
        });
        Ok(())
    }

    /// Advances one configuration call or starts the next required operation.
    /// Returns a hostname only after a complete read or committed update confirms it.
    pub fn tick(&mut self, runtime: &RuntimeClient) -> ModuleResult<Option<RuntimeSettings>> {
        let previous_hostname = self.hostname.clone();
        let previous_target = self.http_target();
        self.advance_pending(runtime);
        self.expire_queued();
        if self.pending.is_none() {
            self.start_next();
        }
        let target = self.http_target();
        let changed = self.hostname != previous_hostname || target != previous_target;
        Ok(changed.then(|| RuntimeSettings {
            hostname: self.hostname.clone(),
            port: target.port,
            address_family: target.address_family,
            bind_address: target.bind_address,
        }))
    }

    fn advance_pending(&mut self, runtime: &RuntimeClient) {
        let Some(mut pending) = self.pending.take() else {
            return;
        };
        match &mut pending.state {
            CallState::Submitting => match runtime.send(request_command(&pending)) {
                Ok(Response::Accepted { id }) => pending.state = CallState::Waiting { child: id },
                Ok(Response::Error { code, message }) => {
                    self.finish_submission_failure(
                        pending.purpose,
                        SettingFailure {
                            code,
                            message,
                            current_revision: None,
                        },
                    );
                    return;
                }
                Ok(response) => {
                    self.finish_submission_failure(
                        pending.purpose,
                        SettingFailure {
                            code: "configuration_unavailable".into(),
                            message: format!("unexpected configuration response: {response:?}"),
                            current_revision: None,
                        },
                    );
                    return;
                }
                Err(error) => {
                    self.last_error = Some(error);
                    self.pending = Some(pending);
                    return;
                }
            },
            CallState::Waiting { child } => match runtime
                .send(Command::TakeResult { request: *child })
            {
                Ok(Response::Pending) => {
                    self.pending = Some(pending);
                    return;
                }
                Ok(Response::Result { payload }) => {
                    pending.state = CallState::Releasing {
                        child: *child,
                        outcome: CallOutcome::Payload(payload),
                    };
                }
                Ok(Response::Error { code, message }) => {
                    if code == "not_found" {
                        self.finish_call(pending.purpose, CallOutcome::Failure { code, message });
                        return;
                    }
                    pending.state = CallState::Releasing {
                        child: *child,
                        outcome: CallOutcome::Failure { code, message },
                    };
                }
                Ok(response) => {
                    pending.state = CallState::Releasing {
                        child: *child,
                        outcome: CallOutcome::Failure {
                            code: "configuration_unavailable".into(),
                            message: format!("unexpected configuration result: {response:?}"),
                        },
                    };
                }
                Err(error) => {
                    self.last_error = Some(error);
                    self.pending = Some(pending);
                    return;
                }
            },
            CallState::Releasing { child, .. } => {
                match runtime.send(Command::ReleaseResult { request: *child }) {
                    Ok(Response::Ok) => {
                        let CallState::Releasing { outcome, .. } = pending.state else {
                            unreachable!()
                        };
                        self.finish_call(pending.purpose, outcome);
                        return;
                    }
                    Ok(Response::Error { code, .. }) if code == "not_found" => {
                        let CallState::Releasing { outcome, .. } = pending.state else {
                            unreachable!()
                        };
                        self.finish_call(pending.purpose, outcome);
                        return;
                    }
                    Ok(response) => {
                        self.last_error =
                            Some(format!("configuration result cleanup failed: {response:?}"));
                        self.pending = Some(pending);
                        return;
                    }
                    Err(error) => {
                        self.last_error = Some(error);
                        self.pending = Some(pending);
                        return;
                    }
                }
            }
        }

        // A just accepted child is polled on the next tick.
        self.pending = Some(pending);
    }

    fn expire_queued(&mut self) {
        let now = Instant::now();
        let mut active = VecDeque::new();
        while let Some(request) = self.queued.pop_front() {
            if request.deadline <= now {
                self.queue_completion(
                    request.request,
                    failure(
                        "settings_timeout",
                        "settings request expired before execution",
                    ),
                );
            } else {
                active.push_back(request);
            }
        }
        self.queued = active;
    }

    fn start_next(&mut self) {
        if self.completions.iter().any(|completion| {
            completion.required_http_target.is_some() || completion.required_rtsp_target.is_some()
        }) {
            return;
        }
        if !self.loaded {
            if Instant::now() >= self.next_retry {
                self.start_load(None);
            } else if let Some(error) = self.last_error.clone() {
                self.fail_queued(&error);
            }
            return;
        }

        let Some(request) = self.queued.pop_front() else {
            return;
        };
        match request.action {
            AdminAction::Get => {
                self.queue_completion(request.request, self.settings_payload());
            }
            AdminAction::Update {
                hostname,
                port,
                address_family,
                bind_address,
                output_name,
                audio_sink,
                virtual_sink,
                audio_sink_capture_only,
                install_steam_audio_drivers,
                nvenc_spatial_aq,
                external_ip,
                stream_audio,
                capture,
                video_max_batch_size_kb,
                max_bitrate,
                qp,
                fec_percentage,
                minimum_fps_target,
                wgc_pacing_smoothing,
                software_encoder,
                nvenc_settings,
                ping_timeout_ms,
                global_preparation,
                legacy_global_preparation,
                frame_limiter,
                display_policy,
                encryption_modes,
                upnp,
                expected_revision,
                require_listener_apply,
            } => {
                if settings::validate_configured_hostname(&hostname).is_err() {
                    self.queue_completion(
                        request.request,
                        failure("invalid_hostname", "hostname is invalid"),
                    );
                    return;
                }
                if settings::validate_port(port).is_err() {
                    self.queue_completion(
                        request.request,
                        failure("invalid_port", "port is outside the supported range"),
                    );
                    return;
                }
                let output_name = match apply_output_name_update(
                    output_name,
                    self.configured_output_name.clone(),
                ) {
                    Ok(output_name) => output_name,
                    Err(()) => {
                        self.queue_completion(
                            request.request,
                            failure("invalid_output_name", "output name is invalid"),
                        );
                        return;
                    }
                };
                let audio_sink =
                    match apply_audio_sink_update(audio_sink, self.configured_audio_sink.clone()) {
                        Ok(audio_sink) => audio_sink,
                        Err(()) => {
                            self.queue_completion(
                                request.request,
                                failure("invalid_audio_sink", "audio_sink is invalid"),
                            );
                            return;
                        }
                    };
                let virtual_sink = match apply_virtual_sink_update(
                    virtual_sink,
                    self.configured_virtual_sink.clone(),
                ) {
                    Ok(virtual_sink) => virtual_sink,
                    Err(()) => {
                        self.queue_completion(
                            request.request,
                            failure("invalid_virtual_sink", "virtual_sink is invalid"),
                        );
                        return;
                    }
                };
                let audio_sink_capture_only = match apply_boolean_update(
                    audio_sink_capture_only,
                    self.audio_sink_capture_only,
                ) {
                    Ok(value) => value,
                    Err(()) => {
                        self.queue_completion(
                            request.request,
                            failure(
                                "invalid_audio_sink_capture_only",
                                "audio_sink_capture_only must be a boolean",
                            ),
                        );
                        return;
                    }
                };
                let install_steam_audio_drivers = match apply_boolean_update(
                    install_steam_audio_drivers,
                    self.install_steam_audio_drivers,
                ) {
                    Ok(value) => value,
                    Err(()) => {
                        self.queue_completion(
                            request.request,
                            failure(
                                "invalid_install_steam_audio_drivers",
                                "install_steam_audio_drivers must be a boolean",
                            ),
                        );
                        return;
                    }
                };
                let nvenc_spatial_aq =
                    apply_nvenc_spatial_aq_update(nvenc_spatial_aq, self.nvenc_spatial_aq);
                let external_ip = match apply_external_ip_update(
                    external_ip,
                    self.configured_external_ip.clone(),
                ) {
                    Ok(external_ip) => external_ip,
                    Err(()) => {
                        self.queue_completion(
                            request.request,
                            failure("invalid_external_ip", "external_ip is invalid"),
                        );
                        return;
                    }
                };
                let stream_audio = match apply_boolean_update(stream_audio, self.stream_audio) {
                    Ok(stream_audio) => stream_audio,
                    Err(()) => {
                        self.queue_completion(
                            request.request,
                            failure("invalid_stream_audio", "stream_audio must be a boolean"),
                        );
                        return;
                    }
                };
                let capture = apply_capture_update(capture, self.configured_capture);
                let video_max_batch_size_kb = match apply_video_max_batch_size_update(
                    video_max_batch_size_kb,
                    self.configured_video_max_batch_size_kb,
                ) {
                    Ok(value) => value,
                    Err(()) => {
                        self.queue_completion(
                            request.request,
                            failure(
                                "invalid_video_max_batch_size_kb",
                                "video_max_batch_size_kb must be an integer from 0 to 64 or null",
                            ),
                        );
                        return;
                    }
                };
                let max_bitrate = apply_field_update(max_bitrate, self.configured_max_bitrate);
                let qp = apply_field_update(qp, self.configured_qp);
                let fec_percentage = match apply_fec_percentage_update(
                    fec_percentage,
                    self.configured_fec_percentage,
                ) {
                    Ok(value) => value,
                    Err(()) => {
                        self.queue_completion(
                            request.request,
                            failure(
                                "invalid_fec_percentage",
                                "fec_percentage must be an integer from 1 to 255 or null",
                            ),
                        );
                        return;
                    }
                };
                let minimum_fps_target = match apply_minimum_fps_update(
                    minimum_fps_target,
                    self.configured_minimum_fps_target,
                ) {
                    Ok(value) => value,
                    Err(()) => {
                        self.queue_completion(
                            request.request,
                            failure(
                                "invalid_minimum_fps_target",
                                "minimum_fps_target must be a finite number from 0 to 1000 or null",
                            ),
                        );
                        return;
                    }
                };
                let wgc_pacing_smoothing =
                    apply_field_update(wgc_pacing_smoothing, self.configured_wgc_pacing_smoothing);
                let software_encoder = match apply_software_encoder_update(
                    software_encoder,
                    &self.configured_software_encoder,
                ) {
                    Ok(options) => options,
                    Err(code) => {
                        self.queue_completion(
                            request.request,
                            failure(code, "software encoder options are invalid"),
                        );
                        return;
                    }
                };
                let nvenc_settings =
                    match update_nvenc_settings(nvenc_settings, &self.configured_nvenc_settings) {
                        Ok(settings) => settings,
                        Err(code) => {
                            self.queue_completion(
                                request.request,
                                failure(code, "NVENC settings are invalid"),
                            );
                            return;
                        }
                    };
                let ping_timeout_ms = match apply_ping_timeout_update(
                    ping_timeout_ms,
                    self.configured_ping_timeout_ms,
                ) {
                    Ok(value) => value,
                    Err(()) => {
                        self.queue_completion(
                            request.request,
                            failure(
                                "invalid_ping_timeout_ms",
                                "ping_timeout_ms must be -1, null, or an integer from 0 to 2147483647",
                            ),
                        );
                        return;
                    }
                };
                let global_preparation = match apply_global_preparation_update(
                    global_preparation,
                    self.configured_global_preparation.clone(),
                ) {
                    Ok(value) => value,
                    Err(()) => {
                        self.queue_completion(
                            request.request,
                            failure(
                                "invalid_global_preparation",
                                "global_preparation must contain at most 8 valid preparation steps",
                            ),
                        );
                        return;
                    }
                };
                let legacy_global_preparation = match apply_legacy_global_preparation_update(
                    legacy_global_preparation,
                    self.configured_legacy_global_preparation.clone(),
                ) {
                    Ok(preparation) => preparation,
                    Err(()) => {
                        self.queue_completion(
                            request.request,
                            failure(
                                "invalid_legacy_global_preparation",
                                "legacy_global_preparation contains invalid or oversized command strings",
                            ),
                        );
                        return;
                    }
                };
                let frame_limiter = match apply_frame_limiter_update(
                    frame_limiter,
                    self.configured_frame_limiter.clone(),
                ) {
                    Ok(settings) => settings,
                    Err(code) => {
                        self.queue_completion(
                            request.request,
                            failure(code, "frame-limiter settings are invalid"),
                        );
                        return;
                    }
                };
                let display_policy = match apply_display_policy_update(
                    display_policy,
                    &self.configured_display_policy,
                ) {
                    Ok(policy) => policy,
                    Err(code) => {
                        self.queue_completion(
                            request.request,
                            failure(code, "display policy is invalid"),
                        );
                        return;
                    }
                };
                let lan_encryption_mode = match apply_encryption_mode_update(
                    encryption_modes.lan_encryption_mode,
                    self.lan_encryption_mode,
                    DEFAULT_LAN_ENCRYPTION_MODE,
                ) {
                    Ok(mode) => mode,
                    Err(()) => {
                        self.queue_completion(
                            request.request,
                            failure(
                                "invalid_lan_encryption_mode",
                                "lan_encryption_mode must be an integer from 0 to 2",
                            ),
                        );
                        return;
                    }
                };
                let wan_encryption_mode = match apply_encryption_mode_update(
                    encryption_modes.wan_encryption_mode,
                    self.wan_encryption_mode,
                    DEFAULT_WAN_ENCRYPTION_MODE,
                ) {
                    Ok(mode) => mode,
                    Err(()) => {
                        self.queue_completion(
                            request.request,
                            failure(
                                "invalid_wan_encryption_mode",
                                "wan_encryption_mode must be an integer from 0 to 2",
                            ),
                        );
                        return;
                    }
                };
                let upnp = match apply_boolean_update(upnp, self.configured_upnp) {
                    Ok(value) => value,
                    Err(()) => {
                        self.queue_completion(
                            request.request,
                            failure("invalid_upnp", "upnp must be a boolean"),
                        );
                        return;
                    }
                };
                let target = NetworkTarget {
                    port,
                    address_family: apply_field_update(
                        address_family,
                        self.configured_address_family,
                    ),
                    bind_address: apply_field_update(
                        bind_address,
                        self.configured_bind_address.clone(),
                    ),
                };
                let mut validation_settings = self.bootstrap_settings.clone();
                validation_settings.http_bind.set_port(port);
                validation_settings
                    .https_bind
                    .set_port(settings::https_port(port));
                validation_settings.address_family =
                    target.address_family.or(self.bootstrap_address_family);
                validation_settings.bind_address = target
                    .bind_address
                    .clone()
                    .or_else(|| self.bootstrap_bind_address.clone());
                if validation_settings
                    .validate_network_policy(
                        validation_settings.address_family,
                        validation_settings.bind_address.as_deref(),
                    )
                    .is_err()
                {
                    self.queue_completion(
                        request.request,
                        failure(
                            "invalid_network_policy",
                            "listener address policy is invalid",
                        ),
                    );
                    return;
                }
                let remaining_ms = request
                    .deadline
                    .saturating_duration_since(Instant::now())
                    .as_millis() as u64;
                if remaining_ms == 0 {
                    self.queue_completion(
                        request.request,
                        failure(
                            "settings_timeout",
                            "settings request expired before execution",
                        ),
                    );
                    return;
                }
                self.start_call(
                    product_update_payload(
                        expected_revision,
                        &hostname,
                        &target,
                        output_name.as_deref(),
                        ProductStreamingSettings {
                            audio_sink: audio_sink.clone(),
                            virtual_sink: virtual_sink.clone(),
                            audio_sink_capture_only,
                            install_steam_audio_drivers,
                            nvenc_spatial_aq,
                            external_ip: external_ip.clone(),
                            stream_audio,
                            capture,
                            video_max_batch_size_kb,
                            max_bitrate,
                            qp,
                            fec_percentage,
                            minimum_fps_target,
                            wgc_pacing_smoothing,
                            software_encoder: software_encoder.clone(),
                            nvenc_settings: nvenc_settings.clone(),
                            ping_timeout_ms,
                            global_preparation: global_preparation.clone(),
                            legacy_global_preparation: legacy_global_preparation.clone(),
                            frame_limiter: frame_limiter.clone(),
                            display_policy: display_policy.clone(),
                            lan_encryption_mode,
                            wan_encryption_mode,
                            upnp,
                        },
                    ),
                    Some(request.request),
                    remaining_ms.min(CONFIGURATION_TIMEOUT.as_millis() as u64),
                    Purpose::Update(Box::new(UpdatePurpose {
                        request: request.request,
                        hostname,
                        target,
                        output_name,
                        audio_sink,
                        virtual_sink,
                        audio_sink_capture_only,
                        install_steam_audio_drivers,
                        nvenc_spatial_aq,
                        external_ip,
                        stream_audio,
                        capture,
                        video_max_batch_size_kb,
                        max_bitrate,
                        qp,
                        fec_percentage,
                        minimum_fps_target,
                        wgc_pacing_smoothing,
                        software_encoder,
                        nvenc_settings,
                        ping_timeout_ms,
                        global_preparation,
                        legacy_global_preparation,
                        frame_limiter,
                        display_policy,
                        lan_encryption_mode,
                        wan_encryption_mode,
                        upnp,
                        expected_revision,
                        require_listener_apply,
                    })),
                );
            }
        }
    }

    fn start_load(&mut self, followup: Option<Followup>) {
        self.loaded = false;
        self.start_call(
            json!({"action":"product_get"}),
            None,
            CONFIGURATION_TIMEOUT.as_millis() as u64,
            Purpose::Load { followup },
        );
    }

    fn start_call(
        &mut self,
        payload: Value,
        parent: Option<u64>,
        timeout_ms: u64,
        purpose: Purpose,
    ) {
        let Some(sequence) = self.sequence.checked_add(1) else {
            match purpose {
                Purpose::Load { .. } => {
                    self.record_load_failure("configuration operation identifier exhausted".into())
                }
                Purpose::Update(update) => self.queue_completion(
                    update.request,
                    failure(
                        "resource_exhausted",
                        "configuration operation identifier exhausted",
                    ),
                ),
            }
            return;
        };
        self.sequence = sequence;
        let action = payload
            .get("action")
            .and_then(Value::as_str)
            .unwrap_or("call");
        self.pending = Some(PendingCall {
            operation_id: format!("nvhttp.product_settings.{sequence}.{action}"),
            payload,
            timeout_ms,
            parent,
            purpose,
            state: CallState::Submitting,
        });
    }

    fn finish_submission_failure(&mut self, purpose: Purpose, error: SettingFailure) {
        match purpose {
            Purpose::Load { .. } => {
                let description = format!("{}: {}", error.code, error.message);
                self.record_load_failure(description.clone());
                self.fail_queued(&description);
            }
            Purpose::Update(update) => {
                self.queue_completion(update.request, error_response(&error));
            }
        }
    }

    fn finish_call(&mut self, purpose: Purpose, outcome: CallOutcome) {
        match purpose {
            Purpose::Load { followup } => {
                let result = match outcome {
                    CallOutcome::Payload(payload) => parse_document(&payload),
                    CallOutcome::Failure { code, message } => Err(SettingFailure {
                        code,
                        message,
                        current_revision: None,
                    }),
                };
                match result {
                    Ok(document) if self.validate_document(&document).is_ok() => {
                        self.apply_document(document);
                        self.record_load_success();
                        if let Some(followup) = followup {
                            self.complete_followup(followup, Ok(()));
                        }
                    }
                    Ok(_) => {
                        let error = invalid_state("persisted listener address policy is invalid");
                        let description = format!("{}: {}", error.code, error.message);
                        self.record_load_failure(description.clone());
                        self.fail_queued(&description);
                        if let Some(followup) = followup {
                            self.complete_followup(followup, Err(error));
                        }
                    }
                    Err(error) => {
                        let description = format!("{}: {}", error.code, error.message);
                        self.record_load_failure(description.clone());
                        self.fail_queued(&description);
                        if let Some(followup) = followup {
                            self.complete_followup(followup, Err(error));
                        }
                    }
                }
            }
            Purpose::Update(update) => {
                let UpdatePurpose {
                    request,
                    hostname,
                    target,
                    output_name,
                    audio_sink,
                    virtual_sink,
                    audio_sink_capture_only,
                    install_steam_audio_drivers,
                    nvenc_spatial_aq,
                    external_ip,
                    stream_audio,
                    capture,
                    video_max_batch_size_kb,
                    max_bitrate,
                    qp,
                    fec_percentage,
                    minimum_fps_target,
                    wgc_pacing_smoothing,
                    software_encoder,
                    nvenc_settings,
                    ping_timeout_ms,
                    global_preparation,
                    legacy_global_preparation,
                    frame_limiter,
                    display_policy,
                    lan_encryption_mode,
                    wan_encryption_mode,
                    upnp,
                    expected_revision,
                    require_listener_apply,
                } = *update;
                match outcome {
                    CallOutcome::Payload(payload) => {
                        let expected = UpdateExpectation {
                            revision: expected_revision,
                            hostname: &hostname,
                            target: &target,
                            output_name: output_name.as_deref(),
                            audio_sink: audio_sink.as_deref(),
                            virtual_sink: virtual_sink.as_deref(),
                            audio_sink_capture_only,
                            install_steam_audio_drivers,
                            nvenc_spatial_aq,
                            external_ip: external_ip.as_deref(),
                            stream_audio,
                            capture,
                            video_max_batch_size_kb,
                            max_bitrate,
                            qp,
                            fec_percentage,
                            minimum_fps_target,
                            wgc_pacing_smoothing,
                            software_encoder: &software_encoder,
                            nvenc_settings: &nvenc_settings,
                            ping_timeout_ms,
                            global_preparation: &global_preparation,
                            legacy_global_preparation: &legacy_global_preparation,
                            frame_limiter: &frame_limiter,
                            display_policy: &display_policy,
                            lan_encryption_mode,
                            wan_encryption_mode,
                            upnp,
                        };
                        match update_result(&payload, &expected) {
                            Ok(document) if self.validate_document(&document).is_ok() => {
                                let previous_http_target = self.http_target();
                                let previous_rtsp_target = self.rtsp_target();
                                self.apply_document(document);
                                let desired_http_target = self.http_target();
                                let desired_rtsp_target = self.rtsp_target();
                                let network_changed = previous_http_target != desired_http_target
                                    || previous_rtsp_target != desired_rtsp_target;
                                self.record_load_success();
                                if !require_listener_apply && network_changed {
                                    self.listener_error = Some(
                                        "NVHTTP listener is disabled; stored network settings are not active".into(),
                                    );
                                    self.queue_completion(
                                        request,
                                        json!({
                                            "ok":false,
                                            "code":"listener_not_active",
                                            "message":"settings were persisted, but NVHTTP is disabled",
                                            "persisted":true,
                                        }),
                                    );
                                } else {
                                    self.queue_listener_update_completion(
                                        request,
                                        self.settings_payload(),
                                        (require_listener_apply
                                            && self.active_http_target.as_ref()
                                                != Some(&desired_http_target))
                                        .then_some(desired_http_target),
                                        (require_listener_apply
                                            && self.active_rtsp_target.as_ref()
                                                != Some(&desired_rtsp_target))
                                        .then_some(desired_rtsp_target),
                                    );
                                }
                            }
                            Ok(_) => {
                                self.start_load(Some(Followup::Unknown {
                                    request,
                                    reason: "product_update committed invalid settings".into(),
                                }));
                            }
                            Err(error) if error.code == "revision_conflict" => {
                                let revision = error.current_revision;
                                self.start_load(Some(Followup::Conflict { request, revision }));
                            }
                            Err(error) if known_precommit_error(&error.code) => {
                                self.queue_completion(request, error_response(&error));
                            }
                            Err(error) => {
                                self.start_load(Some(Followup::Unknown {
                                    request,
                                    reason: format!("{}: {}", error.code, error.message),
                                }));
                            }
                        }
                    }
                    CallOutcome::Failure { code, message } => {
                        self.start_load(Some(Followup::Unknown {
                            request,
                            reason: format!("{code}: {message}"),
                        }));
                    }
                }
            }
        }
    }

    fn complete_followup(
        &mut self,
        followup: Followup,
        reconciliation: Result<(), SettingFailure>,
    ) {
        let (request, payload) = match followup {
            Followup::Conflict { request, revision } => {
                let current_revision = if reconciliation.is_ok() {
                    Some(self.revision)
                } else {
                    revision
                };
                (
                    request,
                    failure_with_revision(
                        "revision_conflict",
                        "configuration revision differs",
                        current_revision,
                    ),
                )
            }
            Followup::Unknown { request, reason } => {
                let detail = reconciliation
                    .err()
                    .map(|failure| {
                        format!("; readback failed: {}: {}", failure.code, failure.message)
                    })
                    .unwrap_or_default();
                (
                    request,
                    failure(
                        "settings_outcome_unknown",
                        format!("update outcome could not be confirmed ({reason}){detail}"),
                    ),
                )
            }
        };
        self.queue_completion(request, payload);
    }

    fn queue_completion(&mut self, request: u64, payload: Value) {
        self.completions.push_back(Completion {
            request,
            payload,
            required_http_target: None,
            required_rtsp_target: None,
        });
    }

    pub(crate) fn queue_listener_update_completion(
        &mut self,
        request: u64,
        payload: Value,
        required_http_target: Option<NetworkTarget>,
        required_rtsp_target: Option<NetworkTarget>,
    ) {
        self.completions.push_back(Completion {
            request,
            payload,
            required_http_target,
            required_rtsp_target,
        });
    }

    #[cfg(test)]
    pub(crate) fn queue_update_completion(
        &mut self,
        request: u64,
        payload: Value,
        required_http_port: Option<u16>,
        required_rtsp_port: Option<u16>,
    ) {
        let http_target = required_http_port.map(|port| {
            let mut target = self.http_target();
            target.port = port;
            target
        });
        let rtsp_target = required_rtsp_port.map(|port| {
            let mut target = self.rtsp_target();
            target.port = port;
            target
        });
        self.queue_listener_update_completion(request, payload, http_target, rtsp_target);
    }

    pub fn flush_completion(&mut self, runtime: &RuntimeClient) {
        let Some(completion) = self.completions.front() else {
            return;
        };
        if completion
            .required_http_target
            .as_ref()
            .is_some_and(|target| {
                self.active_http_target.as_ref() != Some(target)
                    || self.active_http_port != Some(target.port)
                    || self.active_https_port != Some(settings::https_port(target.port))
            })
        {
            return;
        }
        if completion
            .required_rtsp_target
            .as_ref()
            .is_some_and(|target| {
                self.active_rtsp_target.as_ref() != Some(target)
                    || self.active_rtsp_base_port != Some(target.port)
            })
        {
            return;
        }
        let mut payload = completion.payload.clone();
        if payload.get("ok").and_then(Value::as_bool) == Some(true) {
            payload["active_http_port"] = json!(self.active_http_port);
            payload["active_https_port"] = json!(self.active_https_port);
            payload["active_rtsp_port"] = json!(self.active_rtsp_base_port);
            payload["http_addresses"] = json!(self.active_http_addresses);
            payload["https_addresses"] = json!(self.active_https_addresses);
            payload["rtsp_addresses"] = json!(self.active_rtsp_addresses);
            payload["listener_error"] = json!(self.listener_error);
            payload["rtsp_listener_error"] = json!(self.rtsp_listener_error);
        }
        match runtime.send(Command::Complete {
            request: completion.request,
            payload,
        }) {
            Ok(Response::Ok) => {
                self.completions.pop_front();
            }
            Ok(Response::Error { code, .. }) if code == "request_ended" || code == "not_found" => {
                self.completions.pop_front();
            }
            Ok(response) => {
                self.last_error =
                    Some(format!("settings response completion failed: {response:?}"));
            }
            Err(error) => self.last_error = Some(error),
        }
    }

    fn validate_document(&self, document: &ProductDocument) -> Result<(), SettingFailure> {
        validate_display_policy_values(&document.display_policy)
            .map_err(|_| invalid_state("persisted display policy is invalid"))?;
        document
            .nvenc_settings
            .validate()
            .map_err(|_| invalid_state("persisted NVENC settings are invalid"))?;
        if document
            .output_name
            .as_deref()
            .is_some_and(|name| normalize_output_name(name).is_err())
        {
            return Err(invalid_state("persisted output name is invalid"));
        }
        if document
            .audio_sink
            .as_deref()
            .is_some_and(|sink| normalize_audio_sink(sink).is_err())
        {
            return Err(invalid_state("persisted audio sink is invalid"));
        }
        if document
            .external_ip
            .as_deref()
            .is_some_and(|address| normalize_external_ip(address).is_err())
        {
            return Err(invalid_state("persisted external_ip is invalid"));
        }
        if document
            .video_max_batch_size_kb
            .is_some_and(|value| value > 64)
        {
            return Err(invalid_state(
                "persisted video_max_batch_size_kb is outside 0..=64",
            ));
        }
        if document
            .minimum_fps_target
            .is_some_and(|value| !valid_minimum_fps_target(value))
        {
            return Err(invalid_state(
                "persisted minimum_fps_target is outside 0..=1000",
            ));
        }
        if document
            .fec_percentage
            .is_some_and(|percentage| percentage == 0)
        {
            return Err(invalid_state("persisted fec_percentage is outside 1..=255"));
        }
        if document.ping_timeout_ms.is_some_and(|value| value < 0) {
            return Err(invalid_state(
                "persisted ping_timeout_ms is outside 0..=2147483647",
            ));
        }
        if !validate_legacy_preparation(&document.legacy_global_preparation) {
            return Err(invalid_state(
                "persisted legacy_global_preparation is invalid",
            ));
        }
        document
            .frame_limiter
            .validate()
            .map_err(|_| invalid_state("persisted frame-limiter settings are invalid"))?;
        if !valid_encryption_mode(document.lan_encryption_mode)
            || !valid_encryption_mode(document.wan_encryption_mode)
        {
            return Err(invalid_state("persisted encryption mode is invalid"));
        }
        let mut validation_settings = self.bootstrap_settings.clone();
        let port = document.port.unwrap_or(self.bootstrap_port);
        validation_settings.http_bind.set_port(port);
        validation_settings
            .https_bind
            .set_port(settings::https_port(port));
        validation_settings.address_family =
            document.address_family.or(self.bootstrap_address_family);
        validation_settings.bind_address = document
            .bind_address
            .clone()
            .or_else(|| self.bootstrap_bind_address.clone());
        validation_settings
            .validate_network_policy(
                validation_settings.address_family,
                validation_settings.bind_address.as_deref(),
            )
            .map_err(|_| invalid_state("persisted listener address policy is invalid"))
    }

    fn apply_document(&mut self, document: ProductDocument) {
        self.revision = document.revision;
        self.configured_hostname = document.hostname.unwrap_or_default();
        self.hostname = if self.configured_hostname.is_empty() {
            self.bootstrap_hostname.clone()
        } else {
            self.configured_hostname.clone()
        };
        self.port = document.port.unwrap_or(self.bootstrap_port);
        self.configured_address_family = document.address_family;
        self.configured_bind_address = document.bind_address;
        self.configured_output_name = document.output_name;
        self.configured_audio_sink = document.audio_sink;
        self.configured_virtual_sink = document.virtual_sink;
        self.audio_sink_capture_only = document.audio_sink_capture_only;
        self.install_steam_audio_drivers = document.install_steam_audio_drivers;
        self.nvenc_spatial_aq = document.nvenc_spatial_aq;
        self.configured_external_ip = document.external_ip;
        self.stream_audio = document.stream_audio;
        self.configured_capture = document.capture;
        self.configured_video_max_batch_size_kb = document.video_max_batch_size_kb;
        self.configured_max_bitrate = document.max_bitrate;
        self.configured_qp = document.qp;
        self.configured_fec_percentage = document.fec_percentage;
        self.configured_minimum_fps_target = document.minimum_fps_target;
        self.configured_wgc_pacing_smoothing = document.wgc_pacing_smoothing;
        self.configured_software_encoder = document.software_encoder;
        self.configured_nvenc_settings = document.nvenc_settings;
        self.configured_ping_timeout_ms = document.ping_timeout_ms;
        self.configured_global_preparation = document.global_preparation;
        self.configured_legacy_global_preparation = document.legacy_global_preparation;
        self.configured_frame_limiter = document.frame_limiter;
        self.configured_display_policy = document.display_policy;
        self.lan_encryption_mode = document.lan_encryption_mode;
        self.wan_encryption_mode = document.wan_encryption_mode;
        self.configured_upnp = document.upnp;
        self.loaded = true;
    }

    fn settings_payload(&self) -> Value {
        let mut payload = serde_json::Map::new();
        for fragment in [
            json!({
                "ok":true,
                "hostname":self.hostname,
                "configured_hostname":self.configured_hostname,
                "port":self.port,
                "upnp":self.configured_upnp,
                "upnp_status":self.upnp_status,
                "upnp_error":self.upnp_error,
            }),
            json!({
                "https_port":settings::https_port(self.port),
                "address_family":self.effective_address_family(),
                "bind_address":self.effective_bind_address(),
                "configured_address_family":self.configured_address_family,
            }),
            json!({
                "configured_bind_address":self.configured_bind_address,
                "configured_output_name":self.configured_output_name,
                "configured_audio_sink":self.configured_audio_sink,
                "configured_virtual_sink":self.configured_virtual_sink,
                "install_steam_audio_drivers":self.install_steam_audio_drivers,
                "nvenc_spatial_aq":self.nvenc_spatial_aq,
            }),
            json!({
                "configured_global_preparation":self.configured_global_preparation,
                "configured_legacy_global_preparation":self.configured_legacy_global_preparation,
                "configured_frame_limiter":self.configured_frame_limiter,
                "effective_frame_limiter":self.configured_frame_limiter.effective(),
            }),
            json!({
                "configured_display_policy":sparse_display_policy(&self.configured_display_policy),
                "display_policy_revision":self.revision,
            }),
            json!({
                "lan_encryption_mode":self.lan_encryption_mode,
                "wan_encryption_mode":self.wan_encryption_mode,
                "audio_sink_capture_only":self.audio_sink_capture_only,
                "configured_external_ip":self.configured_external_ip,
            }),
            json!({
                "effective_audio_sink":self.effective_audio_sink(),
                "configured_capture":self.configured_capture.as_str(),
                "configured_video_max_batch_size_kb":self.configured_video_max_batch_size_kb(),
                "effective_video_max_batch_size_kb":self.effective_video_max_batch_size_kb(),
            }),
            json!({
                "video_batch_size_fallback":self.video_batch_size_fallback(),
                "configured_max_bitrate":self.configured_max_bitrate(),
                "effective_max_bitrate_kbps":self.effective_max_bitrate_kbps(),
                "configured_qp":self.configured_qp,
                "effective_qp":self.configured_qp.unwrap_or(28),
                "configured_fec_percentage":self.configured_fec_percentage,
                "effective_fec_percentage":self.effective_fec_percentage(),
                "configured_minimum_fps_target":self.configured_minimum_fps_target(),
            }),
            json!({
                "effective_minimum_fps_target":self.effective_minimum_fps_target(),
                "configured_wgc_pacing_smoothing":self.configured_wgc_pacing_smoothing(),
                "effective_wgc_pacing_smoothing":self.effective_wgc_pacing_smoothing(),
                "configured_sw_preset":self.configured_software_encoder.sw_preset,
                "configured_sw_tune":self.configured_software_encoder.sw_tune,
                "configured_encoder":self.configured_software_encoder.encoder,
                "configured_min_threads":self.configured_software_encoder.min_threads,
                "configured_nvenc_preset":self.configured_nvenc_settings.nvenc_preset,
                "configured_nvenc_h264_cavlc":self.configured_nvenc_settings.nvenc_h264_cavlc,
                "configured_nvenc_twopass":self.configured_nvenc_settings.nvenc_twopass,
                "configured_nvenc_vbv_increase":self.configured_nvenc_settings.nvenc_vbv_increase,
                "configured_nvenc_split_encode":self.configured_nvenc_settings.nvenc_split_encode,
                "configured_nvenc_realtime_hags":self.configured_nvenc_settings.nvenc_realtime_hags,
                "configured_nvenc_opengl_vulkan_on_dxgi":self.configured_nvenc_settings.nvenc_opengl_vulkan_on_dxgi,
                "configured_nvenc_latency_over_power":self.configured_nvenc_settings.nvenc_latency_over_power,
                "configured_vaapi_strict_rc_buffer":self.configured_nvenc_settings.vaapi_strict_rc_buffer,
                "effective_sw_preset":self.configured_software_encoder.effective_preset(),
                "effective_sw_tune":self.configured_software_encoder.effective_tune(),
                "effective_min_threads":self.configured_software_encoder.effective_threads(),
                "configured_ping_timeout_ms":self.configured_ping_timeout_ms(),
            }),
            json!({
                "effective_ping_timeout_ms":self.effective_ping_timeout_ms(),
                "stream_audio":self.stream_audio,
                "effective_output_name":self.effective_output_name(),
                "capture_provider":self.capture_provider(),
            }),
            json!({
                "active_http_port":self.active_http_port,
                "active_https_port":self.active_https_port,
                "http_addresses":self.active_http_addresses,
                "https_addresses":self.active_https_addresses,
            }),
            json!({
                "listener_error":self.listener_error,
                "active_rtsp_port":self.active_rtsp_base_port,
                "rtsp_addresses":self.active_rtsp_addresses,
                "rtsp_listener_error":self.rtsp_listener_error,
            }),
            json!({
                "revision":self.revision,
            }),
        ] {
            let Value::Object(fields) = fragment else {
                unreachable!("product settings response fragments are objects");
            };
            payload.extend(fields);
        }
        Value::Object(payload)
    }

    fn record_load_success(&mut self) {
        self.last_error = None;
        self.retry_delay = Duration::from_secs(1);
        self.next_retry = Instant::now() + self.retry_delay;
    }

    fn record_load_failure(&mut self, message: String) {
        self.loaded = false;
        self.last_error = Some(message);
        self.next_retry = Instant::now() + self.retry_delay;
        self.retry_delay = (self.retry_delay * 2).min(MAX_RETRY_DELAY);
    }

    fn fail_queued(&mut self, reason: &str) {
        while let Some(request) = self.queued.pop_front() {
            self.queue_completion(
                request.request,
                failure(
                    "configuration_unavailable",
                    format!("product settings could not be loaded ({reason})"),
                ),
            );
        }
    }
}

/// Builds a complete current-version stored document using the product's
/// canonical defaults and the startup listener configuration.
pub fn default_document(settings: &Settings) -> Result<Value, &'static str> {
    settings.validate()?;
    let bootstrap = ProductSettings::with_bootstrap_settings(settings.hostname.clone(), settings);
    let values = product_update_payload(
        1,
        bootstrap.hostname(),
        &NetworkTarget {
            port: bootstrap.port,
            address_family: bootstrap.bootstrap_address_family,
            bind_address: bootstrap.bootstrap_bind_address.clone(),
        },
        None,
        ProductStreamingSettings {
            audio_sink: None,
            virtual_sink: None,
            audio_sink_capture_only: false,
            install_steam_audio_drivers: true,
            nvenc_spatial_aq: false,
            external_ip: None,
            stream_audio: true,
            capture: CaptureMode::Auto,
            video_max_batch_size_kb: None,
            max_bitrate: None,
            qp: None,
            fec_percentage: None,
            minimum_fps_target: None,
            wgc_pacing_smoothing: None,
            software_encoder: SoftwareEncoderOptions::default(),
            nvenc_settings: NvencSettings::default(),
            ping_timeout_ms: None,
            global_preparation: Vec::new(),
            legacy_global_preparation: Vec::new(),
            frame_limiter: FrameLimiterSettings::default(),
            display_policy: empty_display_policy(),
            lan_encryption_mode: DEFAULT_LAN_ENCRYPTION_MODE,
            wan_encryption_mode: DEFAULT_WAN_ENCRYPTION_MODE,
            upnp: false,
        },
    )
    .get("values")
    .cloned()
    .ok_or("invalid_product_settings_defaults")?;
    let document = json!({
        "ok": true,
        "found": true,
        "version": SETTINGS_VERSION,
        "revision": 1,
        "values": values,
    });
    validate_document(&document)?;
    Ok(document)
}

/// Validates a stored product document through the same strict parser used
/// for service readback, including its supported legacy migrations.
pub fn validate_document(document: &Value) -> Result<(), &'static str> {
    parse_document(document)
        .map(|_| ())
        .map_err(|_| "invalid_product_settings_document")
}

fn request_command(pending: &PendingCall) -> Command {
    Command::Request {
        service: CONFIGURATION_SERVICE.into(),
        payload: pending.payload.clone(),
        timeout_ms: pending.timeout_ms,
        operation_id: pending.operation_id.clone(),
        parent: pending.parent,
    }
}

fn product_update_payload(
    expected_revision: u64,
    hostname: &str,
    target: &NetworkTarget,
    output_name: Option<&str>,
    streaming: ProductStreamingSettings,
) -> Value {
    let mut values = json!({
        "hostname":hostname,
        "port":target.port,
        "address_family":target.address_family,
        "bind_address":target.bind_address,
        "output_name":output_name,
        "audio_sink":streaming.audio_sink,
        "virtual_sink":streaming.virtual_sink,
        "audio_sink_capture_only":streaming.audio_sink_capture_only,
        "install_steam_audio_drivers":streaming.install_steam_audio_drivers,
        "nvenc_spatial_aq":streaming.nvenc_spatial_aq,
        "external_ip":streaming.external_ip,
        "stream_audio":streaming.stream_audio,
        "capture":streaming.capture,
        "video_max_batch_size_kb":streaming.video_max_batch_size_kb,
        "max_bitrate":streaming.max_bitrate,
        "qp":streaming.qp,
        "fec_percentage":streaming.fec_percentage,
        "minimum_fps_target":streaming.minimum_fps_target,
        "wgc_pacing_smoothing":streaming.wgc_pacing_smoothing,
        "sw_preset":streaming.software_encoder.sw_preset,
        "sw_tune":streaming.software_encoder.sw_tune,
        "encoder":streaming.software_encoder.encoder,
        "min_threads":streaming.software_encoder.min_threads,
        "ping_timeout_ms":streaming.ping_timeout_ms,
        "global_preparation":streaming.global_preparation,
        "legacy_global_preparation":streaming.legacy_global_preparation,
        "lan_encryption_mode":streaming.lan_encryption_mode,
        "wan_encryption_mode":streaming.wan_encryption_mode,
        "upnp":streaming.upnp,
    });
    values
        .as_object_mut()
        .expect("product settings values")
        .extend(
            streaming
                .display_policy
                .as_object()
                .expect("display policy values")
                .clone(),
        );
    values
        .as_object_mut()
        .expect("product settings values are an object")
        .extend(nvenc_settings_values(&streaming.nvenc_settings));
    let frame_limiter_values =
        serde_json::to_value(streaming.frame_limiter).expect("frame-limiter settings serialize");
    values
        .as_object_mut()
        .expect("product settings values are an object")
        .extend(
            frame_limiter_values
                .as_object()
                .expect("frame-limiter settings serialize to an object")
                .clone(),
        );
    json!({
        "action":"product_update",
        "expected_revision":expected_revision,
        "version":SETTINGS_VERSION,
        "values":values,
    })
}

fn frame_limiter_value_names() -> &'static [&'static str; 11] {
    &[
        "frame_limiter_enable",
        "frame_limiter_fps_limit",
        "frame_limiter_provider",
        "frame_limiter_disable_vsync",
        "frame_limiter_auto_virtual_framegen",
        "rtss_frame_limit_type",
        "rtss_allow_virtual_display_override",
        "rtss_install_path",
        "mangohud_limiter_method",
        "mangohud_preset",
        "mangohud_always_show_graph",
    ]
}

fn persisted_encryption_mode(
    values: &serde_json::Map<String, Value>,
    version: u64,
    name: &'static str,
    default: u8,
) -> Result<u8, SettingFailure> {
    if version < ENCRYPTION_MODE_SETTINGS_VERSION {
        return Ok(default);
    }
    values
        .get(name)
        .and_then(Value::as_u64)
        .and_then(|value| u8::try_from(value).ok())
        .filter(|value| valid_encryption_mode(*value))
        .ok_or_else(|| invalid_state(&format!("persisted {name} is invalid")))
}

fn valid_encryption_mode(value: u8) -> bool {
    value <= 2
}

#[derive(Debug)]
struct SettingFailure {
    code: String,
    message: String,
    current_revision: Option<u64>,
}

fn parse_document(payload: &Value) -> Result<ProductDocument, SettingFailure> {
    if payload.get("ok").and_then(Value::as_bool) != Some(true) {
        return Err(parse_failure(payload));
    }
    let found = payload
        .get("found")
        .and_then(Value::as_bool)
        .ok_or_else(|| invalid_state("product_get omitted found"))?;
    let revision = payload
        .get("revision")
        .and_then(Value::as_u64)
        .ok_or_else(|| invalid_state("product_get omitted revision"))?;
    let values = payload
        .get("values")
        .and_then(Value::as_object)
        .ok_or_else(|| invalid_state("product_get values are not an object"))?;

    if !found {
        if revision != 0
            || !payload.get("version").is_some_and(Value::is_null)
            || !values.is_empty()
        {
            return Err(invalid_state(
                "missing product document has inconsistent metadata",
            ));
        }
        return Ok(ProductDocument {
            revision: 0,
            hostname: None,
            port: None,
            address_family: None,
            bind_address: None,
            output_name: None,
            audio_sink: None,
            virtual_sink: None,
            audio_sink_capture_only: false,
            install_steam_audio_drivers: true,
            nvenc_spatial_aq: false,
            external_ip: None,
            stream_audio: true,
            capture: CaptureMode::Auto,
            video_max_batch_size_kb: None,
            max_bitrate: None,
            qp: None,
            fec_percentage: None,
            minimum_fps_target: None,
            wgc_pacing_smoothing: None,
            software_encoder: SoftwareEncoderOptions::default(),
            nvenc_settings: NvencSettings::default(),
            ping_timeout_ms: None,
            global_preparation: Vec::new(),
            legacy_global_preparation: Vec::new(),
            frame_limiter: FrameLimiterSettings::default(),
            display_policy: empty_display_policy(),
            lan_encryption_mode: DEFAULT_LAN_ENCRYPTION_MODE,
            wan_encryption_mode: DEFAULT_WAN_ENCRYPTION_MODE,
            upnp: false,
        });
    }

    let version = payload
        .get("version")
        .and_then(Value::as_u64)
        .ok_or_else(|| invalid_state("product settings version is missing"))?;
    if !matches!(
        version,
        LEGACY_SETTINGS_VERSION
            | PORT_SETTINGS_VERSION
            | NETWORK_SETTINGS_VERSION
            | OUTPUT_SETTINGS_VERSION
            | STREAM_AUDIO_SETTINGS_VERSION
            | CAPTURE_SETTINGS_VERSION
            | VIDEO_BATCH_SETTINGS_VERSION
            | MAX_BITRATE_SETTINGS_VERSION
            | MINIMUM_FPS_SETTINGS_VERSION
            | AUDIO_SINK_SETTINGS_VERSION
            | WGC_PACING_SMOOTHING_SETTINGS_VERSION
            | EXTERNAL_IP_SETTINGS_VERSION
            | PING_TIMEOUT_SETTINGS_VERSION
            | AUDIO_SINK_CAPTURE_ONLY_SETTINGS_VERSION
            | VIRTUAL_SINK_SETTINGS_VERSION
            | GLOBAL_PREPARATION_SETTINGS_VERSION
            | GLOBAL_RAW_PREPARATION_SETTINGS_VERSION
            | DISPLAY_POLICY_SETTINGS_VERSION
            | SOFTWARE_ENCODER_SETTINGS_VERSION
            | MIN_THREADS_SETTINGS_VERSION
            | UPNP_SETTINGS_VERSION
            | QP_SETTINGS_VERSION
            | FEC_SETTINGS_VERSION
            | NVENC_SETTINGS_VERSION
            | STEAM_AUDIO_DRIVER_SETTINGS_VERSION
            | FULL_DISPLAY_POLICY_SETTINGS_VERSION
    ) || revision == 0
    {
        return Err(invalid_state(
            "product settings version or revision is unsupported",
        ));
    }
    let mut migrated_values = values.clone();
    if version >= FULL_DISPLAY_POLICY_SETTINGS_VERSION
        && let Some(legacy_count) = migrated_values.remove(LEGACY_PERMANENT_MONITOR_COUNT_KEY)
        && !migrated_values.contains_key("dd_virtual_display_permanent_count")
    {
        migrated_values.insert("dd_virtual_display_permanent_count".into(), legacy_count);
    }
    let values = &migrated_values;
    let expected_value_count = match version {
        LEGACY_SETTINGS_VERSION => 1,
        PORT_SETTINGS_VERSION => 2,
        NETWORK_SETTINGS_VERSION => 4,
        OUTPUT_SETTINGS_VERSION => 5,
        STREAM_AUDIO_SETTINGS_VERSION => 6,
        CAPTURE_SETTINGS_VERSION => 7,
        VIDEO_BATCH_SETTINGS_VERSION => 8,
        MAX_BITRATE_SETTINGS_VERSION => 9,
        MINIMUM_FPS_SETTINGS_VERSION => 10,
        AUDIO_SINK_SETTINGS_VERSION => 11,
        WGC_PACING_SMOOTHING_SETTINGS_VERSION => 12,
        EXTERNAL_IP_SETTINGS_VERSION => 13,
        PING_TIMEOUT_SETTINGS_VERSION => 14,
        AUDIO_SINK_CAPTURE_ONLY_SETTINGS_VERSION => 15,
        VIRTUAL_SINK_SETTINGS_VERSION => 16,
        GLOBAL_PREPARATION_SETTINGS_VERSION => 17,
        GLOBAL_RAW_PREPARATION_SETTINGS_VERSION => 32,
        DISPLAY_POLICY_SETTINGS_VERSION => 40,
        SOFTWARE_ENCODER_SETTINGS_VERSION => 43,
        MIN_THREADS_SETTINGS_VERSION => 44,
        UPNP_SETTINGS_VERSION => 45,
        QP_SETTINGS_VERSION => 46,
        FEC_SETTINGS_VERSION => 47,
        NVENC_SETTINGS_VERSION => 56,
        STEAM_AUDIO_DRIVER_SETTINGS_VERSION => 57,
        FULL_DISPLAY_POLICY_SETTINGS_VERSION => 79,
        _ => unreachable!(),
    };
    let matches_expected_value_count = values.len() == expected_value_count
        || (version == GLOBAL_RAW_PREPARATION_SETTINGS_VERSION && values.len() == 31);
    if (version >= SOFTWARE_ENCODER_SETTINGS_VERSION
        && ["sw_preset", "sw_tune", "encoder"]
            .iter()
            .any(|key| !values.contains_key(*key)))
        || (version >= MIN_THREADS_SETTINGS_VERSION && !values.contains_key("min_threads"))
        || (version >= QP_SETTINGS_VERSION && !values.contains_key("qp"))
        || (version >= FEC_SETTINGS_VERSION && !values.contains_key("fec_percentage"))
        || (version >= NVENC_SETTINGS_VERSION
            && NVENC_SETTINGS_KEYS
                .iter()
                .any(|key| !values.contains_key(*key)))
        || !matches_expected_value_count
        || !values.contains_key("hostname")
        || (version >= PORT_SETTINGS_VERSION && !values.contains_key("port"))
        || (version >= NETWORK_SETTINGS_VERSION
            && (!values.contains_key("address_family") || !values.contains_key("bind_address")))
        || (version >= OUTPUT_SETTINGS_VERSION && !values.contains_key("output_name"))
        || (version >= STREAM_AUDIO_SETTINGS_VERSION && !values.contains_key("stream_audio"))
        || (version >= CAPTURE_SETTINGS_VERSION && !values.contains_key("capture"))
        || (version >= VIDEO_BATCH_SETTINGS_VERSION
            && !values.contains_key("video_max_batch_size_kb"))
        || (version >= MAX_BITRATE_SETTINGS_VERSION && !values.contains_key("max_bitrate"))
        || (version >= MINIMUM_FPS_SETTINGS_VERSION && !values.contains_key("minimum_fps_target"))
        || (version >= AUDIO_SINK_SETTINGS_VERSION && !values.contains_key("audio_sink"))
        || (version >= EXTERNAL_IP_SETTINGS_VERSION && !values.contains_key("external_ip"))
        || (version >= WGC_PACING_SMOOTHING_SETTINGS_VERSION
            && !values.contains_key("wgc_pacing_smoothing"))
        || (version >= PING_TIMEOUT_SETTINGS_VERSION && !values.contains_key("ping_timeout_ms"))
        || (version >= AUDIO_SINK_CAPTURE_ONLY_SETTINGS_VERSION
            && !values.contains_key("audio_sink_capture_only"))
        || (version >= VIRTUAL_SINK_SETTINGS_VERSION && !values.contains_key("virtual_sink"))
        || (version >= GLOBAL_PREPARATION_SETTINGS_VERSION
            && !values.contains_key("global_preparation"))
        || (version >= GLOBAL_RAW_PREPARATION_SETTINGS_VERSION
            && !values.contains_key("legacy_global_preparation"))
        || (version >= FRAME_LIMITER_SETTINGS_VERSION
            && frame_limiter_value_names()
                .iter()
                .any(|name| !values.contains_key(*name)))
        || (version >= ENCRYPTION_MODE_SETTINGS_VERSION
            && (!values.contains_key("lan_encryption_mode")
                || !values.contains_key("wan_encryption_mode")))
        || (version >= DISPLAY_POLICY_SETTINGS_VERSION
            && LEGACY_DISPLAY_POLICY_KEYS
                .iter()
                .any(|key| !values.contains_key(*key)))
        || (version >= FULL_DISPLAY_POLICY_SETTINGS_VERSION
            && DISPLAY_POLICY_KEYS
                .iter()
                .any(|key| !values.contains_key(*key)))
        || (version >= UPNP_SETTINGS_VERSION && !values.contains_key("upnp"))
        || (version >= STEAM_AUDIO_DRIVER_SETTINGS_VERSION
            && !values.contains_key("install_steam_audio_drivers"))
    {
        return Err(invalid_state(
            "product settings contain unknown or missing values",
        ));
    }
    let hostname = values
        .get("hostname")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid_state("product hostname is not a string"))?;
    settings::validate_configured_hostname(hostname)
        .map_err(|_| invalid_state("persisted product hostname is invalid"))?;
    let port = if version == LEGACY_SETTINGS_VERSION {
        None
    } else {
        let port = values
            .get("port")
            .and_then(Value::as_u64)
            .and_then(|port| u16::try_from(port).ok())
            .ok_or_else(|| invalid_state("persisted product port is not a 16-bit integer"))?;
        settings::validate_port(port)
            .map_err(|_| invalid_state("persisted product port is outside the supported range"))?;
        Some(port)
    };
    let (address_family, bind_address) = if version >= NETWORK_SETTINGS_VERSION {
        let address_family = serde_json::from_value::<Option<AddressFamily>>(
            values.get("address_family").cloned().unwrap_or(Value::Null),
        )
        .map_err(|_| invalid_state("persisted address_family is invalid"))?;
        let bind_address = serde_json::from_value::<Option<String>>(
            values.get("bind_address").cloned().unwrap_or(Value::Null),
        )
        .map_err(|_| invalid_state("persisted bind_address is invalid"))?;
        (address_family, bind_address)
    } else {
        (None, None)
    };
    let output_name = if version >= OUTPUT_SETTINGS_VERSION {
        match values.get("output_name") {
            Some(Value::Null) => None,
            Some(Value::String(value)) => normalize_output_name(value)
                .map_err(|_| invalid_state("persisted output name is invalid"))?,
            _ => return Err(invalid_state("persisted output name is invalid")),
        }
    } else {
        None
    };
    let audio_sink = if version >= AUDIO_SINK_SETTINGS_VERSION {
        match values.get("audio_sink") {
            Some(Value::Null) => None,
            Some(Value::String(value)) => normalize_audio_sink(value)
                .map_err(|_| invalid_state("persisted audio sink is invalid"))?,
            _ => return Err(invalid_state("persisted audio sink is invalid")),
        }
    } else {
        None
    };
    let virtual_sink = if version >= VIRTUAL_SINK_SETTINGS_VERSION {
        match values.get("virtual_sink") {
            Some(Value::Null) => None,
            Some(Value::String(value)) => normalize_virtual_sink(value)
                .map_err(|_| invalid_state("persisted virtual sink is invalid"))?,
            _ => return Err(invalid_state("persisted virtual sink is invalid")),
        }
    } else {
        None
    };
    let external_ip = if version >= EXTERNAL_IP_SETTINGS_VERSION {
        match values.get("external_ip") {
            Some(Value::Null) => None,
            Some(Value::String(value)) => normalize_external_ip(value)
                .map_err(|_| invalid_state("persisted external_ip is invalid"))?,
            _ => return Err(invalid_state("persisted external_ip is invalid")),
        }
    } else {
        None
    };
    let stream_audio = if version >= STREAM_AUDIO_SETTINGS_VERSION {
        values
            .get("stream_audio")
            .and_then(Value::as_bool)
            .ok_or_else(|| invalid_state("persisted stream_audio is not a boolean"))?
    } else {
        true
    };
    let capture = if version >= CAPTURE_SETTINGS_VERSION {
        serde_json::from_value::<CaptureMode>(
            values
                .get("capture")
                .cloned()
                .ok_or_else(|| invalid_state("persisted capture mode is missing"))?,
        )
        .map_err(|_| invalid_state("persisted capture mode is invalid"))?
    } else {
        CaptureMode::Auto
    };
    let video_max_batch_size_kb = if version >= VIDEO_BATCH_SETTINGS_VERSION {
        match values.get("video_max_batch_size_kb") {
            Some(Value::Null) => None,
            Some(value) => value
                .as_u64()
                .and_then(|value| u8::try_from(value).ok())
                .filter(|value| *value <= 64)
                .map(Some)
                .ok_or_else(|| invalid_state("persisted video_max_batch_size_kb is invalid"))?,
            None => {
                return Err(invalid_state(
                    "persisted video_max_batch_size_kb is missing",
                ));
            }
        }
    } else {
        None
    };
    let max_bitrate = if version >= MAX_BITRATE_SETTINGS_VERSION {
        match values.get("max_bitrate") {
            Some(Value::Null) => None,
            Some(value) => value
                .as_i64()
                .and_then(|value| i32::try_from(value).ok())
                .map(Some)
                .ok_or_else(|| {
                    invalid_state("persisted max_bitrate is not a signed 32-bit integer")
                })?,
            None => return Err(invalid_state("persisted max_bitrate is missing")),
        }
    } else {
        None
    };
    let qp = if version >= QP_SETTINGS_VERSION {
        match values.get("qp") {
            Some(Value::Null) => None,
            Some(value) => value
                .as_i64()
                .and_then(|value| i32::try_from(value).ok())
                .map(Some)
                .ok_or_else(|| invalid_state("persisted qp is not a signed 32-bit integer"))?,
            None => return Err(invalid_state("persisted qp is missing")),
        }
    } else {
        None
    };
    let fec_percentage = if version >= FEC_SETTINGS_VERSION {
        match values.get("fec_percentage") {
            Some(Value::Null) => None,
            Some(value) => Some(
                value
                    .as_u64()
                    .and_then(|value| u8::try_from(value).ok())
                    .filter(|percentage| *percentage != 0)
                    .ok_or_else(|| invalid_state("persisted fec_percentage is invalid"))?,
            ),
            None => return Err(invalid_state("persisted fec_percentage is missing")),
        }
    } else {
        None
    };
    let minimum_fps_target = if version >= MINIMUM_FPS_SETTINGS_VERSION {
        match values.get("minimum_fps_target") {
            Some(Value::Null) => None,
            Some(value) => value
                .as_f64()
                .filter(|value| valid_minimum_fps_target(*value))
                .map(Some)
                .ok_or_else(|| invalid_state("persisted minimum_fps_target is invalid"))?,
            None => return Err(invalid_state("persisted minimum_fps_target is missing")),
        }
    } else {
        None
    };
    let wgc_pacing_smoothing = if version >= WGC_PACING_SMOOTHING_SETTINGS_VERSION {
        match values.get("wgc_pacing_smoothing") {
            Some(Value::Null) => None,
            Some(Value::Bool(value)) => Some(*value),
            _ => return Err(invalid_state("persisted wgc_pacing_smoothing is invalid")),
        }
    } else {
        None
    };
    let software_encoder: SoftwareEncoderOptions = if version >= SOFTWARE_ENCODER_SETTINGS_VERSION {
        let options: SoftwareEncoderOptions = serde_json::from_value(json!({"sw_preset":values["sw_preset"],"sw_tune":values["sw_tune"],"encoder":values["encoder"],"min_threads":values.get("min_threads").cloned().unwrap_or(Value::Null)})).map_err(|_| invalid_state("persisted software encoder options are invalid"))?;
        options
            .validate()
            .map_err(|_| invalid_state("persisted software encoder options are invalid"))?;
        options
    } else {
        SoftwareEncoderOptions::default()
    };
    let nvenc_settings = parse_nvenc_settings(values, version)?;
    let ping_timeout_ms = if version >= PING_TIMEOUT_SETTINGS_VERSION {
        match values.get("ping_timeout_ms") {
            Some(Value::Null) => None,
            Some(value) => value
                .as_i64()
                .and_then(|value| i32::try_from(value).ok())
                .filter(|value| *value >= 0)
                .map(Some)
                .ok_or_else(|| invalid_state("persisted ping_timeout_ms is invalid"))?,
            None => return Err(invalid_state("persisted ping_timeout_ms is missing")),
        }
    } else {
        None
    };
    let audio_sink_capture_only = if version >= AUDIO_SINK_CAPTURE_ONLY_SETTINGS_VERSION {
        values
            .get("audio_sink_capture_only")
            .and_then(Value::as_bool)
            .ok_or_else(|| invalid_state("persisted audio_sink_capture_only is not a boolean"))?
    } else {
        false
    };
    let install_steam_audio_drivers = if version >= STEAM_AUDIO_DRIVER_SETTINGS_VERSION {
        values
            .get("install_steam_audio_drivers")
            .and_then(Value::as_bool)
            .ok_or_else(|| {
                invalid_state("persisted install_steam_audio_drivers is not a boolean")
            })?
    } else {
        true
    };
    let nvenc_spatial_aq_update = if version >= GLOBAL_RAW_PREPARATION_SETTINGS_VERSION {
        parse_nvenc_spatial_aq_update(values.get("nvenc_spatial_aq"))
            .map_err(|()| invalid_state("persisted nvenc_spatial_aq is not a boolean"))?
    } else {
        FieldUpdate::Omitted
    };
    let nvenc_spatial_aq = match nvenc_spatial_aq_update {
        FieldUpdate::Value(value) => value,
        FieldUpdate::Omitted
            if version < GLOBAL_RAW_PREPARATION_SETTINGS_VERSION
                || values.len() == expected_value_count - 1 =>
        {
            false
        }
        _ => return Err(invalid_state("persisted nvenc_spatial_aq is not a boolean")),
    };
    let global_preparation = if version >= GLOBAL_PREPARATION_SETTINGS_VERSION {
        serde_json::from_value::<Vec<PreparationStep>>(
            values
                .get("global_preparation")
                .cloned()
                .ok_or_else(|| invalid_state("persisted global_preparation is missing"))?,
        )
        .map_err(|_| invalid_state("persisted global_preparation is invalid"))?
    } else {
        Vec::new()
    };
    if !validate_preparation(&global_preparation) {
        return Err(invalid_state("persisted global_preparation is invalid"));
    }
    let legacy_global_preparation = if version >= GLOBAL_RAW_PREPARATION_SETTINGS_VERSION {
        serde_json::from_value::<Vec<LegacyPreparationStep>>(
            values
                .get("legacy_global_preparation")
                .cloned()
                .ok_or_else(|| invalid_state("persisted legacy_global_preparation is missing"))?,
        )
        .map_err(|_| invalid_state("persisted legacy_global_preparation is invalid"))?
    } else {
        Vec::new()
    };
    if !validate_legacy_preparation(&legacy_global_preparation) {
        return Err(invalid_state(
            "persisted legacy_global_preparation is invalid",
        ));
    }
    let frame_limiter = if version >= FRAME_LIMITER_SETTINGS_VERSION {
        let frame_limiter_values = frame_limiter_value_names()
            .iter()
            .map(|name| {
                (
                    (*name).to_owned(),
                    values.get(*name).cloned().unwrap_or(Value::Null),
                )
            })
            .collect::<serde_json::Map<_, _>>();
        serde_json::from_value::<FrameLimiterSettings>(Value::Object(frame_limiter_values))
            .map_err(|_| invalid_state("persisted frame-limiter settings are invalid"))?
    } else {
        FrameLimiterSettings::default()
    };
    frame_limiter
        .validate()
        .map_err(|_| invalid_state("persisted frame-limiter settings are invalid"))?;
    let display_policy = if version >= DISPLAY_POLICY_SETTINGS_VERSION {
        let mut policy = serde_json::Map::new();
        for key in DISPLAY_POLICY_KEYS {
            let value = values.get(key).cloned().unwrap_or(Value::Null);
            if version < FULL_DISPLAY_POLICY_SETTINGS_VERSION
                && !LEGACY_DISPLAY_POLICY_KEYS.contains(&key)
            {
                policy.insert(key.to_owned(), Value::Null);
            } else {
                policy.insert(key.to_owned(), value);
            }
        }
        let policy = Value::Object(policy);
        validate_display_policy_values(&policy)
            .map_err(|_| invalid_state("persisted display policy is invalid"))?;
        policy
    } else {
        empty_display_policy()
    };
    let lan_encryption_mode = persisted_encryption_mode(
        values,
        version,
        "lan_encryption_mode",
        DEFAULT_LAN_ENCRYPTION_MODE,
    )?;
    let wan_encryption_mode = persisted_encryption_mode(
        values,
        version,
        "wan_encryption_mode",
        DEFAULT_WAN_ENCRYPTION_MODE,
    )?;
    let upnp = if version >= UPNP_SETTINGS_VERSION {
        values
            .get("upnp")
            .and_then(Value::as_bool)
            .ok_or_else(|| invalid_state("persisted upnp setting is invalid"))?
    } else {
        false
    };
    Ok(ProductDocument {
        revision,
        hostname: Some(hostname.to_owned()),
        port,
        address_family,
        bind_address,
        output_name,
        audio_sink,
        virtual_sink,
        audio_sink_capture_only,
        install_steam_audio_drivers,
        nvenc_spatial_aq,
        external_ip,
        stream_audio,
        capture,
        video_max_batch_size_kb,
        max_bitrate,
        qp,
        fec_percentage,
        minimum_fps_target,
        wgc_pacing_smoothing,
        software_encoder,
        nvenc_settings,
        ping_timeout_ms,
        global_preparation,
        legacy_global_preparation,
        frame_limiter,
        display_policy,
        lan_encryption_mode,
        wan_encryption_mode,
        upnp,
    })
}

#[derive(Clone, Copy)]
struct UpdateExpectation<'a> {
    revision: u64,
    hostname: &'a str,
    target: &'a NetworkTarget,
    output_name: Option<&'a str>,
    audio_sink: Option<&'a str>,
    virtual_sink: Option<&'a str>,
    audio_sink_capture_only: bool,
    install_steam_audio_drivers: bool,
    nvenc_spatial_aq: bool,
    external_ip: Option<&'a str>,
    stream_audio: bool,
    capture: CaptureMode,
    video_max_batch_size_kb: Option<u8>,
    max_bitrate: Option<i32>,
    qp: Option<i32>,
    fec_percentage: Option<u8>,
    minimum_fps_target: Option<f64>,
    wgc_pacing_smoothing: Option<bool>,
    software_encoder: &'a SoftwareEncoderOptions,
    nvenc_settings: &'a NvencSettings,
    ping_timeout_ms: Option<i32>,
    global_preparation: &'a [PreparationStep],
    legacy_global_preparation: &'a [LegacyPreparationStep],
    frame_limiter: &'a FrameLimiterSettings,
    display_policy: &'a Value,
    lan_encryption_mode: u8,
    wan_encryption_mode: u8,
    upnp: bool,
}

fn update_result(
    payload: &Value,
    expected: &UpdateExpectation<'_>,
) -> Result<ProductDocument, SettingFailure> {
    if payload.get("ok").and_then(Value::as_bool) != Some(true) {
        return Err(parse_failure(payload));
    }
    if payload.get("version").and_then(Value::as_u64) != Some(SETTINGS_VERSION) {
        return Err(invalid_state(
            "product_update did not confirm current settings",
        ));
    }
    let document = parse_document(payload)?;
    if document.hostname.as_deref() != Some(expected.hostname)
        || document.port != Some(expected.target.port)
        || document.address_family != expected.target.address_family
        || document.bind_address != expected.target.bind_address
        || document.output_name.as_deref() != expected.output_name
        || document.audio_sink.as_deref() != expected.audio_sink
        || document.virtual_sink.as_deref() != expected.virtual_sink
        || document.audio_sink_capture_only != expected.audio_sink_capture_only
        || document.install_steam_audio_drivers != expected.install_steam_audio_drivers
        || document.nvenc_spatial_aq != expected.nvenc_spatial_aq
        || document.external_ip.as_deref() != expected.external_ip
        || document.stream_audio != expected.stream_audio
        || document.capture != expected.capture
        || document.video_max_batch_size_kb != expected.video_max_batch_size_kb
        || document.max_bitrate != expected.max_bitrate
        || document.qp != expected.qp
        || document.fec_percentage != expected.fec_percentage
        || document.minimum_fps_target != expected.minimum_fps_target
        || document.wgc_pacing_smoothing != expected.wgc_pacing_smoothing
        || &document.nvenc_settings != expected.nvenc_settings
        || &document.software_encoder != expected.software_encoder
        || document.ping_timeout_ms != expected.ping_timeout_ms
        || document.global_preparation != expected.global_preparation
        || document.legacy_global_preparation != expected.legacy_global_preparation
        || &document.frame_limiter != expected.frame_limiter
        || &document.display_policy != expected.display_policy
        || document.lan_encryption_mode != expected.lan_encryption_mode
        || document.wan_encryption_mode != expected.wan_encryption_mode
        || document.upnp != expected.upnp
        || expected.revision.checked_add(1) != Some(document.revision)
    {
        return Err(invalid_state(
            "product_update response does not match the requested write",
        ));
    }
    Ok(document)
}

fn valid_minimum_fps_target(value: f64) -> bool {
    value.is_finite() && (0.0..=1000.0).contains(&value)
}

fn apply_minimum_fps_update(
    update: FieldUpdate<f64>,
    current: Option<f64>,
) -> Result<Option<f64>, ()> {
    match update {
        FieldUpdate::Omitted => Ok(current),
        FieldUpdate::Null => Ok(None),
        FieldUpdate::Value(value) if valid_minimum_fps_target(value) => Ok(Some(value)),
        FieldUpdate::Value(_) => Err(()),
    }
}

fn apply_ping_timeout_update(
    update: FieldUpdate<i32>,
    current: Option<i32>,
) -> Result<Option<i32>, ()> {
    match update {
        FieldUpdate::Omitted => Ok(current),
        FieldUpdate::Null | FieldUpdate::Value(-1) => Ok(None),
        FieldUpdate::Value(value) if value >= 0 => Ok(Some(value)),
        FieldUpdate::Value(_) => Err(()),
    }
}

fn parse_nvenc_spatial_aq_update(value: Option<&Value>) -> Result<FieldUpdate<bool>, ()> {
    match value {
        None => Ok(FieldUpdate::Omitted),
        Some(Value::Null) => Ok(FieldUpdate::Null),
        Some(Value::Bool(value)) => Ok(FieldUpdate::Value(*value)),
        Some(_) => Err(()),
    }
}

fn apply_nvenc_spatial_aq_update(update: FieldUpdate<bool>, current: bool) -> bool {
    match update {
        FieldUpdate::Omitted => current,
        FieldUpdate::Null => false,
        FieldUpdate::Value(value) => value,
    }
}

fn apply_global_preparation_update(
    update: FieldUpdate<Vec<PreparationStep>>,
    current: Vec<PreparationStep>,
) -> Result<Vec<PreparationStep>, ()> {
    let preparation = match update {
        FieldUpdate::Omitted => current,
        FieldUpdate::Null => Vec::new(),
        FieldUpdate::Value(preparation) => preparation,
    };
    validate_preparation(&preparation)
        .then_some(preparation)
        .ok_or(())
}

fn apply_legacy_global_preparation_update(
    update: FieldUpdate<Vec<LegacyPreparationStep>>,
    current: Vec<LegacyPreparationStep>,
) -> Result<Vec<LegacyPreparationStep>, ()> {
    let preparation = match update {
        FieldUpdate::Omitted => current,
        FieldUpdate::Null => Vec::new(),
        FieldUpdate::Value(preparation) => preparation,
    };
    validate_legacy_preparation(&preparation)
        .then_some(preparation)
        .ok_or(())
}

fn apply_frame_limiter_update(
    update: FrameLimiterUpdate,
    current: FrameLimiterSettings,
) -> Result<FrameLimiterSettings, &'static str> {
    let disable_vsync_update = match (
        update.frame_limiter_disable_vsync,
        update.rtss_disable_vsync_ullm,
    ) {
        (FieldUpdate::Omitted, alias) => alias,
        (canonical, FieldUpdate::Omitted) => canonical,
        (FieldUpdate::Null, FieldUpdate::Null) => FieldUpdate::Null,
        (FieldUpdate::Value(canonical), FieldUpdate::Value(alias)) if canonical == alias => {
            FieldUpdate::Value(canonical)
        }
        _ => return Err("conflicting_frame_limiter_disable_vsync_alias"),
    };
    let settings = FrameLimiterSettings {
        frame_limiter_enable: apply_field_update(
            update.frame_limiter_enable,
            current.frame_limiter_enable,
        ),
        frame_limiter_fps_limit: apply_field_update(
            update.frame_limiter_fps_limit,
            current.frame_limiter_fps_limit,
        ),
        frame_limiter_provider: apply_field_update(
            update.frame_limiter_provider,
            current.frame_limiter_provider,
        ),
        frame_limiter_disable_vsync: apply_field_update(
            disable_vsync_update,
            current.frame_limiter_disable_vsync,
        ),
        frame_limiter_auto_virtual_framegen: apply_field_update(
            update.frame_limiter_auto_virtual_framegen,
            current.frame_limiter_auto_virtual_framegen,
        ),
        rtss_frame_limit_type: apply_field_update(
            update.rtss_frame_limit_type,
            current.rtss_frame_limit_type,
        ),
        rtss_allow_virtual_display_override: apply_field_update(
            update.rtss_allow_virtual_display_override,
            current.rtss_allow_virtual_display_override,
        ),
        rtss_install_path: apply_field_update(update.rtss_install_path, current.rtss_install_path),
        mangohud_limiter_method: apply_field_update(
            update.mangohud_limiter_method,
            current.mangohud_limiter_method,
        ),
        mangohud_preset: apply_field_update(update.mangohud_preset, current.mangohud_preset),
        mangohud_always_show_graph: apply_field_update(
            update.mangohud_always_show_graph,
            current.mangohud_always_show_graph,
        ),
    };
    settings.validate()?;
    Ok(settings)
}

fn normalize_output_name(value: &str) -> Result<Option<String>, ()> {
    if value.is_empty() {
        return Ok(None);
    }
    if value.len() > MAX_OUTPUT_NAME_BYTES
        || value.trim() != value
        || value.trim().is_empty()
        || value.chars().any(char::is_control)
    {
        return Err(());
    }
    Ok(Some(value.to_owned()))
}

fn normalize_audio_sink(value: &str) -> Result<Option<String>, ()> {
    if value.is_empty() {
        return Ok(None);
    }
    if value.len() > 4096 || value.chars().any(char::is_control) {
        return Err(());
    }
    Ok(Some(value.to_owned()))
}

fn normalize_virtual_sink(value: &str) -> Result<Option<String>, ()> {
    if value.len() > 4096 || value.chars().any(char::is_control) {
        return Err(());
    }
    Ok(Some(value.to_owned()))
}

fn normalize_external_ip(value: &str) -> Result<Option<String>, ()> {
    if value.is_empty() {
        return Ok(None);
    }
    if value.len() > 4096 || value.chars().any(char::is_control) {
        return Err(());
    }
    Ok(Some(value.to_owned()))
}

fn apply_output_name_update(
    update: FieldUpdate<String>,
    current: Option<String>,
) -> Result<Option<String>, ()> {
    match update {
        FieldUpdate::Omitted => Ok(current),
        FieldUpdate::Null => Ok(None),
        FieldUpdate::Value(value) => normalize_output_name(&value),
    }
}

fn apply_audio_sink_update(
    update: FieldUpdate<String>,
    current: Option<String>,
) -> Result<Option<String>, ()> {
    match update {
        FieldUpdate::Omitted => Ok(current),
        FieldUpdate::Null => Ok(None),
        FieldUpdate::Value(value) => normalize_audio_sink(&value),
    }
}

fn apply_virtual_sink_update(
    update: FieldUpdate<String>,
    current: Option<String>,
) -> Result<Option<String>, ()> {
    match update {
        FieldUpdate::Omitted => Ok(current),
        FieldUpdate::Null => Ok(None),
        FieldUpdate::Value(value) => normalize_virtual_sink(&value),
    }
}

fn apply_external_ip_update(
    update: FieldUpdate<String>,
    current: Option<String>,
) -> Result<Option<String>, ()> {
    match update {
        FieldUpdate::Omitted => Ok(current),
        FieldUpdate::Null => Ok(None),
        FieldUpdate::Value(value) => normalize_external_ip(&value),
    }
}

fn apply_boolean_update(update: FieldUpdate<bool>, current: bool) -> Result<bool, ()> {
    match update {
        FieldUpdate::Omitted => Ok(current),
        FieldUpdate::Null => Err(()),
        FieldUpdate::Value(value) => Ok(value),
    }
}

fn apply_encryption_mode_update(
    update: FieldUpdate<i64>,
    current: u8,
    default: u8,
) -> Result<u8, ()> {
    match update {
        FieldUpdate::Omitted => Ok(current),
        FieldUpdate::Null => Ok(default),
        FieldUpdate::Value(value) => u8::try_from(value)
            .ok()
            .filter(|mode| valid_encryption_mode(*mode))
            .ok_or(()),
    }
}

fn apply_capture_update(update: FieldUpdate<CaptureMode>, current: CaptureMode) -> CaptureMode {
    match update {
        FieldUpdate::Omitted => current,
        FieldUpdate::Null => CaptureMode::Auto,
        FieldUpdate::Value(value) => value,
    }
}

fn apply_video_max_batch_size_update(
    update: FieldUpdate<u8>,
    current: Option<u8>,
) -> Result<Option<u8>, ()> {
    match update {
        FieldUpdate::Omitted => Ok(current),
        FieldUpdate::Null => Ok(None),
        FieldUpdate::Value(value) if value <= 64 => Ok(Some(value)),
        FieldUpdate::Value(_) => Err(()),
    }
}

fn effective_video_max_batch_size_kb(value: u8) -> u8 {
    match value {
        16 | 32 | 64 => value,
        _ => 64,
    }
}

fn video_batch_size_fallback(value: u8) -> bool {
    value != 0 && !matches!(value, 16 | 32 | 64)
}

fn apply_fec_percentage_update(
    update: FieldUpdate<i32>,
    current: Option<u8>,
) -> Result<Option<u8>, ()> {
    let value = match update {
        FieldUpdate::Omitted => return Ok(current),
        FieldUpdate::Null => return Ok(None),
        FieldUpdate::Value(value) => value,
    };
    if !(1..=255).contains(&value) {
        return Err(());
    }
    Ok(Some(u8::try_from(value).map_err(|_| ())?))
}

fn apply_field_update<T>(update: FieldUpdate<T>, current: Option<T>) -> Option<T> {
    match update {
        FieldUpdate::Omitted => current,
        FieldUpdate::Null => None,
        FieldUpdate::Value(value) => Some(value),
    }
}

fn parse_failure(payload: &Value) -> SettingFailure {
    let error = payload.get("error");
    SettingFailure {
        code: error
            .and_then(|value| value.get("code"))
            .and_then(Value::as_str)
            .unwrap_or("configuration_unavailable")
            .to_owned(),
        message: error
            .and_then(|value| value.get("message"))
            .and_then(Value::as_str)
            .unwrap_or("configuration service rejected the request")
            .to_owned(),
        current_revision: error
            .and_then(|value| value.get("current_revision"))
            .and_then(Value::as_u64),
    }
}

fn invalid_state(message: &str) -> SettingFailure {
    SettingFailure {
        code: "invalid_state_response".into(),
        message: message.into(),
        current_revision: None,
    }
}

fn known_precommit_error(code: &str) -> bool {
    matches!(
        code,
        "invalid_request" | "invalid_values" | "invalid_version" | "resource_exhausted"
    )
}

fn error_response(error: &SettingFailure) -> Value {
    failure_with_revision(&error.code, &error.message, error.current_revision)
}

fn failure(code: &str, message: impl Into<String>) -> Value {
    json!({"ok":false,"code":code,"message":message.into()})
}

fn failure_with_revision(code: &str, message: &str, revision: Option<u64>) -> Value {
    match revision {
        Some(revision) => {
            json!({"ok":false,"code":code,"message":message,"current_revision":revision})
        }
        None => json!({"ok":false,"code":code,"message":message}),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_document_helpers_use_canonical_v26_defaults_and_legacy_migration() {
        let mut current = default_document(&Settings::default()).unwrap();
        assert_eq!(current["version"], SETTINGS_VERSION);
        assert_eq!(current["values"].as_object().unwrap().len(), 79);
        assert_eq!(current["values"]["install_steam_audio_drivers"], true);
        assert_eq!(current["values"]["nvenc_preset"], 1);
        assert_eq!(current["values"]["vaapi_strict_rc_buffer"], false);
        assert!(validate_document(&current).is_ok());

        let mut v24 = current.clone();
        v24["version"] = json!(NVENC_SETTINGS_VERSION);
        remove_extended_display_policy_fields(&mut v24);
        v24["values"]
            .as_object_mut()
            .unwrap()
            .remove("install_steam_audio_drivers");
        assert_eq!(v24["values"].as_object().unwrap().len(), 56);
        assert!(validate_document(&v24).is_ok());
        let migrated_v24 = parse_document(&v24).unwrap();
        assert!(migrated_v24.install_steam_audio_drivers);
        assert_eq!(migrated_v24.nvenc_settings.nvenc_preset, 1);

        let mut legacy = current.clone();
        legacy["version"] = json!(FEC_SETTINGS_VERSION);
        remove_extended_display_policy_fields(&mut legacy);
        for key in NVENC_SETTINGS_KEYS {
            legacy["values"].as_object_mut().unwrap().remove(key);
        }
        legacy["values"]
            .as_object_mut()
            .unwrap()
            .remove("install_steam_audio_drivers");
        assert_eq!(legacy["values"].as_object().unwrap().len(), 47);
        assert!(validate_document(&legacy).is_ok());

        current["values"]["unexpected"] = json!(true);
        assert_eq!(
            validate_document(&current),
            Err("invalid_product_settings_document")
        );
    }

    #[test]
    fn steam_audio_driver_policy_migrates_v24_defaults_true_and_persists_globally() {
        let mut v24 = default_document(&Settings::default()).unwrap();
        v24["version"] = json!(NVENC_SETTINGS_VERSION);
        remove_extended_display_policy_fields(&mut v24);
        v24["values"]
            .as_object_mut()
            .unwrap()
            .remove("install_steam_audio_drivers");
        v24["values"]["hostname"] = json!("Host");
        for (key, value) in [
            ("nvenc_preset", json!(7)),
            ("nvenc_h264_cavlc", json!(true)),
            ("nvenc_twopass", json!("full_res")),
            ("nvenc_vbv_increase", json!(400)),
            ("nvenc_split_encode", json!("disabled")),
            ("nvenc_realtime_hags", json!(false)),
            ("nvenc_opengl_vulkan_on_dxgi", json!(false)),
            ("nvenc_latency_over_power", json!(false)),
            ("vaapi_strict_rc_buffer", json!(true)),
        ] {
            v24["values"][key] = value;
        }
        let v24_values = v24["values"].clone();
        let mut product = ProductSettings::new("Bootstrap".into(), settings::DEFAULT_PORT);
        let migrated = parse_document(&v24).unwrap();
        assert!(migrated.install_steam_audio_drivers);
        assert_eq!(migrated.nvenc_settings.nvenc_preset, 7);
        product.apply_document(migrated);
        assert!(product.install_steam_audio_drivers());

        let mut action = display_update_action(DisplayPolicyUpdate::default(), 1);
        let AdminAction::Update {
            install_steam_audio_drivers,
            ..
        } = &mut action
        else {
            unreachable!()
        };
        *install_steam_audio_drivers = FieldUpdate::Value(false);
        product.enqueue(82, 5_000, action).unwrap();
        product.start_next();
        let pending = product.pending.take().expect("Steam driver policy update");
        assert_eq!(pending.payload["version"], SETTINGS_VERSION);
        assert_eq!(pending.payload["values"].as_object().unwrap().len(), 79);
        assert_eq!(
            pending.payload["values"]["install_steam_audio_drivers"],
            false
        );
        for (key, value) in v24_values.as_object().unwrap() {
            assert_eq!(pending.payload["values"][key], *value, "v24 value {key}");
        }
        assert_eq!(pending.payload["values"]["nvenc_preset"], 7);
        let response = json!({
            "ok":true,"found":true,"version":SETTINGS_VERSION,"revision":2,
            "values":pending.payload["values"].clone()
        });
        product.finish_call(pending.purpose, CallOutcome::Payload(response.clone()));
        assert!(!product.install_steam_audio_drivers());

        let mut restarted = ProductSettings::new("Bootstrap".into(), settings::DEFAULT_PORT);
        restarted.apply_document(parse_document(&response).unwrap());
        assert!(!restarted.install_steam_audio_drivers());
        assert_eq!(restarted.nvenc_settings().nvenc_preset, 7);

        let mut invalid = display_update_action(DisplayPolicyUpdate::default(), 2);
        let AdminAction::Update {
            install_steam_audio_drivers,
            ..
        } = &mut invalid
        else {
            unreachable!()
        };
        *install_steam_audio_drivers = FieldUpdate::Null;
        restarted.enqueue(83, 5_000, invalid).unwrap();
        restarted.start_next();
        assert!(restarted.pending.is_none());
        assert_eq!(
            restarted.completions.front().unwrap().payload["code"],
            "invalid_install_steam_audio_drivers"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn new_linux_host_supports_automatic_video_encryption() {
        use amaterasu_gamestream::network::{NetworkEncryptionPolicy, VideoEncryptionMode};

        let settings = ProductSettings::new("Bootstrap".into(), settings::DEFAULT_PORT);
        let policy = NetworkEncryptionPolicy {
            lan_mode: VideoEncryptionMode::try_from(i64::from(settings.lan_encryption_mode()))
                .unwrap(),
            wan_mode: VideoEncryptionMode::try_from(i64::from(settings.wan_encryption_mode()))
                .unwrap(),
        };
        assert!(policy.accepts_video_encryption_for_peer("192.168.0.134".parse().unwrap(), true));
        assert!(policy.accepts_video_encryption_for_peer("192.168.0.134".parse().unwrap(), false));
    }

    fn v17_update_confirmation(mut payload: Value) -> Value {
        payload["version"] = json!(SETTINGS_VERSION);
        let values = payload["values"]
            .as_object_mut()
            .expect("update confirmation values are an object");
        values
            .entry("legacy_global_preparation")
            .or_insert_with(|| json!([]));
        for name in frame_limiter_value_names() {
            values.entry((*name).to_owned()).or_insert(Value::Null);
        }
        values
            .entry("lan_encryption_mode")
            .or_insert_with(|| json!(DEFAULT_LAN_ENCRYPTION_MODE));
        values
            .entry("wan_encryption_mode")
            .or_insert_with(|| json!(DEFAULT_WAN_ENCRYPTION_MODE));
        values.entry("upnp").or_insert_with(|| json!(false));
        values.entry("fec_percentage").or_insert(Value::Null);
        values
            .entry("nvenc_spatial_aq")
            .or_insert_with(|| json!(false));
        for key in DISPLAY_POLICY_KEYS {
            values.entry(key.to_owned()).or_insert(Value::Null);
        }
        for key in ["sw_preset", "sw_tune", "encoder", "min_threads", "qp"] {
            values.entry(key.to_owned()).or_insert(Value::Null);
        }
        for (key, value) in nvenc_settings_values(&NvencSettings::default()) {
            values.entry(key).or_insert(value);
        }
        values
            .entry("install_steam_audio_drivers")
            .or_insert_with(|| json!(true));
        payload
    }

    fn remove_nvenc_settings(document: &mut Value) {
        if let Some(values) = document["values"].as_object_mut() {
            for key in NVENC_SETTINGS_KEYS {
                values.remove(key);
            }
        }
    }

    fn remove_extended_display_policy_fields(document: &mut Value) {
        if let Some(values) = document["values"].as_object_mut() {
            for key in DISPLAY_POLICY_KEYS {
                if !LEGACY_DISPLAY_POLICY_KEYS.contains(&key) {
                    values.remove(key);
                }
            }
        }
    }

    fn display_update_action(
        display_policy: DisplayPolicyUpdate,
        expected_revision: u64,
    ) -> AdminAction {
        AdminAction::Update {
            hostname: "Host".into(),
            port: settings::DEFAULT_PORT,
            address_family: FieldUpdate::Omitted,
            bind_address: FieldUpdate::Omitted,
            output_name: FieldUpdate::Omitted,
            audio_sink: FieldUpdate::Omitted,
            virtual_sink: FieldUpdate::Omitted,
            audio_sink_capture_only: FieldUpdate::Omitted,
            install_steam_audio_drivers: FieldUpdate::Omitted,
            nvenc_spatial_aq: FieldUpdate::Omitted,
            external_ip: FieldUpdate::Omitted,
            stream_audio: FieldUpdate::Omitted,
            capture: FieldUpdate::Omitted,
            video_max_batch_size_kb: FieldUpdate::Omitted,
            max_bitrate: FieldUpdate::Omitted,
            qp: FieldUpdate::Omitted,
            fec_percentage: FieldUpdate::Omitted,
            minimum_fps_target: FieldUpdate::Omitted,
            wgc_pacing_smoothing: FieldUpdate::Omitted,
            software_encoder: SoftwareEncoderUpdate::default(),
            nvenc_settings: NvencSettingsUpdate::default(),
            ping_timeout_ms: FieldUpdate::Omitted,
            global_preparation: FieldUpdate::Omitted,
            legacy_global_preparation: FieldUpdate::Omitted,
            frame_limiter: FrameLimiterUpdate::default(),
            display_policy,
            encryption_modes: EncryptionModeUpdate::default(),
            expected_revision,
            require_listener_apply: false,

            upnp: FieldUpdate::Omitted,
        }
    }

    fn display_v18_document(revision: u64) -> Value {
        v17_update_confirmation(json!({
            "ok":true,"found":true,"version":SETTINGS_VERSION,"revision":revision,
            "values":{"hostname":"Host","port":settings::DEFAULT_PORT,
                "address_family":null,"bind_address":null,"output_name":null,
                "audio_sink":null,"virtual_sink":null,"external_ip":null,
                "stream_audio":true,"capture":"auto","video_max_batch_size_kb":null,
                "max_bitrate":null,"minimum_fps_target":null,"wgc_pacing_smoothing":null,
                "ping_timeout_ms":null,"audio_sink_capture_only":false,
                "global_preparation":[]}
        }))
    }

    #[test]
    fn legacy_static_monitor_alias_migrates_to_canonical_without_losing_zero_or_precedence() {
        let absent = display_v18_document(7);
        assert!(
            parse_document(&absent).unwrap().display_policy["dd_virtual_display_permanent_count"]
                .is_null()
        );

        let mut legacy_zero = display_v18_document(7);
        legacy_zero["values"]
            .as_object_mut()
            .unwrap()
            .remove("dd_virtual_display_permanent_count");
        legacy_zero["values"][LEGACY_PERMANENT_MONITOR_COUNT_KEY] = json!(0);
        assert_eq!(
            parse_document(&legacy_zero).unwrap().display_policy["dd_virtual_display_permanent_count"],
            0
        );

        for (canonical, legacy) in [(json!(2), json!(3)), (Value::Null, json!(3))] {
            let mut both = display_v18_document(7);
            both["values"]["dd_virtual_display_permanent_count"] = canonical.clone();
            both["values"][LEGACY_PERMANENT_MONITOR_COUNT_KEY] = legacy;
            assert_eq!(
                parse_document(&both).unwrap().display_policy["dd_virtual_display_permanent_count"],
                canonical
            );
        }

        let mut invalid = display_v18_document(7);
        invalid["values"]
            .as_object_mut()
            .unwrap()
            .remove("dd_virtual_display_permanent_count");
        invalid["values"][LEGACY_PERMANENT_MONITOR_COUNT_KEY] = json!(5);
        assert!(parse_document(&invalid).is_err());
    }

    #[test]
    fn global_display_fields_upgrade_v18_to_v26_and_survive_restart() {
        let mut product = ProductSettings::new("Bootstrap".into(), settings::DEFAULT_PORT);
        product.apply_document(parse_document(&display_v18_document(7)).unwrap());
        product
            .enqueue(
                51,
                5_000,
                display_update_action(
                    DisplayPolicyUpdate {
                        dd_resolution_option: FieldUpdate::Value("manual".into()),
                        dd_manual_resolution: FieldUpdate::Value("1920x1080".into()),
                        dd_refresh_rate_option: FieldUpdate::Value("manual".into()),
                        dd_manual_refresh_rate: FieldUpdate::Value("59.94".into()),
                        dd_hdr_option: FieldUpdate::Value("disabled".into()),
                        dd_configuration_option: FieldUpdate::Value("verify_only".into()),
                        dd_hdr_request_override: FieldUpdate::Value("force_off".into()),
                        dd_mode_remapping: FieldUpdate::Value(json!({"mixed":[{
                            "final_resolution":"1280x720","final_refresh_rate":"60"
                        }]})),
                        additional: FieldUpdate::Value(json!({
                            "adapter_name":"/dev/dri/renderD128",
                            "adapter_pnp_id":"PCI\\VEN_10DE&DEV_2684",
                            "virtual_display_mode":"disabled",
                            "virtual_display_layout":"exclusive",
                            "dd_virtual_display_scale":-1,
                            "dd_virtual_display_permanent_count":2,
                            "virtual_display_outputs":["Vibeshine-1"],
                            "dd_snapshot_exclude_devices":["DISPLAY\\VIBESHINE"],
                            "vulkan_hdr_layer":true,
                            "wayland_hdr_compatibility":false
                        })),
                    },
                    7,
                ),
            )
            .unwrap();
        product.start_next();
        let pending = product.pending.take().unwrap();
        assert_eq!(pending.payload["version"], SETTINGS_VERSION);
        assert_eq!(pending.payload["expected_revision"], 7);
        assert_eq!(pending.payload["values"].as_object().unwrap().len(), 79);
        let write = pending.payload["values"].clone();
        let response =
            json!({"ok":true,"found":true,"version":SETTINGS_VERSION,"revision":8,"values":write});
        product.finish_call(pending.purpose, CallOutcome::Payload(response.clone()));
        assert_eq!(product.display_policy_snapshot().unwrap().0, 8);
        assert_eq!(
            product.settings_payload()["configured_display_policy"]["dd_manual_refresh_rate"],
            "59.94"
        );
        assert_eq!(
            product.settings_payload()["configured_display_policy"]["adapter_name"],
            "/dev/dri/renderD128"
        );
        let mut restarted = ProductSettings::new("Bootstrap".into(), settings::DEFAULT_PORT);
        restarted.apply_document(parse_document(&response).unwrap());
        assert_eq!(
            restarted.display_policy_snapshot(),
            product.display_policy_snapshot()
        );

        product
            .enqueue(
                52,
                5_000,
                display_update_action(
                    DisplayPolicyUpdate {
                        dd_refresh_rate_option: FieldUpdate::Null,
                        ..DisplayPolicyUpdate::default()
                    },
                    8,
                ),
            )
            .unwrap();
        product.start_next();
        let pending = product.pending.take().unwrap();
        assert!(pending.payload["values"]["dd_refresh_rate_option"].is_null());
        assert_eq!(
            pending.payload["values"]["dd_manual_resolution"],
            "1920x1080"
        );
    }

    #[test]
    fn malformed_global_display_values_fail_before_a_cas_write() {
        let mut product = ProductSettings::new("Bootstrap".into(), settings::DEFAULT_PORT);
        product.apply_document(parse_document(&display_v18_document(7)).unwrap());
        for (index, invalid) in [
            DisplayPolicyUpdate {
                dd_refresh_rate_option: FieldUpdate::Value("unknown".into()),
                ..Default::default()
            },
            DisplayPolicyUpdate {
                dd_manual_resolution: FieldUpdate::Value("bad".into()),
                ..Default::default()
            },
            DisplayPolicyUpdate {
                dd_manual_refresh_rate: FieldUpdate::Value("0.0000000001".into()),
                ..Default::default()
            },
            DisplayPolicyUpdate {
                dd_mode_remapping: FieldUpdate::Value(json!({"mixed":[{}]})),
                ..Default::default()
            },
            DisplayPolicyUpdate {
                dd_mode_remapping: FieldUpdate::Value(json!({"refresh_rate_only":[{
                    "requested_fps":"0", "final_refresh_rate":"60"
                }]})),
                ..Default::default()
            },
        ]
        .into_iter()
        .enumerate()
        {
            product
                .enqueue(60 + index as u64, 5_000, display_update_action(invalid, 7))
                .unwrap();
            product.start_next();
            assert!(product.pending.is_none());
            assert_eq!(product.revision(), Some(7));
            assert_eq!(
                product.completions.pop_front().unwrap().payload["code"],
                "invalid_display_policy"
            );
        }
        let mut invalid = display_v18_document(7);
        invalid["values"]["dd_hdr_option"] = json!("force_on");
        assert!(parse_document(&invalid).is_err());
        invalid = display_v18_document(7);
        invalid["values"]
            .as_object_mut()
            .unwrap()
            .remove("dd_hdr_option");
        assert!(parse_document(&invalid).is_err());
    }

    fn bootstrap_with_capture_output(output: &str) -> Settings {
        bootstrap_with_capture_and_audio(output, "default")
    }

    fn bootstrap_with_capture_and_audio(output: &str, audio_endpoint: &str) -> Settings {
        Settings {
            streaming: Some(crate::launch::StreamingConfig {
                capture: crate::launch::CaptureConfig {
                    capture_provider: crate::launch::CaptureProvider::Dxgi,
                    output: output.into(),
                    encoder: amaterasu_module_sdk::EncoderSelection::Index(0),
                    audio_endpoint: audio_endpoint.into(),
                },
                desktop: crate::launch::DesktopSettings::default(),
                profile: crate::launch::StreamProfile {
                    codec: amaterasu_media::VideoCodec::H264,
                    max_width: 1920,
                    max_height: 1080,
                    max_fps: 60,
                    bitrate_kbps: 10_000,
                    max_reference_frames: 1,
                    packet_size: 1024,
                    fec_percentage: 20,
                    min_parity_shards: 2,
                    max_fec_blocks: 1,
                    packet_ms: 10,
                    audio_bitrate: 128_000,
                    encrypt_video: true,
                    encrypt_audio: true,
                    permit_legacy_audio_iv_wrap: false,
                },
            }),
            ..Settings::default()
        }
    }

    #[test]
    fn parses_missing_and_persisted_hostname_documents() {
        let missing = parse_document(&json!({
            "ok":true,"found":false,"version":null,"revision":0,"values":{}
        }))
        .unwrap();
        assert_eq!(missing.revision, 0);
        assert_eq!(missing.hostname, None);
        assert_eq!(missing.port, None);
        assert!(missing.stream_audio);
        assert_eq!(missing.capture, CaptureMode::Auto);

        let persisted = parse_document(&json!({
            "ok":true,"found":true,"version":1,"revision":7,"values":{"hostname":"Studio PC"}
        }))
        .unwrap();
        assert_eq!(persisted.revision, 7);
        assert_eq!(persisted.hostname.as_deref(), Some("Studio PC"));
        assert_eq!(persisted.port, None);
        assert_eq!(persisted.output_name, None);
        assert_eq!(persisted.audio_sink, None);
        assert!(persisted.stream_audio);
        assert_eq!(persisted.capture, CaptureMode::Auto);

        let defaulted = parse_document(&json!({
            "ok":true,"found":true,"version":1,"revision":8,"values":{"hostname":""}
        }))
        .unwrap();
        assert_eq!(defaulted.hostname.as_deref(), Some(""));

        let migrated = parse_document(&json!({
            "ok":true,"found":true,"version":2,"revision":9,"values":{"hostname":"Studio PC","port":48000}
        }))
        .unwrap();
        assert_eq!(migrated.hostname.as_deref(), Some("Studio PC"));
        assert_eq!(migrated.port, Some(48_000));
        let network_document = parse_document(&json!({
            "ok":true,"found":true,"version":3,"revision":10,
            "values":{"hostname":"Studio PC","port":48000,"address_family":null,"bind_address":null}
        }))
        .unwrap();
        assert_eq!(network_document.output_name, None);
        assert!(network_document.stream_audio);
        assert_eq!(network_document.capture, CaptureMode::Auto);
    }

    #[test]
    fn output_name_update_uses_null_empty_and_omitted_as_intended() {
        assert_eq!(
            apply_output_name_update(FieldUpdate::Omitted, Some("existing-id".into())),
            Ok(Some("existing-id".into()))
        );
        assert_eq!(
            apply_output_name_update(FieldUpdate::Null, Some("existing-id".into())),
            Ok(None)
        );
        assert_eq!(
            apply_output_name_update(
                FieldUpdate::Value(String::new()),
                Some("existing-id".into())
            ),
            Ok(None)
        );
        assert_eq!(
            apply_output_name_update(FieldUpdate::Value("selected-display-id".into()), None),
            Ok(Some("selected-display-id".into()))
        );

        for invalid in [" ", " display-id", "display-id ", "display\nid"] {
            assert_eq!(normalize_output_name(invalid), Err(()));
        }
        assert_eq!(
            normalize_output_name(&"é".repeat(256)),
            Ok(Some("é".repeat(256)))
        );
        assert_eq!(normalize_output_name(&"é".repeat(257)), Err(()));
    }

    #[test]
    fn v4_requires_nullable_output_name_and_normalizes_empty_to_automatic() {
        let automatic = parse_document(&json!({
            "ok":true,"found":true,"version":4,"revision":1,
            "values":{"hostname":"Host","port":47989,"address_family":null,"bind_address":null,"output_name":""}
        }))
        .unwrap();
        assert_eq!(automatic.output_name, None);
        assert!(automatic.stream_audio);

        for payload in [
            json!({"ok":true,"found":true,"version":4,"revision":1,"values":{"hostname":"Host","port":47989,"address_family":null,"bind_address":null}}),
            json!({"ok":true,"found":true,"version":4,"revision":1,"values":{"hostname":"Host","port":47989,"address_family":null,"bind_address":null,"output_name":" "}}),
            json!({"ok":true,"found":true,"version":4,"revision":1,"values":{"hostname":"Host","port":47989,"address_family":null,"bind_address":null,"output_name":" display-id"}}),
            json!({"ok":true,"found":true,"version":4,"revision":1,"values":{"hostname":"Host","port":47989,"address_family":null,"bind_address":null,"output_name":"display\nid"}}),
        ] {
            assert_eq!(
                parse_document(&payload).unwrap_err().code,
                "invalid_state_response"
            );
        }
    }

    #[test]
    fn v5_requires_a_boolean_and_old_documents_migrate_with_auto_capture() {
        let current = parse_document(&json!({
            "ok":true,"found":true,"version":5,"revision":2,
            "values":{"hostname":"Host","port":47989,"address_family":null,
                "bind_address":null,"output_name":null,"stream_audio":false}
        }))
        .unwrap();
        assert!(!current.stream_audio);
        assert_eq!(current.capture, CaptureMode::Auto);

        for version in 1..=4 {
            let values = match version {
                1 => json!({"hostname":"Host"}),
                2 => json!({"hostname":"Host","port":47989}),
                3 => {
                    json!({"hostname":"Host","port":47989,"address_family":null,"bind_address":null})
                }
                4 => {
                    json!({"hostname":"Host","port":47989,"address_family":null,"bind_address":null,"output_name":null})
                }
                _ => unreachable!(),
            };
            let migrated = parse_document(&json!({
                "ok":true,"found":true,"version":version,"revision":1,"values":values
            }))
            .unwrap();
            assert!(migrated.stream_audio, "version {version}");
            assert_eq!(migrated.capture, CaptureMode::Auto, "version {version}");
        }

        for malformed in [
            json!({"ok":true,"found":true,"version":5,"revision":1,
                "values":{"hostname":"Host","port":47989,"address_family":null,"bind_address":null,"output_name":null}}),
            json!({"ok":true,"found":true,"version":5,"revision":1,
                "values":{"hostname":"Host","port":47989,"address_family":null,"bind_address":null,"output_name":null,"stream_audio":null}}),
            json!({"ok":true,"found":true,"version":5,"revision":1,
                "values":{"hostname":"Host","port":47989,"address_family":null,"bind_address":null,"output_name":null,"stream_audio":"false"}}),
        ] {
            assert_eq!(
                parse_document(&malformed).unwrap_err().code,
                "invalid_state_response"
            );
        }
    }

    #[test]
    fn v6_capture_mode_is_strict_and_legacy_versions_migrate_to_auto() {
        let current = parse_document(&json!({
            "ok":true,"found":true,"version":6,"revision":2,
            "values":{"hostname":"Host","port":47989,"address_family":null,
                "bind_address":null,"output_name":null,"stream_audio":false,"capture":"wgcc"}
        }))
        .unwrap();
        assert_eq!(current.capture, CaptureMode::Wgcc);

        for mode in ["auto", "ddx", "wgc", "wgcc"] {
            let document = parse_document(&json!({
                "ok":true,"found":true,"version":6,"revision":2,
                "values":{"hostname":"Host","port":47989,"address_family":null,
                    "bind_address":null,"output_name":null,"stream_audio":false,"capture":mode}
            }))
            .unwrap();
            assert_eq!(document.capture.as_str(), mode);
        }

        for malformed in [
            json!({"ok":true,"found":true,"version":6,"revision":1,
                "values":{"hostname":"Host","port":47989,"address_family":null,
                    "bind_address":null,"output_name":null,"stream_audio":true}}),
            json!({"ok":true,"found":true,"version":6,"revision":1,
                "values":{"hostname":"Host","port":47989,"address_family":null,
                    "bind_address":null,"output_name":null,"stream_audio":true,"capture":null}}),
            json!({"ok":true,"found":true,"version":6,"revision":1,
                "values":{"hostname":"Host","port":47989,"address_family":null,
                    "bind_address":null,"output_name":null,"stream_audio":true,"capture":"unknown"}}),
        ] {
            assert_eq!(
                parse_document(&malformed).unwrap_err().code,
                "invalid_state_response"
            );
        }
    }

    #[test]
    fn v7_video_batch_size_migrates_defaults_and_survives_restart() {
        let v6 = parse_document(&json!({
            "ok":true,"found":true,"version":6,"revision":2,
            "values":{"hostname":"Host","port":47989,"address_family":null,
                "bind_address":null,"output_name":null,"stream_audio":true,"capture":"auto"}
        }))
        .unwrap();
        assert_eq!(v6.video_max_batch_size_kb, None);
        assert_eq!(v6.max_bitrate, None);

        let selected_document = json!({
            "ok":true,"found":true,"version":7,"revision":3,
            "values":{"hostname":"Host","port":47989,"address_family":null,
                "bind_address":null,"output_name":null,"stream_audio":true,"capture":"auto",
                "video_max_batch_size_kb":17}
        });
        assert_eq!(
            parse_document(&selected_document).unwrap().max_bitrate,
            None
        );
        let mut first_start = ProductSettings::new("Bootstrap".into(), settings::DEFAULT_PORT);
        first_start.apply_document(parse_document(&selected_document).unwrap());
        assert_eq!(first_start.configured_video_max_batch_size_kb(), Some(17));
        assert_eq!(first_start.effective_video_max_batch_size_kb(), 64);
        assert!(first_start.video_batch_size_fallback());
        assert_eq!(
            first_start.settings_payload()["configured_video_max_batch_size_kb"],
            17
        );
        assert_eq!(
            first_start.settings_payload()["effective_video_max_batch_size_kb"],
            64
        );
        assert_eq!(
            first_start.settings_payload()["video_batch_size_fallback"],
            true
        );

        let mut restarted = ProductSettings::new("Bootstrap".into(), settings::DEFAULT_PORT);
        restarted.apply_document(parse_document(&selected_document).unwrap());
        assert_eq!(restarted.configured_video_max_batch_size_kb(), Some(17));
        assert_eq!(restarted.effective_video_max_batch_size_kb(), 64);
        assert!(restarted.video_batch_size_fallback());

        for invalid in [
            json!({"ok":true,"found":true,"version":7,"revision":1,
                "values":{"hostname":"Host","port":47989,"address_family":null,
                    "bind_address":null,"output_name":null,"stream_audio":true,"capture":"auto",
                    "video_max_batch_size_kb":65}}),
            json!({"ok":true,"found":true,"version":7,"revision":1,
                "values":{"hostname":"Host","port":47989,"address_family":null,
                    "bind_address":null,"output_name":null,"stream_audio":true,"capture":"auto",
                    "video_max_batch_size_kb":-1}}),
            json!({"ok":true,"found":true,"version":7,"revision":1,
                "values":{"hostname":"Host","port":47989,"address_family":null,
                    "bind_address":null,"output_name":null,"stream_audio":true,"capture":"auto"}}),
        ] {
            assert_eq!(
                parse_document(&invalid).unwrap_err().code,
                "invalid_state_response"
            );
        }
    }

    #[test]
    fn v8_max_bitrate_preserves_signed_raw_values_and_derives_only_positive_caps() {
        let legacy_v7 = parse_document(&json!({
            "ok":true,"found":true,"version":7,"revision":3,
            "values":{"hostname":"Host","port":47989,"address_family":null,
                "bind_address":null,"output_name":null,"stream_audio":true,"capture":"auto",
                "video_max_batch_size_kb":32}
        }))
        .unwrap();
        assert_eq!(legacy_v7.max_bitrate, None);

        for (raw, effective) in [
            (i32::MIN, None),
            (-1, None),
            (0, None),
            (1, Some(1)),
            (15_000, Some(15_000)),
            (i32::MAX, Some(i32::MAX as u32)),
        ] {
            let document = json!({
                "ok":true,"found":true,"version":8,"revision":4,
                "values":{"hostname":"Host","port":47989,"address_family":null,
                    "bind_address":null,"output_name":null,"stream_audio":true,"capture":"auto",
                    "video_max_batch_size_kb":32,"max_bitrate":raw}
            });
            let parsed = parse_document(&document).unwrap();
            assert_eq!(parsed.max_bitrate, Some(raw));

            let mut first_start = ProductSettings::new("Bootstrap".into(), settings::DEFAULT_PORT);
            first_start.apply_document(parsed);
            assert_eq!(first_start.configured_max_bitrate(), Some(raw));
            assert_eq!(first_start.effective_max_bitrate_kbps(), effective);
            assert_eq!(
                first_start.settings_payload()["configured_max_bitrate"],
                raw
            );
            assert_eq!(
                first_start.settings_payload()["effective_max_bitrate_kbps"],
                effective.map_or(Value::Null, |value| json!(value))
            );

            let mut restarted = ProductSettings::new("Bootstrap".into(), settings::DEFAULT_PORT);
            restarted.apply_document(parse_document(&document).unwrap());
            assert_eq!(restarted.configured_max_bitrate(), Some(raw));
            assert_eq!(restarted.effective_max_bitrate_kbps(), effective);
        }

        let reset = json!({
            "ok":true,"found":true,"version":8,"revision":4,
            "values":{"hostname":"Host","port":47989,"address_family":null,
                "bind_address":null,"output_name":null,"stream_audio":true,"capture":"auto",
                "video_max_batch_size_kb":32,"max_bitrate":null}
        });
        assert_eq!(parse_document(&reset).unwrap().max_bitrate, None);

        for invalid in [
            json!({"ok":true,"found":true,"version":8,"revision":1,
                "values":{"hostname":"Host","port":47989,"address_family":null,
                    "bind_address":null,"output_name":null,"stream_audio":true,"capture":"auto",
                    "video_max_batch_size_kb":32,"max_bitrate":2147483648_i64}}),
            json!({"ok":true,"found":true,"version":8,"revision":1,
                "values":{"hostname":"Host","port":47989,"address_family":null,
                    "bind_address":null,"output_name":null,"stream_audio":true,"capture":"auto",
                    "video_max_batch_size_kb":32,"max_bitrate":1.5}}),
            json!({"ok":true,"found":true,"version":8,"revision":1,
                "values":{"hostname":"Host","port":47989,"address_family":null,
                    "bind_address":null,"output_name":null,"stream_audio":true,"capture":"auto",
                    "video_max_batch_size_kb":32}}),
        ] {
            assert_eq!(
                parse_document(&invalid).unwrap_err().code,
                "invalid_state_response"
            );
        }
    }

    #[test]
    fn v9_minimum_fps_target_migrates_defaults_and_survives_restart() {
        let legacy = parse_document(&json!({
            "ok":true,"found":true,"version":8,"revision":3,
            "values":{"hostname":"Host","port":47989,"address_family":null,
                "bind_address":null,"output_name":null,"stream_audio":true,"capture":"auto",
                "video_max_batch_size_kb":32,"max_bitrate":null}
        }))
        .unwrap();
        assert_eq!(legacy.minimum_fps_target, None);
        let mut migrated = ProductSettings::new("Bootstrap".into(), settings::DEFAULT_PORT);
        migrated.apply_document(legacy);
        assert_eq!(migrated.configured_minimum_fps_target(), None);
        assert_eq!(migrated.effective_minimum_fps_target(), 20.0);

        for target in [0.0, 23.5, 1000.0] {
            let document = json!({
                "ok":true,"found":true,"version":9,"revision":4,
                "values":{"hostname":"Host","port":47989,"address_family":null,
                    "bind_address":null,"output_name":null,"stream_audio":true,"capture":"auto",
                    "video_max_batch_size_kb":32,"max_bitrate":null,
                    "minimum_fps_target":target}
            });
            let parsed = parse_document(&document).unwrap();
            assert_eq!(parsed.minimum_fps_target, Some(target));

            let mut first_start = ProductSettings::new("Bootstrap".into(), settings::DEFAULT_PORT);
            first_start.apply_document(parsed);
            assert_eq!(first_start.configured_minimum_fps_target(), Some(target));
            assert_eq!(first_start.effective_minimum_fps_target(), target);
            assert_eq!(
                first_start.settings_payload()["configured_minimum_fps_target"],
                target
            );
            assert_eq!(
                first_start.settings_payload()["effective_minimum_fps_target"],
                target
            );

            let mut restarted = ProductSettings::new("Bootstrap".into(), settings::DEFAULT_PORT);
            restarted.apply_document(parse_document(&document).unwrap());
            assert_eq!(restarted.configured_minimum_fps_target(), Some(target));
            assert_eq!(restarted.effective_minimum_fps_target(), target);
        }

        for invalid in [
            json!({"ok":true,"found":true,"version":9,"revision":1,
                "values":{"hostname":"Host","port":47989,"address_family":null,
                    "bind_address":null,"output_name":null,"stream_audio":true,"capture":"auto",
                    "video_max_batch_size_kb":32,"max_bitrate":null,"minimum_fps_target":-0.1}}),
            json!({"ok":true,"found":true,"version":9,"revision":1,
                "values":{"hostname":"Host","port":47989,"address_family":null,
                    "bind_address":null,"output_name":null,"stream_audio":true,"capture":"auto",
                    "video_max_batch_size_kb":32,"max_bitrate":null,"minimum_fps_target":1000.1}}),
            json!({"ok":true,"found":true,"version":9,"revision":1,
                "values":{"hostname":"Host","port":47989,"address_family":null,
                    "bind_address":null,"output_name":null,"stream_audio":true,"capture":"auto",
                    "video_max_batch_size_kb":32,"max_bitrate":null,"minimum_fps_target":"30"}}),
            json!({"ok":true,"found":true,"version":9,"revision":1,
                "values":{"hostname":"Host","port":47989,"address_family":null,
                    "bind_address":null,"output_name":null,"stream_audio":true,"capture":"auto",
                    "video_max_batch_size_kb":32,"max_bitrate":null}}),
        ] {
            assert_eq!(
                parse_document(&invalid).unwrap_err().code,
                "invalid_state_response"
            );
        }
        assert!(!valid_minimum_fps_target(f64::NAN));
        assert!(!valid_minimum_fps_target(f64::INFINITY));
    }

    #[test]
    fn v10_audio_sink_migrates_defaults_and_survives_restart() {
        let bootstrap = bootstrap_with_capture_and_audio("display", "render.bootstrap");
        let legacy = parse_document(&json!({
            "ok":true,"found":true,"version":9,"revision":8,
            "values":{"hostname":"Host","port":47989,"address_family":null,
                "bind_address":null,"output_name":null,"stream_audio":true,"capture":"auto",
                "video_max_batch_size_kb":32,"max_bitrate":null,"minimum_fps_target":20.0}
        }))
        .unwrap();
        assert_eq!(legacy.audio_sink, None);
        let mut migrated = ProductSettings::with_bootstrap_settings("Bootstrap".into(), &bootstrap);
        migrated.apply_document(legacy);
        assert_eq!(migrated.configured_audio_sink(), None);
        assert_eq!(migrated.effective_audio_sink(), "render.bootstrap");

        let selected = "{0.0.1.00000000}.{endpoint-guid}";
        let document = json!({
            "ok":true,"found":true,"version":10,"revision":9,
            "values":{"hostname":"Host","port":47989,"address_family":null,
                "bind_address":null,"output_name":null,"audio_sink":selected,
                "stream_audio":true,"capture":"auto","video_max_batch_size_kb":32,
                "max_bitrate":null,"minimum_fps_target":20.0}
        });
        let parsed = parse_document(&document).unwrap();
        assert_eq!(parsed.wgc_pacing_smoothing, None);
        let mut first_start =
            ProductSettings::with_bootstrap_settings("Bootstrap".into(), &bootstrap);
        first_start.apply_document(parsed);
        assert_eq!(first_start.configured_audio_sink(), Some(selected));
        assert_eq!(first_start.effective_audio_sink(), selected);
        assert_eq!(
            first_start.settings_payload()["configured_audio_sink"],
            selected
        );
        assert_eq!(
            first_start.settings_payload()["effective_audio_sink"],
            selected
        );

        let mut restarted =
            ProductSettings::with_bootstrap_settings("Bootstrap".into(), &bootstrap);
        restarted.apply_document(parse_document(&document).unwrap());
        assert_eq!(restarted.configured_audio_sink(), Some(selected));
        assert_eq!(restarted.effective_audio_sink(), selected);
        assert_eq!(restarted.configured_wgc_pacing_smoothing(), None);
        assert!(restarted.effective_wgc_pacing_smoothing());

        for invalid_sink in [json!("render\ninvalid"), json!("é".repeat(2049)), json!(7)] {
            let mut invalid = document.clone();
            invalid["values"]["audio_sink"] = invalid_sink;
            assert_eq!(
                parse_document(&invalid).unwrap_err().code,
                "invalid_state_response"
            );
        }
        let mut missing = document;
        missing["values"]
            .as_object_mut()
            .unwrap()
            .remove("audio_sink");
        assert_eq!(
            parse_document(&missing).unwrap_err().code,
            "invalid_state_response"
        );
    }

    #[test]
    fn v11_wgc_pacing_smoothing_migrates_v10_default_and_persists_bool_or_reset() {
        let legacy_v10 = json!({
            "ok":true,"found":true,"version":10,"revision":9,
            "values":{"hostname":"Host","port":47989,"address_family":null,
                "bind_address":null,"output_name":null,"audio_sink":null,
                "stream_audio":true,"capture":"auto","video_max_batch_size_kb":32,
                "max_bitrate":null,"minimum_fps_target":20.0}
        });
        let mut migrated = ProductSettings::new("Bootstrap".into(), settings::DEFAULT_PORT);
        migrated.apply_document(parse_document(&legacy_v10).unwrap());
        assert_eq!(migrated.configured_wgc_pacing_smoothing(), None);
        assert!(migrated.effective_wgc_pacing_smoothing());

        for (raw, effective) in [
            (json!(true), true),
            (json!(false), false),
            (Value::Null, true),
        ] {
            let document = json!({
                "ok":true,"found":true,"version":11,"revision":10,
                "values":{"hostname":"Host","port":47989,"address_family":null,
                    "bind_address":null,"output_name":null,"audio_sink":null,
                    "stream_audio":true,"capture":"auto","video_max_batch_size_kb":32,
                    "max_bitrate":null,"minimum_fps_target":20.0,
                    "wgc_pacing_smoothing":raw}
            });
            let parsed = parse_document(&document).unwrap();
            let configured = raw.as_bool();
            assert_eq!(parsed.wgc_pacing_smoothing, configured);

            let mut product = ProductSettings::new("Bootstrap".into(), settings::DEFAULT_PORT);
            product.apply_document(parsed);
            assert_eq!(product.configured_wgc_pacing_smoothing(), configured);
            assert_eq!(product.effective_wgc_pacing_smoothing(), effective);
            assert_eq!(
                product.settings_payload()["configured_wgc_pacing_smoothing"],
                raw
            );
            assert_eq!(
                product.settings_payload()["effective_wgc_pacing_smoothing"],
                effective
            );
        }

        for invalid in [
            json!({"ok":true,"found":true,"version":11,"revision":10,
                "values":{"hostname":"Host","port":47989,"address_family":null,
                    "bind_address":null,"output_name":null,"audio_sink":null,
                    "stream_audio":true,"capture":"auto","video_max_batch_size_kb":32,
                    "max_bitrate":null,"minimum_fps_target":20.0}}),
            json!({"ok":true,"found":true,"version":11,"revision":10,
                "values":{"hostname":"Host","port":47989,"address_family":null,
                    "bind_address":null,"output_name":null,"audio_sink":null,
                    "stream_audio":true,"capture":"auto","video_max_batch_size_kb":32,
                    "max_bitrate":null,"minimum_fps_target":20.0,
                    "wgc_pacing_smoothing":"true"}}),
        ] {
            assert_eq!(
                parse_document(&invalid).unwrap_err().code,
                "invalid_state_response"
            );
        }
    }

    #[test]
    fn v12_external_ip_migrates_legacy_and_preserves_exact_text() {
        let legacy = json!({
            "ok":true,"found":true,"version":11,"revision":1,
            "values":{"hostname":"Host","port":47989,"address_family":null,
                "bind_address":null,"output_name":null,"audio_sink":null,
                "stream_audio":true,"capture":"auto","video_max_batch_size_kb":null,
                "max_bitrate":null,"minimum_fps_target":null,"wgc_pacing_smoothing":null}
        });
        let parsed = parse_document(&legacy).unwrap();
        assert_eq!(parsed.external_ip, None);

        let mut current = legacy.clone();
        current["version"] = json!(12);
        current["values"]["external_ip"] = json!(" 203.0.113.42 ");
        let mut settings = ProductSettings::new("Bootstrap".into(), settings::DEFAULT_PORT);
        settings.apply_document(parse_document(&current).unwrap());
        assert_eq!(
            settings.settings_payload()["configured_external_ip"],
            " 203.0.113.42 "
        );
        assert_eq!(
            apply_external_ip_update(FieldUpdate::Omitted, Some(" 203.0.113.42 ".into())),
            Ok(Some(" 203.0.113.42 ".into()))
        );
        assert_eq!(
            apply_external_ip_update(FieldUpdate::Null, Some("old".into())),
            Ok(None)
        );
        assert_eq!(
            apply_external_ip_update(FieldUpdate::Value(String::new()), Some("old".into())),
            Ok(None)
        );

        for invalid in [json!(42), json!("bad\naddress"), json!("x".repeat(4097))] {
            current["values"]["external_ip"] = invalid;
            assert!(parse_document(&current).is_err());
        }
        current["values"]
            .as_object_mut()
            .unwrap()
            .remove("external_ip");
        assert!(parse_document(&current).is_err());
    }

    #[test]
    fn external_ip_and_nvenc_admin_updates_persist_and_read_back() {
        let target = NetworkTarget::from(settings::DEFAULT_PORT);
        let initial_update = product_update_payload(
            4,
            "Host",
            &target,
            None,
            ProductStreamingSettings {
                display_policy: empty_display_policy(),
                audio_sink: None,
                virtual_sink: None,
                audio_sink_capture_only: false,
                install_steam_audio_drivers: true,
                nvenc_spatial_aq: true,
                external_ip: Some("198.51.100.7".into()),
                stream_audio: true,
                capture: CaptureMode::Auto,
                video_max_batch_size_kb: None,
                max_bitrate: None,
                qp: None,
                fec_percentage: None,
                minimum_fps_target: None,
                wgc_pacing_smoothing: None,
                software_encoder: SoftwareEncoderOptions::default(),
                nvenc_settings: NvencSettings::default(),
                ping_timeout_ms: None,
                global_preparation: Vec::new(),
                legacy_global_preparation: Vec::new(),
                frame_limiter: FrameLimiterSettings::default(),
                lan_encryption_mode: DEFAULT_LAN_ENCRYPTION_MODE,
                wan_encryption_mode: DEFAULT_WAN_ENCRYPTION_MODE,

                upnp: false,
            },
        );
        let initial_document = json!({
            "ok":true,
            "found":true,
            "version":SETTINGS_VERSION,
            "revision":4,
            "values":initial_update["values"].clone()
        });
        assert_eq!(initial_document["version"], SETTINGS_VERSION);

        let mut product = ProductSettings::new("Bootstrap".into(), settings::DEFAULT_PORT);
        product.apply_document(parse_document(&initial_document).unwrap());
        let external_ip = " 203.0.113.42 ";
        product
            .enqueue(
                72,
                5_000,
                AdminAction::Update {
                    display_policy: DisplayPolicyUpdate::default(),
                    software_encoder: SoftwareEncoderUpdate::default(),
                    nvenc_settings: NvencSettingsUpdate::default(),
                    hostname: "Host".into(),
                    port: settings::DEFAULT_PORT,
                    address_family: FieldUpdate::Omitted,
                    bind_address: FieldUpdate::Omitted,
                    output_name: FieldUpdate::Omitted,
                    audio_sink: FieldUpdate::Omitted,
                    virtual_sink: FieldUpdate::Omitted,
                    audio_sink_capture_only: FieldUpdate::Omitted,
                    install_steam_audio_drivers: FieldUpdate::Omitted,
                    nvenc_spatial_aq: FieldUpdate::Value(false),
                    external_ip: FieldUpdate::Value(external_ip.into()),
                    stream_audio: FieldUpdate::Omitted,
                    capture: FieldUpdate::Omitted,
                    video_max_batch_size_kb: FieldUpdate::Omitted,
                    max_bitrate: FieldUpdate::Omitted,
                    qp: FieldUpdate::Omitted,
                    fec_percentage: FieldUpdate::Omitted,
                    minimum_fps_target: FieldUpdate::Omitted,
                    wgc_pacing_smoothing: FieldUpdate::Omitted,
                    ping_timeout_ms: FieldUpdate::Omitted,
                    global_preparation: FieldUpdate::Omitted,
                    legacy_global_preparation: FieldUpdate::Omitted,
                    frame_limiter: FrameLimiterUpdate::default(),
                    encryption_modes: EncryptionModeUpdate::default(),
                    expected_revision: 4,
                    require_listener_apply: false,

                    upnp: FieldUpdate::Omitted,
                },
            )
            .unwrap();
        product.start_next();

        let pending = product.pending.take().expect("product update request");
        assert_eq!(pending.payload["version"], SETTINGS_VERSION);
        assert_eq!(pending.payload["version"], initial_document["version"]);
        assert_eq!(pending.payload["expected_revision"], 4);
        assert_eq!(pending.payload["values"]["external_ip"], external_ip);
        assert_eq!(pending.payload["values"]["nvenc_spatial_aq"], false);

        let confirmation = v17_update_confirmation(json!({
            "ok":true,
            "found":true,
            "version":SETTINGS_VERSION,
            "revision":5,
            "values":pending.payload["values"].clone()
        }));
        assert_eq!(confirmation["version"], initial_document["version"]);
        assert_eq!(confirmation["values"]["external_ip"], external_ip);
        product.finish_call(pending.purpose, CallOutcome::Payload(confirmation.clone()));

        let readback = &product
            .completions
            .front()
            .expect("settings response")
            .payload;
        assert_eq!(readback["configured_external_ip"], external_ip);
        assert_eq!(readback["nvenc_spatial_aq"], false);
        assert_eq!(readback["revision"], 5);

        let mut restarted = ProductSettings::new("Bootstrap".into(), settings::DEFAULT_PORT);
        restarted.apply_document(parse_document(&confirmation).unwrap());
        assert_eq!(
            restarted.settings_payload()["configured_external_ip"],
            external_ip
        );
        assert_eq!(restarted.settings_payload()["nvenc_spatial_aq"], false);
    }

    #[test]
    fn v13_ping_timeout_migrates_with_default_and_persists_signed_values() {
        let version_twelve = json!({
            "ok":true,"found":true,"version":12,"revision":4,
            "values":{"hostname":"Host","port":47989,"address_family":null,
                "bind_address":null,"output_name":null,"audio_sink":null,"external_ip":null,
                "stream_audio":true,"capture":"auto","video_max_batch_size_kb":32,
                "max_bitrate":null,"minimum_fps_target":20.0,"wgc_pacing_smoothing":null}
        });
        let mut settings = ProductSettings::new("Bootstrap".into(), settings::DEFAULT_PORT);
        settings.apply_document(parse_document(&version_twelve).unwrap());
        assert_eq!(settings.configured_ping_timeout_ms(), None);
        assert_eq!(settings.effective_ping_timeout_ms(), 10_000);
        assert_eq!(
            settings.settings_payload()["configured_ping_timeout_ms"],
            Value::Null
        );
        assert_eq!(
            settings.settings_payload()["effective_ping_timeout_ms"],
            10_000
        );

        for (stored, effective) in [(0, 0), (i32::MAX, i32::MAX as u32)] {
            let mut document = version_twelve.clone();
            document["version"] = json!(13);
            document["revision"] = json!(5);
            document["values"]["ping_timeout_ms"] = json!(stored);
            let parsed = parse_document(&document).unwrap();
            settings.apply_document(parsed);
            assert_eq!(settings.configured_ping_timeout_ms(), Some(stored));
            assert_eq!(settings.effective_ping_timeout_ms(), effective);

            let restarted = parse_document(&document).unwrap();
            let mut restarted_settings =
                ProductSettings::new("Bootstrap".into(), settings::DEFAULT_PORT);
            restarted_settings.apply_document(restarted);
            assert_eq!(
                restarted_settings.configured_ping_timeout_ms(),
                Some(stored)
            );
            assert_eq!(restarted_settings.effective_ping_timeout_ms(), effective);
        }

        for raw in [json!(-1), json!(i64::from(i32::MAX) + 1), json!("1000")] {
            let mut invalid = version_twelve.clone();
            invalid["version"] = json!(13);
            invalid["values"]["ping_timeout_ms"] = raw;
            assert_eq!(
                parse_document(&invalid).unwrap_err().code,
                "invalid_state_response"
            );
        }

        assert_eq!(
            apply_ping_timeout_update(FieldUpdate::Omitted, Some(2_000)),
            Ok(Some(2_000))
        );
        assert_eq!(
            apply_ping_timeout_update(FieldUpdate::Null, Some(2_000)),
            Ok(None)
        );
        assert_eq!(
            apply_ping_timeout_update(FieldUpdate::Value(-1), Some(2_000)),
            Ok(None)
        );
        assert_eq!(
            apply_ping_timeout_update(FieldUpdate::Value(-2), None),
            Err(())
        );
    }

    #[test]
    fn ping_timeout_reset_editor_value_persists_as_default() {
        let reset = apply_ping_timeout_update(FieldUpdate::Value(-1), Some(2_500)).unwrap();
        let payload = product_update_payload(
            7,
            "Host",
            &NetworkTarget {
                port: 47_989,
                address_family: None,
                bind_address: None,
            },
            None,
            ProductStreamingSettings {
                display_policy: empty_display_policy(),
                audio_sink: None,
                virtual_sink: None,
                audio_sink_capture_only: false,
                install_steam_audio_drivers: true,
                nvenc_spatial_aq: false,
                external_ip: None,
                stream_audio: true,
                capture: CaptureMode::Auto,
                video_max_batch_size_kb: None,
                max_bitrate: None,
                qp: None,
                fec_percentage: None,
                minimum_fps_target: None,
                wgc_pacing_smoothing: None,
                software_encoder: SoftwareEncoderOptions::default(),
                nvenc_settings: NvencSettings::default(),
                ping_timeout_ms: reset,
                global_preparation: Vec::new(),
                legacy_global_preparation: Vec::new(),
                frame_limiter: FrameLimiterSettings::default(),
                lan_encryption_mode: DEFAULT_LAN_ENCRYPTION_MODE,
                wan_encryption_mode: DEFAULT_WAN_ENCRYPTION_MODE,

                upnp: false,
            },
        );

        assert_eq!(payload["version"], SETTINGS_VERSION);
        assert_eq!(payload["values"]["ping_timeout_ms"], Value::Null);
    }

    #[test]
    fn wgc_pacing_smoothing_admin_update_preserves_selects_and_resets() {
        let mut product = ProductSettings::new("Bootstrap".into(), settings::DEFAULT_PORT);
        product.apply_document(
            parse_document(&json!({
                "ok":true,"found":true,"version":12,"revision":5,
                "values":{"hostname":"Host","port":47989,"address_family":null,
                    "bind_address":null,"output_name":null,"audio_sink":null,"external_ip":null,
                    "stream_audio":true,"capture":"auto","video_max_batch_size_kb":32,
                    "max_bitrate":null,"minimum_fps_target":20.0,
                    "wgc_pacing_smoothing":true}
            }))
            .unwrap(),
        );

        for (request, revision, update, expected) in [
            (41, 5, FieldUpdate::Omitted, Some(true)),
            (42, 6, FieldUpdate::Value(false), Some(false)),
            (43, 7, FieldUpdate::Null, None),
        ] {
            product
                .enqueue(
                    request,
                    5_000,
                    AdminAction::Update {
                        display_policy: DisplayPolicyUpdate::default(),
                        software_encoder: SoftwareEncoderUpdate::default(),
                        nvenc_settings: NvencSettingsUpdate::default(),
                        hostname: "Host".into(),
                        port: 47_989,
                        address_family: FieldUpdate::Omitted,
                        bind_address: FieldUpdate::Omitted,
                        output_name: FieldUpdate::Omitted,
                        audio_sink: FieldUpdate::Omitted,
                        virtual_sink: FieldUpdate::Omitted,
                        audio_sink_capture_only: FieldUpdate::Omitted,
                        install_steam_audio_drivers: FieldUpdate::Omitted,
                        nvenc_spatial_aq: FieldUpdate::Omitted,
                        external_ip: FieldUpdate::Omitted,
                        stream_audio: FieldUpdate::Omitted,
                        capture: FieldUpdate::Omitted,
                        video_max_batch_size_kb: FieldUpdate::Omitted,
                        max_bitrate: FieldUpdate::Omitted,
                        qp: FieldUpdate::Omitted,
                        fec_percentage: FieldUpdate::Omitted,
                        minimum_fps_target: FieldUpdate::Omitted,
                        wgc_pacing_smoothing: update,
                        ping_timeout_ms: FieldUpdate::Omitted,
                        global_preparation: FieldUpdate::Omitted,
                        legacy_global_preparation: FieldUpdate::Omitted,
                        frame_limiter: FrameLimiterUpdate::default(),
                        encryption_modes: EncryptionModeUpdate::default(),
                        expected_revision: revision,
                        require_listener_apply: false,

                        upnp: FieldUpdate::Omitted,
                    },
                )
                .unwrap();
            product.start_next();
            let pending = product.pending.take().expect("product update request");
            let expected_raw = expected.map_or(Value::Null, |value| json!(value));
            assert_eq!(pending.payload["version"], SETTINGS_VERSION);
            assert_eq!(
                pending.payload["values"]["wgc_pacing_smoothing"],
                expected_raw
            );

            product.finish_call(
                pending.purpose,
                CallOutcome::Payload(v17_update_confirmation(json!({
                    "ok":true,"found":true,"version":16,"revision":revision + 1,
                    "values":{"hostname":"Host","port":47989,"address_family":null,
                        "bind_address":null,"output_name":null,"audio_sink":null,"virtual_sink":null,"external_ip":null,
                        "stream_audio":true,"capture":"auto","video_max_batch_size_kb":32,
                        "max_bitrate":null,"minimum_fps_target":20.0,
                        "wgc_pacing_smoothing":expected_raw,"ping_timeout_ms":null,"audio_sink_capture_only":false,"global_preparation":[]}
                }))),
            );
            assert_eq!(product.configured_wgc_pacing_smoothing(), expected);
            assert_eq!(
                product.effective_wgc_pacing_smoothing(),
                expected.unwrap_or(true)
            );
        }
    }

    #[test]
    fn audio_sink_updates_preserve_omission_reset_empty_and_validate_exact_ids() {
        assert_eq!(
            apply_audio_sink_update(FieldUpdate::Omitted, Some("render.old".into())),
            Ok(Some("render.old".into()))
        );
        assert_eq!(
            apply_audio_sink_update(FieldUpdate::Null, Some("render.old".into())),
            Ok(None)
        );
        assert_eq!(
            apply_audio_sink_update(FieldUpdate::Value(String::new()), Some("render.old".into())),
            Ok(None)
        );
        assert_eq!(
            apply_audio_sink_update(FieldUpdate::Value(" render.exact ".into()), None),
            Ok(Some(" render.exact ".into()))
        );
        assert_eq!(
            normalize_audio_sink(&"é".repeat(2048)),
            Ok(Some("é".repeat(2048)))
        );
        assert_eq!(normalize_audio_sink(&"é".repeat(2049)), Err(()));
        assert_eq!(normalize_audio_sink("render\ninvalid"), Err(()));
    }

    #[test]
    fn audio_sink_capture_only_defaults_false_then_persists_with_revisioned_v17_write() {
        let legacy = json!({
            "ok":true,"found":true,"version":13,"revision":11,
            "values":{
                "hostname":"Host","port":47989,"address_family":null,
                "bind_address":null,"output_name":null,"audio_sink":"render.global",
                "external_ip":null,"stream_audio":true,"capture":"auto",
                "video_max_batch_size_kb":32,"max_bitrate":null,
                "minimum_fps_target":null,"wgc_pacing_smoothing":null,
                "ping_timeout_ms":null
            }
        });
        let mut product = ProductSettings::new("Bootstrap".into(), settings::DEFAULT_PORT);
        product.apply_document(parse_document(&legacy).unwrap());
        assert!(!product.audio_sink_capture_only());

        product
            .enqueue(
                41,
                5_000,
                AdminAction::Update {
                    display_policy: DisplayPolicyUpdate::default(),
                    software_encoder: SoftwareEncoderUpdate::default(),
                    nvenc_settings: NvencSettingsUpdate::default(),
                    hostname: "Host".into(),
                    port: 47_989,
                    address_family: FieldUpdate::Omitted,
                    bind_address: FieldUpdate::Omitted,
                    output_name: FieldUpdate::Omitted,
                    audio_sink: FieldUpdate::Omitted,
                    virtual_sink: FieldUpdate::Omitted,
                    audio_sink_capture_only: FieldUpdate::Value(true),
                    install_steam_audio_drivers: FieldUpdate::Omitted,
                    nvenc_spatial_aq: FieldUpdate::Omitted,
                    external_ip: FieldUpdate::Omitted,
                    stream_audio: FieldUpdate::Omitted,
                    capture: FieldUpdate::Omitted,
                    video_max_batch_size_kb: FieldUpdate::Omitted,
                    max_bitrate: FieldUpdate::Omitted,
                    qp: FieldUpdate::Omitted,
                    fec_percentage: FieldUpdate::Omitted,
                    minimum_fps_target: FieldUpdate::Omitted,
                    wgc_pacing_smoothing: FieldUpdate::Omitted,
                    ping_timeout_ms: FieldUpdate::Omitted,
                    global_preparation: FieldUpdate::Omitted,
                    legacy_global_preparation: FieldUpdate::Omitted,
                    frame_limiter: FrameLimiterUpdate::default(),
                    encryption_modes: EncryptionModeUpdate::default(),
                    expected_revision: 11,
                    require_listener_apply: false,

                    upnp: FieldUpdate::Omitted,
                },
            )
            .unwrap();
        product.start_next();
        let pending = product.pending.take().expect("v17 product update");
        assert_eq!(pending.payload["version"], SETTINGS_VERSION);
        assert_eq!(pending.payload["expected_revision"], 11);
        assert_eq!(pending.payload["values"]["audio_sink_capture_only"], true);
        let response = v17_update_confirmation(json!({
            "ok":true,"found":true,"version":SETTINGS_VERSION,"revision":12,
            "values":pending.payload["values"].clone()
        }));
        product.finish_call(pending.purpose, CallOutcome::Payload(response.clone()));
        assert!(product.audio_sink_capture_only());
        assert_eq!(product.settings_payload()["audio_sink_capture_only"], true);

        let mut restarted = ProductSettings::new("Bootstrap".into(), settings::DEFAULT_PORT);
        restarted.apply_document(parse_document(&response).unwrap());
        assert!(restarted.audio_sink_capture_only());

        let mut invalid = response;
        invalid["values"]["audio_sink_capture_only"] = json!("true");
        assert_eq!(
            parse_document(&invalid).unwrap_err().code,
            "invalid_state_response"
        );
        assert_eq!(apply_boolean_update(FieldUpdate::Omitted, true), Ok(true));
        assert_eq!(apply_boolean_update(FieldUpdate::Null, true), Err(()));
    }

    #[test]
    fn audio_sink_admin_update_persists_and_confirms_the_selected_endpoint() {
        let bootstrap = bootstrap_with_capture_and_audio("display", "render.bootstrap");
        let mut product = ProductSettings::with_bootstrap_settings("Bootstrap".into(), &bootstrap);
        product.apply_document(
            parse_document(&json!({
                "ok":true,"found":true,"version":9,"revision":8,
                "values":{"hostname":"Host","port":47989,"address_family":null,
                    "bind_address":null,"output_name":null,"stream_audio":true,
                    "capture":"auto","video_max_batch_size_kb":32,"max_bitrate":null,
                    "minimum_fps_target":20.0}
            }))
            .unwrap(),
        );
        product
            .enqueue(
                41,
                5_000,
                AdminAction::Update {
                    display_policy: DisplayPolicyUpdate::default(),
                    software_encoder: SoftwareEncoderUpdate::default(),
                    nvenc_settings: NvencSettingsUpdate::default(),
                    hostname: "Host".into(),
                    port: 47_989,
                    address_family: FieldUpdate::Omitted,
                    bind_address: FieldUpdate::Omitted,
                    output_name: FieldUpdate::Omitted,
                    audio_sink: FieldUpdate::Value("render.selected".into()),
                    virtual_sink: FieldUpdate::Omitted,
                    audio_sink_capture_only: FieldUpdate::Omitted,
                    install_steam_audio_drivers: FieldUpdate::Omitted,
                    nvenc_spatial_aq: FieldUpdate::Omitted,
                    external_ip: FieldUpdate::Omitted,
                    stream_audio: FieldUpdate::Omitted,
                    capture: FieldUpdate::Omitted,
                    video_max_batch_size_kb: FieldUpdate::Omitted,
                    max_bitrate: FieldUpdate::Omitted,
                    qp: FieldUpdate::Omitted,
                    fec_percentage: FieldUpdate::Omitted,
                    minimum_fps_target: FieldUpdate::Omitted,
                    wgc_pacing_smoothing: FieldUpdate::Omitted,
                    ping_timeout_ms: FieldUpdate::Omitted,
                    global_preparation: FieldUpdate::Omitted,
                    legacy_global_preparation: FieldUpdate::Omitted,
                    frame_limiter: FrameLimiterUpdate::default(),
                    encryption_modes: EncryptionModeUpdate::default(),
                    expected_revision: 8,
                    require_listener_apply: false,

                    upnp: FieldUpdate::Omitted,
                },
            )
            .unwrap();
        product.start_next();
        let pending = product.pending.take().expect("product update request");
        assert_eq!(pending.payload["version"], SETTINGS_VERSION);
        assert_eq!(pending.payload["values"]["audio_sink"], "render.selected");
        product.finish_call(
            pending.purpose,
            CallOutcome::Payload(v17_update_confirmation(json!({
                "ok":true,"found":true,"version":16,"revision":9,
                "values":{"hostname":"Host","port":47989,"address_family":null,
                    "bind_address":null,"output_name":null,"audio_sink":"render.selected","virtual_sink":null,"external_ip":null,
                    "stream_audio":true,"capture":"auto","video_max_batch_size_kb":32,
                    "max_bitrate":null,"minimum_fps_target":20.0,"wgc_pacing_smoothing":null,"ping_timeout_ms":null,"audio_sink_capture_only":false,"global_preparation":[]}
            }))),
        );

        assert_eq!(product.configured_audio_sink(), Some("render.selected"));
        assert_eq!(product.effective_audio_sink(), "render.selected");
        assert_eq!(
            product.completions.front().unwrap().payload["configured_audio_sink"],
            "render.selected"
        );
    }

    #[test]
    fn minimum_fps_updates_preserve_omission_and_null_resets_to_default() {
        let mut product = ProductSettings::new("Bootstrap".into(), settings::DEFAULT_PORT);
        product.apply_document(
            parse_document(&json!({
                "ok":true,"found":true,"version":9,"revision":4,
                "values":{"hostname":"Host","port":47989,"address_family":null,
                    "bind_address":null,"output_name":null,"stream_audio":true,"capture":"auto",
                    "video_max_batch_size_kb":32,"max_bitrate":null,"minimum_fps_target":23.5}
            }))
            .unwrap(),
        );

        for (request, revision, update, reply_revision, expected_raw) in [
            (31, 4, FieldUpdate::Omitted, 5, json!(23.5)),
            (32, 5, FieldUpdate::Null, 6, Value::Null),
        ] {
            product
                .enqueue(
                    request,
                    5_000,
                    AdminAction::Update {
                        display_policy: DisplayPolicyUpdate::default(),
                        software_encoder: SoftwareEncoderUpdate::default(),
                        nvenc_settings: NvencSettingsUpdate::default(),
                        hostname: "Host".into(),
                        port: 47_989,
                        address_family: FieldUpdate::Omitted,
                        bind_address: FieldUpdate::Omitted,
                        output_name: FieldUpdate::Omitted,
                        audio_sink: FieldUpdate::Omitted,
                        virtual_sink: FieldUpdate::Omitted,
                        audio_sink_capture_only: FieldUpdate::Omitted,
                        install_steam_audio_drivers: FieldUpdate::Omitted,
                        nvenc_spatial_aq: FieldUpdate::Omitted,
                        external_ip: FieldUpdate::Omitted,
                        stream_audio: FieldUpdate::Omitted,
                        capture: FieldUpdate::Omitted,
                        video_max_batch_size_kb: FieldUpdate::Omitted,
                        max_bitrate: FieldUpdate::Omitted,
                        qp: FieldUpdate::Omitted,
                        fec_percentage: FieldUpdate::Omitted,
                        minimum_fps_target: update,
                        wgc_pacing_smoothing: FieldUpdate::Omitted,
                        ping_timeout_ms: FieldUpdate::Omitted,
                        global_preparation: FieldUpdate::Omitted,
                        legacy_global_preparation: FieldUpdate::Omitted,
                        frame_limiter: FrameLimiterUpdate::default(),
                        encryption_modes: EncryptionModeUpdate::default(),
                        expected_revision: revision,
                        require_listener_apply: false,

                        upnp: FieldUpdate::Omitted,
                    },
                )
                .unwrap();
            product.start_next();
            let pending = product.pending.take().expect("product update request");
            assert_eq!(pending.payload["version"], SETTINGS_VERSION);
            assert_eq!(
                pending.payload["values"]["minimum_fps_target"],
                expected_raw
            );
            let persisted_value = if expected_raw.is_null() {
                Value::Null
            } else {
                expected_raw.clone()
            };
            product.finish_call(
                pending.purpose,
                CallOutcome::Payload(v17_update_confirmation(json!({
                    "ok":true,"found":true,"version":16,"revision":reply_revision,
                    "values":{"hostname":"Host","port":47989,"address_family":null,
                        "bind_address":null,"output_name":null,"audio_sink":null,"virtual_sink":null,"external_ip":null,
                        "stream_audio":true,"capture":"auto",
                        "video_max_batch_size_kb":32,"max_bitrate":null,
                        "minimum_fps_target":persisted_value,"wgc_pacing_smoothing":null,"ping_timeout_ms":null,"audio_sink_capture_only":false,"global_preparation":[]}
                }))),
            );
        }

        assert_eq!(product.configured_minimum_fps_target(), None);
        assert_eq!(product.effective_minimum_fps_target(), 20.0);
        assert_eq!(
            product.settings_payload()["configured_minimum_fps_target"],
            Value::Null
        );
    }

    #[test]
    fn max_bitrate_updates_preserve_omission_and_support_signed_value_and_null_reset() {
        let mut product = ProductSettings::new("Bootstrap".into(), settings::DEFAULT_PORT);
        product.apply_document(
            parse_document(&json!({
                "ok":true,"found":true,"version":8,"revision":1,
                "values":{"hostname":"Host","port":47989,"address_family":null,
                    "bind_address":null,"output_name":null,"stream_audio":true,"capture":"auto",
                    "video_max_batch_size_kb":32,"max_bitrate":12000}
            }))
            .unwrap(),
        );

        for (request, revision, update, expected) in [
            (20, 1, FieldUpdate::Omitted, Some(12_000)),
            (21, 2, FieldUpdate::Value(-7), Some(-7)),
            (22, 3, FieldUpdate::Null, None),
        ] {
            product
                .enqueue(
                    request,
                    5_000,
                    AdminAction::Update {
                        display_policy: DisplayPolicyUpdate::default(),
                        software_encoder: SoftwareEncoderUpdate::default(),
                        nvenc_settings: NvencSettingsUpdate::default(),
                        hostname: "Host".into(),
                        port: 47_989,
                        address_family: FieldUpdate::Omitted,
                        bind_address: FieldUpdate::Omitted,
                        output_name: FieldUpdate::Omitted,
                        audio_sink: FieldUpdate::Omitted,
                        virtual_sink: FieldUpdate::Omitted,
                        audio_sink_capture_only: FieldUpdate::Omitted,
                        install_steam_audio_drivers: FieldUpdate::Omitted,
                        nvenc_spatial_aq: FieldUpdate::Omitted,
                        external_ip: FieldUpdate::Omitted,
                        stream_audio: FieldUpdate::Omitted,
                        capture: FieldUpdate::Omitted,
                        video_max_batch_size_kb: FieldUpdate::Omitted,
                        max_bitrate: update,
                        qp: FieldUpdate::Omitted,
                        fec_percentage: FieldUpdate::Omitted,
                        minimum_fps_target: FieldUpdate::Omitted,
                        wgc_pacing_smoothing: FieldUpdate::Omitted,
                        ping_timeout_ms: FieldUpdate::Omitted,
                        global_preparation: FieldUpdate::Omitted,
                        legacy_global_preparation: FieldUpdate::Omitted,
                        frame_limiter: FrameLimiterUpdate::default(),
                        encryption_modes: EncryptionModeUpdate::default(),
                        expected_revision: revision,
                        require_listener_apply: false,

                        upnp: FieldUpdate::Omitted,
                    },
                )
                .unwrap();
            product.start_next();
            let pending = product.pending.take().expect("product update request");
            assert_eq!(pending.payload["version"], SETTINGS_VERSION);
            assert_eq!(
                pending.payload["values"]["max_bitrate"],
                expected.map_or(Value::Null, |value| json!(value))
            );

            let response = v17_update_confirmation(json!({
                "ok":true,"found":true,"version":SETTINGS_VERSION,"revision":revision + 1,
                "values":{"hostname":"Host","port":47989,"address_family":null,
                    "bind_address":null,"output_name":null,"audio_sink":null,"virtual_sink":null,"external_ip":null,
                    "stream_audio":true,"capture":"auto",
                    "video_max_batch_size_kb":32,"max_bitrate":expected,"minimum_fps_target":null,"wgc_pacing_smoothing":null,"ping_timeout_ms":null,"audio_sink_capture_only":false,"global_preparation":[]}
            }));
            product.finish_call(pending.purpose, CallOutcome::Payload(response.clone()));
            assert_eq!(product.configured_max_bitrate(), expected);
            assert_eq!(
                product.effective_max_bitrate_kbps(),
                expected
                    .filter(|value| *value > 0)
                    .map(|value| value as u32)
            );

            let mut restarted = ProductSettings::new("Bootstrap".into(), settings::DEFAULT_PORT);
            restarted.apply_document(parse_document(&response).unwrap());
            assert_eq!(restarted.configured_max_bitrate(), expected);
        }
    }

    #[test]
    fn capture_selection_survives_restart_and_reports_the_resolved_provider() {
        let mut bootstrap = bootstrap_with_capture_output("bootstrap-display-id");
        bootstrap
            .streaming
            .as_mut()
            .expect("test streaming config")
            .capture
            .capture_provider = crate::launch::CaptureProvider::Wgc;
        let selected_document = json!({
            "ok":true,"found":true,"version":6,"revision":3,
            "values":{"hostname":"Host","port":47989,"address_family":null,
                "bind_address":null,"output_name":null,"stream_audio":true,"capture":"wgcc"}
        });

        let mut first_start =
            ProductSettings::with_bootstrap_settings("Bootstrap".into(), &bootstrap);
        first_start.apply_document(parse_document(&selected_document).unwrap());
        assert_eq!(first_start.configured_capture(), CaptureMode::Wgcc);
        assert_eq!(first_start.capture_provider(), Some("wgc"));
        assert_eq!(first_start.settings_payload()["configured_capture"], "wgcc");

        let mut restarted =
            ProductSettings::with_bootstrap_settings("Bootstrap".into(), &bootstrap);
        restarted.apply_document(parse_document(&selected_document).unwrap());
        assert_eq!(restarted.configured_capture(), CaptureMode::Wgcc);
        assert_eq!(restarted.capture_provider(), Some("wgc"));
    }

    #[test]
    fn each_capture_mode_resolves_to_its_effective_provider() {
        let bootstrap = bootstrap_with_capture_output("bootstrap-display-id");
        for (mode, provider) in [
            (CaptureMode::Auto, "dxgi"),
            (CaptureMode::Ddx, "dxgi"),
            (CaptureMode::Wgc, "wgc"),
            (CaptureMode::Wgcc, "wgc"),
            (CaptureMode::X11, "x11"),
            (CaptureMode::Kms, "kms"),
        ] {
            let document = json!({
                "ok":true,"found":true,"version":6,"revision":3,
                "values":{"hostname":"Host","port":47989,"address_family":null,
                    "bind_address":null,"output_name":null,"stream_audio":true,
                    "capture":mode.as_str()}
            });
            let mut settings =
                ProductSettings::with_bootstrap_settings("Bootstrap".into(), &bootstrap);
            settings.apply_document(parse_document(&document).unwrap());
            assert_eq!(settings.capture_provider(), Some(provider), "{mode:?}");
        }
    }

    #[test]
    fn automatic_capture_reports_pipewire_bootstrap_provider() {
        let mut bootstrap = bootstrap_with_capture_output("portal-selected-session-source");
        bootstrap
            .streaming
            .as_mut()
            .expect("test streaming config")
            .capture
            .capture_provider = crate::launch::CaptureProvider::PipeWire;
        let settings = ProductSettings::with_bootstrap_settings("Bootstrap".into(), &bootstrap);

        assert_eq!(settings.capture_provider(), Some("pipewire"));
    }

    #[test]
    fn v4_output_selection_survives_restart_and_null_uses_bootstrap_output() {
        let bootstrap = bootstrap_with_capture_output("bootstrap-display-id");
        let selected_document = json!({
            "ok":true,"found":true,"version":4,"revision":11,
            "values":{"hostname":"Host","port":47989,"address_family":null,"bind_address":null,"output_name":"selected-display-id"}
        });
        let mut first_start =
            ProductSettings::with_bootstrap_settings("Bootstrap".into(), &bootstrap);
        first_start.apply_document(parse_document(&selected_document).unwrap());
        assert_eq!(
            first_start.configured_output_name(),
            Some("selected-display-id")
        );
        assert_eq!(
            first_start.effective_output_name(),
            Some("selected-display-id")
        );
        assert_eq!(first_start.settings_payload()["capture_provider"], "dxgi");
        assert_eq!(
            first_start.settings_payload()["configured_output_name"],
            "selected-display-id"
        );
        assert_eq!(
            first_start.settings_payload()["effective_output_name"],
            "selected-display-id"
        );

        let mut restarted =
            ProductSettings::with_bootstrap_settings("Bootstrap".into(), &bootstrap);
        restarted.apply_document(parse_document(&selected_document).unwrap());
        assert_eq!(
            restarted.effective_output_name(),
            Some("selected-display-id")
        );

        let automatic_document = json!({
            "ok":true,"found":true,"version":4,"revision":12,
            "values":{"hostname":"Host","port":47989,"address_family":null,"bind_address":null,"output_name":null}
        });
        restarted.apply_document(parse_document(&automatic_document).unwrap());
        assert_eq!(restarted.configured_output_name(), None);
        assert_eq!(
            restarted.effective_output_name(),
            Some("bootstrap-display-id")
        );
        assert_eq!(
            restarted.settings_payload()["effective_output_name"],
            "bootstrap-display-id"
        );
    }

    #[test]
    fn rejects_unsupported_or_malformed_persisted_settings() {
        for payload in [
            json!({"ok":true,"found":true,"version":3,"revision":1,"values":{"hostname":"Host","port":47989}}),
            json!({"ok":true,"found":true,"version":1,"revision":1,"values":{"hostname":"Host","extra":true}}),
            json!({"ok":true,"found":true,"version":2,"revision":1,"values":{"hostname":"Host"}}),
            json!({"ok":true,"found":true,"version":2,"revision":1,"values":{"hostname":"Host","port":1028}}),
            json!({"ok":true,"found":false,"version":null,"revision":1,"values":{}}),
        ] {
            assert_eq!(
                parse_document(&payload).unwrap_err().code,
                "invalid_state_response"
            );
        }
    }

    #[test]
    fn update_reply_must_confirm_the_requested_revision_and_hostname() {
        let success = v17_update_confirmation(json!({
            "ok":true,"found":true,"version":16,"revision":4,
            "values":{"hostname":"New Host","port":48000,"address_family":null,"bind_address":null,"output_name":null,"audio_sink":null,"virtual_sink":null,"external_ip":null,"stream_audio":true,"capture":"auto","video_max_batch_size_kb":null,"max_bitrate":null,"minimum_fps_target":null,"wgc_pacing_smoothing":null,"ping_timeout_ms":null,"audio_sink_capture_only":false,"global_preparation":[]}
        }));
        let target = NetworkTarget {
            port: 48_000,
            address_family: None,
            bind_address: None,
        };
        let default_frame_limiter = FrameLimiterSettings::default();
        let expected_display_policy = empty_display_policy();
        let expected = UpdateExpectation {
            display_policy: &expected_display_policy,
            software_encoder: &SoftwareEncoderOptions::default(),
            nvenc_settings: &NvencSettings::default(),
            revision: 3,
            hostname: "New Host",
            target: &target,
            output_name: None,
            audio_sink: None,
            virtual_sink: None,
            audio_sink_capture_only: false,
            install_steam_audio_drivers: true,
            nvenc_spatial_aq: false,
            external_ip: None,
            stream_audio: true,
            capture: CaptureMode::Auto,
            video_max_batch_size_kb: None,
            max_bitrate: None,
            qp: None,
            fec_percentage: None,
            minimum_fps_target: None,
            wgc_pacing_smoothing: None,
            ping_timeout_ms: None,
            global_preparation: &[],
            legacy_global_preparation: &[],
            frame_limiter: &default_frame_limiter,
            lan_encryption_mode: DEFAULT_LAN_ENCRYPTION_MODE,
            wan_encryption_mode: DEFAULT_WAN_ENCRYPTION_MODE,

            upnp: false,
        };
        assert_eq!(update_result(&success, &expected).unwrap().revision, 4);
        assert_eq!(
            update_result(
                &success,
                &UpdateExpectation {
                    revision: 2,
                    ..expected
                }
            )
            .unwrap_err()
            .code,
            "invalid_state_response"
        );
        assert_eq!(
            update_result(
                &success,
                &UpdateExpectation {
                    hostname: "Other Host",
                    ..expected
                }
            )
            .unwrap_err()
            .code,
            "invalid_state_response"
        );
        assert_eq!(
            update_result(
                &success,
                &UpdateExpectation {
                    target: &NetworkTarget {
                        port: 48_001,
                        ..target.clone()
                    },
                    ..expected
                }
            )
            .unwrap_err()
            .code,
            "invalid_state_response"
        );

        let reset_to_machine_name = v17_update_confirmation(json!({
            "ok":true,"found":true,"version":16,"revision":5,
            "values":{"hostname":"","port":48000,"address_family":null,"bind_address":null,"output_name":null,"audio_sink":null,"virtual_sink":null,"external_ip":null,"stream_audio":true,"capture":"auto","video_max_batch_size_kb":null,"max_bitrate":null,"minimum_fps_target":null,"wgc_pacing_smoothing":null,"ping_timeout_ms":null,"audio_sink_capture_only":false,"global_preparation":[]}
        }));
        assert_eq!(
            update_result(
                &reset_to_machine_name,
                &UpdateExpectation {
                    revision: 4,
                    hostname: "",
                    ..expected
                }
            )
            .unwrap()
            .hostname
            .as_deref(),
            Some("")
        );

        let selected = v17_update_confirmation(json!({
            "ok":true,"found":true,"version":16,"revision":9,
            "values":{"hostname":"New Host","port":48000,"address_family":null,"bind_address":null,"output_name":"selected-display-id","audio_sink":null,"virtual_sink":null,"external_ip":null,"stream_audio":true,"capture":"auto","video_max_batch_size_kb":null,"max_bitrate":null,"minimum_fps_target":null,"wgc_pacing_smoothing":null,"ping_timeout_ms":null,"audio_sink_capture_only":false,"global_preparation":[]}
        }));
        assert_eq!(
            update_result(
                &selected,
                &UpdateExpectation {
                    revision: 8,
                    output_name: Some("selected-display-id"),
                    ..expected
                }
            )
            .unwrap()
            .output_name
            .as_deref(),
            Some("selected-display-id")
        );
        assert_eq!(
            update_result(
                &selected,
                &UpdateExpectation {
                    revision: 8,
                    ..expected
                }
            )
            .unwrap_err()
            .code,
            "invalid_state_response"
        );
    }

    #[test]
    fn v16_migration_defaults_new_fields_and_preserves_structured_preparation() {
        let structured: PreparationStep = serde_json::from_value(json!({
            "run":{"executable":std::env::current_exe().unwrap(),"args":["keep-me"]}
        }))
        .unwrap();
        let version_16 = json!({
            "ok":true,"found":true,"version":16,"revision":7,
            "values":{"hostname":"Host","port":47989,"address_family":null,
                "bind_address":null,"output_name":null,"audio_sink":null,"virtual_sink":null,
                "audio_sink_capture_only":false,"external_ip":null,"stream_audio":true,
                "capture":"auto","video_max_batch_size_kb":null,"max_bitrate":null,
                "minimum_fps_target":null,"wgc_pacing_smoothing":null,"ping_timeout_ms":null,
                "global_preparation":[structured]}
        });
        let migrated_document = parse_document(&version_16).unwrap();
        assert!(!migrated_document.nvenc_spatial_aq);
        assert_eq!(
            migrated_document.global_preparation.as_slice(),
            std::slice::from_ref(&structured)
        );
        assert!(migrated_document.legacy_global_preparation.is_empty());
        assert_eq!(
            migrated_document.frame_limiter,
            FrameLimiterSettings::default()
        );
        assert_eq!(
            migrated_document.lan_encryption_mode,
            DEFAULT_LAN_ENCRYPTION_MODE
        );
        assert_eq!(
            migrated_document.wan_encryption_mode,
            DEFAULT_WAN_ENCRYPTION_MODE
        );

        let mut product = ProductSettings::new("Bootstrap".into(), settings::DEFAULT_PORT);
        product.apply_document(migrated_document);
        assert_eq!(
            product.global_preparation(),
            std::slice::from_ref(&structured)
        );
        assert_eq!(product.legacy_global_preparation(), []);
        assert_eq!(
            product.settings_payload()["effective_frame_limiter"]["frame_limiter_fps_limit_millihz"],
            0
        );

        let update = product_update_payload(
            7,
            "Host",
            &NetworkTarget {
                port: 47_989,
                address_family: None,
                bind_address: None,
            },
            None,
            ProductStreamingSettings {
                display_policy: empty_display_policy(),
                audio_sink: None,
                virtual_sink: None,
                audio_sink_capture_only: false,
                install_steam_audio_drivers: true,
                nvenc_spatial_aq: product.nvenc_spatial_aq,
                external_ip: None,
                stream_audio: true,
                capture: CaptureMode::Auto,
                video_max_batch_size_kb: None,
                max_bitrate: None,
                qp: None,
                fec_percentage: None,
                minimum_fps_target: None,
                wgc_pacing_smoothing: None,
                software_encoder: SoftwareEncoderOptions::default(),
                nvenc_settings: NvencSettings::default(),
                ping_timeout_ms: None,
                global_preparation: product.global_preparation().to_vec(),
                legacy_global_preparation: product.legacy_global_preparation().to_vec(),
                frame_limiter: product.configured_frame_limiter().clone(),
                lan_encryption_mode: product.lan_encryption_mode(),
                wan_encryption_mode: product.wan_encryption_mode(),

                upnp: false,
            },
        );
        assert_eq!(update["version"], SETTINGS_VERSION);
        assert_eq!(update["values"].as_object().unwrap().len(), 79);
        assert_eq!(update["values"]["nvenc_spatial_aq"], false);
        assert_eq!(
            update["values"]["global_preparation"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        assert_eq!(update["values"]["legacy_global_preparation"], json!([]));
        assert_eq!(update["values"]["frame_limiter_fps_limit"], Value::Null);
    }

    #[test]
    fn v17_roundtrip_preserves_raw_commands_frame_zero_and_explicit_false() {
        let structured: PreparationStep = serde_json::from_value(json!({
            "run":{"executable":std::env::current_exe().unwrap(),"args":["structured"]}
        }))
        .unwrap();
        let raw: LegacyPreparationStep = serde_json::from_value(json!({
            "do":"  echo $(DISPLAY)  ","undo":"restore $HOME","elevated":true
        }))
        .unwrap();
        let frame_limiter = FrameLimiterSettings {
            frame_limiter_enable: Some(false),
            frame_limiter_fps_limit: Some(0.0),
            frame_limiter_provider: Some("none".into()),
            ..FrameLimiterSettings::default()
        };
        let payload = product_update_payload(
            9,
            "Host",
            &NetworkTarget {
                port: 47_989,
                address_family: None,
                bind_address: None,
            },
            None,
            ProductStreamingSettings {
                display_policy: empty_display_policy(),
                audio_sink: None,
                virtual_sink: None,
                audio_sink_capture_only: false,
                install_steam_audio_drivers: true,
                nvenc_spatial_aq: true,
                external_ip: None,
                stream_audio: true,
                capture: CaptureMode::Auto,
                video_max_batch_size_kb: None,
                max_bitrate: None,
                qp: None,
                fec_percentage: None,
                minimum_fps_target: None,
                wgc_pacing_smoothing: None,
                software_encoder: SoftwareEncoderOptions::default(),
                nvenc_settings: NvencSettings::default(),
                ping_timeout_ms: None,
                global_preparation: vec![structured.clone()],
                legacy_global_preparation: vec![raw.clone()],
                frame_limiter: frame_limiter.clone(),
                lan_encryption_mode: 2,
                wan_encryption_mode: 0,

                upnp: false,
            },
        );
        let reply = v17_update_confirmation(json!({
            "ok":true,"found":true,"version":SETTINGS_VERSION,"revision":10,
            "values":payload["values"].clone()
        }));
        let document = parse_document(&reply).unwrap();
        assert!(document.nvenc_spatial_aq);
        assert_eq!(
            document.global_preparation.as_slice(),
            std::slice::from_ref(&structured)
        );
        assert_eq!(
            document.legacy_global_preparation.as_slice(),
            std::slice::from_ref(&raw)
        );
        assert_eq!(document.frame_limiter, frame_limiter);
        assert_eq!(document.lan_encryption_mode, 2);
        assert_eq!(document.wan_encryption_mode, 0);
        for (name, invalid_mode) in [
            ("lan_encryption_mode", json!(3)),
            ("wan_encryption_mode", json!(-1)),
            ("lan_encryption_mode", json!("2")),
        ] {
            let mut invalid_reply = reply.clone();
            invalid_reply["values"][name] = invalid_mode;
            assert_eq!(
                parse_document(&invalid_reply).unwrap_err().code,
                "invalid_state_response"
            );
        }

        let mut restarted = ProductSettings::new("Bootstrap".into(), settings::DEFAULT_PORT);
        restarted.apply_document(parse_document(&reply).unwrap());
        assert_eq!(restarted.global_preparation(), [structured]);
        assert_eq!(restarted.legacy_global_preparation(), [raw]);
        assert_eq!(restarted.configured_frame_limiter(), &frame_limiter);
        assert_eq!(restarted.lan_encryption_mode(), 2);
        assert_eq!(restarted.wan_encryption_mode(), 0);
        let readback = restarted.settings_payload();
        assert_eq!(readback["nvenc_spatial_aq"], true);
        assert_eq!(
            readback["configured_legacy_global_preparation"][0]["do"],
            "  echo $(DISPLAY)  "
        );
        assert_eq!(
            readback["configured_frame_limiter"]["frame_limiter_enable"],
            false
        );
        assert_eq!(
            readback["configured_frame_limiter"]["frame_limiter_fps_limit"],
            0.0
        );

        let mut old_v17 = reply.clone();
        old_v17["version"] = json!(GLOBAL_RAW_PREPARATION_SETTINGS_VERSION);
        remove_nvenc_settings(&mut old_v17);
        old_v17["values"].as_object_mut().unwrap().remove("upnp");
        for key in ["sw_preset", "sw_tune", "encoder", "min_threads", "qp"] {
            old_v17["values"].as_object_mut().unwrap().remove(key);
        }
        for key in DISPLAY_POLICY_KEYS {
            old_v17["values"].as_object_mut().unwrap().remove(key);
        }
        old_v17["values"]
            .as_object_mut()
            .unwrap()
            .remove("nvenc_spatial_aq");
        old_v17["values"]
            .as_object_mut()
            .unwrap()
            .remove("fec_percentage");
        old_v17["values"]
            .as_object_mut()
            .unwrap()
            .remove("install_steam_audio_drivers");
        let old_v17_document = parse_document(&old_v17).unwrap();
        assert!(!old_v17_document.nvenc_spatial_aq);
        let mut old_v17_restart = ProductSettings::new("Bootstrap".into(), settings::DEFAULT_PORT);
        old_v17_restart.apply_document(old_v17_document);
        assert_eq!(
            old_v17_restart.settings_payload()["nvenc_spatial_aq"],
            false
        );
    }

    #[test]
    fn nvenc_spatial_aq_update_preserves_omission_resets_null_and_rejects_other_types() {
        let current = true;
        assert!(apply_nvenc_spatial_aq_update(
            parse_nvenc_spatial_aq_update(None).unwrap(),
            current
        ),);
        assert!(!apply_nvenc_spatial_aq_update(
            parse_nvenc_spatial_aq_update(Some(&Value::Null)).unwrap(),
            current,
        ));
        for value in [json!(false), json!(true)] {
            let update = parse_nvenc_spatial_aq_update(Some(&value)).unwrap();
            assert_eq!(
                apply_nvenc_spatial_aq_update(update, current),
                value.as_bool().unwrap()
            );
        }
        for invalid in [json!(0), json!("true"), json!([]), json!({})] {
            assert!(parse_nvenc_spatial_aq_update(Some(&invalid)).is_err());
        }

        let persisted_value = apply_nvenc_spatial_aq_update(
            parse_nvenc_spatial_aq_update(Some(&Value::Null)).unwrap(),
            current,
        );
        let write = product_update_payload(
            4,
            "Host",
            &NetworkTarget::from(settings::DEFAULT_PORT),
            None,
            ProductStreamingSettings {
                display_policy: empty_display_policy(),
                audio_sink: None,
                virtual_sink: None,
                audio_sink_capture_only: false,
                install_steam_audio_drivers: true,
                nvenc_spatial_aq: persisted_value,
                external_ip: None,
                stream_audio: true,
                capture: CaptureMode::Auto,
                video_max_batch_size_kb: None,
                max_bitrate: None,
                qp: None,
                fec_percentage: None,
                minimum_fps_target: None,
                wgc_pacing_smoothing: None,
                software_encoder: SoftwareEncoderOptions::default(),
                nvenc_settings: NvencSettings::default(),
                ping_timeout_ms: None,
                global_preparation: Vec::new(),
                legacy_global_preparation: Vec::new(),
                frame_limiter: FrameLimiterSettings::default(),
                lan_encryption_mode: DEFAULT_LAN_ENCRYPTION_MODE,
                wan_encryption_mode: DEFAULT_WAN_ENCRYPTION_MODE,

                upnp: false,
            },
        );
        assert_eq!(write["values"]["nvenc_spatial_aq"], false);
        let persisted = json!({
            "ok":true,"found":true,"version":SETTINGS_VERSION,"revision":5,
            "values":write["values"].clone()
        });
        let mut restarted = ProductSettings::new("Bootstrap".into(), settings::DEFAULT_PORT);
        restarted.apply_document(parse_document(&persisted).unwrap());
        assert_eq!(restarted.settings_payload()["nvenc_spatial_aq"], false);
    }

    #[test]
    fn encryption_mode_admin_update_persists_and_returns_flat_readback() {
        let target = NetworkTarget::from(settings::DEFAULT_PORT);
        let initial_update = product_update_payload(
            4,
            "Host",
            &target,
            None,
            ProductStreamingSettings {
                display_policy: empty_display_policy(),
                audio_sink: None,
                virtual_sink: None,
                audio_sink_capture_only: false,
                install_steam_audio_drivers: true,
                nvenc_spatial_aq: true,
                external_ip: None,
                stream_audio: true,
                capture: CaptureMode::Auto,
                video_max_batch_size_kb: None,
                max_bitrate: None,
                qp: None,
                fec_percentage: None,
                minimum_fps_target: None,
                wgc_pacing_smoothing: None,
                software_encoder: SoftwareEncoderOptions::default(),
                nvenc_settings: NvencSettings::default(),
                ping_timeout_ms: None,
                global_preparation: Vec::new(),
                legacy_global_preparation: Vec::new(),
                frame_limiter: FrameLimiterSettings::default(),
                lan_encryption_mode: DEFAULT_LAN_ENCRYPTION_MODE,
                wan_encryption_mode: DEFAULT_WAN_ENCRYPTION_MODE,

                upnp: false,
            },
        );
        let initial_document = parse_document(&json!({
            "ok":true,
            "found":true,
            "version":SETTINGS_VERSION,
            "revision":4,
            "values":initial_update["values"].clone()
        }))
        .unwrap();
        let mut product = ProductSettings::new("Bootstrap".into(), settings::DEFAULT_PORT);
        product.apply_document(initial_document);
        product
            .enqueue(
                71,
                5_000,
                AdminAction::Update {
                    display_policy: DisplayPolicyUpdate::default(),
                    software_encoder: SoftwareEncoderUpdate::default(),
                    nvenc_settings: NvencSettingsUpdate::default(),
                    hostname: "Host".into(),
                    port: settings::DEFAULT_PORT,
                    address_family: FieldUpdate::Omitted,
                    bind_address: FieldUpdate::Omitted,
                    output_name: FieldUpdate::Omitted,
                    audio_sink: FieldUpdate::Omitted,
                    virtual_sink: FieldUpdate::Omitted,
                    audio_sink_capture_only: FieldUpdate::Omitted,
                    install_steam_audio_drivers: FieldUpdate::Omitted,
                    nvenc_spatial_aq: FieldUpdate::Omitted,
                    external_ip: FieldUpdate::Omitted,
                    stream_audio: FieldUpdate::Omitted,
                    capture: FieldUpdate::Omitted,
                    video_max_batch_size_kb: FieldUpdate::Omitted,
                    max_bitrate: FieldUpdate::Omitted,
                    qp: FieldUpdate::Omitted,
                    fec_percentage: FieldUpdate::Omitted,
                    minimum_fps_target: FieldUpdate::Omitted,
                    wgc_pacing_smoothing: FieldUpdate::Omitted,
                    ping_timeout_ms: FieldUpdate::Omitted,
                    global_preparation: FieldUpdate::Omitted,
                    legacy_global_preparation: FieldUpdate::Omitted,
                    frame_limiter: FrameLimiterUpdate::default(),
                    encryption_modes: EncryptionModeUpdate {
                        lan_encryption_mode: FieldUpdate::Value(2),
                        wan_encryption_mode: FieldUpdate::Null,
                    },
                    expected_revision: 4,
                    require_listener_apply: false,

                    upnp: FieldUpdate::Omitted,
                },
            )
            .unwrap();
        product.start_next();

        let pending = product.pending.take().expect("product update request");
        assert_eq!(pending.payload["version"], SETTINGS_VERSION);
        assert_eq!(pending.payload["values"]["lan_encryption_mode"], 2);
        assert_eq!(pending.payload["values"]["wan_encryption_mode"], 1);
        assert_eq!(pending.payload["values"]["nvenc_spatial_aq"], true);
        let confirmation = v17_update_confirmation(json!({
            "ok":true,
            "found":true,
            "version":SETTINGS_VERSION,
            "revision":5,
            "values":pending.payload["values"].clone()
        }));
        product.finish_call(pending.purpose, CallOutcome::Payload(confirmation));

        let readback = &product
            .completions
            .front()
            .expect("settings response")
            .payload;
        assert_eq!(readback["lan_encryption_mode"], 2);
        assert_eq!(readback["wan_encryption_mode"], 1);
        assert_eq!(readback["nvenc_spatial_aq"], true);
        assert_eq!(readback["revision"], 5);
    }

    #[test]
    fn frame_limiter_alias_normalizes_and_rejects_conflicting_values() {
        let current = FrameLimiterSettings::default();
        let alias = apply_frame_limiter_update(
            FrameLimiterUpdate {
                rtss_disable_vsync_ullm: FieldUpdate::Value(false),
                ..FrameLimiterUpdate::default()
            },
            current.clone(),
        );
        #[cfg(windows)]
        assert_eq!(alias.unwrap().frame_limiter_disable_vsync, Some(false));
        #[cfg(not(windows))]
        assert_eq!(alias, Err("unsupported_frame_limiter_setting"));

        let same_values = apply_frame_limiter_update(
            FrameLimiterUpdate {
                frame_limiter_disable_vsync: FieldUpdate::Value(true),
                rtss_disable_vsync_ullm: FieldUpdate::Value(true),
                ..FrameLimiterUpdate::default()
            },
            current.clone(),
        );
        #[cfg(windows)]
        assert_eq!(same_values.unwrap().frame_limiter_disable_vsync, Some(true));
        #[cfg(not(windows))]
        assert_eq!(same_values, Err("unsupported_frame_limiter_setting"));

        let conflict = apply_frame_limiter_update(
            FrameLimiterUpdate {
                frame_limiter_disable_vsync: FieldUpdate::Value(true),
                rtss_disable_vsync_ullm: FieldUpdate::Value(false),
                ..FrameLimiterUpdate::default()
            },
            current,
        );
        assert_eq!(
            conflict,
            Err("conflicting_frame_limiter_disable_vsync_alias")
        );
    }

    #[test]
    fn bootstrap_hostname_remains_visible_until_a_readback_succeeds() {
        let settings = ProductSettings::new("Bootstrap".into(), settings::DEFAULT_PORT);
        assert_eq!(settings.hostname(), "Bootstrap");
        assert_eq!(settings.configured_hostname(), "");
        assert_eq!(settings.port(), settings::DEFAULT_PORT);
        assert_eq!(settings.revision(), None);
        assert!(!settings.loaded);
    }

    #[test]
    fn empty_stored_name_uses_bootstrap_but_remains_configured_as_empty() {
        let mut settings = ProductSettings::new("Computer Name".into(), settings::DEFAULT_PORT);
        let document = parse_document(&json!({
            "ok":true,"found":true,"version":1,"revision":3,"values":{"hostname":""}
        }))
        .unwrap();
        settings.apply_document(document);

        assert_eq!(settings.hostname(), "Computer Name");
        assert_eq!(settings.configured_hostname(), "");
        assert_eq!(settings.settings_payload(), {
            let mut expected_payload = serde_json::Map::new();
            for fragment in [
                json!({
                    "ok":true,
                    "hostname":"Computer Name",
                    "configured_hostname":"",
                    "port":47989,
                    "upnp":false,
                    "upnp_status":"disabled",
                    "upnp_error":null,
                }),
                json!({
                    "https_port":47984,
                    "address_family":"ipv4",
                    "bind_address":"127.0.0.1",
                    "configured_address_family":null,
                }),
                json!({
                    "configured_bind_address":null,
                    "configured_output_name":null,
                    "configured_audio_sink":null,
                    "configured_virtual_sink":null,
                    "install_steam_audio_drivers":true,
                    "nvenc_spatial_aq":false,
                    "configured_qp":null,
                    "effective_qp":28,
                    "configured_fec_percentage":null,
                    "effective_fec_percentage":20,
                }),
                json!({
                    "configured_global_preparation":[],
                    "configured_legacy_global_preparation":[],
                    "configured_frame_limiter":{
                        "frame_limiter_enable":null,
                        "frame_limiter_fps_limit":null,
                        "frame_limiter_provider":null,
                        "frame_limiter_disable_vsync":null,
                        "frame_limiter_auto_virtual_framegen":null,
                        "rtss_frame_limit_type":null,
                        "rtss_allow_virtual_display_override":null,
                        "rtss_install_path":null,
                        "mangohud_limiter_method":null,
                        "mangohud_preset":null,
                        "mangohud_always_show_graph":null,
                    },
                    "effective_frame_limiter":{
                        "frame_limiter_enable":false,
                        "frame_limiter_fps_limit_millihz":0,
                        "frame_limiter_provider":"auto",
                        "frame_limiter_disable_vsync":false,
                        "frame_limiter_auto_virtual_framegen":"enabled",
                        "rtss_frame_limit_type":"async",
                        "rtss_allow_virtual_display_override":false,
                        "rtss_install_path":"",
                        "mangohud_limiter_method":"late",
                        "mangohud_preset":"custom",
                        "mangohud_always_show_graph":false,
                    },
                }),
                json!({
                    "configured_display_policy":{},
                    "display_policy_revision":3,
                }),
                json!({
                    "lan_encryption_mode":DEFAULT_LAN_ENCRYPTION_MODE,
                    "wan_encryption_mode":DEFAULT_WAN_ENCRYPTION_MODE,
                    "audio_sink_capture_only":false,
                    "configured_external_ip":null,
                }),
                json!({
                    "effective_audio_sink":"",
                    "configured_capture":"auto",
                    "configured_video_max_batch_size_kb":null,
                    "effective_video_max_batch_size_kb":64,
                }),
                json!({
                    "video_batch_size_fallback":false,
                    "configured_max_bitrate":null,
                    "effective_max_bitrate_kbps":null,
                    "configured_minimum_fps_target":null,
                }),
                json!({
                    "effective_minimum_fps_target":20.0,
                    "configured_wgc_pacing_smoothing":null,
                    "configured_sw_preset":null,"configured_sw_tune":null,"configured_encoder":null,
                    "effective_sw_preset":"superfast","effective_sw_tune":"zerolatency",
                    "configured_min_threads":null,"effective_min_threads":2,
                    "configured_nvenc_preset":1,
                    "configured_nvenc_h264_cavlc":false,
                    "configured_nvenc_twopass":"quarter_res",
                    "configured_nvenc_vbv_increase":0,
                    "configured_nvenc_split_encode":"auto",
                    "configured_nvenc_realtime_hags":true,
                    "configured_nvenc_opengl_vulkan_on_dxgi":true,
                    "configured_nvenc_latency_over_power":true,
                    "configured_vaapi_strict_rc_buffer":false,
                    "effective_wgc_pacing_smoothing":true,
                    "configured_ping_timeout_ms":null,
                }),
                json!({
                    "effective_ping_timeout_ms":10000,
                    "stream_audio":true,
                    "effective_output_name":null,
                    "capture_provider":null,
                }),
                json!({
                    "active_http_port":null,
                    "active_https_port":null,
                    "http_addresses":null,
                    "https_addresses":null,
                }),
                json!({
                    "listener_error":null,
                    "active_rtsp_port":null,
                    "rtsp_addresses":null,
                    "rtsp_listener_error":null,
                }),
                json!({"revision":3}),
            ] {
                let Value::Object(fields) = fragment else {
                    unreachable!("expected product settings fragments are objects");
                };
                expected_payload.extend(fields);
            }
            Value::Object(expected_payload)
        });
    }

    #[test]
    fn configured_hostname_is_preserved_exactly_in_effective_and_admin_values() {
        let configured = "  Living Room & Games  ";
        let mut settings = ProductSettings::new("Computer Name".into(), settings::DEFAULT_PORT);
        let document = parse_document(&json!({
            "ok":true,"found":true,"version":1,"revision":4,"values":{"hostname":configured}
        }))
        .unwrap();
        settings.apply_document(document);

        assert_eq!(settings.hostname(), configured);
        assert_eq!(settings.configured_hostname(), configured);
        assert_eq!(
            settings.settings_payload()["configured_hostname"],
            configured
        );
    }

    #[test]
    fn legacy_document_keeps_bootstrap_port_and_v2_port_is_applied() {
        let mut settings = ProductSettings::new("Computer Name".into(), 48_100);
        let legacy = parse_document(&json!({
            "ok":true,"found":true,"version":1,"revision":2,"values":{"hostname":"Old Host"}
        }))
        .unwrap();
        settings.apply_document(legacy);
        assert_eq!(settings.port(), 48_100);
        assert!(!settings.port_needs_application());

        let current = parse_document(&json!({
            "ok":true,"found":true,"version":2,"revision":3,"values":{"hostname":"Old Host","port":48000}
        }))
        .unwrap();
        settings.apply_document(current);
        assert_eq!(settings.port(), 48_000);
        assert!(settings.port_needs_application());

        settings.set_active_ports(Some(48_000), Some(47_995));
        assert!(!settings.port_needs_application());
        assert_eq!(settings.settings_payload()["https_port"], 47_995);
        assert_eq!(settings.settings_payload()["active_http_port"], 48_000);
    }

    #[test]
    fn disabled_nvhttp_persists_a_port_but_never_claims_it_is_active() {
        let mut settings = ProductSettings::new("Computer Name".into(), settings::DEFAULT_PORT);
        settings.apply_document(
            parse_document(&json!({
                "ok":true,"found":true,"version":1,"revision":1,"values":{"hostname":"Old Host"}
            }))
            .unwrap(),
        );
        assert!(!crate::should_attempt_listener_rebind(None, &settings));

        settings.finish_call(
            Purpose::Update(Box::new(UpdatePurpose {
                display_policy: empty_display_policy(),
                request: 12,
                hostname: "New Host".into(),
                target: NetworkTarget {
                    port: 48_000,
                    address_family: None,
                    bind_address: None,
                },
                output_name: None,
                audio_sink: None,
                virtual_sink: None,
                audio_sink_capture_only: false,
            install_steam_audio_drivers: true,
                nvenc_spatial_aq: false,
                external_ip: None,
                stream_audio: true,
                capture: CaptureMode::Auto,
                video_max_batch_size_kb: None,
                max_bitrate: None,
                qp: None,
                fec_percentage: None,
                minimum_fps_target: None,
                wgc_pacing_smoothing: None,
                software_encoder: SoftwareEncoderOptions::default(),
            nvenc_settings: NvencSettings::default(),
                ping_timeout_ms: None,
                global_preparation: Vec::new(),
                legacy_global_preparation: Vec::new(),
                frame_limiter: FrameLimiterSettings::default(),
                lan_encryption_mode: DEFAULT_LAN_ENCRYPTION_MODE,
                wan_encryption_mode: DEFAULT_WAN_ENCRYPTION_MODE,
                expected_revision: 1,
                require_listener_apply: false,

                upnp: false,})),
            CallOutcome::Payload(v17_update_confirmation(json!({
                "ok":true,
                "found":true,
                "version":16,
                "revision":2,
                "values":{"hostname":"New Host","port":48000,"address_family":null,"bind_address":null,"output_name":null,"audio_sink":null,"virtual_sink":null,"external_ip":null,"stream_audio":true,"capture":"auto","video_max_batch_size_kb":null,"max_bitrate":null,"minimum_fps_target":null,"wgc_pacing_smoothing":null,"ping_timeout_ms":null,"audio_sink_capture_only":false,"global_preparation":[]}
            }))),
        );

        assert_eq!(settings.port(), 48_000);
        assert!(settings.port_needs_application());
        assert!(!crate::should_attempt_listener_rebind(None, &settings));
        let completion = settings.completions.front().unwrap();
        assert_eq!(completion.payload["ok"], false);
        assert_eq!(completion.payload["code"], "listener_not_active");
        assert_eq!(completion.payload["persisted"], true);
    }

    #[test]
    fn hostname_only_update_succeeds_without_waiting_for_rtsp_port_activation() {
        let mut settings = ProductSettings::new("Computer Name".into(), settings::DEFAULT_PORT);
        settings.apply_document(
            parse_document(&json!({
                "ok":true,"found":true,"version":2,"revision":1,
                "values":{"hostname":"Old Host","port":47989}
            }))
            .unwrap(),
        );
        let http_target = settings.http_target();
        let rtsp_target = settings.rtsp_target();
        settings.set_active_http_state(
            Some(http_target),
            Some(vec!["127.0.0.1:47989".into()]),
            Some(vec!["127.0.0.1:47984".into()]),
        );
        settings.set_active_rtsp_state(
            Some(rtsp_target),
            Some(47_989),
            Some(vec!["127.0.0.1:48010".into()]),
        );
        settings.finish_call(
            Purpose::Update(Box::new(UpdatePurpose {
                display_policy: empty_display_policy(),
                request: 12,
                hostname: "New Host".into(),
                target: NetworkTarget {
                    port: 47_989,
                    address_family: None,
                    bind_address: None,
                },
                output_name: None,
                audio_sink: None,
                virtual_sink: None,
                audio_sink_capture_only: false,
            install_steam_audio_drivers: true,
                nvenc_spatial_aq: false,
                external_ip: None,
                stream_audio: true,
                capture: CaptureMode::Auto,
                video_max_batch_size_kb: None,
                max_bitrate: None,
                qp: None,
                fec_percentage: None,
                minimum_fps_target: None,
                wgc_pacing_smoothing: None,
                software_encoder: SoftwareEncoderOptions::default(),
            nvenc_settings: NvencSettings::default(),
                ping_timeout_ms: None,
                global_preparation: Vec::new(),
                legacy_global_preparation: Vec::new(),
                frame_limiter: FrameLimiterSettings::default(),
                lan_encryption_mode: DEFAULT_LAN_ENCRYPTION_MODE,
                wan_encryption_mode: DEFAULT_WAN_ENCRYPTION_MODE,
                expected_revision: 1,
                require_listener_apply: true,

                upnp: false,})),
            CallOutcome::Payload(v17_update_confirmation(json!({
                "ok":true,"found":true,"version":16,"revision":2,
                "values":{"hostname":"New Host","port":47989,"address_family":null,"bind_address":null,"output_name":null,"audio_sink":null,"virtual_sink":null,"external_ip":null,"stream_audio":true,"capture":"auto","video_max_batch_size_kb":null,"max_bitrate":null,"minimum_fps_target":null,"wgc_pacing_smoothing":null,"ping_timeout_ms":null,"audio_sink_capture_only":false,"global_preparation":[]}
            }))),
        );

        let completion = settings.completions.front().unwrap();
        assert_eq!(completion.payload["ok"], true);
        assert_eq!(completion.payload["configured_hostname"], "New Host");
        assert_eq!(completion.required_http_target, None);
        assert_eq!(completion.required_rtsp_target, None);
    }

    #[test]
    fn failed_live_port_apply_never_reports_a_committed_update_as_applied() {
        let mut settings = ProductSettings::new("Computer Name".into(), settings::DEFAULT_PORT);
        settings.set_active_ports(Some(47_989), Some(47_984));
        settings.queue_update_completion(
            12,
            settings.settings_payload(),
            Some(48_000),
            Some(48_000),
        );

        settings.record_port_apply_failure(48_000, "HTTPS listener unavailable".into());

        let completion = settings.completions.front().unwrap();
        assert_eq!(completion.request, 12);
        assert_eq!(completion.payload["ok"], false);
        assert_eq!(completion.payload["code"], "listener_apply_failed");
        assert_eq!(completion.payload["persisted"], true);
        assert_eq!(completion.required_http_target, None);
    }

    #[test]
    fn settings_update_waits_for_rtsp_base_port_and_reports_persisted_pending_on_failure() {
        let mut settings = ProductSettings::new("Computer Name".into(), settings::DEFAULT_PORT);
        settings.apply_document(
            parse_document(&json!({
                "ok":true,"found":true,"version":2,"revision":2,
                "values":{"hostname":"Old Host","port":47989}
            }))
            .unwrap(),
        );
        settings.set_active_ports(Some(47_989), Some(47_984));
        settings.queue_update_completion(
            77,
            settings.settings_payload(),
            Some(47_989),
            Some(47_989),
        );

        assert_eq!(settings.rtsp_completion_request(47_989), Some(77));
        assert_eq!(settings.completions.front().unwrap().payload["ok"], true);

        settings.record_rtsp_apply_failure(47_989, "listener_apply_pending: active stream".into());
        assert_eq!(settings.rtsp_completion_request(47_989), None);
        let completion = settings.completions.front().unwrap();
        let payload = &completion.payload;
        assert_eq!(payload["ok"], false);
        assert_eq!(payload["code"], "listener_apply_pending");
        assert_eq!(payload["persisted"], true);
        assert_eq!(
            settings.settings_payload()["rtsp_listener_error"],
            "listener_apply_pending: active stream"
        );
    }

    #[test]
    fn v3_preserves_null_and_explicit_empty_bind_address_distinctly() {
        let cleared = parse_document(&json!({
            "ok":true,"found":true,"version":3,"revision":8,
            "values":{"hostname":"Host","port":47989,"address_family":null,"bind_address":null}
        }))
        .unwrap();
        let empty = parse_document(&json!({
            "ok":true,"found":true,"version":3,"revision":9,
            "values":{"hostname":"Host","port":47989,"address_family":"both","bind_address":""}
        }))
        .unwrap();
        assert_eq!(cleared.address_family, None);
        assert_eq!(cleared.bind_address, None);
        assert_eq!(empty.address_family, Some(AddressFamily::Both));
        assert_eq!(empty.bind_address.as_deref(), Some(""));
    }

    #[test]
    fn resetting_the_last_network_override_reapplies_startup_listener_policy() {
        let bootstrap = Settings {
            address_family: Some(AddressFamily::Ipv4),
            bind_address: Some("127.0.0.1".into()),
            ..Settings::default()
        };
        let mut product = ProductSettings::with_bootstrap_settings("Bootstrap".into(), &bootstrap);
        let overridden = parse_document(&json!({
            "ok":true,"found":true,"version":3,"revision":4,
            "values":{"hostname":"Host","port":47989,"address_family":"both","bind_address":"::1"}
        }))
        .unwrap();
        product.apply_document(overridden);
        product.set_active_http_state(
            Some(product.http_target()),
            Some(vec!["[::1]:47989".into()]),
            Some(vec!["[::1]:47984".into()]),
        );
        assert!(!product.listeners_need_application());

        product.apply_document(
            parse_document(&json!({
                "ok":true,"found":true,"version":3,"revision":5,
                "values":{"hostname":"Host","port":47989,"address_family":null,"bind_address":null}
            }))
            .unwrap(),
        );
        assert!(product.listeners_need_application());
        assert_eq!(
            product.http_target().address_family,
            Some(AddressFamily::Ipv4)
        );
        assert_eq!(
            product.http_target().bind_address.as_deref(),
            Some("127.0.0.1")
        );
    }

    #[test]
    fn persisted_null_reset_waits_for_startup_bind_to_reapply() {
        let bootstrap = Settings {
            address_family: Some(AddressFamily::Ipv4),
            bind_address: Some(String::new()),
            ..Settings::default()
        };
        let mut product = ProductSettings::with_bootstrap_settings("Bootstrap".into(), &bootstrap);
        product.apply_document(
            parse_document(&json!({
                "ok":true,"found":true,"version":3,"revision":3,
                "values":{"hostname":"Host","port":47989,"address_family":"both","bind_address":"::1"}
            }))
            .unwrap(),
        );
        let old_http = product.http_target();
        let old_rtsp = product.rtsp_target();
        product.set_active_http_state(
            Some(old_http),
            Some(vec!["[::1]:47989".into()]),
            Some(vec!["[::1]:47984".into()]),
        );
        product.set_active_rtsp_state(
            Some(old_rtsp),
            Some(47_989),
            Some(vec!["[::1]:48010".into()]),
        );

        product.finish_call(
            Purpose::Update(Box::new(UpdatePurpose {
                display_policy: empty_display_policy(),
                request: 21,
                hostname: "Host".into(),
                target: NetworkTarget {
                    port: 47_989,
                    address_family: None,
                    bind_address: None,
                },
                output_name: None,
                audio_sink: None,
                virtual_sink: None,
                audio_sink_capture_only: false,
            install_steam_audio_drivers: true,
                nvenc_spatial_aq: false,
                external_ip: None,
                stream_audio: true,
                capture: CaptureMode::Auto,
                video_max_batch_size_kb: None,
                max_bitrate: None,
                qp: None,
                fec_percentage: None,
                minimum_fps_target: None,
                wgc_pacing_smoothing: None,
                software_encoder: SoftwareEncoderOptions::default(),
            nvenc_settings: NvencSettings::default(),
                ping_timeout_ms: None,
                global_preparation: Vec::new(),
                legacy_global_preparation: Vec::new(),
                frame_limiter: FrameLimiterSettings::default(),
                lan_encryption_mode: DEFAULT_LAN_ENCRYPTION_MODE,
                wan_encryption_mode: DEFAULT_WAN_ENCRYPTION_MODE,
                expected_revision: 3,
                require_listener_apply: true,

                upnp: false,})),
            CallOutcome::Payload(v17_update_confirmation(json!({
                "ok":true,"found":true,"version":16,"revision":4,
                "values":{"hostname":"Host","port":47989,"address_family":null,"bind_address":null,"output_name":null,"audio_sink":null,"virtual_sink":null,"external_ip":null,"stream_audio":true,"capture":"auto","video_max_batch_size_kb":null,"max_bitrate":null,"minimum_fps_target":null,"wgc_pacing_smoothing":null,"ping_timeout_ms":null,"audio_sink_capture_only":false,"global_preparation":[]}
            }))),
        );

        let completion = product.completions.front().unwrap();
        assert_eq!(completion.required_http_target, Some(product.http_target()));
        assert_eq!(completion.required_rtsp_target, Some(product.rtsp_target()));
        assert!(product.listeners_need_application());
    }

    #[test]
    fn persisted_remote_override_is_rejected_when_bootstrap_disallows_remote_access() {
        let product = ProductSettings::new("Bootstrap".into(), settings::DEFAULT_PORT);
        let document = parse_document(&json!({
            "ok":true,"found":true,"version":3,"revision":2,
            "values":{"hostname":"Host","port":47989,"address_family":"ipv4","bind_address":"0.0.0.0"}
        }))
        .unwrap();
        assert_eq!(
            product.validate_document(&document).unwrap_err().code,
            "invalid_state_response"
        );
    }

    #[test]
    fn omitted_update_fields_preserve_while_null_clears_overrides() {
        assert_eq!(
            apply_field_update(FieldUpdate::Omitted, Some(AddressFamily::Both)),
            Some(AddressFamily::Both)
        );
        assert_eq!(
            apply_field_update::<AddressFamily>(FieldUpdate::Null, Some(AddressFamily::Both)),
            None
        );
        assert_eq!(
            apply_field_update(FieldUpdate::Value(String::new()), Some("127.0.0.1".into())),
            Some(String::new())
        );
    }

    #[test]
    fn encryption_mode_update_preserves_resets_and_validates_supported_values() {
        assert_eq!(
            apply_encryption_mode_update(FieldUpdate::Omitted, 2, DEFAULT_LAN_ENCRYPTION_MODE),
            Ok(2)
        );
        assert_eq!(
            apply_encryption_mode_update(FieldUpdate::Null, 2, DEFAULT_WAN_ENCRYPTION_MODE),
            Ok(DEFAULT_WAN_ENCRYPTION_MODE)
        );
        for (value, expected) in [(0_i64, 0_u8), (1, 1), (2, 2)] {
            assert_eq!(
                apply_encryption_mode_update(FieldUpdate::Value(value), 1, 0),
                Ok(expected)
            );
        }
        for value in [-1, 3, 256] {
            assert_eq!(
                apply_encryption_mode_update(FieldUpdate::Value(value), 1, 0),
                Err(())
            );
        }
    }

    #[test]
    fn virtual_sink_update_preserves_omission_clear_and_explicit_empty() {
        let legacy_v14 = json!({
            "ok":true,"found":true,"version":14,"revision":1,
            "values":{
                "hostname":"Host","port":47989,"address_family":null,
                "bind_address":null,"output_name":null,"audio_sink":"render.regular",
                "external_ip":null,"stream_audio":true,"capture":"auto",
                "video_max_batch_size_kb":32,"max_bitrate":null,
                "minimum_fps_target":20.0,"wgc_pacing_smoothing":null,
                "ping_timeout_ms":null,"audio_sink_capture_only":true
            }
        });
        let mut product = ProductSettings::new("Bootstrap".into(), settings::DEFAULT_PORT);
        product.apply_document(parse_document(&legacy_v14).unwrap());
        assert_eq!(product.configured_virtual_sink(), None);

        let enqueue_update = |product: &mut ProductSettings,
                              virtual_sink: FieldUpdate<String>,
                              expected_revision| {
            product
                .enqueue(
                    41,
                    5_000,
                    AdminAction::Update {
                        display_policy: DisplayPolicyUpdate::default(),
                        software_encoder: SoftwareEncoderUpdate::default(),
                        nvenc_settings: NvencSettingsUpdate::default(),
                        hostname: "Host".into(),
                        port: 47_989,
                        address_family: FieldUpdate::Omitted,
                        bind_address: FieldUpdate::Omitted,
                        output_name: FieldUpdate::Omitted,
                        audio_sink: FieldUpdate::Omitted,
                        virtual_sink,
                        audio_sink_capture_only: FieldUpdate::Omitted,
                        install_steam_audio_drivers: FieldUpdate::Omitted,
                        nvenc_spatial_aq: FieldUpdate::Omitted,
                        external_ip: FieldUpdate::Omitted,
                        stream_audio: FieldUpdate::Omitted,
                        capture: FieldUpdate::Omitted,
                        video_max_batch_size_kb: FieldUpdate::Omitted,
                        max_bitrate: FieldUpdate::Omitted,
                        qp: FieldUpdate::Omitted,
                        fec_percentage: FieldUpdate::Omitted,
                        minimum_fps_target: FieldUpdate::Omitted,
                        wgc_pacing_smoothing: FieldUpdate::Omitted,
                        ping_timeout_ms: FieldUpdate::Omitted,
                        global_preparation: FieldUpdate::Omitted,
                        legacy_global_preparation: FieldUpdate::Omitted,
                        frame_limiter: FrameLimiterUpdate::default(),
                        encryption_modes: EncryptionModeUpdate::default(),
                        expected_revision,
                        require_listener_apply: false,

                        upnp: FieldUpdate::Omitted,
                    },
                )
                .unwrap();
            product.start_next();
        };

        enqueue_update(&mut product, FieldUpdate::Value(String::new()), 1);
        let pending = product
            .pending
            .take()
            .expect("explicit empty selector write");
        assert_eq!(pending.payload["version"], SETTINGS_VERSION);
        assert_eq!(pending.payload["values"]["virtual_sink"], "");
        let response = json!({
            "ok":true,"found":true,"version":SETTINGS_VERSION,"revision":2,
            "values":pending.payload["values"].clone()
        });
        product.finish_call(pending.purpose, CallOutcome::Payload(response.clone()));
        assert_eq!(product.configured_virtual_sink(), Some(""));
        assert_eq!(product.settings_payload()["configured_virtual_sink"], "");
        let mut restarted = ProductSettings::new("Bootstrap".into(), settings::DEFAULT_PORT);
        restarted.apply_document(parse_document(&response).unwrap());
        assert_eq!(restarted.configured_virtual_sink(), Some(""));

        enqueue_update(&mut product, FieldUpdate::Omitted, 2);
        let pending = product.pending.take().expect("omitted selector write");
        assert_eq!(pending.payload["values"]["virtual_sink"], "");
        product.finish_call(
            pending.purpose,
            CallOutcome::Payload(json!({
                "ok":true,"found":true,"version":SETTINGS_VERSION,"revision":3,
                "values":pending.payload["values"].clone()
            })),
        );
        assert_eq!(product.configured_virtual_sink(), Some(""));

        enqueue_update(
            &mut product,
            FieldUpdate::Value("Steam Streaming Speakers".into()),
            3,
        );
        let pending = product.pending.take().expect("named selector write");
        assert_eq!(
            pending.payload["values"]["virtual_sink"],
            "Steam Streaming Speakers"
        );
        let response = json!({
            "ok":true,"found":true,"version":SETTINGS_VERSION,"revision":4,
            "values":pending.payload["values"].clone()
        });
        product.finish_call(pending.purpose, CallOutcome::Payload(response.clone()));
        assert_eq!(
            product.configured_virtual_sink(),
            Some("Steam Streaming Speakers")
        );
        let mut restarted = ProductSettings::new("Bootstrap".into(), settings::DEFAULT_PORT);
        restarted.apply_document(parse_document(&response).unwrap());
        assert_eq!(
            restarted.configured_virtual_sink(),
            Some("Steam Streaming Speakers")
        );

        enqueue_update(&mut product, FieldUpdate::Null, 4);
        let pending = product.pending.take().expect("selector reset");
        assert!(pending.payload["values"]["virtual_sink"].is_null());
        product.finish_call(
            pending.purpose,
            CallOutcome::Payload(json!({
                "ok":true,"found":true,"version":SETTINGS_VERSION,"revision":5,
                "values":pending.payload["values"].clone()
            })),
        );
        assert_eq!(product.configured_virtual_sink(), None);

        assert_eq!(normalize_virtual_sink(""), Ok(Some(String::new())));
        assert_eq!(
            normalize_virtual_sink("Steam Streaming Speakers"),
            Ok(Some("Steam Streaming Speakers".into()))
        );
        assert_eq!(normalize_virtual_sink("bad\nselector"), Err(()));
        assert_eq!(normalize_virtual_sink(&"x".repeat(4097)), Err(()));
    }

    #[test]
    fn global_preparation_v15_migration_update_null_restart_and_readback() {
        let legacy_v15 = json!({
            "ok":true,"found":true,"version":15,"revision":1,
            "values":{
                "hostname":"Host","port":47989,"address_family":null,"bind_address":null,
                "output_name":null,"audio_sink":null,"virtual_sink":null,
                "audio_sink_capture_only":false,"external_ip":null,"stream_audio":true,
                "capture":"auto","video_max_batch_size_kb":null,"max_bitrate":null,
                "minimum_fps_target":null,"wgc_pacing_smoothing":null,"ping_timeout_ms":null
            }
        });
        let mut product = ProductSettings::new("Bootstrap".into(), settings::DEFAULT_PORT);
        product.apply_document(parse_document(&legacy_v15).unwrap());
        assert!(product.global_preparation().is_empty());
        assert_eq!(
            product.settings_payload()["configured_global_preparation"],
            json!([])
        );

        let step: PreparationStep = serde_json::from_value(json!({
            "run":{"executable":std::env::current_exe().unwrap(),"args":["setup"]},
            "undo":{"executable":std::env::current_exe().unwrap(),"args":["undo"]}
        }))
        .unwrap();
        let update = |product: &mut ProductSettings,
                      global_preparation: FieldUpdate<Vec<PreparationStep>>,
                      revision: u64| {
            product
                .enqueue(
                    revision + 10,
                    5_000,
                    AdminAction::Update {
                        display_policy: DisplayPolicyUpdate::default(),
                        software_encoder: SoftwareEncoderUpdate::default(),
                        nvenc_settings: NvencSettingsUpdate::default(),
                        hostname: "Host".into(),
                        port: 47_989,
                        address_family: FieldUpdate::Omitted,
                        bind_address: FieldUpdate::Omitted,
                        output_name: FieldUpdate::Omitted,
                        audio_sink: FieldUpdate::Omitted,
                        virtual_sink: FieldUpdate::Omitted,
                        audio_sink_capture_only: FieldUpdate::Omitted,
                        install_steam_audio_drivers: FieldUpdate::Omitted,
                        nvenc_spatial_aq: FieldUpdate::Omitted,
                        external_ip: FieldUpdate::Omitted,
                        stream_audio: FieldUpdate::Omitted,
                        capture: FieldUpdate::Omitted,
                        video_max_batch_size_kb: FieldUpdate::Omitted,
                        max_bitrate: FieldUpdate::Omitted,
                        qp: FieldUpdate::Omitted,
                        fec_percentage: FieldUpdate::Omitted,
                        minimum_fps_target: FieldUpdate::Omitted,
                        wgc_pacing_smoothing: FieldUpdate::Omitted,
                        ping_timeout_ms: FieldUpdate::Omitted,
                        global_preparation,
                        legacy_global_preparation: FieldUpdate::Omitted,
                        frame_limiter: FrameLimiterUpdate::default(),
                        encryption_modes: EncryptionModeUpdate::default(),
                        expected_revision: revision,
                        require_listener_apply: false,

                        upnp: FieldUpdate::Omitted,
                    },
                )
                .unwrap();
            product.start_next();
            let pending = product.pending.take().expect("product update request");
            assert_eq!(pending.payload["version"], SETTINGS_VERSION);
            let response = json!({
                "ok":true,"found":true,"version":SETTINGS_VERSION,"revision":revision + 1,
                "values":pending.payload["values"].clone()
            });
            product.finish_call(pending.purpose, CallOutcome::Payload(response.clone()));
            response
        };

        let persisted = update(&mut product, FieldUpdate::Value(vec![step.clone()]), 1);
        assert_eq!(
            persisted["values"]["global_preparation"][0]["run"]["args"],
            json!(["setup"])
        );
        assert_eq!(product.global_preparation(), std::slice::from_ref(&step));
        assert_eq!(
            product.settings_payload()["configured_global_preparation"],
            persisted["values"]["global_preparation"]
        );
        let mut restarted = ProductSettings::new("Bootstrap".into(), settings::DEFAULT_PORT);
        restarted.apply_document(parse_document(&persisted).unwrap());
        assert_eq!(restarted.global_preparation(), std::slice::from_ref(&step));

        let preserved = update(&mut product, FieldUpdate::Omitted, 2);
        assert_eq!(
            preserved["values"]["global_preparation"][0]["undo"]["args"],
            json!(["undo"])
        );
        let reset = update(&mut product, FieldUpdate::Null, 3);
        assert_eq!(reset["values"]["global_preparation"], json!([]));
        assert!(product.global_preparation().is_empty());

        let mut invalid = reset;
        invalid["values"]["global_preparation"] = Value::Null;
        assert_eq!(
            parse_document(&invalid).unwrap_err().code,
            "invalid_state_response"
        );
    }

    #[test]
    fn global_preparation_update_rejects_invalid_and_over_limit_lists() {
        let invalid: PreparationStep = serde_json::from_value(json!({
            "run":{"executable":"relative-command"}
        }))
        .unwrap();
        assert_eq!(
            apply_global_preparation_update(FieldUpdate::Value(vec![invalid]), Vec::new()),
            Err(())
        );
        let valid: PreparationStep = serde_json::from_value(json!({
            "run":{"executable":std::env::current_exe().unwrap()}
        }))
        .unwrap();
        assert_eq!(
            apply_global_preparation_update(FieldUpdate::Value(vec![valid; 9]), Vec::new()),
            Err(())
        );
    }

    #[test]
    fn v15_product_update_payload_keeps_nullable_values_exact() {
        let reset = product_update_payload(
            7,
            "Host",
            &NetworkTarget {
                port: 48_000,
                address_family: None,
                bind_address: None,
            },
            None,
            ProductStreamingSettings {
                display_policy: empty_display_policy(),
                audio_sink: None,
                virtual_sink: None,
                audio_sink_capture_only: false,
                install_steam_audio_drivers: true,
                nvenc_spatial_aq: false,
                external_ip: None,
                stream_audio: false,
                capture: CaptureMode::Auto,
                video_max_batch_size_kb: None,
                max_bitrate: None,
                qp: None,
                fec_percentage: None,
                minimum_fps_target: None,
                wgc_pacing_smoothing: None,
                software_encoder: SoftwareEncoderOptions::default(),
                nvenc_settings: NvencSettings::default(),
                ping_timeout_ms: None,
                global_preparation: Vec::new(),
                legacy_global_preparation: Vec::new(),
                frame_limiter: FrameLimiterSettings::default(),
                lan_encryption_mode: DEFAULT_LAN_ENCRYPTION_MODE,
                wan_encryption_mode: DEFAULT_WAN_ENCRYPTION_MODE,

                upnp: false,
            },
        );
        assert_eq!(reset["version"], SETTINGS_VERSION);
        assert_eq!(reset["expected_revision"], 7);
        assert_eq!(reset["values"]["stream_audio"], false);
        assert_eq!(reset["values"]["address_family"], Value::Null);
        assert_eq!(reset["values"]["bind_address"], Value::Null);
        assert_eq!(reset["values"]["max_bitrate"], Value::Null);
        assert_eq!(reset["values"]["minimum_fps_target"], Value::Null);
        assert_eq!(reset["values"]["audio_sink"], Value::Null);
        assert_eq!(reset["values"]["wgc_pacing_smoothing"], Value::Null);

        let explicit_blank = product_update_payload(
            8,
            "Host",
            &NetworkTarget {
                port: 48_000,
                address_family: Some(AddressFamily::Both),
                bind_address: Some(String::new()),
            },
            Some("stable-display-id"),
            ProductStreamingSettings {
                display_policy: empty_display_policy(),
                audio_sink: None,
                virtual_sink: None,
                audio_sink_capture_only: false,
                install_steam_audio_drivers: true,
                nvenc_spatial_aq: false,
                external_ip: None,
                stream_audio: true,
                capture: CaptureMode::Wgcc,
                video_max_batch_size_kb: Some(32),
                max_bitrate: Some(15_000),
                qp: None,
                fec_percentage: None,
                minimum_fps_target: None,
                wgc_pacing_smoothing: Some(false),
                software_encoder: SoftwareEncoderOptions::default(),
                nvenc_settings: NvencSettings::default(),
                ping_timeout_ms: None,
                global_preparation: Vec::new(),
                legacy_global_preparation: Vec::new(),
                frame_limiter: FrameLimiterSettings::default(),
                lan_encryption_mode: DEFAULT_LAN_ENCRYPTION_MODE,
                wan_encryption_mode: DEFAULT_WAN_ENCRYPTION_MODE,

                upnp: false,
            },
        );
        assert_eq!(explicit_blank["values"]["address_family"], "both");
        assert_eq!(explicit_blank["values"]["bind_address"], "");
        assert_eq!(explicit_blank["values"]["output_name"], "stable-display-id");
        assert_eq!(explicit_blank["values"]["stream_audio"], true);
        assert_eq!(explicit_blank["values"]["capture"], "wgcc");
        assert_eq!(explicit_blank["values"]["video_max_batch_size_kb"], 32);
        assert_eq!(explicit_blank["values"]["max_bitrate"], 15_000);
        assert_eq!(explicit_blank["values"]["minimum_fps_target"], Value::Null);
        assert_eq!(explicit_blank["values"]["audio_sink"], Value::Null);
        assert_eq!(explicit_blank["values"]["wgc_pacing_smoothing"], false);
    }

    #[test]
    fn stream_audio_update_preserves_omission_and_rejects_null() {
        assert_eq!(apply_boolean_update(FieldUpdate::Omitted, false), Ok(false));
        assert_eq!(apply_boolean_update(FieldUpdate::Omitted, true), Ok(true));
        assert_eq!(
            apply_boolean_update(FieldUpdate::Value(false), true),
            Ok(false)
        );
        assert_eq!(
            apply_boolean_update(FieldUpdate::Value(true), false),
            Ok(true)
        );
        assert_eq!(apply_boolean_update(FieldUpdate::Null, true), Err(()));
    }

    #[test]
    fn capture_update_omission_preserves_and_null_resets_to_auto() {
        for mode in [
            CaptureMode::Ddx,
            CaptureMode::Wgc,
            CaptureMode::Wgcc,
            CaptureMode::X11,
            CaptureMode::Kms,
        ] {
            assert_eq!(apply_capture_update(FieldUpdate::Omitted, mode), mode);
            assert_eq!(
                apply_capture_update(FieldUpdate::Null, mode),
                CaptureMode::Auto
            );
        }
        assert_eq!(
            apply_capture_update(FieldUpdate::Value(CaptureMode::Wgcc), CaptureMode::Ddx),
            CaptureMode::Wgcc
        );
    }

    #[test]
    fn video_batch_update_omission_preserves_and_null_resets_to_default() {
        let mut product = ProductSettings::new("Bootstrap".into(), settings::DEFAULT_PORT);
        product.apply_document(
            parse_document(&json!({
                "ok":true,"found":true,"version":7,"revision":3,
                "values":{"hostname":"Host","port":47989,"address_family":null,
                    "bind_address":null,"output_name":null,"stream_audio":true,"capture":"auto",
                    "video_max_batch_size_kb":32}
            }))
            .unwrap(),
        );

        for (request, revision, update, expected_raw, reply_revision) in [
            (20, 3, FieldUpdate::Omitted, json!(32), 4),
            (21, 4, FieldUpdate::Null, Value::Null, 5),
        ] {
            product
                .enqueue(
                    request,
                    5_000,
                    AdminAction::Update {
                        display_policy: DisplayPolicyUpdate::default(),
                        software_encoder: SoftwareEncoderUpdate::default(),
                        nvenc_settings: NvencSettingsUpdate::default(),
                        hostname: "Host".into(),
                        port: 47_989,
                        address_family: FieldUpdate::Omitted,
                        bind_address: FieldUpdate::Omitted,
                        output_name: FieldUpdate::Omitted,
                        audio_sink: FieldUpdate::Omitted,
                        virtual_sink: FieldUpdate::Omitted,
                        audio_sink_capture_only: FieldUpdate::Omitted,
                        install_steam_audio_drivers: FieldUpdate::Omitted,
                        nvenc_spatial_aq: FieldUpdate::Omitted,
                        external_ip: FieldUpdate::Omitted,
                        stream_audio: FieldUpdate::Omitted,
                        capture: FieldUpdate::Omitted,
                        video_max_batch_size_kb: update,
                        max_bitrate: FieldUpdate::Omitted,
                        qp: FieldUpdate::Omitted,
                        fec_percentage: FieldUpdate::Omitted,
                        minimum_fps_target: FieldUpdate::Omitted,
                        wgc_pacing_smoothing: FieldUpdate::Omitted,
                        ping_timeout_ms: FieldUpdate::Omitted,
                        global_preparation: FieldUpdate::Omitted,
                        legacy_global_preparation: FieldUpdate::Omitted,
                        frame_limiter: FrameLimiterUpdate::default(),
                        encryption_modes: EncryptionModeUpdate::default(),
                        expected_revision: revision,
                        require_listener_apply: false,

                        upnp: FieldUpdate::Omitted,
                    },
                )
                .unwrap();
            product.start_next();
            let pending = product.pending.take().expect("product update request");
            assert_eq!(pending.payload["version"], SETTINGS_VERSION);
            assert_eq!(
                pending.payload["values"]["video_max_batch_size_kb"],
                expected_raw
            );
            let persisted_value = if expected_raw.is_null() {
                Value::Null
            } else {
                expected_raw.clone()
            };
            product.finish_call(
                pending.purpose,
                CallOutcome::Payload(v17_update_confirmation(json!({
                    "ok":true,"found":true,"version":16,"revision":reply_revision,
                    "values":{"hostname":"Host","port":47989,"address_family":null,
                        "bind_address":null,"output_name":null,"audio_sink":null,"virtual_sink":null,"external_ip":null,
                        "stream_audio":true,"capture":"auto",
                        "video_max_batch_size_kb":persisted_value,"max_bitrate":null,
                    "minimum_fps_target":null,"wgc_pacing_smoothing":null,"ping_timeout_ms":null,"audio_sink_capture_only":false,"global_preparation":[]}
                }))),
            );
        }

        assert_eq!(product.configured_video_max_batch_size_kb(), None);
        assert_eq!(product.effective_video_max_batch_size_kb(), 64);
        assert!(!product.video_batch_size_fallback());
        assert_eq!(
            product.settings_payload()["configured_video_max_batch_size_kb"],
            Value::Null
        );
    }

    #[test]
    fn stream_audio_admin_update_migrates_old_settings_and_rejects_null() {
        let mut product = ProductSettings::new("Bootstrap".into(), settings::DEFAULT_PORT);
        product.apply_document(
            parse_document(&json!({
                "ok":true,"found":true,"version":6,"revision":4,
                "values":{"hostname":"Host","port":47989,"address_family":null,
                    "bind_address":null,"output_name":null,"stream_audio":false,"capture":"auto"}
            }))
            .unwrap(),
        );
        product
            .enqueue(
                7,
                5_000,
                AdminAction::Update {
                    display_policy: DisplayPolicyUpdate::default(),
                    software_encoder: SoftwareEncoderUpdate::default(),
                    nvenc_settings: NvencSettingsUpdate::default(),
                    hostname: "Host".into(),
                    port: 47_989,
                    address_family: FieldUpdate::Omitted,
                    bind_address: FieldUpdate::Omitted,
                    output_name: FieldUpdate::Omitted,
                    audio_sink: FieldUpdate::Omitted,
                    virtual_sink: FieldUpdate::Omitted,
                    audio_sink_capture_only: FieldUpdate::Omitted,
                    install_steam_audio_drivers: FieldUpdate::Omitted,
                    nvenc_spatial_aq: FieldUpdate::Omitted,
                    external_ip: FieldUpdate::Omitted,
                    stream_audio: FieldUpdate::Omitted,
                    capture: FieldUpdate::Omitted,
                    video_max_batch_size_kb: FieldUpdate::Omitted,
                    max_bitrate: FieldUpdate::Omitted,
                    qp: FieldUpdate::Omitted,
                    fec_percentage: FieldUpdate::Omitted,
                    minimum_fps_target: FieldUpdate::Omitted,
                    wgc_pacing_smoothing: FieldUpdate::Omitted,
                    ping_timeout_ms: FieldUpdate::Omitted,
                    global_preparation: FieldUpdate::Omitted,
                    legacy_global_preparation: FieldUpdate::Omitted,
                    frame_limiter: FrameLimiterUpdate::default(),
                    encryption_modes: EncryptionModeUpdate::default(),
                    expected_revision: 4,
                    require_listener_apply: true,

                    upnp: FieldUpdate::Omitted,
                },
            )
            .unwrap();
        product.start_next();
        let payload = &product.pending.as_ref().unwrap().payload;
        assert_eq!(payload["version"], SETTINGS_VERSION);
        assert_eq!(payload["expected_revision"], 4);
        assert_eq!(payload["values"]["stream_audio"], false);
        assert_eq!(payload["values"]["capture"], "auto");

        let mut invalid = ProductSettings::new("Bootstrap".into(), settings::DEFAULT_PORT);
        invalid.apply_document(
            parse_document(&json!({
                "ok":true,"found":true,"version":4,"revision":4,
                "values":{"hostname":"Host","port":47989,"address_family":null,
                    "bind_address":null,"output_name":null}
            }))
            .unwrap(),
        );
        invalid
            .enqueue(
                8,
                5_000,
                AdminAction::Update {
                    display_policy: DisplayPolicyUpdate::default(),
                    software_encoder: SoftwareEncoderUpdate::default(),
                    nvenc_settings: NvencSettingsUpdate::default(),
                    hostname: "Host".into(),
                    port: 47_989,
                    address_family: FieldUpdate::Omitted,
                    bind_address: FieldUpdate::Omitted,
                    output_name: FieldUpdate::Omitted,
                    audio_sink: FieldUpdate::Omitted,
                    virtual_sink: FieldUpdate::Omitted,
                    audio_sink_capture_only: FieldUpdate::Omitted,
                    install_steam_audio_drivers: FieldUpdate::Omitted,
                    nvenc_spatial_aq: FieldUpdate::Omitted,
                    external_ip: FieldUpdate::Omitted,
                    stream_audio: FieldUpdate::Null,
                    capture: FieldUpdate::Omitted,
                    video_max_batch_size_kb: FieldUpdate::Omitted,
                    max_bitrate: FieldUpdate::Omitted,
                    qp: FieldUpdate::Omitted,
                    fec_percentage: FieldUpdate::Omitted,
                    minimum_fps_target: FieldUpdate::Omitted,
                    wgc_pacing_smoothing: FieldUpdate::Omitted,
                    ping_timeout_ms: FieldUpdate::Omitted,
                    global_preparation: FieldUpdate::Omitted,
                    legacy_global_preparation: FieldUpdate::Omitted,
                    frame_limiter: FrameLimiterUpdate::default(),
                    encryption_modes: EncryptionModeUpdate::default(),
                    expected_revision: 4,
                    require_listener_apply: true,

                    upnp: FieldUpdate::Omitted,
                },
            )
            .unwrap();
        invalid.start_next();
        assert!(invalid.pending.is_none());
        assert_eq!(
            invalid.completions.front().unwrap().payload["code"],
            "invalid_stream_audio"
        );
    }

    #[test]
    fn capture_admin_update_persists_and_returns_the_selected_mode() {
        let mut product = ProductSettings::new("Bootstrap".into(), settings::DEFAULT_PORT);
        product.apply_document(
            parse_document(&json!({
                "ok":true,"found":true,"version":5,"revision":4,
                "values":{"hostname":"Host","port":47989,"address_family":null,
                    "bind_address":null,"output_name":null,"stream_audio":true}
            }))
            .unwrap(),
        );
        product
            .enqueue(
                11,
                5_000,
                AdminAction::Update {
                    display_policy: DisplayPolicyUpdate::default(),
                    software_encoder: SoftwareEncoderUpdate::default(),
                    nvenc_settings: NvencSettingsUpdate::default(),
                    hostname: "Host".into(),
                    port: 47_989,
                    address_family: FieldUpdate::Omitted,
                    bind_address: FieldUpdate::Omitted,
                    output_name: FieldUpdate::Omitted,
                    audio_sink: FieldUpdate::Omitted,
                    virtual_sink: FieldUpdate::Omitted,
                    audio_sink_capture_only: FieldUpdate::Omitted,
                    install_steam_audio_drivers: FieldUpdate::Omitted,
                    nvenc_spatial_aq: FieldUpdate::Omitted,
                    external_ip: FieldUpdate::Omitted,
                    stream_audio: FieldUpdate::Omitted,
                    capture: FieldUpdate::Value(CaptureMode::Wgcc),
                    video_max_batch_size_kb: FieldUpdate::Omitted,
                    max_bitrate: FieldUpdate::Omitted,
                    qp: FieldUpdate::Omitted,
                    fec_percentage: FieldUpdate::Omitted,
                    minimum_fps_target: FieldUpdate::Omitted,
                    wgc_pacing_smoothing: FieldUpdate::Omitted,
                    ping_timeout_ms: FieldUpdate::Omitted,
                    global_preparation: FieldUpdate::Omitted,
                    legacy_global_preparation: FieldUpdate::Omitted,
                    frame_limiter: FrameLimiterUpdate::default(),
                    encryption_modes: EncryptionModeUpdate::default(),
                    expected_revision: 4,
                    require_listener_apply: false,

                    upnp: FieldUpdate::Omitted,
                },
            )
            .unwrap();
        product.start_next();
        let pending = product.pending.take().expect("product update request");
        assert_eq!(pending.payload["version"], SETTINGS_VERSION);
        assert_eq!(pending.payload["values"]["capture"], "wgcc");

        product.finish_call(
            pending.purpose,
                CallOutcome::Payload(v17_update_confirmation(json!({
                "ok":true,"found":true,"version":16,"revision":5,
                "values":{"hostname":"Host","port":47989,"address_family":null,
                    "bind_address":null,"output_name":null,"audio_sink":null,"virtual_sink":null,"external_ip":null,
                    "stream_audio":true,"capture":"wgcc",
                    "video_max_batch_size_kb":null,"max_bitrate":null,"minimum_fps_target":null,"wgc_pacing_smoothing":null,"ping_timeout_ms":null,"audio_sink_capture_only":false,"global_preparation":[]}
                }))),
        );
        assert_eq!(product.configured_capture(), CaptureMode::Wgcc);
        assert_eq!(
            product.completions.front().unwrap().payload["configured_capture"],
            "wgcc"
        );
    }
    #[test]
    fn software_v23_cas_restart_reset_empty_and_signed_values_are_exact() {
        let mut prior_version = display_v18_document(7);
        prior_version["version"] = json!(SOFTWARE_ENCODER_SETTINGS_VERSION);
        remove_extended_display_policy_fields(&mut prior_version);
        remove_nvenc_settings(&mut prior_version);
        let prior_values = prior_version["values"].as_object_mut().unwrap();
        for key in DISPLAY_POLICY_KEYS {
            if !LEGACY_DISPLAY_POLICY_KEYS.contains(&key) {
                prior_values.remove(key);
            }
        }
        prior_values.remove("upnp");
        prior_values.remove("fec_percentage");
        prior_values.remove("install_steam_audio_drivers");
        prior_values.insert("sw_preset".into(), Value::Null);
        prior_values.insert("sw_tune".into(), Value::Null);
        prior_values.insert("encoder".into(), Value::Null);
        prior_values.remove("min_threads");
        prior_values.remove("qp");
        let mut prior_settings = ProductSettings::new("Bootstrap".into(), settings::DEFAULT_PORT);
        prior_settings.apply_document(parse_document(&prior_version).unwrap());
        assert_eq!(
            prior_settings
                .software_encoder_options()
                .effective_threads(),
            2
        );

        let mut legacy = display_v18_document(7);
        legacy["version"] = json!(DISPLAY_POLICY_SETTINGS_VERSION);
        remove_nvenc_settings(&mut legacy);
        for key in DISPLAY_POLICY_KEYS {
            if !LEGACY_DISPLAY_POLICY_KEYS.contains(&key) {
                legacy["values"].as_object_mut().unwrap().remove(key);
            }
        }
        for key in ["upnp", "fec_percentage", "install_steam_audio_drivers"] {
            legacy["values"].as_object_mut().unwrap().remove(key);
        }
        for key in ["sw_preset", "sw_tune", "encoder", "min_threads", "qp"] {
            legacy["values"].as_object_mut().unwrap().remove(key);
        }
        let mut product = ProductSettings::new("Bootstrap".into(), settings::DEFAULT_PORT);
        product.apply_document(parse_document(&legacy).unwrap());
        assert_eq!(
            product.software_encoder_options().effective_preset(),
            "superfast"
        );
        assert_eq!(
            product.software_encoder_options().effective_tune(),
            "zerolatency"
        );
        let mut action = display_update_action(DisplayPolicyUpdate::default(), 7);
        let AdminAction::Update {
            software_encoder, ..
        } = &mut action
        else {
            unreachable!()
        };
        *software_encoder = SoftwareEncoderUpdate {
            sw_preset: FieldUpdate::Value("slow".into()),
            sw_tune: FieldUpdate::Value(String::new()),
            encoder: FieldUpdate::Value(EncoderBackend::Software),
            min_threads: FieldUpdate::Value(i32::MIN),
        };
        if let AdminAction::Update { qp, .. } = &mut action {
            *qp = FieldUpdate::Value(i32::MAX);
        }
        product.enqueue(51, 5000, action).unwrap();
        product.start_next();
        let pending = product.pending.take().unwrap();
        assert_eq!(pending.payload["version"], SETTINGS_VERSION);
        assert_eq!(pending.payload["expected_revision"], 7);
        assert_eq!(pending.payload["values"]["upnp"], false);
        assert_eq!(pending.payload["values"]["sw_tune"], "");
        assert_eq!(pending.payload["values"]["min_threads"], i32::MIN);
        assert_eq!(pending.payload["values"]["qp"], i32::MAX);
        let saved = json!({"ok":true,"found":true,"version":SETTINGS_VERSION,"revision":8,"values":pending.payload["values"]});
        product.finish_call(pending.purpose, CallOutcome::Payload(saved.clone()));
        assert_eq!(product.revision(), Some(8));
        let mut restarted = ProductSettings::new("Bootstrap".into(), settings::DEFAULT_PORT);
        restarted.apply_document(parse_document(&saved).unwrap());
        assert_eq!(
            restarted.software_encoder_options(),
            product.software_encoder_options()
        );
        assert_eq!(
            restarted.software_encoder_options().effective_threads(),
            i32::MIN
        );
        assert_eq!(restarted.effective_qp(), i32::MAX);
        let mut action = display_update_action(DisplayPolicyUpdate::default(), 8);
        let AdminAction::Update {
            software_encoder, ..
        } = &mut action
        else {
            unreachable!()
        };
        software_encoder.sw_preset = FieldUpdate::Null;
        software_encoder.encoder = FieldUpdate::Null;
        software_encoder.min_threads = FieldUpdate::Null;
        if let AdminAction::Update { qp, .. } = &mut action {
            *qp = FieldUpdate::Null;
        }
        restarted.enqueue(52, 5000, action).unwrap();
        restarted.start_next();
        let pending = restarted.pending.take().unwrap();
        assert!(pending.payload["values"]["sw_preset"].is_null());
        assert_eq!(pending.payload["values"]["sw_tune"], "");
        assert!(pending.payload["values"]["encoder"].is_null());
        assert!(pending.payload["values"]["min_threads"].is_null());
        let mut forged = json!({"ok":true,"found":true,"version":23,"revision":9,"values":pending.payload["values"]});
        forged["values"]["sw_tune"] = json!("zerolatency");
        restarted.finish_call(pending.purpose, CallOutcome::Payload(forged));
        assert_eq!(restarted.revision(), None);
        assert!(!restarted.loaded());
        assert_eq!(
            restarted.software_encoder_options().sw_tune.as_deref(),
            Some("")
        );
        for (field, value) in [
            ("sw_preset", json!(false)),
            ("sw_tune", json!("x".repeat(257))),
            ("encoder", json!("nvenc")),
            ("min_threads", json!(i64::from(i32::MIN) - 1)),
            ("qp", json!(i64::from(i32::MAX) + 1)),
        ] {
            let mut invalid = saved.clone();
            invalid["values"][field] = value;
            assert!(parse_document(&invalid).is_err());
        }
    }

    #[test]
    fn version_twenty_two_migrates_with_prior_upnp_and_qp_values_preserved() {
        let mut prior = display_v18_document(7);
        prior["version"] = json!(MIN_THREADS_SETTINGS_VERSION);
        remove_extended_display_policy_fields(&mut prior);
        remove_nvenc_settings(&mut prior);
        prior["values"].as_object_mut().unwrap().remove("upnp");
        prior["values"].as_object_mut().unwrap().remove("qp");
        prior["values"]
            .as_object_mut()
            .unwrap()
            .remove("fec_percentage");
        prior["values"]
            .as_object_mut()
            .unwrap()
            .remove("install_steam_audio_drivers");
        let migrated = parse_document(&prior).unwrap();
        assert!(!migrated.upnp);

        let mut product = ProductSettings::new("Bootstrap".into(), settings::DEFAULT_PORT);
        product.apply_document(migrated);
        let mut action = display_update_action(DisplayPolicyUpdate::default(), 7);
        let AdminAction::Update { upnp, .. } = &mut action else {
            unreachable!()
        };
        *upnp = FieldUpdate::Value(true);
        product.enqueue(81, 5_000, action).unwrap();
        product.start_next();
        let pending = product.pending.take().unwrap();
        assert_eq!(pending.payload["version"], SETTINGS_VERSION);
        assert_eq!(pending.payload["values"]["upnp"], true);
        assert_eq!(pending.payload["values"]["qp"], Value::Null);
        assert_eq!(pending.payload["values"]["fec_percentage"], Value::Null);

        let saved = json!({
            "ok":true,
            "found":true,
            "version":SETTINGS_VERSION,
            "revision":8,
            "values":pending.payload["values"]
        });
        product.finish_call(pending.purpose, CallOutcome::Payload(saved.clone()));
        assert!(product.upnp_enabled());
        product.set_upnp_runtime_status("active", None);
        assert_eq!(product.settings_payload()["upnp_status"], "active");

        let restarted = parse_document(&saved).unwrap();
        assert!(restarted.upnp);

        let mut version_21 = saved.clone();
        version_21["version"] = json!(UPNP_SETTINGS_VERSION);
        remove_extended_display_policy_fields(&mut version_21);
        remove_nvenc_settings(&mut version_21);
        version_21["values"].as_object_mut().unwrap().remove("qp");
        version_21["values"]
            .as_object_mut()
            .unwrap()
            .remove("fec_percentage");
        version_21["values"]
            .as_object_mut()
            .unwrap()
            .remove("install_steam_audio_drivers");
        let mut upgraded = ProductSettings::new("Bootstrap".into(), settings::DEFAULT_PORT);
        upgraded.apply_document(parse_document(&version_21).unwrap());
        assert!(upgraded.upnp_enabled());
        assert_eq!(upgraded.effective_qp(), 28);
        upgraded
            .enqueue(
                82,
                5_000,
                display_update_action(DisplayPolicyUpdate::default(), 8),
            )
            .unwrap();
        upgraded.start_next();
        let pending = upgraded.pending.take().unwrap();
        assert_eq!(pending.payload["version"], SETTINGS_VERSION);
        assert_eq!(pending.payload["values"]["upnp"], true);
        assert_eq!(pending.payload["values"]["qp"], Value::Null);
        assert_eq!(pending.payload["values"]["fec_percentage"], Value::Null);

        let mut version_22 = saved;
        version_22["version"] = json!(QP_SETTINGS_VERSION);
        remove_extended_display_policy_fields(&mut version_22);
        remove_nvenc_settings(&mut version_22);
        version_22["values"]["qp"] = json!(41);
        version_22["values"]
            .as_object_mut()
            .unwrap()
            .remove("fec_percentage");
        version_22["values"]
            .as_object_mut()
            .unwrap()
            .remove("install_steam_audio_drivers");
        let migrated_v22 = parse_document(&version_22).unwrap();
        assert!(migrated_v22.upnp);
        assert_eq!(migrated_v22.qp, Some(41));
        assert_eq!(migrated_v22.fec_percentage, None);
    }

    #[test]
    fn global_fec_setting_persists_valid_range_and_null_restores_bootstrap() {
        let mut product = ProductSettings::new("Bootstrap".into(), settings::DEFAULT_PORT);
        product.apply_document(parse_document(&display_v18_document(7)).unwrap());
        assert_eq!(product.configured_fec_percentage(), None);
        assert_eq!(product.effective_fec_percentage(), 20);

        let mut action = display_update_action(DisplayPolicyUpdate::default(), 7);
        let AdminAction::Update { fec_percentage, .. } = &mut action else {
            unreachable!()
        };
        *fec_percentage = FieldUpdate::Value(255);
        product.enqueue(91, 5_000, action).unwrap();
        product.start_next();
        let pending = product.pending.take().expect("FEC settings update");
        assert_eq!(pending.payload["version"], SETTINGS_VERSION);
        assert_eq!(pending.payload["values"]["fec_percentage"], 255);
        assert_eq!(pending.payload["values"]["upnp"], false);
        assert_eq!(pending.payload["values"]["qp"], Value::Null);

        let confirmation = json!({
            "ok":true,"found":true,"version":SETTINGS_VERSION,"revision":8,
            "values":pending.payload["values"]
        });
        product.finish_call(pending.purpose, CallOutcome::Payload(confirmation));
        assert_eq!(product.configured_fec_percentage(), Some(255));
        assert_eq!(product.effective_fec_percentage(), 255);
        assert_eq!(product.settings_payload()["configured_fec_percentage"], 255);
        assert_eq!(product.settings_payload()["effective_fec_percentage"], 255);
        assert_eq!(product.completions.pop_front().unwrap().payload["ok"], true);

        let mut reset = display_update_action(DisplayPolicyUpdate::default(), 8);
        let AdminAction::Update { fec_percentage, .. } = &mut reset else {
            unreachable!()
        };
        *fec_percentage = FieldUpdate::Null;
        product.enqueue(92, 5_000, reset).unwrap();
        product.start_next();
        let pending = product.pending.take().expect("FEC reset update");
        assert!(pending.payload["values"]["fec_percentage"].is_null());
        let confirmation = json!({
            "ok":true,"found":true,"version":SETTINGS_VERSION,"revision":9,
            "values":pending.payload["values"]
        });
        product.finish_call(pending.purpose, CallOutcome::Payload(confirmation));
        assert_eq!(product.configured_fec_percentage(), None);
        assert_eq!(product.effective_fec_percentage(), 20);
        assert!(product.settings_payload()["configured_fec_percentage"].is_null());
        assert_eq!(product.settings_payload()["effective_fec_percentage"], 20);
        assert_eq!(product.completions.pop_front().unwrap().payload["ok"], true);

        for value in [0, 256] {
            let mut invalid = display_update_action(DisplayPolicyUpdate::default(), 9);
            let AdminAction::Update { fec_percentage, .. } = &mut invalid else {
                unreachable!()
            };
            *fec_percentage = FieldUpdate::Value(value);
            product.enqueue(93, 5_000, invalid).unwrap();
            product.start_next();
            assert!(product.pending.is_none());
            let completion = product
                .completions
                .pop_front()
                .expect("invalid FEC completion");
            assert_eq!(completion.payload["code"], "invalid_fec_percentage");
        }
    }

    #[test]
    fn nvenc_v23_migration_defaults_v26_cas_roundtrip_and_validation() {
        let mut version_23 = display_v18_document(7);
        version_23["version"] = json!(FEC_SETTINGS_VERSION);
        remove_extended_display_policy_fields(&mut version_23);
        remove_nvenc_settings(&mut version_23);
        version_23["values"]
            .as_object_mut()
            .unwrap()
            .remove("install_steam_audio_drivers");
        let migrated = parse_document(&version_23).unwrap();
        assert_eq!(migrated.nvenc_settings, NvencSettings::default());

        let mut product = ProductSettings::new("Bootstrap".into(), settings::DEFAULT_PORT);
        product.apply_document(migrated);
        let mut action = display_update_action(DisplayPolicyUpdate::default(), 7);
        let AdminAction::Update { nvenc_settings, .. } = &mut action else {
            unreachable!()
        };
        *nvenc_settings = NvencSettingsUpdate {
            nvenc_preset: FieldUpdate::Value(7),
            nvenc_h264_cavlc: FieldUpdate::Value(true),
            nvenc_twopass: FieldUpdate::Value("full_res".into()),
            nvenc_vbv_increase: FieldUpdate::Value(400),
            nvenc_split_encode: FieldUpdate::Value("disabled".into()),
            nvenc_realtime_hags: FieldUpdate::Value(false),
            nvenc_opengl_vulkan_on_dxgi: FieldUpdate::Value(false),
            nvenc_latency_over_power: FieldUpdate::Value(false),
            vaapi_strict_rc_buffer: FieldUpdate::Value(true),
        };
        product.enqueue(99, 5_000, action).unwrap();
        product.start_next();
        let pending = product.pending.take().expect("NVENC settings update");
        assert_eq!(pending.payload["version"], SETTINGS_VERSION);
        assert_eq!(pending.payload["values"].as_object().unwrap().len(), 79);
        assert_eq!(pending.payload["values"]["nvenc_preset"], 7);
        assert_eq!(pending.payload["values"]["nvenc_twopass"], "full_res");
        assert_eq!(pending.payload["values"]["nvenc_split_encode"], "disabled");
        let confirmation = json!({
            "ok":true,"found":true,"version":SETTINGS_VERSION,"revision":8,
            "values":pending.payload["values"]
        });
        product.finish_call(pending.purpose, CallOutcome::Payload(confirmation.clone()));
        assert_eq!(product.completions.pop_front().unwrap().payload["ok"], true);
        let mut restarted = ProductSettings::new("Bootstrap".into(), settings::DEFAULT_PORT);
        restarted.apply_document(parse_document(&confirmation).unwrap());
        assert_eq!(restarted.nvenc_settings().nvenc_preset, 7);
        assert_eq!(
            restarted.nvenc_settings().nvenc_twopass,
            amaterasu_module_sdk::NvencTwoPass::FullRes
        );
        assert!(restarted.nvenc_settings().vaapi_strict_rc_buffer);

        for (preset, increase) in [(8, 0), (1, 401)] {
            let invalid = NvencSettings {
                nvenc_preset: preset,
                nvenc_vbv_increase: increase,
                ..Default::default()
            };
            assert!(invalid.validate().is_err());
        }
    }
}
