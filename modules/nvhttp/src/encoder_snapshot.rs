//! The encoder capability snapshot and the codec offer it allows per launch.
//!
//! The snapshot is the `encoders` list of an `amaterasu.encode/1` enumerate
//! reply, reduced to what codec advertisement needs: each entry's codec and
//! whether it is a hardware encoder. It drives the serverinfo codec mask and
//! the codecs RTSP may offer a launched client. A codec is never offered when
//! no enumerated encoder produces it.
use amaterasu_media::VideoCodec;
use amaterasu_module_sdk::{EncoderBackend, EncoderIdentity, EncoderSelection};
use serde_json::Value;

/// Moonlight's `ServerCodecModeSupport` bits (Limelight.h `SCM_*`). Only 8-bit
/// 4:2:0 modes are advertised: no encoder path here produces 10-bit or 4:4:4.
const SCM_H264: u32 = 0x0000_0001;
const SCM_HEVC: u32 = 0x0000_0100;
const SCM_AV1_MAIN8: u32 = 0x0001_0000;

/// Moonlight treats any nonzero `MaxLumaPixelsHEVC` as HEVC encode support and
/// zero as none. This is the luma rate Sunshine reports for HEVC hosts.
const HEVC_MAX_LUMA_PIXELS: u64 = 1_869_449_984;

/// The largest stream a software encoder is trusted to sustain.
pub const SOFTWARE_MAX_WIDTH: u32 = 1920;
pub const SOFTWARE_MAX_HEIGHT: u32 = 1080;
pub const SOFTWARE_MAX_FPS: u32 = 60;

/// Matches the video module's bound on one enumeration reply.
const MAX_ENCODERS: usize = 64;

#[derive(Clone, Debug, PartialEq, Eq)]
struct EncoderEntry {
    /// `None` for a codec this host cannot stream; it still holds its index.
    codec: Option<VideoCodec>,
    identity: Option<EncoderIdentity>,
    hardware: bool,
}

/// Enumerated encoders in registry order, so a numeric encoder selection
/// refers to the same entry the video module will open.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EncoderSnapshot {
    entries: Vec<EncoderEntry>,
}

/// The codecs one launch may negotiate, in Moonlight's preference order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CodecOffer {
    pub codecs: Vec<VideoCodec>,
    /// Some offered codec has only a software encoder, so negotiation stays
    /// within the software stream limit.
    pub software_limited: bool,
}

/// Values serverinfo advertises for the host's video codecs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CodecAdvertisement {
    pub codec_mode_support: u32,
    pub max_luma_pixels_hevc: u64,
}

impl CodecAdvertisement {
    /// What a host with streaming disabled reports.
    pub const NONE: Self = Self {
        codec_mode_support: 0,
        max_luma_pixels_hevc: 0,
    };
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StreamMode {
    pub width: u32,
    pub height: u32,
    pub fps: u32,
}

impl StreamMode {
    fn within_software_limit(self) -> bool {
        self.width <= SOFTWARE_MAX_WIDTH
            && self.height <= SOFTWARE_MAX_HEIGHT
            && self.fps <= SOFTWARE_MAX_FPS
    }
}

impl EncoderSnapshot {
    /// Parse an enumerate reply. A disabled encoder module yields an empty
    /// snapshot; a malformed reply is an error so the last good one is kept.
    pub fn parse(payload: &Value) -> Result<Self, &'static str> {
        if payload.get("ok").and_then(Value::as_bool) != Some(true) {
            return Err("encoder_enumeration_failed");
        }
        if payload.get("enabled").and_then(Value::as_bool) == Some(false) {
            return Ok(Self::default());
        }
        let encoders = payload
            .get("encoders")
            .and_then(Value::as_array)
            .filter(|encoders| encoders.len() <= MAX_ENCODERS)
            .ok_or("invalid_encoder_enumeration")?;
        let entries = encoders
            .iter()
            .map(encoder_entry)
            .collect::<Result<_, _>>()?;
        Ok(Self { entries })
    }

    /// The serverinfo codec mask. H.264 is always present while streaming is
    /// enabled: Moonlight refuses to start against a zero mask, and a host
    /// without an H.264 encoder refuses the launch with a clear error instead.
    pub fn advertisement(&self) -> CodecAdvertisement {
        let mut codec_mode_support = SCM_H264;
        if self.has(VideoCodec::Hevc) {
            codec_mode_support |= SCM_HEVC;
        }
        if self.has(VideoCodec::Av1) {
            codec_mode_support |= SCM_AV1_MAIN8;
        }
        CodecAdvertisement {
            codec_mode_support,
            max_luma_pixels_hevc: if self.has(VideoCodec::Hevc) {
                HEVC_MAX_LUMA_PIXELS
            } else {
                0
            },
        }
    }

    /// Codecs whose encoders can serve `mode`. A numeric selection pins one
    /// enumerated encoder and so exactly its codec; automatic selection
    /// offers every codec with a capable encoder. Above the software limit
    /// only hardware encoders qualify.
    pub fn offer(
        &self,
        selection: EncoderSelection,
        mode: StreamMode,
    ) -> Result<CodecOffer, &'static str> {
        let candidates: Vec<EncoderEntry> = match selection {
            EncoderSelection::Index(index) => {
                let entry = self
                    .entries
                    .get(index as usize)
                    .ok_or("no video encoder is available")?;
                vec![entry.clone()]
            }
            EncoderSelection::Identity(identity) => self
                .entries
                .iter()
                .filter(|entry| entry.identity.as_ref() == Some(&identity))
                .cloned()
                .collect(),
            EncoderSelection::Backend(EncoderBackend::Auto) => self.entries.clone(),
            EncoderSelection::Backend(EncoderBackend::Software) => self
                .entries
                .iter()
                .filter(|entry| !entry.hardware)
                .cloned()
                .collect(),
        };
        let mut codecs = Vec::new();
        let mut software_limited = false;
        let mut refused_software = false;
        for codec in [VideoCodec::Av1, VideoCodec::Hevc, VideoCodec::H264] {
            let mut encoders = candidates
                .iter()
                .filter(|entry| entry.codec == Some(codec))
                .peekable();
            if encoders.peek().is_none() {
                continue;
            }
            if encoders.any(|entry| entry.hardware) {
                codecs.push(codec);
            } else if mode.within_software_limit() {
                codecs.push(codec);
                software_limited = true;
            } else {
                refused_software = true;
            }
        }
        if codecs.is_empty() {
            return Err(if refused_software {
                "no hardware encoder for this stream mode"
            } else {
                "no video encoder is available"
            });
        }
        Ok(CodecOffer {
            codecs,
            software_limited,
        })
    }

    fn has(&self, codec: VideoCodec) -> bool {
        self.entries.iter().any(|entry| entry.codec == Some(codec))
    }
}

/// Before the first enumeration completes, assume a single software H.264
/// encoder: it never widens what the host offers.
pub fn unknown_encoders_offer(mode: StreamMode) -> Result<CodecOffer, &'static str> {
    if !mode.within_software_limit() {
        return Err("encoder capabilities are not known yet");
    }
    Ok(CodecOffer {
        codecs: vec![VideoCodec::H264],
        software_limited: true,
    })
}

fn encoder_entry(encoder: &Value) -> Result<EncoderEntry, &'static str> {
    let codec = encoder
        .get("codec")
        .and_then(Value::as_str)
        .ok_or("invalid_encoder_enumeration")?;
    let hardware = encoder
        .get("hardware")
        .and_then(Value::as_bool)
        .ok_or("invalid_encoder_enumeration")?;
    Ok(EncoderEntry {
        identity: encoder
            .get("identity")
            .cloned()
            .map(serde_json::from_value)
            .transpose()
            .map_err(|_| "invalid_encoder_enumeration")?,
        codec: match codec {
            "h264" => Some(VideoCodec::H264),
            "hevc" => Some(VideoCodec::Hevc),
            "av1" => Some(VideoCodec::Av1),
            _ => None,
        },
        hardware,
    })
}

#[cfg(test)]
mod tests;
