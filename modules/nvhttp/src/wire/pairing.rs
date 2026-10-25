use super::RequestContext;
use super::query::hex_bytes;
use super::{
    Call, ClientConfigOverrides, Job, PAIRING_TIMEOUT, Purpose, Query, Reply, Router,
    SERVICE_TIMEOUT, xml,
};
use serde_json::{Value, json};
use std::net::IpAddr;
use std::time::{Duration, Instant};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    Challenge,
    ServerResponse,
    ClientSecret,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Stage {
    Beginning,
    Pin,
    Challenge,
    ServerResponse,
    ClientSecret,
    Complete,
}

pub(super) struct Transcript {
    remote: IpAddr,
    certificate_der: Vec<u8>,
    pub pairing_id: Option<String>,
    stage: Stage,
    active: bool,
    pub deadline: Instant,
}

struct BeginRequest {
    pem: String,
    der: Vec<u8>,
    salt: String,
    name: String,
}

struct PairContext<'a> {
    connection: u64,
    client: &'a str,
    peer: &'a RequestContext,
    now: Instant,
}

enum PairRequest {
    Begin(BeginRequest),
    Phase { phase: Phase, value: String },
    Verify,
}

impl PairRequest {
    fn parse(query: &Query) -> Result<Self, &'static str> {
        let selectors = [
            "phrase",
            "clientchallenge",
            "serverchallengeresp",
            "clientpairingsecret",
        ];
        if selectors
            .iter()
            .filter(|name| query.get(name).is_some())
            .count()
            != 1
        {
            return Err("exactly one pairing phase is required");
        }
        if let Some(phrase) = query.get("phrase") {
            return match phrase {
                "getservercert" => {
                    let pem_bytes = hex_bytes(query.required("clientcert")?, 4096)?;
                    let (label, der) = pem_rfc7468::decode_vec(&pem_bytes)
                        .map_err(|_| "invalid client certificate PEM")?;
                    if label != "CERTIFICATE" {
                        return Err("client certificate PEM label is invalid");
                    }
                    let pem = String::from_utf8(pem_bytes)
                        .map_err(|_| "client certificate is not UTF-8 PEM")?;
                    let salt = query.required("salt")?;
                    if hex_bytes(salt, 16)?.len() != 16 {
                        return Err("salt must contain 16 bytes");
                    }
                    let name = query.get("devicename").unwrap_or("Moonlight");
                    if name.is_empty() || name.len() > 128 {
                        return Err("invalid device name");
                    }
                    Ok(Self::Begin(BeginRequest {
                        pem,
                        der,
                        salt: salt.into(),
                        name: name.into(),
                    }))
                }
                "pairchallenge" => Ok(Self::Verify),
                _ => Err("unsupported pairing phrase"),
            };
        }
        let (phase, name, minimum, maximum) = if query.get("clientchallenge").is_some() {
            (Phase::Challenge, "clientchallenge", 16, 16)
        } else if query.get("serverchallengeresp").is_some() {
            (Phase::ServerResponse, "serverchallengeresp", 32, 32)
        } else {
            (Phase::ClientSecret, "clientpairingsecret", 272, 528)
        };
        let value = query.required(name)?;
        if hex_bytes(value, maximum)?.len() < minimum {
            return Err("pairing phase has an invalid length");
        }
        Ok(Self::Phase {
            phase,
            value: value.into(),
        })
    }
}

impl Router {
    pub(super) fn pair(
        &mut self,
        connection: u64,
        query: Query,
        peer: &RequestContext,
        now: Instant,
    ) -> Option<Reply> {
        let client = match query.client_id() {
            Ok(client) => client.to_owned(),
            Err(error) => return Some(xml::error(400, error)),
        };
        let request = match PairRequest::parse(&query) {
            Ok(request) => request,
            Err(error) => return Some(xml::error(400, error)),
        };
        let context = PairContext {
            connection,
            client: &client,
            peer,
            now,
        };
        match request {
            PairRequest::Begin(request) => self.begin(context, request),
            PairRequest::Verify => Some(self.verify(
                &client,
                peer.remote,
                peer.peer_certificate.as_deref(),
                peer.trusted(),
                now,
            )),
            PairRequest::Phase { phase, value } => self.phase(context, &query, phase, value),
        }
    }

    fn begin(&mut self, context: PairContext<'_>, request: BeginRequest) -> Option<Reply> {
        let PairContext {
            connection,
            client,
            peer,
            now,
        } = context;
        let BeginRequest {
            pem,
            der,
            salt,
            name,
        } = request;
        let remote = peer.remote;
        let peer_certificate = peer.peer_certificate.as_deref();
        if peer_certificate.is_some_and(|peer| peer != der) {
            return Some(xml::error(
                403,
                "TLS certificate does not match pairing certificate",
            ));
        }
        // Neither a new remote nor a replacement certificate may cancel a
        // pending client's transcript by merely copying its uniqueid.
        if self.transcripts.contains_key(client) {
            return Some(xml::error(409, "client already has a pairing transcript"));
        }
        if self.transcripts.len() >= 8 {
            return Some(xml::error(503, "pairing capacity exhausted"));
        }
        let deadline = now + PAIRING_TIMEOUT;
        let payload = json!({"action":"begin","client_id":client,"name":name,"client_certificate_pem":pem,"salt":salt});
        if let Err(error) = self.queue(
            Some(connection),
            Purpose::Begin {
                client: client.into(),
            },
            payload,
            deadline,
            now,
        ) {
            return Some(xml::error(503, error));
        }
        self.transcripts.insert(
            client.into(),
            Transcript {
                remote,
                certificate_der: der,
                pairing_id: None,
                stage: Stage::Beginning,
                active: true,
                deadline,
            },
        );
        None
    }

    fn verify(
        &self,
        client: &str,
        remote: IpAddr,
        peer_certificate: Option<&[u8]>,
        trusted: bool,
        now: Instant,
    ) -> Reply {
        if !trusted {
            return xml::error(401, "authenticated paired TLS is required");
        }
        let Some(transcript) = self.transcripts.get(client) else {
            return xml::error(409, "pairing transcript is no longer available");
        };
        if now >= transcript.deadline || transcript.stage != Stage::Complete {
            return xml::error(409, "pairing transcript is incomplete or expired");
        }
        if transcript.remote != remote
            || peer_certificate != Some(transcript.certificate_der.as_slice())
        {
            return xml::error(403, "TLS identity does not match this pairing transcript");
        }
        xml::paired()
    }

    fn phase(
        &mut self,
        context: PairContext<'_>,
        query: &Query,
        phase: Phase,
        value: String,
    ) -> Option<Reply> {
        let PairContext {
            connection,
            client,
            peer,
            now,
        } = context;
        let remote = peer.remote;
        let peer_certificate = peer.peer_certificate.as_deref();
        let Some(transcript) = self.transcripts.get(client) else {
            return Some(xml::error(404, "pairing transcript not found"));
        };
        if transcript.remote != remote
            || peer_certificate.is_some_and(|peer| peer != transcript.certificate_der)
        {
            return Some(xml::error(403, "pairing peer does not match"));
        }
        if let Some(certificate) = query.get("clientcert") {
            let matches = hex_bytes(certificate, 4096)
                .ok()
                .and_then(|pem| {
                    pem_rfc7468::decode_vec(&pem).ok().map(|(label, der)| {
                        label == "CERTIFICATE" && der == transcript.certificate_der
                    })
                })
                .unwrap_or(false);
            if !matches {
                return Some(xml::error(403, "pairing certificate does not match"));
            }
        }
        if now >= transcript.deadline {
            return Some(xml::error(408, "pairing transcript expired"));
        }
        if transcript.active || transcript.stage != phase.expected_stage() {
            return Some(xml::error(
                409,
                "pairing phase is busy, replayed, or out of order",
            ));
        }
        let Some(pairing_id) = &transcript.pairing_id else {
            return Some(xml::error(
                409,
                "pairing transcript has no authority identifier",
            ));
        };
        let mut payload = json!({"action":phase.action(),"pairing_id":pairing_id});
        payload[phase.field()] = value.into();
        let deadline = transcript.deadline.min(now + SERVICE_TIMEOUT);
        if let Err(error) = self.queue(
            Some(connection),
            Purpose::Phase {
                client: client.into(),
                phase,
            },
            payload,
            deadline,
            now,
        ) {
            return Some(xml::error(503, error));
        }
        self.transcripts
            .get_mut(client)
            .expect("validated transcript")
            .active = true;
        None
    }

    pub(super) fn resolve(
        &mut self,
        job: Job,
        result: Result<Value, String>,
        now: Instant,
        replies: &mut Vec<(u64, Reply)>,
    ) -> Option<Job> {
        if matches!(job.purpose, Purpose::Cleanup) {
            return None;
        }
        if let Purpose::LaunchIdentity { .. } = &job.purpose
            && let Ok(payload) = &result
            && payload["ok"] != true
            && payload["code"] == "not_paired"
        {
            complete(
                &job,
                xml::error(401, "authenticated client is no longer paired"),
                replies,
            );
            return None;
        }
        let payload = match result {
            Ok(payload) if payload["ok"] == true => payload,
            _ => {
                if let Some(client) = job.purpose.client() {
                    self.abort_transcript(client, now);
                }
                complete(
                    &job,
                    xml::error(
                        503,
                        "pairing authority rejected or could not complete the operation",
                    ),
                    replies,
                );
                return None;
            }
        };
        match job.purpose.clone() {
            Purpose::Identity { paired, peer } => {
                let current_game = peer
                    .as_ref()
                    .map_or(0, |peer| self.launches.current_game(peer));
                let reply = match payload
                    .get("host_id")
                    .and_then(Value::as_str)
                    .filter(|id| !id.is_empty() && id.len() <= 64)
                {
                    Some(host_id) => xml::server_info(
                        &self.config,
                        host_id,
                        paired,
                        current_game,
                        self.launches.busy(),
                        self.launches.supported(),
                        self.launches.codec_advertisement(),
                    ),
                    None => xml::error(503, "host identity is unavailable"),
                };
                complete(&job, reply, replies);
                None
            }
            Purpose::Unpair => {
                let reply = match payload.get("unpaired").and_then(Value::as_u64) {
                    Some(removed @ (0 | 1)) => xml::unpaired(removed == 1),
                    _ => xml::error(503, "invalid unpair response"),
                };
                complete(&job, reply, replies);
                None
            }
            Purpose::Begin { client } => self.resolve_begin(job, &client, payload, now, replies),
            Purpose::Certificate { client } => {
                self.resolve_certificate(job, &client, payload, now, replies)
            }
            Purpose::Phase { client, phase } => {
                let reply = phase.reply(&payload);
                self.advance_transcript(&client, phase.next_stage(), reply.status == 200, now);
                complete(&job, reply, replies);
                None
            }
            Purpose::LaunchIdentity {
                request,
                peer,
                resume,
            } => {
                let connection = job.connection?;
                let Some(client_id) = payload.get("client_id").and_then(Value::as_str) else {
                    complete(
                        &job,
                        xml::error(503, "invalid paired client response"),
                        replies,
                    );
                    return None;
                };
                let Some(certificate_id) = payload.get("certificate_id").and_then(Value::as_str)
                else {
                    complete(
                        &job,
                        xml::error(503, "invalid paired client response"),
                        replies,
                    );
                    return None;
                };
                let config_overrides = match payload.get("config_overrides") {
                    None | Some(Value::Null) => ClientConfigOverrides::default(),
                    Some(value) => match serde_json::from_value(value.clone()) {
                        Ok(config_overrides) => config_overrides,
                        Err(_) => {
                            complete(
                                &job,
                                xml::error(503, "invalid paired client response"),
                                replies,
                            );
                            return None;
                        }
                    },
                };
                if payload["paired"] != 1 {
                    complete(
                        &job,
                        xml::error(503, "invalid paired client response"),
                        replies,
                    );
                    return None;
                }
                let peer = match peer.with_paired_identity(
                    client_id.into(),
                    certificate_id.into(),
                    config_overrides,
                ) {
                    Ok(peer) => peer,
                    Err(_) => {
                        complete(
                            &job,
                            xml::error(503, "invalid paired client response"),
                            replies,
                        );
                        return None;
                    }
                };
                let reply = if resume {
                    self.launches.resume(connection, request, &peer, now)
                } else {
                    self.launches.launch(connection, request, peer, now)
                };
                if let Some(reply) = reply {
                    complete(&job, reply, replies);
                }
                None
            }
            Purpose::Cleanup | Purpose::Applications { .. } => None,
        }
    }

    fn resolve_begin(
        &mut self,
        mut job: Job,
        client: &str,
        payload: Value,
        now: Instant,
        replies: &mut Vec<(u64, Reply)>,
    ) -> Option<Job> {
        let Some(pairing_id) = payload
            .get("pairing_id")
            .and_then(Value::as_str)
            .filter(|id| !id.is_empty() && id.len() <= 128)
        else {
            self.abort_transcript(client, now);
            complete(
                &job,
                xml::error(503, "invalid pairing authority response"),
                replies,
            );
            return None;
        };
        let transcript = self.transcripts.get_mut(client)?;
        transcript.pairing_id = Some(pairing_id.into());
        transcript.stage = Stage::Pin;
        if job.connection.is_none() {
            self.abort_transcript(client, now);
            return None;
        }
        job.call = Call::Ready {
            payload: json!({"action":"get_server_cert","pairing_id":pairing_id}),
            not_before: now,
        };
        job.purpose = Purpose::Certificate {
            client: client.into(),
        };
        Some(job)
    }

    fn resolve_certificate(
        &mut self,
        mut job: Job,
        client: &str,
        payload: Value,
        now: Instant,
        replies: &mut Vec<(u64, Reply)>,
    ) -> Option<Job> {
        if payload["pending"] == true {
            let transcript = self.transcripts.get(client)?;
            job.call = Call::Ready {
                payload: json!({"action":"get_server_cert","pairing_id":transcript.pairing_id}),
                not_before: now + Duration::from_millis(250),
            };
            return Some(job);
        }
        let reply = phase_reply(&payload, "plaincert", 1, 4096);
        self.advance_transcript(client, Stage::Challenge, reply.status == 200, now);
        complete(&job, reply, replies);
        None
    }

    fn advance_transcript(
        &mut self,
        client: &str,
        next_stage: Stage,
        succeeded: bool,
        now: Instant,
    ) {
        if !succeeded {
            self.abort_transcript(client, now);
            return;
        }
        if let Some(transcript) = self.transcripts.get_mut(client) {
            transcript.stage = next_stage;
            transcript.active = false;
        }
    }
}

impl Phase {
    fn reply(self, payload: &Value) -> Reply {
        match self {
            Self::Challenge => phase_reply(payload, "challengeresponse", 48, 48),
            Self::ServerResponse => phase_reply(payload, "pairingsecret", 272, 528),
            Self::ClientSecret => {
                let persisted = payload["paired"] == 1
                    && payload
                        .get("certificate_id")
                        .and_then(Value::as_str)
                        .is_some_and(|id| hex_bytes(id, 32).is_ok_and(|bytes| bytes.len() == 32));
                if persisted {
                    xml::paired()
                } else {
                    xml::error(503, "pairing persistence was not acknowledged")
                }
            }
        }
    }

    fn expected_stage(self) -> Stage {
        match self {
            Self::Challenge => Stage::Challenge,
            Self::ServerResponse => Stage::ServerResponse,
            Self::ClientSecret => Stage::ClientSecret,
        }
    }
    fn next_stage(self) -> Stage {
        match self {
            Self::Challenge => Stage::ServerResponse,
            Self::ServerResponse => Stage::ClientSecret,
            Self::ClientSecret => Stage::Complete,
        }
    }
    fn action(self) -> &'static str {
        match self {
            Self::Challenge => "client_challenge",
            Self::ServerResponse => "server_challenge_response",
            Self::ClientSecret => "client_pairing_secret",
        }
    }
    fn field(self) -> &'static str {
        match self {
            Self::Challenge => "clientchallenge",
            Self::ServerResponse => "serverchallengeresp",
            Self::ClientSecret => "clientpairingsecret",
        }
    }
}

fn phase_reply(payload: &Value, field: &str, minimum: usize, maximum: usize) -> Reply {
    if payload["paired"] != 1 {
        return xml::error(503, "pairing phase was not acknowledged");
    }
    let Some(value) = payload.get(field).and_then(Value::as_str) else {
        return xml::error(503, "pairing phase response is missing");
    };
    if !hex_bytes(value, maximum).is_ok_and(|bytes| bytes.len() >= minimum) {
        return xml::error(503, "pairing phase response is invalid");
    }
    xml::response(200, "OK", &[("paired", "1"), (field, value)])
}

fn complete(job: &Job, reply: Reply, replies: &mut Vec<(u64, Reply)>) {
    if let Some(connection) = job.connection {
        replies.push((connection, reply));
    }
}
