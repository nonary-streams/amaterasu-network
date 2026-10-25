//! Rustls owns TLS; the pairing provider retains private keys behind IdentityApi.
use amaterasu_identity::IdentityApi;
use amaterasu_module_sdk::{NativeBinding, RuntimeClient, abi::*};
use rustls::{
    CertificateError, DigitallySignedStruct, DistinguishedName, Error, ServerConfig,
    SignatureAlgorithm, SignatureScheme,
    client::danger::HandshakeSignatureValid,
    crypto::CryptoProvider,
    pki_types::{CertificateDer, UnixTime},
    server::danger::{ClientCertVerified, ClientCertVerifier},
    sign::{CertifiedKey, Signer, SigningKey, SingleCertAndKey},
};
use std::{
    ffi::c_void,
    fmt,
    sync::{Arc, Mutex},
};
use x509_cert::{
    Certificate,
    der::{Decode, Encode},
};

struct NativeCalls {
    context: *mut c_void,
    certificate: unsafe extern "C" fn(*mut c_void, ReplySink) -> Status,
    sign: unsafe extern "C" fn(*mut c_void, u32, BorrowedBytes, ReplySink) -> Status,
    verify: unsafe extern "C" fn(*mut c_void, BorrowedBytes) -> Status,
}

struct Bridge {
    calls: NativeCalls,
    active: Mutex<bool>,
}
// SAFETY: IdentityApi explicitly promises concurrent calls are thread-safe while
// its binding lives. The active gate serializes calls and owner shutdown, so
// shutdown waits for in-flight calls before releasing the binding. Rustls objects
// cannot call native pointers after shutdown; neither bindings nor APIs escape.
unsafe impl Send for Bridge {}
// SAFETY: the same gate/lifetime contract protects every shared native operation.
unsafe impl Sync for Bridge {}

impl fmt::Debug for Bridge {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PairingIdentityBridge")
    }
}

impl Bridge {
    fn close(&self) {
        // Poison also means no future operation may call into the provider.
        if let Ok(mut active) = self.active.lock() {
            *active = false;
        }
    }

    fn certificate(&self) -> Result<Vec<u8>, Error> {
        let active = self.active.lock().map_err(|_| identity_error())?;
        if !*active {
            return Err(identity_error());
        }
        collect(amaterasu_identity::MAX_CERTIFICATE_BYTES, |sink| {
            // SAFETY: active gate pins the documented thread-safe native binding.
            unsafe { (self.calls.certificate)(self.calls.context, sink) }
        })
    }

    fn sign(&self, scheme: SignatureScheme, message: &[u8]) -> Result<Vec<u8>, Error> {
        if message.len() > amaterasu_identity::MAX_MESSAGE_BYTES {
            return Err(identity_error());
        }
        let active = self.active.lock().map_err(|_| identity_error())?;
        if !*active {
            return Err(identity_error());
        }
        collect(amaterasu_identity::MAX_SIGNATURE_BYTES, |sink| {
            // SAFETY: message/reply allocation remains live through synchronous
            // callback; the active gate prevents releasing the provider binding.
            unsafe {
                (self.calls.sign)(
                    self.calls.context,
                    u32::from(u16::from(scheme)),
                    BorrowedBytes::new(message),
                    sink,
                )
            }
        })
    }

    fn trusted(&self, certificate: &[u8]) -> bool {
        if certificate.is_empty() || certificate.len() > amaterasu_identity::MAX_CERTIFICATE_BYTES {
            return false;
        }
        let Ok(active) = self.active.lock() else {
            return false;
        };
        if !*active {
            return false;
        }
        // SAFETY: exact committed membership is checked on the live provider;
        // proof of possession was separately checked during the TLS handshake.
        unsafe {
            (self.calls.verify)(self.calls.context, BorrowedBytes::new(certificate)) == STATUS_OK
        }
    }
}

pub struct Identity {
    bridge: Arc<Bridge>,
    binding: Option<NativeBinding>,
}
impl Identity {
    pub fn bind(runtime: &RuntimeClient) -> Result<Self, String> {
        // SAFETY: signed dependency order keeps the identity provider loaded;
        // this owner gates all cloned signer references before releasing binding.
        let binding = unsafe {
            runtime.bind_native(
                amaterasu_identity::SERVICE,
                amaterasu_identity::INTERFACE_MAJOR,
                amaterasu_identity::INTERFACE_MINOR,
                size_of::<IdentityApi>() as u32,
            )
        }?;
        let bridge = {
            // SAFETY: requested product interface/version/size match IdentityApi.
            let api = unsafe { binding.table::<IdentityApi>() }?;
            Arc::new(Bridge {
                calls: NativeCalls {
                    context: binding.context(),
                    certificate: api.certificate,
                    sign: api.sign,
                    verify: api.verify_client,
                },
                active: Mutex::new(true),
            })
        };
        Ok(Self {
            bridge,
            binding: Some(binding),
        })
    }

    pub fn certificate(&self) -> Option<Vec<u8>> {
        self.bridge.certificate().ok()
    }

    pub fn trusted(&self, certificate: &[u8]) -> bool {
        self.bridge.trusted(certificate)
    }

    pub fn configuration(&self, certificate: Vec<u8>) -> Result<Arc<ServerConfig>, Error> {
        let certificate = CertificateDer::from(certificate);
        parse_certificate(&certificate)?;
        let key = CertifiedKey::new(
            vec![certificate],
            Arc::new(DelegatedKey(self.bridge.clone())),
        );
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let verifier = Arc::new(PossessionVerifier {
            provider: provider.clone(),
        });
        let mut configuration = ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()?
            .with_client_cert_verifier(verifier)
            .with_cert_resolver(Arc::new(SingleCertAndKey::from(key)));
        configuration.alpn_protocols = vec![b"http/1.1".to_vec()];
        configuration.max_early_data_size = 0;
        configuration.send_tls13_tickets = 0;
        // No resumption cache can bypass client CertificateVerify or preserve
        // stale identity across pairing/host-certificate changes.
        configuration.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
        Ok(Arc::new(configuration))
    }
}

impl Drop for Identity {
    fn drop(&mut self) {
        self.bridge.close();
        drop(self.binding.take());
    }
}

#[derive(Debug)]
struct DelegatedKey(Arc<Bridge>);
impl SigningKey for DelegatedKey {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        [
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
        ]
        .into_iter()
        .find(|scheme| offered.contains(scheme))
        .map(|scheme| {
            Box::new(DelegatedSigner {
                bridge: self.0.clone(),
                scheme,
            }) as Box<dyn Signer>
        })
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::RSA
    }
}

#[derive(Debug)]
struct DelegatedSigner {
    bridge: Arc<Bridge>,
    scheme: SignatureScheme,
}
impl Signer for DelegatedSigner {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        self.bridge.sign(self.scheme, message)
    }
    fn scheme(&self) -> SignatureScheme {
        self.scheme
    }
}

#[derive(Debug)]
struct PossessionVerifier {
    provider: Arc<CryptoProvider>,
}
impl ClientCertVerifier for PossessionVerifier {
    fn client_auth_mandatory(&self) -> bool {
        false
    }
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _: UnixTime,
    ) -> Result<ClientCertVerified, Error> {
        if end_entity.len() > amaterasu_identity::MAX_CERTIFICATE_BYTES || !intermediates.is_empty()
        {
            return Err(Error::InvalidCertificate(CertificateError::BadEncoding));
        }
        parse_certificate(end_entity)?;
        // Public pairing accepts an untrusted self-issued client certificate.
        // This assertion is ONLY syntactic admission, not application trust.
        // Rustls invokes the signature verifiers below to prove key possession;
        // protected routes additionally require live paired-DER verification.
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.verify_possession(
            message,
            certificate,
            signature.scheme,
            signature.signature(),
            false,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.verify_possession(
            message,
            certificate,
            signature.scheme,
            signature.signature(),
            true,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
            .into_iter()
            .filter(|scheme| rsa_scheme(*scheme, false))
            .collect()
    }
}

impl PossessionVerifier {
    fn verify_possession(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        scheme: SignatureScheme,
        signature: &[u8],
        tls13: bool,
    ) -> Result<HandshakeSignatureValid, Error> {
        if !rsa_scheme(scheme, tls13) {
            return Err(Error::InvalidCertificate(CertificateError::BadSignature));
        }
        let certificate = parse_certificate(certificate)?;
        let public_key = &certificate.tbs_certificate.subject_public_key_info;
        let mut identifier = public_key
            .algorithm
            .oid
            .to_der()
            .map_err(|_| bad_encoding())?;
        if let Some(parameters) = &public_key.algorithm.parameters {
            identifier.extend(parameters.to_der().map_err(|_| bad_encoding())?);
        }
        let bits = public_key
            .subject_public_key
            .as_bytes()
            .ok_or_else(bad_encoding)?;
        let algorithms = self
            .provider
            .signature_verification_algorithms
            .mapping
            .iter()
            .find(|(candidate, _)| *candidate == scheme)
            .map(|(_, algorithms)| *algorithms)
            .ok_or_else(bad_encoding)?;
        // WebPKI's certificate wrappers intentionally reject X.509 v1, which
        // legacy Moonlight certificates use. The vetted x509-cert parser admits
        // those certificates; rustls's configured ring algorithms still perform
        // all signature hashing and verification over the exact handshake bytes.
        // Match the complete SPKI algorithm identifier before selecting crypto.
        for algorithm in algorithms.iter().take(if tls13 { 1 } else { usize::MAX }) {
            if algorithm.public_key_alg_id().as_ref() == identifier
                && algorithm.verify_signature(bits, message, signature).is_ok()
            {
                return Ok(HandshakeSignatureValid::assertion());
            }
        }
        Err(Error::InvalidCertificate(CertificateError::BadSignature))
    }
}

fn rsa_scheme(scheme: SignatureScheme, tls13: bool) -> bool {
    match scheme {
        SignatureScheme::RSA_PSS_SHA256
        | SignatureScheme::RSA_PSS_SHA384
        | SignatureScheme::RSA_PSS_SHA512 => true,
        SignatureScheme::RSA_PKCS1_SHA256
        | SignatureScheme::RSA_PKCS1_SHA384
        | SignatureScheme::RSA_PKCS1_SHA512 => !tls13,
        _ => false,
    }
}

fn parse_certificate(certificate: &CertificateDer<'_>) -> Result<Certificate, Error> {
    if certificate.is_empty() || certificate.len() > amaterasu_identity::MAX_CERTIFICATE_BYTES {
        return Err(bad_encoding());
    }
    Certificate::from_der(certificate).map_err(|_| bad_encoding())
}

fn bad_encoding() -> Error {
    Error::InvalidCertificate(CertificateError::BadEncoding)
}

struct Collected {
    bytes: Vec<u8>,
    maximum: usize,
    calls: usize,
    invalid: bool,
}
fn collect(maximum: usize, call: impl FnOnce(ReplySink) -> Status) -> Result<Vec<u8>, Error> {
    let mut result = Collected {
        bytes: Vec::new(),
        maximum,
        calls: 0,
        invalid: false,
    };
    let sink = ReplySink {
        context: (&mut result as *mut Collected).cast(),
        write: copy_reply,
    };
    if call(sink) != STATUS_OK || result.invalid || result.calls != 1 || result.bytes.is_empty() {
        return Err(identity_error());
    }
    Ok(result.bytes)
}

unsafe extern "C" fn copy_reply(context: *mut c_void, bytes: BorrowedBytes) {
    // SAFETY: this callback receives its exclusive stack collector for one
    // synchronous native call; the provider guarantees reply allocation validity.
    let result = unsafe { &mut *context.cast::<Collected>() };
    result.calls += 1;
    if result.calls != 1 || bytes.len > result.maximum {
        result.invalid = true;
        return;
    }
    match unsafe { bytes.read() } {
        Ok(bytes) => result.bytes.extend_from_slice(bytes),
        Err(_) => result.invalid = true,
    }
}
fn identity_error() -> Error {
    Error::General("pairing identity unavailable".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    unsafe extern "C" fn certificate(_: *mut c_void, sink: ReplySink) -> Status {
        // SAFETY: test passes a synchronous live collector.
        unsafe {
            sink.send(&[1, 2, 3]);
        }
        STATUS_OK
    }

    unsafe extern "C" fn sign(
        context: *mut c_void,
        scheme: u32,
        message: BorrowedBytes,
        sink: ReplySink,
    ) -> Status {
        // SAFETY: fixture context is a live atomic counter and the borrowed
        // input/sink are supplied by the synchronous bridge invocation.
        unsafe { &*context.cast::<AtomicUsize>() }.fetch_add(1, Ordering::SeqCst);
        assert_eq!(scheme, amaterasu_identity::TLS_RSA_PSS_RSAE_SHA256);
        assert_eq!(unsafe { message.read().unwrap() }, b"TLS transcript");
        unsafe {
            sink.send(&[7; 256]);
        }
        STATUS_OK
    }

    unsafe extern "C" fn verify(_: *mut c_void, _: BorrowedBytes) -> Status {
        STATUS_OK
    }

    #[test]
    fn cloned_rustls_signer_cannot_call_identity_after_owner_gate_closes() {
        let counter = AtomicUsize::new(0);
        let bridge = Arc::new(Bridge {
            calls: NativeCalls {
                context: (&counter as *const AtomicUsize).cast_mut().cast(),
                certificate,
                sign,
                verify,
            },
            active: Mutex::new(true),
        });
        let key = DelegatedKey(bridge.clone());
        assert!(key.choose_scheme(&[SignatureScheme::ED25519]).is_none());
        let signer = key
            .choose_scheme(&[SignatureScheme::RSA_PSS_SHA256])
            .unwrap();
        assert_eq!(signer.sign(b"TLS transcript").unwrap().len(), 256);
        bridge.close();
        assert!(signer.sign(b"TLS transcript").is_err());
        assert!(bridge.certificate().is_err());
        assert!(!bridge.trusted(&[1]));
        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn native_reply_limits_and_malformed_client_certificates_fail_closed() {
        assert!(
            collect(4, |sink| {
                unsafe {
                    sink.send(&[0; 5]);
                }
                STATUS_OK
            })
            .is_err()
        );
        assert!(
            collect(4, |sink| {
                unsafe {
                    sink.send(&[1]);
                    sink.send(&[2]);
                }
                STATUS_OK
            })
            .is_err()
        );
        assert!(collect(4, |_| STATUS_OK).is_err());
        let verifier = PossessionVerifier {
            provider: Arc::new(rustls::crypto::ring::default_provider()),
        };
        assert!(
            verifier
                .verify_client_cert(
                    &CertificateDer::from(vec![1, 2, 3]),
                    &[],
                    UnixTime::since_unix_epoch(std::time::Duration::from_secs(0))
                )
                .is_err()
        );
    }
    #[test]
    fn fixture_host_der_builds_delegated_rustls_configuration() {
        let (_, der) = pem_rfc7468::decode_vec(include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/host-cert.pem"
        )))
        .unwrap();
        let identity = Identity {
            bridge: Arc::new(Bridge {
                calls: NativeCalls {
                    context: std::ptr::null_mut(),
                    certificate,
                    sign,
                    verify,
                },
                active: Mutex::new(true),
            }),
            binding: None,
        };
        identity.configuration(der).unwrap();
    }

    #[test]
    fn legacy_v1_client_possession_uses_real_ring_crypto_and_rejects_tampering() {
        use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
        let (_, certificate) = pem_rfc7468::decode_vec(include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/client-cert.pem"
        )))
        .unwrap();
        let certificate = CertificateDer::from(certificate);
        let parsed = parse_certificate(&certificate).unwrap();
        assert_eq!(parsed.tbs_certificate.version, x509_cert::Version::V1);
        let (_, key) = pem_rfc7468::decode_vec(include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/client-key.pem"
        )))
        .unwrap();
        let key = rustls::crypto::ring::sign::any_supported_type(&PrivateKeyDer::Pkcs8(
            PrivatePkcs8KeyDer::from(key),
        ))
        .unwrap();
        let verifier = PossessionVerifier {
            provider: Arc::new(rustls::crypto::ring::default_provider()),
        };
        let (_, foreign) = pem_rfc7468::decode_vec(include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/host-cert.pem"
        )))
        .unwrap();
        let foreign = CertificateDer::from(foreign);
        for scheme in [
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PSS_SHA256,
        ] {
            let signer = key.choose_scheme(&[scheme]).unwrap();
            let message = b"actual TLS possession test transcript";
            let signature = signer.sign(message).unwrap();
            verifier
                .verify_possession(message, &certificate, scheme, &signature, false)
                .unwrap();
            if scheme == SignatureScheme::RSA_PSS_SHA256 {
                verifier
                    .verify_possession(message, &certificate, scheme, &signature, true)
                    .unwrap();
            } else {
                assert!(
                    verifier
                        .verify_possession(message, &certificate, scheme, &signature, true)
                        .is_err()
                );
            }
            assert!(
                verifier
                    .verify_possession(message, &foreign, scheme, &signature, false)
                    .is_err()
            );
            let mut altered = signature.clone();
            altered[0] ^= 1;
            assert!(
                verifier
                    .verify_possession(message, &certificate, scheme, &altered, false)
                    .is_err()
            );
            assert!(
                verifier
                    .verify_possession(
                        b"different transcript",
                        &certificate,
                        scheme,
                        &signature,
                        false
                    )
                    .is_err()
            );
            assert!(
                verifier
                    .verify_possession(
                        message,
                        &certificate,
                        SignatureScheme::RSA_PSS_SHA384,
                        &signature,
                        false
                    )
                    .is_err()
            );
        }
    }
}
