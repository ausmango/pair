use std::{fmt, sync::Arc};

use ring::{
    digest,
    rand::{SecureRandom, SystemRandom},
};
use rustls::{
    ClientConfig, DigitallySignedStruct, Error, ServerConfig, SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    crypto::{CryptoProvider, verify_tls12_signature, verify_tls13_signature},
    pki_types::{CertificateDer, PrivatePkcs8KeyDer, ServerName, UnixTime},
};
use subtle::ConstantTimeEq;

#[derive(Clone)]
pub struct Pairing {
    pub fingerprint: [u8; 32],
    token: [u8; 32],
}

pub fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(DIGITS[(byte >> 4) as usize] as char);
        out.push(DIGITS[(byte & 15) as usize] as char);
    }
    out
}

pub fn unhex(text: &str, max_bytes: usize) -> Result<Vec<u8>, &'static str> {
    if text.len() & 1 != 0 || text.len() / 2 > max_bytes || !text.is_ascii() {
        return Err("Invalid hexadecimal value.");
    }
    let mut out = Vec::with_capacity(text.len() / 2);
    for index in (0..text.len()).step_by(2) {
        let value = u8::from_str_radix(&text[index..index + 2], 16)
            .ok()
            .ok_or("Invalid hexadecimal value.")?;
        out.push(value);
    }
    Ok(out)
}

fn fixed_32(text: &str) -> Result<[u8; 32], &'static str> {
    unhex(text, 32)?
        .try_into()
        .map_err(|_| "Expected 64 hexadecimal digits.")
}

impl Pairing {
    pub fn new(fingerprint: [u8; 32], token: [u8; 32]) -> Self {
        Self { fingerprint, token }
    }

    pub fn parse(code: &str) -> Result<Self, &'static str> {
        let fields: Vec<_> = code.trim().split(':').collect();
        if fields.len() != 3 || fields[0] != "pair1" {
            return Err("Expected pair1:<certificate fingerprint>:<secret token>.");
        }
        Ok(Self::new(fixed_32(fields[1])?, fixed_32(fields[2])?))
    }

    pub fn code(&self) -> String {
        format!("pair1:{}:{}", hex(&self.fingerprint), hex(&self.token))
    }
    pub fn token(&self) -> String {
        hex(&self.token)
    }
    pub fn authenticates(&self, token: &str) -> bool {
        fixed_32(token).is_ok_and(|candidate| bool::from(self.token.ct_eq(&candidate)))
    }
}

pub fn random_bytes<const N: usize>() -> Result<[u8; N], &'static str> {
    let mut bytes = [0; N];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| "Operating system random number generator failed.")?;
    Ok(bytes)
}

pub fn certificate_fingerprint(cert: &[u8]) -> [u8; 32] {
    digest::digest(&digest::SHA256, cert)
        .as_ref()
        .try_into()
        .expect("SHA-256 is 32 bytes")
}

/// Six code words encode 48 fingerprint bits. The words are display encoding,
/// not a password or a cryptographic primitive.
pub fn safety_phrase(fingerprint: &[u8; 32]) -> String {
    const START: [&str; 16] = [
        "amber", "brisk", "calm", "dawn", "ember", "fresh", "gold", "honey", "ivory", "jade",
        "kind", "lunar", "maple", "navy", "opal", "pearl",
    ];
    const END: [&str; 16] = [
        "ant", "bird", "cedar", "deer", "elm", "fern", "goat", "hare", "iris", "jay", "kite",
        "leaf", "moth", "newt", "owl", "pine",
    ];
    fingerprint[..6]
        .iter()
        .map(|byte| {
            format!(
                "{}{}",
                START[(byte >> 4) as usize],
                END[(byte & 15) as usize]
            )
        })
        .collect::<Vec<_>>()
        .join(" ")
}

pub struct Identity {
    pub config: Arc<ServerConfig>,
    pub pairing: Pairing,
    cert_der: Vec<u8>,
    key_der: Vec<u8>,
}

fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

impl Identity {
    pub fn generate() -> Result<Self, &'static str> {
        let generated = rcgen::generate_simple_self_signed(vec!["pair.local".into()])
            .map_err(|_| "Could not generate the host TLS identity.")?;
        Self::from_der(
            generated.cert.der().to_vec(),
            generated.signing_key.serialize_der(),
            random_bytes()?,
        )
    }

    pub fn from_der(
        cert_der: Vec<u8>,
        key_der: Vec<u8>,
        token: [u8; 32],
    ) -> Result<Self, &'static str> {
        if cert_der.is_empty()
            || cert_der.len() > 16 * 1024
            || key_der.is_empty()
            || key_der.len() > 16 * 1024
        {
            return Err("Stored TLS identity is invalid.");
        }
        let fingerprint = certificate_fingerprint(&cert_der);
        let config = ServerConfig::builder_with_provider(provider())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|_| "Could not configure TLS 1.3.")?
            .with_no_client_auth()
            .with_single_cert(
                vec![CertificateDer::from(cert_der.clone())],
                PrivatePkcs8KeyDer::from(key_der.clone()).into(),
            )
            .map_err(|_| "Stored TLS certificate and private key do not match.")?;
        Ok(Self {
            config: Arc::new(config),
            pairing: Pairing::new(fingerprint, token),
            cert_der,
            key_der,
        })
    }

    pub fn cert_der(&self) -> &[u8] {
        &self.cert_der
    }
    pub fn key_der(&self) -> &[u8] {
        &self.key_der
    }
    pub fn set_token(&mut self, token: [u8; 32]) {
        self.pairing = Pairing::new(self.pairing.fingerprint, token);
    }
}

struct CertificateVerifier {
    fingerprint: Option<[u8; 32]>,
    provider: Arc<CryptoProvider>,
}

impl fmt::Debug for CertificateVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(if self.fingerprint.is_some() {
            "PinnedCertificate"
        } else {
            "PendingCertificate"
        })
    }
}

impl ServerCertVerifier for CertificateVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        if let Some(expected) = self.fingerprint {
            let actual = certificate_fingerprint(end_entity.as_ref());
            if !bool::from(expected.ct_eq(&actual)) {
                return Err(Error::General(
                    "Host certificate fingerprint changed.".into(),
                ));
            }
        }
        // None is restricted to the visibly unverified pairing session. That
        // session receives no note state and requires confirmation on both screens.
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

fn config(fingerprint: Option<[u8; 32]>) -> Arc<ClientConfig> {
    Arc::new(
        ClientConfig::builder_with_provider(provider())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .expect("ring supports TLS 1.3")
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(CertificateVerifier {
                fingerprint,
                provider: provider(),
            }))
            .with_no_client_auth(),
    )
}

pub fn client_config(pairing: &Pairing) -> Arc<ClientConfig> {
    config(Some(pairing.fingerprint))
}
pub fn provisional_client_config() -> Arc<ClientConfig> {
    config(None)
}
