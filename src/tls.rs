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

// Neither secrets nor certificates/private keys implement Debug here.
#[derive(Clone)]
pub struct Pairing {
    pub fingerprint: [u8; 32],
    token: [u8; 32],
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(text: &str) -> Result<[u8; 32], &'static str> {
    if text.len() != 64 || !text.is_ascii() {
        return Err("Pairing code must contain two 64-digit hexadecimal values.");
    }
    let mut out = [0; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[i * 2..i * 2 + 2], 16)
            .map_err(|_| "Pairing code contains invalid hexadecimal digits.")?;
    }
    Ok(out)
}

impl Pairing {
    pub fn parse(code: &str) -> Result<Self, &'static str> {
        let fields: Vec<_> = code.trim().split(':').collect();
        if fields.len() != 3 || fields[0] != "pair1" {
            return Err("Expected pair1:<certificate fingerprint>:<secret token>.");
        }
        Ok(Self {
            fingerprint: unhex(fields[1])?,
            token: unhex(fields[2])?,
        })
    }

    pub fn code(&self) -> String {
        format!("pair1:{}:{}", hex(&self.fingerprint), hex(&self.token))
    }

    pub fn token(&self) -> String {
        hex(&self.token)
    }

    pub fn authenticates(&self, token: &str) -> bool {
        unhex(token).is_ok_and(|candidate| bool::from(self.token.ct_eq(&candidate)))
    }
}

pub struct Identity {
    pub config: Arc<ServerConfig>,
    pub pairing: Pairing,
}

fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

impl Identity {
    pub fn generate() -> Result<Self, &'static str> {
        let key = rcgen::generate_simple_self_signed(vec!["pair.local".into()])
            .map_err(|_| "Could not generate the host TLS identity.")?;
        let cert = key.cert.der().clone();
        let fingerprint = digest::digest(&digest::SHA256, cert.as_ref())
            .as_ref()
            .try_into()
            .expect("SHA-256 is 32 bytes");
        let mut token = [0; 32];
        SystemRandom::new()
            .fill(&mut token)
            .map_err(|_| "Operating system random number generator failed.")?;
        let config = ServerConfig::builder_with_provider(provider())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|_| "Could not configure TLS 1.3.")?
            .with_no_client_auth()
            .with_single_cert(
                vec![cert],
                PrivatePkcs8KeyDer::from(key.signing_key.serialize_der()).into(),
            )
            .map_err(|_| "Could not configure the host certificate.")?;
        Ok(Self {
            config: Arc::new(config),
            pairing: Pairing { fingerprint, token },
        })
    }
}

struct PinnedCertificate {
    fingerprint: [u8; 32],
    provider: Arc<CryptoProvider>,
}

impl fmt::Debug for PinnedCertificate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PinnedCertificate")
    }
}

impl ServerCertVerifier for PinnedCertificate {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        let actual = digest::digest(&digest::SHA256, end_entity.as_ref());
        if bool::from(self.fingerprint.as_slice().ct_eq(actual.as_ref())) {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(Error::General(
                "Host certificate fingerprint does not match the pairing code.".into(),
            ))
        }
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
        // The pin checks identity; rustls/ring still verifies proof of possession
        // of that certificate's private key. Never return a signature assertion.
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

pub fn client_config(pairing: &Pairing) -> Arc<ClientConfig> {
    Arc::new(
        ClientConfig::builder_with_provider(provider())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .expect("ring supports TLS 1.3")
            // rustls calls custom verification 'dangerous'. This is strict,
            // out-of-band certificate pinning, not a verification bypass.
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(PinnedCertificate {
                fingerprint: pairing.fingerprint,
                provider: provider(),
            }))
            .with_no_client_auth(),
    )
}
