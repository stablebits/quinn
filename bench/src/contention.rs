use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    num::ParseIntError,
    str::FromStr,
    sync::Arc,
};

use anyhow::{Context, Result};
use quinn::crypto::rustls::QuicClientConfig;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};

pub fn bind_addr_for(remote: SocketAddr) -> SocketAddr {
    let ip = match remote {
        SocketAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        SocketAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
    };
    SocketAddr::new(ip, 0)
}

pub fn parse_byte_size(s: &str) -> Result<u64, ParseIntError> {
    let s = s.trim();

    let multiplier = match s.chars().last() {
        Some('T') => 1024 * 1024 * 1024 * 1024,
        Some('G') => 1024 * 1024 * 1024,
        Some('M') => 1024 * 1024,
        Some('k') => 1024,
        _ => 1,
    };

    let s = match multiplier {
        1 => s,
        _ => &s[..s.len() - 1],
    };

    Ok(u64::from_str(s)? * multiplier)
}

pub fn make_transport_config(
    initial_mtu: u16,
    max_concurrent_uni_streams: u64,
) -> quinn::TransportConfig {
    let mut config = quinn::TransportConfig::default();
    config.initial_mtu(initial_mtu);
    config.max_concurrent_uni_streams(max_concurrent_uni_streams.try_into().unwrap());
    config.stream_receive_window((64_u32 * 1024 * 1024).into());
    config.receive_window((256_u32 * 1024 * 1024).into());
    config.send_window(256 * 1024 * 1024);

    let mut acks = quinn::AckFrequencyConfig::default();
    acks.ack_eliciting_threshold(10u32.into());
    config.ack_frequency_config(Some(acks));

    config
}

pub fn server_endpoint(
    rt: &tokio::runtime::Runtime,
    listen: SocketAddr,
    initial_mtu: u16,
    max_concurrent_uni_streams: u64,
) -> Result<quinn::Endpoint> {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let key = rustls::pki_types::PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der());
    let cert = CertificateDer::from(cert.cert);

    let mut server_config = quinn::ServerConfig::with_single_cert(vec![cert], key.into()).unwrap();
    server_config.transport = Arc::new(make_transport_config(
        initial_mtu,
        max_concurrent_uni_streams,
    ));

    let endpoint = {
        let _guard = rt.enter();
        quinn::Endpoint::server(server_config, listen)
            .context("unable to create server endpoint")?
    };
    Ok(endpoint)
}

pub fn client_endpoint(
    rt: &tokio::runtime::Runtime,
    remote: SocketAddr,
) -> Result<quinn::Endpoint> {
    let endpoint = {
        let _guard = rt.enter();
        quinn::Endpoint::client(bind_addr_for(remote))
            .context("unable to create client endpoint")?
    };
    Ok(endpoint)
}

pub fn insecure_client_config(
    initial_mtu: u16,
    max_concurrent_uni_streams: u64,
) -> Result<quinn::ClientConfig> {
    let default_provider = rustls::crypto::ring::default_provider();
    let provider = Arc::new(rustls::crypto::CryptoProvider {
        cipher_suites: default_provider.cipher_suites.to_vec(),
        ..default_provider
    });

    let crypto = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(SkipServerVerification::new(provider))
        .with_no_client_auth();

    let mut client_config = quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(crypto)?));
    client_config.transport_config(Arc::new(make_transport_config(
        initial_mtu,
        max_concurrent_uni_streams,
    )));
    Ok(client_config)
}

#[derive(Debug)]
struct SkipServerVerification(Arc<rustls::crypto::CryptoProvider>);

impl SkipServerVerification {
    fn new(provider: Arc<rustls::crypto::CryptoProvider>) -> Arc<Self> {
        Arc::new(Self(provider))
    }
}

impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}
