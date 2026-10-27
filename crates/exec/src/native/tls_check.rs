//! Native TLS configuration scanner (direct rustls handshake).
//!
//! Fields (see `plugins/tls-check.toml`):
//! - `target` (string, required) — `host`, `host:port`, or a URL (port
//!   defaults to 443)
//! - `timeout_ms` (integer, 500..=30000, default 10000)

use super::{get_i64_or, get_str, NativeCtx, NativeScanner};
use async_trait::async_trait;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};
use secuscan_core::models::{Finding, FindingKind, Severity};
use serde_json::json;
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio_rustls::TlsConnector;

pub struct TlsCheckScanner;

#[async_trait]
impl NativeScanner for TlsCheckScanner {
    fn id(&self) -> &'static str {
        "tls_check"
    }

    fn name(&self) -> &'static str {
        "TLS Configuration Check"
    }

    fn description(&self) -> &'static str {
        "Performs a real TLS handshake against the target and reports the \
         negotiated protocol version, cipher suite, and trust/validity \
         problems with the server certificate."
    }

    async fn run(
        &self,
        inputs: &BTreeMap<String, serde_json::Value>,
        _ctx: &NativeCtx,
    ) -> Result<Vec<Finding>, String> {
        let (host, port) = parse_target(get_str(inputs, "target")?)?;
        let timeout = Duration::from_millis(
            get_i64_or(inputs, "timeout_ms", 10_000).clamp(500, 30_000) as u64,
        );

        let roots = public_roots();
        let config = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let connector = TlsConnector::from(Arc::new(config));

        let server_name = ServerName::try_from(host.clone())
            .map_err(|_| format!("`{host}` is not a valid TLS server name"))?;

        let tcp = tokio::time::timeout(
            timeout,
            tokio::net::TcpStream::connect((host.as_str(), port)),
        )
        .await
        .map_err(|_| format!("TCP connect to {host}:{port} timed out"))?
        .map_err(|e| format!("TCP connect to {host}:{port} failed: {e}"))?;

        let handshake = tokio::time::timeout(timeout, connector.connect(server_name, tcp)).await;
        let mut stream =
            match handshake {
                Err(_) => {
                    return Ok(vec![tls_finding(
                    Severity::High,
                    format!("TLS handshake with {host}:{port} timed out"),
                    format!("The TLS handshake did not complete within {}ms.", timeout.as_millis()),
                    "Investigate server load or middlebox interference; a healthy TLS endpoint \
                     should complete handshakes well under a second."
                        .to_string(),
                    format!("timeout after {}ms", timeout.as_millis()),
                    json!({"host": host, "port": port}),
                )]);
                }
                Ok(Err(e)) => {
                    let (severity, title, desc, remediation) = e
                        .get_ref()
                        .and_then(|r| r.downcast_ref::<rustls::Error>())
                        .map(classify_handshake_error)
                        .unwrap_or_else(|| {
                            (
                            Severity::Medium,
                            "TLS connection failed".to_string(),
                            format!("The TLS connection could not be established: {e}"),
                            "Verify the endpoint is a TLS service on this port and inspect server \
                             logs."
                                .to_string(),
                        )
                        });
                    return Ok(vec![tls_finding(
                        severity,
                        format!("{title} ({host}:{port})"),
                        desc,
                        remediation,
                        format!("{e}"),
                        json!({"host": host, "port": port, "error": e.to_string()}),
                    )]);
                }
                Ok(Ok(stream)) => stream,
            };

        // Successful handshake: inspect the negotiated session.
        let (version, cipher, version_raw) = {
            let (_, session) = stream.get_ref();
            (
                session
                    .protocol_version()
                    .map(protocol_label)
                    .unwrap_or_else(|| "unknown".to_string()),
                session
                    .negotiated_cipher_suite()
                    .and_then(|c| c.suite().as_str())
                    .unwrap_or("unknown")
                    .to_string(),
                session.protocol_version(),
            )
        };
        // Drain the close so the connection closes cleanly.
        let _ = stream.shutdown().await;

        let (severity, title, description) = match version_raw {
            Some(rustls::ProtocolVersion::TLSv1_3) => (
                Severity::Info,
                format!("TLS 1.3 negotiated with {host}:{port}"),
                "The endpoint negotiates TLS 1.3, the current best protocol version.".to_string(),
            ),
            Some(rustls::ProtocolVersion::TLSv1_2) => (
                Severity::Low,
                format!("TLS 1.2 negotiated with {host}:{port} (TLS 1.3 not selected)"),
                "The endpoint still negotiates TLS 1.2. While acceptable, TLS 1.3 offers better \
                 performance and a cleaner handshake."
                    .to_string(),
            ),
            _ => (
                Severity::High,
                format!("Outdated TLS version negotiated with {host}:{port}: {version}"),
                format!("The endpoint negotiated {version}, which is deprecated and insecure."),
            ),
        };

        Ok(vec![tls_finding(
            severity,
            title,
            description,
            "Prefer TLS 1.3 (and at minimum TLS 1.2) with modern AEAD cipher suites; disable \
             SSLv3/TLS 1.0/1.1 at the server or load balancer."
                .to_string(),
            format!("negotiated {version} with cipher {cipher}"),
            json!({"host": host, "port": port, "version": version, "cipher": cipher}),
        )])
    }
}

fn parse_target(raw: &str) -> Result<(String, u16), String> {
    let s = raw.trim();
    if s.is_empty() {
        return Err("target is empty".into());
    }
    let authority = if let Some(idx) = s.find("://") {
        &s[idx + 3..]
    } else {
        s
    };
    let authority = authority.split(['/', '?', '#']).next().unwrap_or("");
    let authority = match authority.rfind('@') {
        Some(i) => &authority[i + 1..],
        None => authority,
    };
    if let Some(rest) = authority.strip_prefix('[') {
        // IPv6 literal
        let close = rest
            .find(']')
            .ok_or_else(|| "unbalanced IPv6 literal".to_string())?;
        let host = rest[..close].to_string();
        let port = rest[close + 1..]
            .strip_prefix(':')
            .and_then(|p| p.parse().ok())
            .unwrap_or(443);
        return Ok((host, port));
    }
    match authority.rsplit_once(':') {
        Some((h, p)) if !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()) => {
            let port: u16 = p.parse().map_err(|_| format!("bad port `{p}`"))?;
            Ok((h.to_string(), if port == 0 { 443 } else { port }))
        }
        _ => Ok((authority.to_string(), 443)),
    }
}

fn public_roots() -> RootCertStore {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    roots
}

fn protocol_label(v: rustls::ProtocolVersion) -> String {
    match v {
        rustls::ProtocolVersion::SSLv2 => "SSLv2".into(),
        rustls::ProtocolVersion::SSLv3 => "SSLv3".into(),
        rustls::ProtocolVersion::TLSv1_0 => "TLS 1.0".into(),
        rustls::ProtocolVersion::TLSv1_1 => "TLS 1.1".into(),
        rustls::ProtocolVersion::TLSv1_2 => "TLS 1.2".into(),
        rustls::ProtocolVersion::TLSv1_3 => "TLS 1.3".into(),
        rustls::ProtocolVersion::DTLSv1_0 => "DTLS 1.0".into(),
        rustls::ProtocolVersion::DTLSv1_2 => "DTLS 1.2".into(),
        rustls::ProtocolVersion::DTLSv1_3 => "DTLS 1.3".into(),
        _ => format!("unknown ({v:?})"),
    }
}

fn classify_handshake_error(e: &rustls::Error) -> (Severity, String, String, String) {
    match e {
        rustls::Error::InvalidCertificate(reason) => {
            use rustls::CertificateError;
            let (sev, what, desc, fix): (Severity, String, String, String) = match reason {
                CertificateError::UnknownIssuer => (
                    Severity::High,
                    "Server certificate is not publicly trusted".to_string(),
                    "The certificate chain does not anchor to a trusted public CA (self-signed, \
                     private CA, or incomplete chain). Browsers will warn users."
                        .to_string(),
                    "Serve a complete chain from a trusted CA (Let's Encrypt or your CA), or \
                     distribute your private CA to clients explicitly."
                        .to_string(),
                ),
                CertificateError::Expired | CertificateError::ExpiredContext { .. } => (
                    Severity::High,
                    "Server certificate has expired".to_string(),
                    "The presented certificate is past its validity window; clients will refuse \
                     the connection."
                        .to_string(),
                    "Renew the certificate and automate renewal (e.g. ACME).".to_string(),
                ),
                CertificateError::NotValidYet | CertificateError::NotValidYetContext { .. } => (
                    Severity::Medium,
                    "Server certificate is not valid yet".to_string(),
                    "The certificate's notBefore is in the future (wrong server clock or \
                     premature deployment)."
                        .to_string(),
                    "Check server clock synchronization and certificate issuance dates."
                        .to_string(),
                ),
                other => (
                    Severity::Medium,
                    format!("Server certificate was rejected ({other})"),
                    "The certificate failed validation.".to_string(),
                    "Inspect the certificate chain, hostname coverage (SANs) and expiry."
                        .to_string(),
                ),
            };
            (sev, format!("TLS: {what}"), desc, fix)
        }
        rustls::Error::PeerIncompatible(_) => (
            Severity::High,
            "TLS handshake failed".to_string(),
            "The server refused the handshake: no shared protocol version/cipher, or the \
             server requires a client certificate."
                .to_string(),
            "Enable TLS 1.2+ with modern AEAD cipher suites; check mutual-TLS requirements."
                .to_string(),
        ),
        rustls::Error::PeerMisbehaved(_) => (
            Severity::Medium,
            "TLS peer misbehaved".to_string(),
            "The server violated the TLS protocol during the handshake.".to_string(),
            "Update the TLS stack (OpenSSL/nginx/IIS) on the server.".to_string(),
        ),
        _ => (
            Severity::Medium,
            "TLS connection error".to_string(),
            format!("The TLS connection could not be established: {e}"),
            "Verify the endpoint is a TLS service on this port and inspect server logs."
                .to_string(),
        ),
    }
}

fn tls_finding(
    severity: Severity,
    title: String,
    description: String,
    remediation: String,
    proof: String,
    metadata: serde_json::Value,
) -> Finding {
    let mut f = Finding::new(title, "TLS", severity, FindingKind::Observation);
    f.description = description;
    f.remediation = remediation;
    f.proof = proof;
    f.metadata = metadata;
    f
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn target_parsing() {
        assert_eq!(
            parse_target("example.com").unwrap(),
            ("example.com".into(), 443)
        );
        assert_eq!(
            parse_target("example.com:8443").unwrap(),
            ("example.com".into(), 8443)
        );
        assert_eq!(
            parse_target("https://example.com/x").unwrap(),
            ("example.com".into(), 443)
        );
        assert_eq!(
            parse_target("https://example.com:9443/x").unwrap(),
            ("example.com".into(), 9443)
        );
        assert_eq!(parse_target("[::1]:8443").unwrap(), ("::1".into(), 8443));
        assert!(parse_target("").is_err());
    }

    /// Self-signed TLS server → the scanner must report the trust problem.
    #[tokio::test]
    async fn self_signed_cert_is_flagged() {
        crate::init_tls();
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let cert_der = cert.cert.der().clone();
        let key_der =
            rustls::pki_types::PrivateKeyDer::try_from(cert.key_pair.serialize_der()).unwrap();

        let mut server_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key_der)
            .unwrap();
        server_config.alpn_protocols = Vec::new();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((sock, _)) = listener.accept().await else {
                    break;
                };
                let acc = acceptor.clone();
                tokio::spawn(async move {
                    if let Ok(mut tls) = acc.accept(sock).await {
                        let mut buf = [0u8; 64];
                        let _ = tls.read(&mut buf).await;
                        let _ = tls.write_all(b"bye").await;
                        let _ = tls.shutdown().await;
                    }
                });
            }
        });

        let (tx, _rx) = tokio::sync::mpsc::channel(64);
        let ctx = NativeCtx {
            sink: crate::events::EventSink::new(uuid::Uuid::new_v4(), tx),
            cancel: tokio_util::sync::CancellationToken::new(),
            timeout: std::time::Duration::from_secs(10),
            auth: None,
        };
        let inputs: BTreeMap<String, serde_json::Value> = [(
            "target".to_string(),
            serde_json::json!(format!("127.0.0.1:{}", addr.port())),
        )]
        .into_iter()
        .collect();
        let findings = TlsCheckScanner.run(&inputs, &ctx).await.unwrap();
        assert_eq!(findings.len(), 1);
        assert!(
            findings[0].title.contains("not publicly trusted"),
            "{:?}",
            findings[0].title
        );
        assert_eq!(findings[0].severity, Severity::High);
    }
}
