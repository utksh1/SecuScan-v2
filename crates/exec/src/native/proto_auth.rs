//! Network credential-audit protocol clients (Sprint 2.3, issue #27).
//!
//! Native, minimal handshakes for the text-friendly protocols — each returns
//! `Some(username)` on successful authentication and `None` on
//! authentication failure (connection errors are surfaced as Err so callers
//! can distinguish "wrong password" from "host unreachable").
//!
//! Supported natively: Redis (RESP), FTP (USER/PASS), MySQL
//! (native_password handshake), PostgreSQL (md5 auth), MQTT (CONNECT),
//! Docker API (HTTP), WinRM Basic (SOAP/HTTP), Telnet (prompt heuristic),
//! STOMP (CONNECT frame). SSH/SMB/RDP/VNC need real crypto or complex
//! handshakes — delegated to hydra when installed (see `hydra` module).
//!
//! All connections are bounded (connect + read timeouts), single-attempt
//! per credential, and never destructive: valid credentials are *reported*,
//! not used beyond the initial authentication proof.

use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Per-attempt timeouts (connect + handshake + read).
const CONNECT_TIMEOUT: Duration = Duration::from_secs(4);
const READ_TIMEOUT: Duration = Duration::from_secs(5);

pub struct ProtoResult {
    /// Some(username) on successful auth; None on auth failure.
    pub authenticated_as: Option<String>,
    /// Human-readable context for the finding (banner, auth scheme…).
    pub context: String,
}

type ProtoResult2 = Result<ProtoResult, String>;

async fn connect(host: &str, port: u16) -> Result<TcpStream, String> {
    let addr = format!("{host}:{port}");
    let stream = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(addr.as_str()))
        .await
        .map_err(|_| format!("connect {addr}: timed out"))?
        .map_err(|e| format!("connect {addr}: {e}"))?;
    stream.set_nodelay(true).ok();
    Ok(stream)
}

async fn read_some(stream: &mut TcpStream, max: usize) -> Result<Vec<u8>, String> {
    let mut buf = vec![0u8; max];
    let n = tokio::time::timeout(READ_TIMEOUT, stream.read(&mut buf))
        .await
        .map_err(|_| "read timed out".to_string())?
        .map_err(|e| format!("read: {e}"))?;
    buf.truncate(n);
    Ok(buf)
}

/// --- Redis (RESP, port 6379) -----------------------------------------------

pub async fn redis_auth(
    host: &str,
    port: u16,
    username: &str,
    password: &str,
) -> ProtoResult2 {
    let mut stream = connect(host, port).await?;
    // Redis PING without auth: +PONG (no auth needed → not a credential hit)
    // or -NOAUTH (auth required → try credentials).
    let _ = read_some(&mut stream, 256).await;
    let cmd = if password.is_empty() {
        format!("*1\r\n$4\r\nPING\r\n")
    } else if username.is_empty() || username == "default" {
        format!("*2\r\n$4\r\nAUTH\r\n${}\r\n{}\r\n", password.len(), password)
    } else {
        format!(
            "*3\r\n$4\r\nAUTH\r\n${}\r\n{}\r\n${}\r\n{}\r\n",
            username.len(),
            username,
            password.len(),
            password
        )
    };
    stream.write_all(cmd.as_bytes()).await.map_err(|e| format!("write: {e}"))?;
    let resp = read_some(&mut stream, 256).await?;
    let resp_str = String::from_utf8_lossy(&resp);
    if resp_str.starts_with("+PONG") {
        Ok(ProtoResult {
            authenticated_as: Some(String::new()),
            context: "Redis responds to PING without credentials (no auth configured)"
                .into(),
        })
    } else if resp_str.starts_with("+OK") {
        Ok(ProtoResult {
            authenticated_as: Some(if username.is_empty() { "default".into() } else { username.into() }),
            context: "Redis AUTH accepted".into(),
        })
    } else if resp_str.starts_with("-NOAUTH") {
        // Requires auth but we sent PING — not a credential failure.
        Err("Redis requires authentication (NOAUTH)".into())
    } else if resp_str.starts_with("-ERR") || resp_str.starts_with("-WRONGPASS") {
        Ok(ProtoResult { authenticated_as: None, context: String::new() })
    } else if resp_str.starts_with('-') {
        Ok(ProtoResult { authenticated_as: None, context: String::new() })
    } else {
        Err(format!("unexpected Redis response: {}", &resp_str[..resp_str.len().min(64)]))
    }
}

/// --- FTP (port 21) ----------------------------------------------------------

pub async fn ftp_auth(host: &str, port: u16, username: &str, password: &str) -> ProtoResult2 {
    let mut stream = connect(host, port).await?;
    let banner = read_some(&mut stream, 512).await?;
    if !String::from_utf8_lossy(&banner).starts_with("220") {
        return Err("not an FTP control channel (no 220 banner)".into());
    }
    let user_cmd = format!("USER {username}\r\n");
    stream.write_all(user_cmd.as_bytes()).await.map_err(|e| format!("write: {e}"))?;
    let resp = read_some(&mut stream, 256).await?;
    let resp_str = String::from_utf8_lossy(&resp);
    if resp_str.starts_with("331") {
        let pass_cmd = format!("PASS {password}\r\n");
        stream.write_all(pass_cmd.as_bytes()).await.map_err(|e| format!("write: {e}"))?;
        let resp2 = read_some(&mut stream, 256).await?;
        let r2 = String::from_utf8_lossy(&resp2);
        if r2.starts_with("230") {
            Ok(ProtoResult {
                authenticated_as: Some(username.into()),
                context: "FTP credentials accepted (230)".into(),
            })
        } else if r2.starts_with("530") {
            Ok(ProtoResult { authenticated_as: None, context: String::new() })
        } else {
            Err(format!("unexpected FTP response after PASS: {}", &r2[..r2.len().min(64)]))
        }
    } else if resp_str.starts_with("530") {
        Ok(ProtoResult { authenticated_as: None, context: String::new() })
    } else {
        Err(format!("unexpected FTP response after USER: {}", &resp_str[..resp_str.len().min(64)]))
    }
}

/// --- Telnet (port 23, prompt heuristic) --------------------------------------

pub async fn telnet_auth(host: &str, port: u16, username: &str, password: &str) -> ProtoResult2 {
    let mut stream = connect(host, port).await?;
    // Negotiate off (send WON'T/DON'T for all options) then expect a login prompt.
    stream
        .write_all(&[0xff, 0xfb, 0x01, 0xff, 0xfe, 0x01])
        .await
        .map_err(|e| format!("write: {e}"))?;
    let banner = read_some(&mut stream, 1024).await?;
    let b = String::from_utf8_lossy(&banner).to_ascii_lowercase();
    if !(b.contains("login") || b.contains("username") || b.contains("user:")) {
        return Err("no login prompt observed on telnet banner".into());
    }
    stream.write_all(format!("{username}\r\n").as_bytes()).await.map_err(|e| format!("write: {e}"))?;
    let resp = read_some(&mut stream, 512).await?;
    let r = String::from_utf8_lossy(&resp).to_ascii_lowercase();
    if !r.contains("password") {
        return Err("no password prompt after username".into());
    }
    stream.write_all(format!("{password}\r\n").as_bytes()).await.map_err(|e| format!("write: {e}"))?;
    let resp2 = read_some(&mut stream, 1024).await?;
    let r2 = String::from_utf8_lossy(&resp2).to_ascii_lowercase();
    // Successful telnet login usually lands on a shell prompt ($, #, >) and
    // NOT on a repeated login/password prompt or "incorrect"/"failed".
    let failed = r2.contains("incorrect") || r2.contains("failed") || r2.contains("denied")
        || r2.contains("login:") || r2.contains("password:");
    if failed {
        Ok(ProtoResult { authenticated_as: None, context: String::new() })
    } else if r2.contains('$') || r2.contains('#') || r2.contains('>') {
        Ok(ProtoResult {
            authenticated_as: Some(username.into()),
            context: "Telnet shell prompt reached".into(),
        })
    } else {
        Err("telnet outcome inconclusive (no shell prompt, no failure)".into())
    }
}

/// --- MySQL (3306, mysql_native_password) --------------------------------------

pub async fn mysql_auth(host: &str, port: u16, username: &str, password: &str) -> ProtoResult2 {
    use sha1::{Digest, Sha1};
    let mut stream = connect(host, port).await?;
    // Greeting packet: [3 len][seq][protocol][server version NUL][4 fill][auth-plugin-data-part-1(8)][fill][capability(2+2)][charset(1)][status(2)][capability(2)][auth len(1)][reserved(10)][auth-plugin-data-part-2(12+)][auth-plugin-name NUL]
    let greet = read_some(&mut stream, 4096).await?;
    if greet.len() < 40 || greet[4] == 0xff {
        return Err("not a MySQL greeting".into());
    }
    // auth-plugin-data is 8 bytes at offset 35 + up to 12 more after the
    // capability/status block (offset 55, length from capability & 0x200).
    let salt_part1 = &greet[35..43];
    let cap_off = 55.min(greet.len() - 2);
    let caps = u16::from_le_bytes([greet[cap_off], greet.get(cap_off + 1).copied().unwrap_or(0)]);
    let auth_len = if caps & 0x8000 != 0 {
        *greet.get(63).unwrap_or(&13) as usize
    } else {
        13
    };
    let salt_part2 = greet
        .get(43 + 2..43 + 2 + auth_len.saturating_sub(8).max(12))
        .unwrap_or(&[]);
    let mut salt = Vec::new();
    salt.extend_from_slice(salt_part1);
    salt.extend_from_slice(salt_part2);
    // Strip trailing NUL from salt part 2.
    while salt.last() == Some(&0) {
        salt.pop();
    }

    // mysql_native_password: SHA1(password) XOR SHA1(salt + SHA1(SHA1(password)))
    let s1 = Sha1::digest(password.as_bytes());
    let mut h2 = Sha1::new();
    h2.update(&s1);
    let s2 = h2.finalize();
    let mut h3 = Sha1::new();
    h3.update(&salt);
    h3.update(s2);
    let s3 = h3.finalize();
    let token: Vec<u8> = s1.iter().zip(s3.iter()).map(|(a, b)| a ^ b).collect();

    // HandshakeResponse41
    let mut pkt = Vec::new();
    pkt.extend_from_slice(&[0x0a, 0xc2, 0x06, 0x00]); // caps: LONG_PASSWORD | PROTOCOL_41 | SECURE_CONN | PLUGIN_AUTH
    pkt.extend_from_slice(&[0, 0, 0, 0]); // max packet
    pkt.push(0x21); // charset utf8_general_ci
    pkt.extend_from_slice(&[0; 23]); // filler
    pkt.extend_from_slice(username.as_bytes());
    pkt.push(0);
    pkt.push(token.len() as u8);
    pkt.extend_from_slice(&token);
    pkt.extend_from_slice(b"mysql_native_password");
    pkt.push(0);
    let pkt_len = pkt.len() as u32;
    let mut framed = Vec::new();
    framed.extend_from_slice(&pkt_len.to_le_bytes()[..3]);
    framed.push(1); // seq
    framed.extend_from_slice(&pkt);
    stream.write_all(&framed).await.map_err(|e| format!("write: {e}"))?;
    let resp = read_some(&mut stream, 1024).await?;
    // OK = [len][seq][0x00]; ERR = [len][seq][0xff]
    if resp.len() >= 4 && resp[3] == 0x00 {
        Ok(ProtoResult {
            authenticated_as: Some(username.into()),
            context: "MySQL authentication accepted (mysql_native_password)".into(),
        })
    } else if resp.len() >= 4 && resp[3] == 0xff {
        Ok(ProtoResult { authenticated_as: None, context: String::new() })
    } else {
        Err("unexpected MySQL auth response".into())
    }
}

/// --- PostgreSQL (5432, md5 auth) ----------------------------------------------

pub async fn postgres_auth(host: &str, port: u16, username: &str, password: &str) -> ProtoResult2 {
    use md5::{Digest, Md5};
    let mut stream = connect(host, port).await?;
    // StartupMessage: len(4) + protocol(196608) + "user\0<user>\0\0"
    let mut startup = Vec::new();
    let mut payload = Vec::new();
    payload.extend_from_slice(b"user\0");
    payload.extend_from_slice(username.as_bytes());
    payload.push(0);
    payload.push(0);
    let len = (payload.len() + 4) as u32;
    startup.extend_from_slice(&len.to_be_bytes());
    startup.extend_from_slice(&196608u32.to_be_bytes());
    startup.extend_from_slice(&payload);
    stream.write_all(&startup).await.map_err(|e| format!("write: {e}"))?;
    let resp = read_some(&mut stream, 1024).await?;
    // AuthenticationMD5Password: 'R' len(4) 5 salt(4)
    if resp.len() < 12 || resp[0] != b'R' || resp[8] != 5 {
        if resp.len() >= 9 && resp[0] == b'R' && resp[8] == 0 {
            // AuthenticationOk — trust-authenticated server (no password).
            return Ok(ProtoResult {
                authenticated_as: Some(username.into()),
                context: "PostgreSQL accepted the connection without a password (trust auth)"
                    .into(),
            });
        }
        return Err("expected PostgreSQL md5 auth request".into());
    }
    let salt = &resp[9..13];
    // md5 = "md5" + md5(md5(password + user) + salt)
    let mut d1 = Md5::new();
    d1.update(password.as_bytes());
    d1.update(username.as_bytes());
    let inner = hex::encode(d1.finalize());
    let mut d2 = Md5::new();
    d2.update(inner.as_bytes());
    d2.update(salt);
    let response = format!("md5{}", hex::encode(d2.finalize()));
    // psql message: len + "p" + response + \0
    let mut msg = vec![b'p'];
    msg.extend_from_slice(response.as_bytes());
    msg.push(0);
    let len = (msg.len() + 4) as u32;
    let mut framed = len.to_be_bytes().to_vec();
    framed.extend_from_slice(&msg);
    stream.write_all(&framed).await.map_err(|e| format!("write: {e}"))?;
    let resp2 = read_some(&mut stream, 256).await?;
    // AuthenticationOk ('R' code 0) or ErrorResponse ('E')
    if resp2.len() >= 9 && resp2[0] == b'R' && resp2[8] == 0 {
        Ok(ProtoResult {
            authenticated_as: Some(username.into()),
            context: "PostgreSQL md5 authentication accepted".into(),
        })
    } else if !resp2.is_empty() && resp2[0] == b'E' {
        Ok(ProtoResult { authenticated_as: None, context: String::new() })
    } else {
        Err("unexpected PostgreSQL auth response".into())
    }
}

/// --- MQTT (1883/8883, CONNECT) -----------------------------------------------

pub async fn mqtt_auth(host: &str, port: u16, username: &str, password: &str) -> ProtoResult2 {
    let mut stream = connect(host, port).await?;
    // CONNECT: fixed header 0x10 + remaining len; variable header: "MQTT"(4) level(1) 0x02 keepalive(2); payload: client-id + user + pass
    let client_id = format!("secuscan-audit-{}/{}", host, port);
    let mut vh = Vec::new();
    vh.extend_from_slice(b"MQTT");
    vh.push(4); // level 4 (MQTT 3.1.1)
    vh.push(0x82); // username + password flags
    vh.extend_from_slice(&300u16.to_be_bytes()); // keepalive 300s
    let mut pl = Vec::new();
    for field in [&client_id, username, password] {
        pl.extend_from_slice(&(field.len() as u16).to_be_bytes());
        pl.extend_from_slice(field.as_bytes());
    }
    let remaining = vh.len() + pl.len();
    let mut pkt = vec![0x10];
    // MQTT remaining-length varint encoding
    let mut rl = remaining;
    loop {
        let mut byte = (rl % 128) as u8;
        rl /= 128;
        if rl > 0 {
            byte |= 0x80;
        }
        pkt.push(byte);
        if rl == 0 {
            break;
        }
    }
    pkt.extend_from_slice(&vh);
    pkt.extend_from_slice(&pl);
    stream.write_all(&pkt).await.map_err(|e| format!("write: {e}"))?;
    let resp = read_some(&mut stream, 64).await?;
    // CONNACK: 0x20 0x02 flags return-code; return code 0 = accepted, 4/5 = bad user/pass
    if resp.len() >= 4 && resp[0] == 0x20 {
        let rc = resp[3];
        if rc == 0 {
            Ok(ProtoResult {
                authenticated_as: Some(if username.is_empty() { "anonymous".into() } else { username.into() }),
                context: "MQTT CONNECT accepted".into(),
            })
        } else if rc == 4 || rc == 5 {
            Ok(ProtoResult { authenticated_as: None, context: String::new() })
        } else {
            Err(format!("MQTT CONNACK return code {rc}"))
        }
    } else {
        Err("not an MQTT CONNACK".into())
    }
}

/// --- Docker API (2375/2376, HTTP /version) -------------------------------------

pub async fn docker_check(host: &str, port: u16) -> ProtoResult2 {
    let mut stream = connect(host, port).await?;
    let req = format!("GET /version HTTP/1.1\r\nHost: {host}:{port}\r\nConnection: close\r\n\r\n");
    stream.write_all(req.as_bytes()).await.map_err(|e| format!("write: {e}"))?;
    let resp = read_some(&mut stream, 4096).await?;
    let s = String::from_utf8_lossy(&resp);
    if s.starts_with("HTTP/1.") && s.contains("200") && (s.contains("ApiVersion") || s.contains("MinAPIVersion")) {
        let version = s
            .split("\"Version\":\"")
            .nth(1)
            .and_then(|v| v.split('"').next())
            .unwrap_or("?");
        Ok(ProtoResult {
            authenticated_as: Some("unauthenticated".into()),
            context: format!("Docker API unauthenticated (version {version}) — full host control"),
        })
    } else {
        Err("no unauthenticated Docker API on this port".into())
    }
}

/// --- WinRM (5985, HTTP Basic over SOAP) -----------------------------------------

pub async fn winrm_auth(host: &str, port: u16, username: &str, password: &str) -> ProtoResult2 {
    let auth = format!(
        "Basic {}",
        (format!("{username}:{password}"))
    );
    let encoded = {
        // base64 is already a dependency of api; here we re-implement with the
        // same crate surface available in exec (base64 = "0.22").
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD.encode(auth.as_bytes())
    };
    let mut stream = connect(host, port).await?;
    // Minimal SOAP envelope for WinRM shell enumeration.
    let soap = r#"<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Header></s:Header><s:Body></s:Body></s:Envelope>"#;
    let req = format!(
        "POST /wsman HTTP/1.1\r\nHost: {host}:{port}\r\nAuthorization: Basic {encoded}\r\nContent-Type: application/soap+xml;charset=UTF-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        soap.len(),
        soap
    );
    stream.write_all(req.as_bytes()).await.map_err(|e| format!("write: {e}"))?;
    let resp = read_some(&mut stream, 2048).await?;
    let s = String::from_utf8_lossy(&resp);
    if s.starts_with("HTTP/1.") {
        if s.contains("200") || s.contains("500") {
            // 500 with a SOAP fault still means credentials were ACCEPTED
            // (the fault is about the empty body), while 401 means rejected.
            if s.contains("401") {
                return Ok(ProtoResult { authenticated_as: None, context: String::new() });
            }
            return Ok(ProtoResult {
                authenticated_as: Some(username.into()),
                context: "WinRM Basic authentication accepted".into(),
            });
        }
        if s.contains("401") {
            return Ok(ProtoResult { authenticated_as: None, context: String::new() });
        }
    }
    Err("unexpected WinRM response".into())
}

/// --- STOMP (61613, CONNECT frame) -----------------------------------------------

pub async fn stomp_auth(host: &str, port: u16, username: &str, password: &str) -> ProtoResult2 {
    let mut stream = connect(host, port).await?;
    let frame = format!(
        "CONNECT\naccept-version:1.2\nlogin:{username}\npasscode:{password}\n\n\x00"
    );
    stream.write_all(frame.as_bytes()).await.map_err(|e| format!("write: {e}"))?;
    let resp = read_some(&mut stream, 1024).await?;
    let s = String::from_utf8_lossy(&resp);
    if s.starts_with("CONNECTED") {
        Ok(ProtoResult {
            authenticated_as: Some(username.into()),
            context: "STOMP CONNECT accepted".into(),
        })
    } else if s.starts_with("ERROR") {
        Ok(ProtoResult { authenticated_as: None, context: String::new() })
    } else {
        Err("not a STOMP server".into())
    }
}
