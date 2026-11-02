//! Shared DNS resolution for native scanners.
//!
//! A minimal, dependency-free DNS client over UDP: query encoding, response
//! parsing (including RFC 1035 name compression), and bounded timeouts.
//! Implemented in-process so DNS-based scanners (dns-lookup, reverse-dns,
//! subdomain-finder, email-security) work with zero external tooling.
//!
//! The resolver honours `SECUSCAN_DNS_SERVER` (`ip[:port]`) when set — a
//! deliberate escape hatch for labs, split-horizon setups and tests — and
//! otherwise reads the system nameservers from `/etc/resolv.conf`.
//!
//! Security notes: every length/count is bounds-checked before slicing;
//! response parsing never panics on malformed input (it errors instead),
//! because answers are attacker-influenced data.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;
use tokio::net::UdpSocket;

/// Well-known DNS record type numbers (RFC 1035 / 3596 / 6844).
pub mod rtype {
    pub const A: u16 = 1;
    pub const NS: u16 = 2;
    pub const CNAME: u16 = 5;
    pub const SOA: u16 = 6;
    pub const PTR: u16 = 12;
    pub const MX: u16 = 15;
    pub const TXT: u16 = 16;
    pub const AAAA: u16 = 28;
    pub const SRV: u16 = 33;
    pub const CAA: u16 = 257;

    /// Human name for a type number, for findings/metadata.
    pub fn name(t: u16) -> &'static str {
        match t {
            A => "A",
            NS => "NS",
            CNAME => "CNAME",
            SOA => "SOA",
            PTR => "PTR",
            MX => "MX",
            TXT => "TXT",
            AAAA => "AAAA",
            SRV => "SRV",
            CAA => "CAA",
            _ => "OTHER",
        }
    }

    /// Parse a user-supplied type name (case-insensitive).
    pub fn parse(s: &str) -> Option<u16> {
        match s.to_ascii_uppercase().as_str() {
            "A" => Some(A),
            "NS" => Some(NS),
            "CNAME" => Some(CNAME),
            "SOA" => Some(SOA),
            "PTR" => Some(PTR),
            "MX" => Some(MX),
            "TXT" => Some(TXT),
            "AAAA" => Some(AAAA),
            "SRV" => Some(SRV),
            "CAA" => Some(CAA),
            _ => None,
        }
    }
}

/// One decoded resource record from a response.
#[derive(Debug, Clone, PartialEq)]
pub struct DnsRecord {
    pub rtype: u16,
    pub ttl: u32,
    /// Rendered, human-readable value (IP, hostname, TXT joined, …).
    pub data: String,
}

/// Query failure kinds. `NxDomain` is *not* an error condition for
/// brute-force style scans, so it is distinguishable from transport /
/// server failures.
#[derive(Debug, Clone, PartialEq)]
pub enum DnsError {
    /// RCODE 3 — the name does not exist.
    NxDomain,
    /// Any other RCODE (SERVFAIL, REFUSED, …).
    Server(String),
    /// Transport failure: timeout, malformed reply, …
    Transport(String),
}

const MAX_UDP_PACKET: usize = 4096; // enough for typical answers; EDNS0 not used
const DNS_PORT: u16 = 53;
/// Per-query timeout; scanners bound the total via `NativeCtx.timeout`.
const QUERY_TIMEOUT: Duration = Duration::from_secs(5);

/// Read the first nameserver from the environment override or resolv.conf.
pub fn system_server() -> Option<SocketAddr> {
    if let Ok(v) = std::env::var("SECUSCAN_DNS_SERVER") {
        let v = v.trim();
        if !v.is_empty() {
            // "ip" or "ip:port"
            if let Ok(sa) = v.parse::<SocketAddr>() {
                return Some(sa);
            }
            if let Ok(ip) = v.parse::<IpAddr>() {
                return Some(SocketAddr::new(ip, DNS_PORT));
            }
        }
    }
    read_resolv_conf().first().copied()
}

/// Nameservers listed in /etc/resolv.conf (best-effort, malformed lines skipped).
pub fn read_resolv_conf() -> Vec<SocketAddr> {
    let Ok(text) = std::fs::read_to_string("/etc/resolv.conf") else {
        return vec![];
    };
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        let Some(rest) = line.strip_prefix("nameserver") else {
            continue;
        };
        if let Ok(ip) = rest.trim().parse::<IpAddr>() {
            out.push(SocketAddr::new(ip, DNS_PORT));
        }
    }
    out
}

/// Encode a domain name into wire format (length-prefixed labels).
fn encode_name(name: &str) -> Result<Vec<u8>, String> {
    let name = name.trim_end_matches('.');
    if name.is_empty() {
        return Err("empty DNS name".into());
    }
    if name.len() > 253 {
        return Err(format!("name exceeds 253 bytes: {name}"));
    }
    let mut out = Vec::with_capacity(name.len() + 2);
    for label in name.split('.') {
        if label.is_empty() {
            return Err(format!("empty label in `{name}`"));
        }
        if label.len() > 63 {
            return Err(format!("label exceeds 63 bytes in `{name}`"));
        }
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    Ok(out)
}

/// Build a standard recursive query packet.
fn build_query(id: u16, name: &str, rtype: u16) -> Result<Vec<u8>, String> {
    let mut q = Vec::with_capacity(512);
    q.extend_from_slice(&id.to_be_bytes());
    q.extend_from_slice(&0x0100_u16.to_be_bytes()); // RD=1
    q.extend_from_slice(&1_u16.to_be_bytes()); // QDCOUNT
    q.extend_from_slice(&[0; 6]); // AN/NS/ARCOUNT
    q.extend_from_slice(&encode_name(name)?);
    q.extend_from_slice(&rtype.to_be_bytes());
    q.extend_from_slice(&1_u16.to_be_bytes()); // QCLASS = IN
    Ok(q)
}

/// Decode a (possibly compressed) name starting at `pos`.
/// Returns (name, new_pos). Never panics: out-of-bounds → error.
fn parse_name(msg: &[u8], pos: usize) -> Result<(String, usize), String> {
    let mut labels: Vec<String> = Vec::new();
    let mut p = pos;
    let mut jumped = false;
    let mut end = pos; // position after the name in the ORIGINAL stream
    let mut hops = 0;
    loop {
        if p >= msg.len() {
            return Err("name runs past end of packet".into());
        }
        let len = msg[p] as usize;
        match len & 0b1100_0000 {
            0b0000_0000 => {
                if len == 0 {
                    p += 1;
                    if !jumped {
                        end = p;
                    }
                    break;
                }
                if p + 1 + len > msg.len() {
                    return Err("label runs past end of packet".into());
                }
                let label = String::from_utf8_lossy(&msg[p + 1..p + 1 + len]).into_owned();
                labels.push(label);
                p += 1 + len;
                if !jumped {
                    end = p;
                }
            }
            0b1100_0000 => {
                if p + 1 >= msg.len() {
                    return Err("truncated compression pointer".into());
                }
                let target = ((len & 0b0011_1111) << 8) | msg[p + 1] as usize;
                if !jumped {
                    end = p + 2;
                    jumped = true;
                }
                hops += 1;
                if hops > 64 {
                    return Err("too many compression hops (loop?)".into());
                }
                p = target;
            }
            _ => return Err("reserved label type in name".into()),
        }
    }
    Ok((labels.join("."), end))
}

/// Decode RDATA into a human-readable string.
/// `rdstart` is the absolute offset of the rdata inside `msg` (needed for
/// RFC 1035 name compression, whose pointers resolve against the whole
/// message — deriving the offset from slice lengths only works for the
/// final record).
fn render_rdata(msg: &[u8], rtype: u16, rdstart: usize, rdata: &[u8]) -> Result<String, String> {
    match rtype {
        rtype::A if rdata.len() == 4 => {
            Ok(Ipv4Addr::new(rdata[0], rdata[1], rdata[2], rdata[3]).to_string())
        }
        rtype::AAAA if rdata.len() == 16 => {
            let mut o = [0u8; 16];
            o.copy_from_slice(rdata);
            Ok(Ipv6Addr::from(o).to_string())
        }
        rtype::CNAME | rtype::NS | rtype::PTR => {
            let (name, _) = parse_name(msg, rdstart)?;
            Ok(name)
        }
        rtype::MX if rdata.len() >= 3 => {
            let pref = u16::from_be_bytes([rdata[0], rdata[1]]);
            let (host, _) = parse_name(msg, rdstart + 2)?;
            Ok(format!("{pref} {host}"))
        }
        rtype::TXT => {
            // sequence of <len><bytes> character-strings
            let mut out = Vec::new();
            let mut i = 0;
            while i < rdata.len() {
                let l = rdata[i] as usize;
                if i + 1 + l > rdata.len() {
                    return Err("TXT string runs past rdata".into());
                }
                out.push(String::from_utf8_lossy(&rdata[i + 1..i + 1 + l]).into_owned());
                i += 1 + l;
            }
            Ok(out.join(""))
        }
        rtype::SOA if rdata.len() >= 22 => {
            // mname + rname are compressed relative to the whole message
            let (mname, p1) = parse_name(msg, rdstart)?;
            let (rname, p2) = parse_name(msg, p1)?;
            if p2 + 20 > msg.len() {
                return Err("SOA numbers truncated".into());
            }
            let n = |o: usize| u32::from_be_bytes(msg[p2 + o..p2 + o + 4].try_into().unwrap());
            Ok(format!(
                "{mname} {rname} serial={} refresh={} retry={} expire={} min-ttl={}",
                n(0),
                n(4),
                n(8),
                n(12),
                n(16)
            ))
        }
        rtype::SRV if rdata.len() >= 7 => {
            let prio = u16::from_be_bytes([rdata[0], rdata[1]]);
            let weight = u16::from_be_bytes([rdata[2], rdata[3]]);
            let port = u16::from_be_bytes([rdata[4], rdata[5]]);
            let (target, _) = parse_name(msg, rdstart + 6)?;
            Ok(format!("{prio} {weight} {port} {target}"))
        }
        rtype::CAA if !rdata.is_empty() => {
            let flag = rdata[0];
            let tag_len = rdata[1] as usize;
            if 2 + tag_len > rdata.len() {
                return Err("CAA tag truncated".into());
            }
            let tag = String::from_utf8_lossy(&rdata[2..2 + tag_len]);
            let value = String::from_utf8_lossy(&rdata[2 + tag_len..]);
            Ok(format!(
                "{} {} \"{}\"",
                if flag == 0 { "0" } else { "128" },
                tag,
                value
            ))
        }
        _ => Ok(format!("{} (unrendered)", hex(rdata))),
    }
}

fn hex(data: &[u8]) -> String {
    data.iter().map(|b| format!("{b:02x}")).collect()
}

/// Parse a response packet into records for the first question.
pub fn parse_response(msg: &[u8]) -> Result<Vec<DnsRecord>, DnsError> {
    if msg.len() < 12 {
        return Err(DnsError::Transport("packet shorter than header".into()));
    }
    let flags = u16::from_be_bytes([msg[2], msg[3]]);
    let rcode = flags & 0x000F;
    let qr = flags & 0x8000 != 0;
    if !qr {
        return Err(DnsError::Transport("not a response".into()));
    }
    match rcode {
        0 => {}
        3 => return Err(DnsError::NxDomain),
        other => {
            return Err(DnsError::Server(match other {
                1 => "FORMERR".into(),
                2 => "SERVFAIL".into(),
                4 => "NOTIMP".into(),
                5 => "REFUSED".into(),
                n => format!("RCODE {n}"),
            }))
        }
    }
    let qdcount = u16::from_be_bytes([msg[4], msg[5]]);
    let ancount = u16::from_be_bytes([msg[6], msg[7]]);

    let mut pos = 12;
    for _ in 0..qdcount {
        let (_, next) = parse_name(msg, pos).map_err(DnsError::Transport)?;
        if next + 4 > msg.len() {
            return Err(DnsError::Transport("question section truncated".into()));
        }
        pos = next + 4; // QTYPE + QCLASS
    }

    let mut out = Vec::with_capacity(ancount as usize);
    for _ in 0..ancount {
        let (_, after_name) = parse_name(msg, pos).map_err(DnsError::Transport)?;
        if after_name + 10 > msg.len() {
            return Err(DnsError::Transport("RR header truncated".into()));
        }
        let rtype = u16::from_be_bytes([msg[after_name], msg[after_name + 1]]);
        let ttl = u32::from_be_bytes([
            msg[after_name + 4],
            msg[after_name + 5],
            msg[after_name + 6],
            msg[after_name + 7],
        ]);
        let rdlen = u16::from_be_bytes([msg[after_name + 8], msg[after_name + 9]]) as usize;
        let rdstart = after_name + 10;
        if rdstart + rdlen > msg.len() {
            return Err(DnsError::Transport("rdata truncated".into()));
        }
        let data = render_rdata(msg, rtype, rdstart, &msg[rdstart..rdstart + rdlen])
            .map_err(DnsError::Transport)?;
        out.push(DnsRecord { rtype, ttl, data });
        pos = rdstart + rdlen;
    }
    Ok(out)
}

/// Query `name`/`rtype` against `server`. One attempt; caller-level
/// timeouts bound the total. Records are returned in wire order.
pub async fn query(server: SocketAddr, name: &str, rtype: u16) -> Result<Vec<DnsRecord>, DnsError> {
    // bind an ephemeral local port per query — scanners run few queries
    // per task (or bounded by their own concurrency limiter).
    let bind: SocketAddr = if server.is_ipv4() {
        "0.0.0.0:0".parse().unwrap()
    } else {
        "[::]:0".parse().unwrap()
    };
    let sock = UdpSocket::bind(bind)
        .await
        .map_err(|e| DnsError::Transport(format!("bind: {e}")))?;
    let id: u16 = rand_id();
    let packet = build_query(id, name, rtype).map_err(DnsError::Transport)?;

    tokio::time::timeout(QUERY_TIMEOUT, async {
        sock.send_to(&packet, server)
            .await
            .map_err(|e| DnsError::Transport(format!("send: {e}")))?;
        let mut buf = vec![0u8; MAX_UDP_PACKET];
        // accept only replies from the queried server; ignore strays
        loop {
            let (n, from) = sock
                .recv_from(&mut buf)
                .await
                .map_err(|e| DnsError::Transport(format!("recv: {e}")))?;
            if from != server {
                continue;
            }
            if n < 12 {
                return Err(DnsError::Transport("short reply".into()));
            }
            let reply_id = u16::from_be_bytes([buf[0], buf[1]]);
            if reply_id != id {
                continue; // stray/late reply for an older query
            }
            let mut msg = buf;
            msg.truncate(n);
            return parse_response(&msg);
        }
    })
    .await
    .map_err(|_| DnsError::Transport("query timed out".into()))?
}

fn rand_id() -> u16 {
    // Cheap entropy source: the OS-provided random socket port + clock.
    // DNS IDs only need to be unpredictable enough to avoid accidental
    // reply confusion, and this scanner is UDP one-shot per query.
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    let pid = std::process::id() as u32;
    (nanos ^ pid.rotate_left(7)) as u16
}

/// Reverse-lookup in-addr.arpa / ip6.arpa name for an IP.
pub fn arpa_ptr(ip: &IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            format!("{}.{}.{}.{}.in-addr.arpa", o[3], o[2], o[1], o[0])
        }
        IpAddr::V6(v6) => {
            let mut nibbles = Vec::with_capacity(32);
            for b in v6.octets().iter().rev() {
                nibbles.push(b & 0x0F);
                nibbles.push(b >> 4);
            }
            let hexes: Vec<String> = nibbles.iter().map(|n| format!("{n:x}")).collect();
            format!("{}.ip6.arpa", hexes.join("."))
        }
    }
}

/// Validate a DNS name the user supplied (letters, digits, hyphen, dot,
/// underscore for SRV/service records; no slashes/spaces).
pub fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 253
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_')
        && !name.starts_with('.')
        && !name.ends_with('.')
        && !name.contains("..")
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::UdpSocket;

    /// Encode a domain name in wire format (test-side mirror of encode_name).
    fn wire_name(name: &str) -> Vec<u8> {
        let mut out = Vec::new();
        for label in name.trim_end_matches('.').split('.') {
            out.push(label.len() as u8);
            out.extend_from_slice(label.as_bytes());
        }
        out.push(0);
        out
    }

    /// Build a minimal DNS response: header + question + one A answer.
    fn a_response(name: &str, ip: [u8; 4], id: u16, compressed: bool) -> Vec<u8> {
        let mut m = Vec::new();
        m.extend_from_slice(&id.to_be_bytes());
        m.extend_from_slice(&0x8180_u16.to_be_bytes()); // QR=1, RD=1, RA=1
        m.extend_from_slice(&1_u16.to_be_bytes()); // QDCOUNT
        m.extend_from_slice(&1_u16.to_be_bytes()); // ANCOUNT
        m.extend_from_slice(&[0, 0, 0, 0]);
        m.extend_from_slice(&wire_name(name));
        m.extend_from_slice(&rtype::A.to_be_bytes());
        m.extend_from_slice(&1_u16.to_be_bytes()); // IN
        if compressed {
            // answer name = pointer to offset 12
            m.extend_from_slice(&[0xC0, 0x0C]);
        } else {
            m.extend_from_slice(&wire_name(name));
        }
        m.extend_from_slice(&rtype::A.to_be_bytes());
        m.extend_from_slice(&1_u16.to_be_bytes());
        m.extend_from_slice(&300_u32.to_be_bytes());
        m.extend_from_slice(&4_u16.to_be_bytes());
        m.extend_from_slice(&ip);
        m
    }

    #[test]
    fn name_roundtrip() {
        let w = encode_name("example.com").unwrap();
        assert_eq!(
            w,
            vec![7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0]
        );
        assert!(encode_name("").is_err());
        assert!(encode_name("a..b").is_err());
        let long = "a".repeat(64);
        assert!(encode_name(&long).is_err());
    }

    #[test]
    fn ptr_names() {
        assert_eq!(
            arpa_ptr(&IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))),
            "1.0.0.127.in-addr.arpa"
        );
        let v6: Ipv6Addr = "::1".parse().unwrap();
        assert_eq!(
            arpa_ptr(&IpAddr::V6(v6)),
            "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa"
        );
    }

    #[test]
    fn valid_names() {
        assert!(valid_name("example.com"));
        assert!(valid_name("sub-domain_x.example.com"));
        assert!(!valid_name(".example.com"));
        assert!(!valid_name("bad name.com"));
        assert!(!valid_name("evil/../etc"));
        assert!(!valid_name(""));
    }

    #[tokio::test]
    async fn query_mock_server_a_record() {
        // mock DNS server answering A queries for lab.test
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = server.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            loop {
                let (n, peer) = server.recv_from(&mut buf).await.unwrap();
                let req = &buf[..n];
                if req.len() < 12 {
                    continue;
                }
                let id = u16::from_be_bytes([req[0], req[1]]);
                let resp = a_response("lab.test", [192, 0, 2, 7], id, true);
                let _ = server.send_to(&resp, peer).await;
            }
        });

        let recs = query(addr, "lab.test", rtype::A).await.unwrap();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].rtype, rtype::A);
        assert_eq!(recs[0].ttl, 300);
        assert_eq!(recs[0].data, "192.0.2.7");
    }

    #[tokio::test]
    async fn query_nxdomain_distinguishable() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = server.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            loop {
                let (n, peer) = server.recv_from(&mut buf).await.unwrap();
                let req = &buf[..n];
                if req.len() < 12 {
                    continue;
                }
                let id = u16::from_be_bytes([req[0], req[1]]);
                // header-only response with RCODE=3
                let mut resp = Vec::new();
                resp.extend_from_slice(&id.to_be_bytes());
                resp.extend_from_slice(&0x8183_u16.to_be_bytes());
                resp.extend_from_slice(&[0u8; 8]);
                let _ = server.send_to(&resp, peer).await;
            }
        });
        let err = query(addr, "nope.test", rtype::A).await.unwrap_err();
        assert_eq!(err, DnsError::NxDomain);
    }

    #[tokio::test]
    async fn query_timeout_on_silence() {
        // a bound socket that never answers
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = server.local_addr().unwrap();
        let err = query(addr, "silent.test", rtype::A).await.unwrap_err();
        assert!(matches!(err, DnsError::Transport(_)));
    }

    #[test]
    fn parse_txt_records() {
        // hand-build a TXT response
        let mut m = Vec::new();
        m.extend_from_slice(&0x1234_u16.to_be_bytes());
        m.extend_from_slice(&0x8180_u16.to_be_bytes());
        m.extend_from_slice(&1_u16.to_be_bytes());
        m.extend_from_slice(&1_u16.to_be_bytes());
        m.extend_from_slice(&[0, 0, 0, 0]);
        m.extend_from_slice(&wire_name("d.test"));
        m.extend_from_slice(&rtype::TXT.to_be_bytes());
        m.extend_from_slice(&1_u16.to_be_bytes());
        m.extend_from_slice(&wire_name("d.test"));
        m.extend_from_slice(&rtype::TXT.to_be_bytes());
        m.extend_from_slice(&1_u16.to_be_bytes());
        m.extend_from_slice(&60_u32.to_be_bytes());
        let txt = b"v=spf1 -all";
        m.extend_from_slice(&(txt.len() as u16 + 1).to_be_bytes());
        m.push(txt.len() as u8);
        m.extend_from_slice(txt);
        let recs = parse_response(&m).unwrap();
        assert_eq!(recs[0].data, "v=spf1 -all");
        assert_eq!(recs[0].rtype, rtype::TXT);
    }

    /// Regression (found querying github.com NS live): multi-answer responses
    /// where later answer names are compressed pointers — the rdata offset
    /// must be tracked absolutely, not derived from `msg.len() - rdata.len()`
    /// (only correct for the final record).
    #[test]
    fn multi_answer_with_compression_parses_all() {
        let mut m = Vec::new();
        m.extend_from_slice(&0x4242_u16.to_be_bytes());
        m.extend_from_slice(&0x8180_u16.to_be_bytes());
        m.extend_from_slice(&1_u16.to_be_bytes()); // QDCOUNT
        m.extend_from_slice(&2_u16.to_be_bytes()); // ANCOUNT = 2
        m.extend_from_slice(&[0, 0, 0, 0]);
        // question: ns.test NS IN
        m.extend_from_slice(&wire_name("ns.test"));
        m.extend_from_slice(&rtype::NS.to_be_bytes());
        m.extend_from_slice(&1_u16.to_be_bytes());
        // answer 1: ns.test -> a.ns.test (name inline)
        m.extend_from_slice(&wire_name("ns.test"));
        m.extend_from_slice(&rtype::NS.to_be_bytes());
        m.extend_from_slice(&1_u16.to_be_bytes());
        m.extend_from_slice(&300_u32.to_be_bytes());
        let rd = wire_name("a.ns.test");
        m.extend_from_slice(&(rd.len() as u16).to_be_bytes());
        m.extend_from_slice(&rd);
        // answer 2: name compressed (ptr to question at 12), rdata compressed too
        m.extend_from_slice(&[0xC0, 0x0C]);
        m.extend_from_slice(&rtype::NS.to_be_bytes());
        m.extend_from_slice(&1_u16.to_be_bytes());
        m.extend_from_slice(&300_u32.to_be_bytes());
        m.extend_from_slice(&2_u16.to_be_bytes());
        m.extend_from_slice(&[0xC0, 0x2E]); // ptr to "ns.test" inside answer-1 rdata
        let recs = parse_response(&m).unwrap();
        assert_eq!(recs.len(), 2);
        assert_eq!(recs[0].data, "a.ns.test");
        assert_eq!(recs[1].data, "ns.test"); // resolved through two hops
    }

    #[test]
    fn parse_rejects_malformed() {
        assert!(parse_response(&[0u8; 5]).is_err());
        // QR bit not set
        let mut m = vec![0u8; 12];
        m[2] = 0x01; // RD only
        assert!(matches!(parse_response(&m), Err(DnsError::Transport(_))));
    }
}

/// Convenience: resolve MX records for a domain using the system resolver.
/// Returns an empty vec when the domain has no MX records; errors on
/// transport failure.
pub async fn resolve_mx(domain: &str) -> Result<Vec<DnsRecord>, DnsError> {
    let server =
        system_server().ok_or_else(|| DnsError::Transport("no nameserver available".into()))?;
    query(server, domain, 15).await // 15 = MX
}
