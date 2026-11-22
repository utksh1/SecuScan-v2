//! SecuScan DNS OOB receiver (Max-Parity Sprint 4.3, issue #36).
//!
//! A lightweight authoritative DNS server that:
//! 1. Listens on a configurable UDP port (default 5353 — non-privileged;
//!    point NS delegation at the mapped port or use a port-forward to 53).
//! 2. Records every query (source IP, qname, query type, timestamp) into
//!    the shared `oob_hits` table via the same `oob_handlers`/marker
//!    correlation used by the HTTP OOB receiver.
//! 3. Answers A queries with a fixed address (configurable) and TXT queries
//!    with a configurable response — the content doesn't matter, only the
//!    fact that the DNS query was made.
//!
//! The qname embeds the task marker: `<random>.<ptt-marker>.oob.<domain>`.
//! The marker is extracted and the hit is correlated to the originating
//! task, auto-opening a validated finding.
//!
//! Usage:
//! ```bash
//! SECUSCAN_DB_URL=sqlite://./data/secuscan.db \
//! SECUSCAN_OOB_DNS_PORT=5353 \
//! SECUSCAN_OOB_DNS_DOMAIN=oob.example.com \
//! SECUSCAN_OOB_DNS_A_RECORD=127.0.0.1 \
//! ./target/release/secuscan-oob-dns
//! ```

use secuscan_db::repo;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key)
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| default.to_string())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "secuscan_oob_dns=info".into()),
        )
        .init();
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(run())
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let db_url = env_or("SECUSCAN_DB_URL", "sqlite://./data/secuscan.db?mode=rwc");
    let pool = secuscan_db::open(&db_url).await?;

    let port: u16 = env_or("SECUSCAN_OOB_DNS_PORT", "5353").parse()?;
    let domain = env_or("SECUSCAN_OOB_DNS_DOMAIN", "oob.secuscan.local");
    let a_record = env_or("SECUSCAN_OOB_DNS_A_RECORD", "127.0.0.1");
    let txt_record = env_or("SECUSCAN_OOB_DNS_TXT_RECORD", "secuscan-oob-receiver");

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    let socket = Arc::new(UdpSocket::bind(addr).await?);
    tracing::info!(
        "DNS OOB receiver listening on UDP {addr} (domain: {domain}, A: {a_record})"
    );

    let mut buf = vec![0u8; 512];
    loop {
        let (size, source) = match socket.recv_from(&mut buf).await {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!("DNS recv error: {e}");
                continue;
            }
        };
        let packet = buf[..size].to_vec();
        let socket = socket.clone();
        let pool = pool.clone();
        let domain = domain.clone();
        let a_record = a_record.clone();
        let txt_record = txt_record.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_query(&socket, source, &packet, &pool, &domain, &a_record, &txt_record).await {
                tracing::debug!("DNS query from {source} handling error: {e}");
            }
        });
    }
}

/// Handle a single DNS query: parse the qname, record the hit, respond.
async fn handle_query(
    socket: &UdpSocket,
    source: SocketAddr,
    packet: &[u8],
    pool: &sqlx::SqlitePool,
    domain: &str,
    a_record: &str,
    txt_record: &str,
) -> Result<(), String> {
    // Parse the DNS header + question section.
    if packet.len() < 12 {
        return Err("packet too short".into());
    }
    let tx_id = u16::from_be_bytes([packet[0], packet[1]]);
    let flags = u16::from_be_bytes([packet[2], packet[3]]);
    let is_query = (flags & 0x8000) == 0;
    if !is_query {
        return Ok(()); // response, not query
    }
    let qd_count = u16::from_be_bytes([packet[4], packet[5]]);
    if qd_count == 0 {
        return Ok(());
    }

    // Parse the qname (label sequence).
    let mut offset = 12;
    let mut labels = Vec::new();
    loop {
        if offset >= packet.len() {
            return Err("qname truncated".into());
        }
        let len = packet[offset];
        if len == 0 {
            offset += 1;
            break;
        }
        let label = String::from_utf8_lossy(&packet[offset + 1..offset + 1 + len as usize]).to_string();
        labels.push(label);
        offset += 1 + len as usize;
    }
    // Query type (2 bytes after qname).
    let qtype = if offset + 2 <= packet.len() {
        u16::from_be_bytes([packet[offset], packet[offset + 1]])
    } else {
        1 // A
    };
    let qtype_name = match qtype {
        1 => "A",
        2 => "NS",
        5 => "CNAME",
        6 => "SOA",
        12 => "PTR",
        15 => "MX",
        16 => "TXT",
        28 => "AAAA",
        _ => "TYPE",
    };
    let qname = labels.join(".");

    // Extract the OOB marker from the qname labels.
    let marker = labels
        .iter()
        .find(|l| l.starts_with("ptt") && l.len() == 15)
        .cloned();

    // Look up the handler and correlate to a task.
    // Use the first http_logger handler (DNS hits share the HTTP handler
    // space for a unified hits view; the handler's kind covers both).
    let handler = secuscan_db::repo::oob::list_handlers(pool, None)
        .await
        .ok()
        .and_then(|handlers| handlers.into_iter().find(|h| h.kind == "http_logger"));

    let task_id: Option<String> = if let Some(ref m) = marker {
        sqlx::query_scalar::<_, Option<String>>(
            "SELECT id FROM tasks WHERE oob_marker = ?1 LIMIT 1",
        )
        .bind(m)
        .fetch_optional(pool)
        .await
        .ok()
        .flatten()
        .flatten()
    } else {
        None
    };

    // Record the hit.
    if let Some(handler) = &handler {
        let payload = serde_json::json!({
            "source_ip": source.ip().to_string(),
            "method": "DNS",
            "url": format!("dns:{qtype_name}:{qname}"),
            "qname": qname,
            "qtype": qtype_name,
            "domain": domain,
            "headers": {},
            "body": String::new(),
            "user_agent": "",
            "marker": marker,
            "stream": qtype_name,
            "data": qname,
        });
        let payload_json = serde_json::to_string(&payload).unwrap_or_default();
        if let Err(e) = secuscan_db::repo::oob::record_hit(
            pool,
            &handler.id,
            task_id.as_deref(),
            &payload_json,
        )
        .await
        {
            tracing::warn!("DNS hit recording failed: {e}");
        }

        tracing::info!(
            "DNS hit: {qtype_name} {qname} from {source} → task {task_id:?}"
        );
    }

    // Build and send a DNS response.
    let mut response = Vec::new();
    response.extend_from_slice(&tx_id.to_be_bytes());
    // Flags: QR=1, AA=1, RD=1, RA=1
    response.extend_from_slice(&[0x84, 0x80]);
    response.extend_from_slice(&packet[4..6]); // QDCOUNT (copy)
    response.extend_from_slice(&[0, 1]); // ANCOUNT = 1
    response.extend_from_slice(&[0, 0]); // NSCOUNT
    response.extend_from_slice(&[0, 0]); // ARCOUNT

    // Copy the question section (qname + qtype + qclass).
    let qname_start = 12;
    let qname_end = offset + 2; // + qtype(2) + qclass(2) = offset+4
    let qtype_end = (offset + 4).min(packet.len());
    response.extend_from_slice(&packet[qname_start..qtype_end.min(packet.len())]);

    // Answer section: name pointer (0xc00c) + type + class + ttl + rdlen + rdata
    response.extend_from_slice(&[0xc0, 0x0c]); // pointer to qname at offset 12
    let answer_type = if qtype == 16 { 16u16 } else { 1u16 }; // TXT or A
    response.extend_from_slice(&answer_type.to_be_bytes());
    response.extend_from_slice(&[0, 1]); // class IN
    response.extend_from_slice(&60u32.to_be_bytes()); // TTL 60s
    if answer_type == 16 {
        // TXT record
        let txt = txt_record.as_bytes();
        response.extend_from_slice(&(txt.len() as u16 + 1).to_be_bytes());
        response.push(txt.len() as u8);
        response.extend_from_slice(txt);
    } else {
        // A record
        response.extend_from_slice(&4u16.to_be_bytes());
        match a_record.parse::<std::net::Ipv4Addr>() {
            Ok(addr) => response.extend_from_slice(&addr.octets()),
            Err(_) => response.extend_from_slice(&[127, 0, 0, 1]),
        }
    }

    socket
        .send_to(&response, source)
        .await
        .map_err(|e| format!("send: {e}"))?;
    Ok(())
}
