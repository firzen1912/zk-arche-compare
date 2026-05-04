use anyhow::{anyhow, Context, Result};
use rand::{rngs::OsRng, RngCore};
use rustls::{RootCertStore, ServerConfig};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fs;
use std::sync::Arc;
use std::time::{Duration as StdDuration, Instant, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tokio::time::{timeout, Duration};
use tokio_rustls::TlsAcceptor;

#[path = "../common/certs.rs"]
mod certs;
#[path = "../common/counting_stream.rs"]
mod counting_stream;

use certs::{load_certs, load_private_key};
use counting_stream::{CountingStream, IoCounters};

const MAX_FRAME: usize = 4096;
const IO_TIMEOUT: Duration = Duration::from_secs(5);
const MTLS_REQ_V1: u8 = 0x41;
const MTLS_RESP_V1: u8 = 0x42;
const DEFAULT_MAX_ACTIVE_CONNECTIONS: usize = 128;
const MAX_CLOCK_SKEW: StdDuration = StdDuration::from_secs(300);

#[derive(Debug)]
struct AuthRequest {
    device_id: String,
    timestamp_ms: u64,
    nonce: [u8; 32],
    payload: Vec<u8>,
}

fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

fn random_nonce() -> [u8; 32] {
    let mut nonce = [0u8; 32];
    OsRng.fill_bytes(&mut nonce);
    nonce
}

fn load_allowed_fingerprints() -> Result<HashSet<String>> {
    let mut allowed = HashSet::new();

    if let Ok(csv) = std::env::var("MTLS_ALLOWED_CLIENT_FINGERPRINTS") {
        for item in csv.split(',') {
            let fp = item.trim().to_ascii_lowercase();
            if !fp.is_empty() {
                allowed.insert(fp);
            }
        }
    }

    let path = std::env::var("MTLS_ALLOWED_CLIENTS_FILE")
        .unwrap_or_else(|_| "certs/authorized_clients.txt".to_string());
    if let Ok(contents) = fs::read_to_string(path) {
        for line in contents.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            allowed.insert(line.to_ascii_lowercase());
        }
    }

    Ok(allowed)
}

fn parse_auth_request(buf: &[u8]) -> Result<AuthRequest> {
    if buf.len() < 1 + 1 + 8 + 32 + 2 {
        anyhow::bail!("request too short: {}", buf.len());
    }
    if buf[0] != MTLS_REQ_V1 {
        anyhow::bail!("bad request type: 0x{:02x}", buf[0]);
    }

    let id_len = buf[1] as usize;
    let mut offset = 2;
    if buf.len() < offset + id_len + 8 + 32 + 2 {
        anyhow::bail!("malformed request length");
    }

    let device_id = std::str::from_utf8(&buf[offset..offset + id_len])
        .context("device_id is not UTF-8")?
        .to_string();
    offset += id_len;

    let mut ts = [0u8; 8];
    ts.copy_from_slice(&buf[offset..offset + 8]);
    let timestamp_ms = u64::from_be_bytes(ts);
    offset += 8;

    let mut nonce = [0u8; 32];
    nonce.copy_from_slice(&buf[offset..offset + 32]);
    offset += 32;

    let mut payload_len = [0u8; 2];
    payload_len.copy_from_slice(&buf[offset..offset + 2]);
    let payload_len = u16::from_be_bytes(payload_len) as usize;
    offset += 2;

    if buf.len() != offset + payload_len {
        anyhow::bail!("payload length mismatch");
    }

    let now = now_millis();
    let skew_ms = now.abs_diff(timestamp_ms);
    if skew_ms > MAX_CLOCK_SKEW.as_millis() as u64 {
        anyhow::bail!("request timestamp outside allowed clock skew: {} ms", skew_ms);
    }

    Ok(AuthRequest {
        device_id,
        timestamp_ms,
        nonce,
        payload: buf[offset..].to_vec(),
    })
}

fn build_auth_response(request_raw: &[u8]) -> Vec<u8> {
    let server_nonce = random_nonce();
    let request_hash = Sha256::digest(request_raw);

    let mut out = Vec::with_capacity(1 + 1 + 32 + 32);
    out.push(MTLS_RESP_V1);
    out.push(0x00); // OK
    out.extend_from_slice(&server_nonce);
    out.extend_from_slice(&request_hash);
    out
}

async fn write_frame<W>(w: &mut W, data: &[u8]) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    if data.len() > MAX_FRAME {
        anyhow::bail!("frame too large: {}", data.len());
    }
    let len = data.len() as u32;
    timeout(IO_TIMEOUT, w.write_all(&len.to_be_bytes())).await??;
    timeout(IO_TIMEOUT, w.write_all(data)).await??;
    timeout(IO_TIMEOUT, w.flush()).await??;
    Ok(())
}

async fn read_frame<R>(r: &mut R) -> Result<Vec<u8>>
where
    R: AsyncRead + Unpin,
{
    let mut len_buf = [0u8; 4];
    timeout(IO_TIMEOUT, r.read_exact(&mut len_buf)).await??;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_FRAME {
        anyhow::bail!("received frame too large: {}", len);
    }
    let mut buf = vec![0u8; len];
    timeout(IO_TIMEOUT, r.read_exact(&mut buf)).await??;
    Ok(buf)
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();

    let bind_addr = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "0.0.0.0:7443".to_string());

    let max_active = std::env::var("MTLS_MAX_ACTIVE_CONNECTIONS")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(DEFAULT_MAX_ACTIVE_CONNECTIONS);

    let server_cert = load_certs("certs/server.crt")?;
    let server_key = load_private_key("certs/server.key")?;
    let ca_cert = load_certs("certs/ca.crt")?;

    let allowed_fingerprints = Arc::new(load_allowed_fingerprints()?);
    if allowed_fingerprints.is_empty() {
        eprintln!(
            "mTLS warning: no explicit client fingerprint allowlist found; trusting any client cert signed by configured CA"
        );
    } else {
        println!(
            "mTLS loaded {} allowed client certificate fingerprint(s)",
            allowed_fingerprints.len()
        );
    }

    let mut client_roots = RootCertStore::empty();
    for cert in ca_cert {
        client_roots.add(cert)?;
    }

    let client_verifier =
        rustls::server::WebPkiClientVerifier::builder(Arc::new(client_roots)).build()?;

    let config = ServerConfig::builder()
        .with_client_cert_verifier(client_verifier)
        .with_single_cert(server_cert, server_key)?;

    let acceptor = TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind(&bind_addr).await?;
    let permits = Arc::new(Semaphore::new(max_active));

    println!(
        "mTLS upgraded server listening on {} with max_active_connections={}",
        bind_addr, max_active
    );

    loop {
        let (tcp, peer_addr) = listener.accept().await?;
        let acceptor = acceptor.clone();
        let allowed_fingerprints = allowed_fingerprints.clone();
        let permit = match permits.clone().try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                eprintln!("mTLS rejecting {:?}: too many active connections", peer_addr);
                continue;
            }
        };

        tokio::spawn(async move {
            let _permit = permit;
            let counters = IoCounters::default();

            let result: Result<()> = async {
                tcp.set_nodelay(true)?;
                let counted_tcp = CountingStream::new(tcp, counters.clone());

                // Match the other protocols: start immediately before protocol processing.
                let start = Instant::now();

                let mut tls_stream = timeout(IO_TIMEOUT, acceptor.accept(counted_tcp))
                    .await
                    .context("TLS accept timed out")??;

                let (_, session) = tls_stream.get_ref();
                let peer_certs = session
                    .peer_certificates()
                    .ok_or_else(|| anyhow!("client certificate missing"))?;
                let leaf = peer_certs
                    .first()
                    .ok_or_else(|| anyhow!("client leaf certificate missing"))?;
                let client_fp = sha256_hex(leaf.as_ref()).to_ascii_lowercase();

                if !allowed_fingerprints.is_empty() && !allowed_fingerprints.contains(&client_fp) {
                    anyhow::bail!("unauthorized client certificate fingerprint: {}", client_fp);
                }

                let request_raw = read_frame(&mut tls_stream).await?;
                let request = parse_auth_request(&request_raw)?;
                let response = build_auth_response(&request_raw);
                write_frame(&mut tls_stream, &response).await?;

                println!(
                    "SERVER METRICS -> Peer: {:?}, Protocol: mTLS/TCP, Duration: {:?}, Sent: {} bytes, Received: {} bytes, DeviceID: {}, ClientCertSHA256: {}, RequestBytes: {}, ResponseBytes: {}, PayloadBytes: {}, TimestampMs: {}",
                    peer_addr,
                    start.elapsed(),
                    counters.sent(),
                    counters.recv(),
                    request.device_id,
                    client_fp,
                    request_raw.len(),
                    response.len(),
                    request.payload.len(),
                    request.timestamp_ms,
                );

                let _ = timeout(IO_TIMEOUT, tls_stream.shutdown()).await;
                Ok(())
            }
            .await;

            if let Err(e) = result {
                eprintln!("mTLS server: request from {:?} failed: {}", peer_addr, e);
            }
        });
    }
}
