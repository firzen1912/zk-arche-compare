use anyhow::{anyhow, Context, Result};
use rand::{rngs::OsRng, RngCore};
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};
use tokio_rustls::TlsConnector;

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

fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn random_nonce() -> [u8; 32] {
    let mut nonce = [0u8; 32];
    OsRng.fill_bytes(&mut nonce);
    nonce
}

fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

fn build_auth_request(device_id: &str, payload: &[u8]) -> Result<Vec<u8>> {
    let device_id_bytes = device_id.as_bytes();
    if device_id_bytes.len() > u8::MAX as usize {
        anyhow::bail!("device_id is too long; max 255 bytes");
    }
    if payload.len() > u16::MAX as usize {
        anyhow::bail!("payload too large; max 65535 bytes");
    }

    let nonce = random_nonce();
    let timestamp_ms = now_millis();

    let mut out = Vec::with_capacity(1 + 1 + device_id_bytes.len() + 8 + 32 + 2 + payload.len());
    out.push(MTLS_REQ_V1);
    out.push(device_id_bytes.len() as u8);
    out.extend_from_slice(device_id_bytes);
    out.extend_from_slice(&timestamp_ms.to_be_bytes());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    out.extend_from_slice(payload);
    Ok(out)
}

fn parse_auth_response(resp: &[u8], request: &[u8]) -> Result<()> {
    if resp.len() != 1 + 1 + 32 + 32 {
        anyhow::bail!("bad response length: {}", resp.len());
    }
    if resp[0] != MTLS_RESP_V1 {
        anyhow::bail!("bad response type: 0x{:02x}", resp[0]);
    }
    if resp[1] != 0x00 {
        anyhow::bail!("server returned non-OK status: 0x{:02x}", resp[1]);
    }

    let expected_hash = Sha256::digest(request);
    if resp[34..66] != expected_hash[..] {
        anyhow::bail!("server response hash does not match request");
    }
    Ok(())
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

    let server_addr = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:7443".to_string());
    let server_name = std::env::args()
        .nth(2)
        .unwrap_or_else(|| "localhost".to_string());
    let device_id = std::env::var("MTLS_DEVICE_ID").unwrap_or_else(|_| "mtls-device-001".to_string());
    let payload = std::env::var("MTLS_PAYLOAD").unwrap_or_else(|_| "industry-style-mtls-auth-check".to_string());

    let ca_cert = load_certs("certs/ca.crt")?;
    let client_cert = load_certs("certs/client.crt")?;
    let client_key = load_private_key("certs/client.key")?;

    let client_leaf_fp = client_cert
        .first()
        .map(|c| sha256_hex(c.as_ref()))
        .unwrap_or_else(|| "missing-client-cert".to_string());

    let mut roots = RootCertStore::empty();
    for cert in ca_cert {
        roots.add(cert)?;
    }

    let config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_client_auth_cert(client_cert, client_key)?;

    let connector = TlsConnector::from(Arc::new(config));

    let tcp = timeout(IO_TIMEOUT, TcpStream::connect(&server_addr))
        .await
        .context("TCP connect timed out")??;
    tcp.set_nodelay(true)?;

    let counters = IoCounters::default();
    let counted_tcp = CountingStream::new(tcp, counters.clone());
    let dns_name = ServerName::try_from(server_name)?.to_owned();

    // Match the other protocols: start immediately before protocol bytes.
    let start = Instant::now();

    let mut tls = timeout(IO_TIMEOUT, connector.connect(dns_name, counted_tcp))
        .await
        .context("TLS connect timed out")??;

    let request = build_auth_request(&device_id, payload.as_bytes())?;
    write_frame(&mut tls, &request).await?;

    let response = read_frame(&mut tls).await?;
    parse_auth_response(&response, &request)?;

    let elapsed = start.elapsed();
    println!(
        "CLIENT METRICS -> Protocol: mTLS/TCP, Duration: {:?}, Sent: {} bytes, Received: {} bytes, DeviceID: {}, ClientCertSHA256: {}, RequestBytes: {}, ResponseBytes: {}",
        elapsed,
        counters.sent(),
        counters.recv(),
        device_id,
        client_leaf_fp,
        request.len(),
        response.len()
    );

    let _ = timeout(IO_TIMEOUT, tls.shutdown()).await;
    Ok(())
}
