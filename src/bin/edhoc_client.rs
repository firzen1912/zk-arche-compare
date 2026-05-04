use anyhow::{anyhow, Result};
use hexlit::hex;
use hmac::{Hmac, Mac};
use hkdf::Hkdf;
use lakers::{
    credential_check_or_fetch, Credential, CredentialTransfer, EDHOCMethod, EDHOCSuite,
    EdhocInitiator, EdhocMessageBuffer,
};
use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256};
use std::convert::TryInto;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::net::TcpStream;
use tokio::time::timeout;

#[path = "../common/framing.rs"]
mod framing;
#[path = "../common/metrics.rs"]
mod metrics;

use framing::{recv_frame, send_frame};
use metrics::HandshakeMetrics;

type HmacSha256 = Hmac<Sha256>;

const MAX_FRAME: usize = 4096;
const DEFAULT_TIMEOUT_SECS: u64 = 5;
const APP_REQ_VERSION: u8 = 1;
const APP_RESP_VERSION: u8 = 1;

const CRED_I: &[u8] = &hex!(
    "A2027734322D35302D33312D46462D45462D33372D33322D333908A101A5010202412B2001215820AC75E9ECE3E50BFC8ED60399889522405C47BF16DF96660A41298CB4307F7EB62258206E5DE611388A4B8A8211334AC7D37ECB52A387D257E6DB3C2A93DF21FF3AFFC8"
);
const I: &[u8] = &hex!(
    "fb13adeb6518cee5f88417660841142e830a81fe334380a953406a1305e8706b"
);
const CRED_R: &[u8] = &hex!(
    "A2026008A101A5010202410A2001215820BBC34960526EA4D32E940CAD2A234148DDC21791A12AFBCBAC93622046DD44F02258204519E257236B2A0CE2023F0931F1F386CA7AFDA64FCDE0108C224C51EABF6072"
);

fn new_crypto() -> lakers_crypto::Crypto<OsRng> {
    lakers_crypto::Crypto::new(OsRng)
}

fn env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(default)
}

async fn send_frame_timeout(
    stream: &mut TcpStream,
    data: &[u8],
    sent: &mut usize,
    io_timeout: Duration,
) -> Result<()> {
    timeout(io_timeout, send_frame(stream, data, sent))
        .await
        .map_err(|_| anyhow!("send timeout"))??;
    Ok(())
}

async fn recv_frame_timeout(
    stream: &mut TcpStream,
    recv: &mut usize,
    io_timeout: Duration,
) -> Result<Vec<u8>> {
    let data = timeout(io_timeout, recv_frame(stream, recv, MAX_FRAME))
        .await
        .map_err(|_| anyhow!("receive timeout"))??;
    Ok(data)
}

fn derive_app_keys(oscore_secret: &[u8]) -> Result<([u8; 32], [u8; 32])> {
    let hk = Hkdf::<Sha256>::new(Some(b"edhoc-app-channel-v1"), oscore_secret);
    let mut c2s = [0u8; 32];
    let mut s2c = [0u8; 32];
    hk.expand(b"client-to-server request authentication", &mut c2s)
        .map_err(|_| anyhow!("HKDF expand c2s failed"))?;
    hk.expand(b"server-to-client response authentication", &mut s2c)
        .map_err(|_| anyhow!("HKDF expand s2c failed"))?;
    Ok((c2s, s2c))
}

fn hmac_tag(key: &[u8; 32], label: &[u8], data: &[u8]) -> Result<[u8; 32]> {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key)?;
    mac.update(label);
    mac.update(data);
    let out = mac.finalize().into_bytes();
    let mut tag = [0u8; 32];
    tag.copy_from_slice(&out);
    Ok(tag)
}

fn unix_time_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn build_protected_request(device_id: &str, payload: &[u8], c2s_key: &[u8; 32]) -> Result<Vec<u8>> {
    let device_id_bytes = device_id.as_bytes();
    if device_id_bytes.is_empty() || device_id_bytes.len() > 64 {
        return Err(anyhow!("EDHOC_DEVICE_ID must be 1..64 bytes"));
    }
    if payload.len() > u16::MAX as usize {
        return Err(anyhow!("EDHOC_PAYLOAD too large"));
    }

    let mut nonce = [0u8; 32];
    OsRng.fill_bytes(&mut nonce);

    let mut body = Vec::with_capacity(1 + 1 + device_id_bytes.len() + 8 + 32 + 2 + payload.len());
    body.push(APP_REQ_VERSION);
    body.push(device_id_bytes.len() as u8);
    body.extend_from_slice(device_id_bytes);
    body.extend_from_slice(&unix_time_ms().to_le_bytes());
    body.extend_from_slice(&nonce);
    body.extend_from_slice(&(payload.len() as u16).to_le_bytes());
    body.extend_from_slice(payload);

    let tag = hmac_tag(c2s_key, b"edhoc-app-request-v1", &body)?;
    body.extend_from_slice(&tag);
    Ok(body)
}

fn parse_and_verify_response(response: &[u8], request: &[u8], s2c_key: &[u8; 32]) -> Result<u8> {
    // version(1) | status(1) | server_nonce(32) | sha256(request)(32) | tag(32)
    if response.len() != 98 {
        return Err(anyhow!("bad EDHOC application response length: {}", response.len()));
    }
    if response[0] != APP_RESP_VERSION {
        return Err(anyhow!("unsupported EDHOC application response version"));
    }

    let body = &response[..66];
    let got_tag: [u8; 32] = response[66..98].try_into().unwrap();
    let expected_tag = hmac_tag(s2c_key, b"edhoc-app-response-v1", body)?;
    if got_tag != expected_tag {
        return Err(anyhow!("invalid EDHOC application response HMAC"));
    }

    let request_hash = Sha256::digest(request);
    if response[34..66] != request_hash[..] {
        return Err(anyhow!("EDHOC response did not bind to request hash"));
    }
    Ok(response[1])
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();

    let server_addr = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:5688".to_string());
    let io_timeout = Duration::from_secs(env_u64("EDHOC_TIMEOUT_SECS", DEFAULT_TIMEOUT_SECS));
    let device_id = std::env::var("EDHOC_DEVICE_ID").unwrap_or_else(|_| "edhoc-device".to_string());
    let payload = std::env::var("EDHOC_PAYLOAD")
        .unwrap_or_else(|_| "industry-style-edhoc-authenticated-request".to_string());

    let mut stream = timeout(io_timeout, TcpStream::connect(&server_addr))
        .await
        .map_err(|_| anyhow!("connect timeout"))??;
    stream.set_nodelay(true)?;

    let start = Instant::now();
    let mut metrics = HandshakeMetrics::new("EDHOC/TCP", "client", &server_addr);

    let cred_i: Credential = Credential::parse_ccs(CRED_I.try_into().unwrap()).unwrap();
    let cred_r: Credential = Credential::parse_ccs(CRED_R.try_into().unwrap()).unwrap();

    let initiator = EdhocInitiator::new(
        new_crypto(),
        EDHOCMethod::StatStat,
        EDHOCSuite::CipherSuite2,
    );

    let (initiator, message_1) = initiator
        .prepare_message_1(None, &None)
        .map_err(|e| anyhow!("prepare_message_1 failed: {e:?}"))?;
    send_frame_timeout(&mut stream, message_1.as_slice(), &mut metrics.bytes_sent, io_timeout).await?;

    let message_2_raw = recv_frame_timeout(&mut stream, &mut metrics.bytes_received, io_timeout).await?;
    let message_2 = EdhocMessageBuffer::new_from_slice(&message_2_raw)
        .map_err(|e| anyhow!("invalid message_2 buffer: {e:?}"))?;

    let (mut initiator, _c_r, id_cred_r, _ead_2) = initiator
        .parse_message_2(&message_2)
        .map_err(|e| anyhow!("parse_message_2 failed: {e:?}"))?;

    let valid_cred_r = credential_check_or_fetch(Some(cred_r), id_cred_r)
        .map_err(|e| anyhow!("credential_check_or_fetch failed: {e:?}"))?;

    initiator
        .set_identity(
            I.try_into().expect("Wrong length of initiator private key"),
            cred_i.clone(),
        )
        .map_err(|e| anyhow!("set_identity failed: {e:?}"))?;

    let initiator = initiator
        .verify_message_2(valid_cred_r)
        .map_err(|e| anyhow!("verify_message_2 failed: {e:?}"))?;

    let (mut initiator, message_3, _i_prk_out) = initiator
        .prepare_message_3(CredentialTransfer::ByReference, &None)
        .map_err(|e| anyhow!("prepare_message_3 failed: {e:?}"))?;
    send_frame_timeout(&mut stream, message_3.as_slice(), &mut metrics.bytes_sent, io_timeout).await?;

    let message_4_raw = recv_frame_timeout(&mut stream, &mut metrics.bytes_received, io_timeout).await?;
    let message_4 = EdhocMessageBuffer::new_from_slice(&message_4_raw)
        .map_err(|e| anyhow!("invalid message_4 buffer: {e:?}"))?;

    let (mut initiator_done, _ead_4) = initiator
        .process_message_4(&message_4)
        .map_err(|e| anyhow!("process_message_4 failed: {e:?}"))?;

    let oscore_secret = initiator_done.edhoc_exporter(0u8, &[], 16);
    let (c2s_key, s2c_key) = derive_app_keys(&oscore_secret)?;

    let request = build_protected_request(&device_id, payload.as_bytes(), &c2s_key)?;
    let request_bytes = request.len();
    send_frame_timeout(&mut stream, &request, &mut metrics.bytes_sent, io_timeout).await?;

    let response = recv_frame_timeout(&mut stream, &mut metrics.bytes_received, io_timeout).await?;
    let response_status = parse_and_verify_response(&response, &request, &s2c_key)?;
    if response_status != 0 {
        return Err(anyhow!("EDHOC application authorization failed with status={response_status}"));
    }
    let response_bytes = response.len();

    metrics.note = Some(format!(
        "device_id={}, request_bytes={}, response_bytes={}, derived_oscore_secret={}",
        device_id,
        request_bytes,
        response_bytes,
        hex::encode(oscore_secret)
    ));
    metrics.finalize(start.elapsed(), true);

    println!(
        "CLIENT METRICS -> Protocol: EDHOC/TCP, Duration: {:?}, Sent: {} bytes, Received: {} bytes, RequestBytes: {}, ResponseBytes: {}, DeviceID: {}",
        start.elapsed(),
        metrics.bytes_sent,
        metrics.bytes_received,
        request_bytes,
        response_bytes,
        device_id
    );

    Ok(())
}
