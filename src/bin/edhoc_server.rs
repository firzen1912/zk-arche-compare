use anyhow::{anyhow, Result};
use hexlit::hex;
use hmac::{Hmac, Mac};
use hkdf::Hkdf;
use lakers::{
    credential_check_or_fetch, Credential, CredentialTransfer, EDHOCMethod, EdhocMessageBuffer,
    EdhocResponder,
};
use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::convert::TryInto;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
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
const DEFAULT_MAX_ACTIVE_CONNECTIONS: usize = 128;
const APP_REQ_VERSION: u8 = 1;
const APP_RESP_VERSION: u8 = 1;

const CRED_I: &[u8] = &hex!(
    "A2027734322D35302D33312D46462D45462D33372D33322D333908A101A5010202412B2001215820AC75E9ECE3E50BFC8ED60399889522405C47BF16DF96660A41298CB4307F7EB62258206E5DE611388A4B8A8211334AC7D37ECB52A387D257E6DB3C2A93DF21FF3AFFC8"
);
const CRED_R: &[u8] = &hex!(
    "A2026008A101A5010202410A2001215820BBC34960526EA4D32E940CAD2A234148DDC21791A12AFBCBAC93622046DD44F02258204519E257236B2A0CE2023F0931F1F386CA7AFDA64FCDE0108C224C51EABF6072"
);
const R: &[u8] = &hex!(
    "72cc4761dbd4c78f758931aa589d348d1ef874a7e303ede2f140dcf3e6aa4aac"
);

#[derive(Clone, Debug)]
struct ProtectedRequest {
    device_id: String,
    timestamp_ms: u64,
    payload_len: usize,
}

fn new_crypto() -> lakers_crypto::Crypto<OsRng> {
    lakers_crypto::Crypto::new(OsRng)
}

fn env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(default)
}

fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(default)
}

fn allowed_device_ids_from_env() -> HashSet<String> {
    std::env::var("EDHOC_ALLOWED_DEVICE_IDS")
        .unwrap_or_default()
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
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

fn parse_and_verify_request(request: &[u8], c2s_key: &[u8; 32]) -> Result<ProtectedRequest> {
    if request.len() < 1 + 1 + 8 + 32 + 2 + 32 {
        return Err(anyhow!("EDHOC protected request too short"));
    }
    if request[0] != APP_REQ_VERSION {
        return Err(anyhow!("unsupported EDHOC protected request version"));
    }

    let device_len = request[1] as usize;
    if device_len == 0 || device_len > 64 {
        return Err(anyhow!("invalid EDHOC device id length"));
    }

    let fixed_without_device = 1 + 1 + 8 + 32 + 2 + 32;
    if request.len() < fixed_without_device + device_len {
        return Err(anyhow!("truncated EDHOC protected request"));
    }

    let tag_start = request.len() - 32;
    let body = &request[..tag_start];
    let got_tag: [u8; 32] = request[tag_start..].try_into().unwrap();
    let expected_tag = hmac_tag(c2s_key, b"edhoc-app-request-v1", body)?;
    if got_tag != expected_tag {
        return Err(anyhow!("invalid EDHOC protected request HMAC"));
    }

    let mut offset = 2;
    let device_id = std::str::from_utf8(&request[offset..offset + device_len])?.to_string();
    offset += device_len;

    let timestamp_ms = u64::from_le_bytes(request[offset..offset + 8].try_into().unwrap());
    offset += 8;

    offset += 32; // client nonce

    let payload_len = u16::from_le_bytes(request[offset..offset + 2].try_into().unwrap()) as usize;
    offset += 2;

    if offset + payload_len != tag_start {
        return Err(anyhow!("EDHOC protected request payload length mismatch"));
    }

    Ok(ProtectedRequest {
        device_id,
        timestamp_ms,
        payload_len,
    })
}

fn build_response(status: u8, request: &[u8], s2c_key: &[u8; 32]) -> Result<Vec<u8>> {
    let mut server_nonce = [0u8; 32];
    OsRng.fill_bytes(&mut server_nonce);

    let request_hash = Sha256::digest(request);

    let mut body = Vec::with_capacity(66 + 32);
    body.push(APP_RESP_VERSION);
    body.push(status);
    body.extend_from_slice(&server_nonce);
    body.extend_from_slice(&request_hash);

    let tag = hmac_tag(s2c_key, b"edhoc-app-response-v1", &body)?;
    body.extend_from_slice(&tag);
    Ok(body)
}

async fn handle_connection(
    mut stream: TcpStream,
    peer: String,
    io_timeout: Duration,
    allowed_device_ids: Arc<HashSet<String>>,
) -> Result<()> {
    let start = Instant::now();
    let mut metrics = HandshakeMetrics::new("EDHOC/TCP", "server", &peer);

    let cred_r: Credential = Credential::parse_ccs(CRED_R.try_into().unwrap()).unwrap();

    let responder = EdhocResponder::new(
        new_crypto(),
        EDHOCMethod::StatStat,
        R.try_into().expect("Wrong length of responder private key"),
        cred_r.clone(),
    );

    let message_1_raw = recv_frame_timeout(&mut stream, &mut metrics.bytes_received, io_timeout).await?;
    let message_1 = EdhocMessageBuffer::new_from_slice(&message_1_raw)
        .map_err(|e| anyhow!("invalid message_1 buffer: {e:?}"))?;

    let (responder, _c_i, _ead_1) = responder
        .process_message_1(&message_1)
        .map_err(|e| anyhow!("process_message_1 failed: {e:?}"))?;

    let (responder, message_2) = responder
        .prepare_message_2(CredentialTransfer::ByReference, None, &None)
        .map_err(|e| anyhow!("prepare_message_2 failed: {e:?}"))?;

    send_frame_timeout(&mut stream, message_2.as_slice(), &mut metrics.bytes_sent, io_timeout).await?;

    let message_3_raw = recv_frame_timeout(&mut stream, &mut metrics.bytes_received, io_timeout).await?;
    let message_3 = EdhocMessageBuffer::new_from_slice(&message_3_raw)
        .map_err(|e| anyhow!("invalid message_3 buffer: {e:?}"))?;

    let (responder, id_cred_i, _ead_3) = responder
        .parse_message_3(&message_3)
        .map_err(|e| anyhow!("parse_message_3 failed: {e:?}"))?;

    let cred_i: Credential = Credential::parse_ccs(CRED_I.try_into().unwrap()).unwrap();
    let valid_cred_i = credential_check_or_fetch(Some(cred_i), id_cred_i)
        .map_err(|e| anyhow!("credential_check_or_fetch failed: {e:?}"))?;

    let (mut responder, _r_prk_out) = responder
        .verify_message_3(valid_cred_i)
        .map_err(|e| anyhow!("verify_message_3 failed: {e:?}"))?;

    let (mut responder_done, message_4) = responder
        .prepare_message_4(&None)
        .map_err(|e| anyhow!("prepare_message_4 failed: {e:?}"))?;

    send_frame_timeout(&mut stream, message_4.as_slice(), &mut metrics.bytes_sent, io_timeout).await?;

    let oscore_secret = responder_done.edhoc_exporter(0u8, &[], 16);
    let (c2s_key, s2c_key) = derive_app_keys(&oscore_secret)?;

    let request = recv_frame_timeout(&mut stream, &mut metrics.bytes_received, io_timeout).await?;
    let parsed_request = parse_and_verify_request(&request, &c2s_key)?;

    let authorized = allowed_device_ids.is_empty() || allowed_device_ids.contains(&parsed_request.device_id);
    let status = if authorized { 0u8 } else { 1u8 };
    let response = build_response(status, &request, &s2c_key)?;
    let response_bytes = response.len();
    send_frame_timeout(&mut stream, &response, &mut metrics.bytes_sent, io_timeout).await?;

    if !authorized {
        return Err(anyhow!("unauthorized EDHOC device id: {}", parsed_request.device_id));
    }

    metrics.note = Some(format!(
        "device_id={}, request_bytes={}, response_bytes={}, request_timestamp_ms={}, payload_len={}",
        parsed_request.device_id,
        request.len(),
        response_bytes,
        parsed_request.timestamp_ms,
        parsed_request.payload_len
    ));
    metrics.finalize(start.elapsed(), true);

    println!(
        "SERVER METRICS -> Peer: {}, Protocol: EDHOC/TCP, Duration: {:?}, Sent: {} bytes, Received: {} bytes, RequestBytes: {}, ResponseBytes: {}, DeviceID: {}",
        peer,
        start.elapsed(),
        metrics.bytes_sent,
        metrics.bytes_received,
        request.len(),
        response_bytes,
        parsed_request.device_id
    );

    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();

    let bind_addr = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "0.0.0.0:5688".to_string());
    let io_timeout = Duration::from_secs(env_u64("EDHOC_TIMEOUT_SECS", DEFAULT_TIMEOUT_SECS));
    let max_active = env_usize("EDHOC_MAX_ACTIVE_CONNECTIONS", DEFAULT_MAX_ACTIVE_CONNECTIONS);
    let allowed_device_ids = Arc::new(allowed_device_ids_from_env());
    let permits = Arc::new(Semaphore::new(max_active));

    let listener = TcpListener::bind(&bind_addr).await?;
    println!(
        "EDHOC/TCP upgraded server listening on {bind_addr}; max_active={max_active}; allowed_device_ids={}",
        if allowed_device_ids.is_empty() { "<any authenticated device>".to_string() } else { allowed_device_ids.len().to_string() }
    );

    loop {
        let (stream, peer_addr) = listener.accept().await?;
        let Ok(permit) = permits.clone().try_acquire_owned() else {
            eprintln!("EDHOC server: rejecting {peer_addr}, too many active connections");
            continue;
        };
        let allowed = allowed_device_ids.clone();
        let peer = peer_addr.to_string();

        tokio::spawn(async move {
            let _permit = permit;
            if let Err(e) = handle_connection(stream, peer.clone(), io_timeout, allowed).await {
                eprintln!("EDHOC server: request from {peer} failed: {e}");
            }
        });
    }
}
