use anyhow::{anyhow, Result};
use hexlit::hex;
use lakers::{
    credential_check_or_fetch,
    Credential,
    CredentialTransfer,
    EDHOCMethod,
    EDHOCSuite,
    EdhocInitiator,
    EdhocMessageBuffer,
};
use rand::rngs::OsRng;
use std::time::Instant;
use tokio::net::TcpStream;

#[path = "../common/framing.rs"]
mod framing;
#[path = "../common/metrics.rs"]
mod metrics;

use framing::{recv_frame, send_frame};
use metrics::HandshakeMetrics;

const MAX_FRAME: usize = 4096;

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

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();

    let server_addr = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:5688".to_string());

    let mut stream = TcpStream::connect(&server_addr).await?;
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
    send_frame(
        &mut stream,
        message_1.as_slice(),
        &mut metrics.bytes_sent,
    )
    .await?;

    let message_2_raw = recv_frame(&mut stream, &mut metrics.bytes_received, MAX_FRAME).await?;
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
    send_frame(
        &mut stream,
        message_3.as_slice(),
        &mut metrics.bytes_sent,
    )
    .await?;

    let message_4_raw = recv_frame(&mut stream, &mut metrics.bytes_received, MAX_FRAME).await?;
    let message_4 = EdhocMessageBuffer::new_from_slice(&message_4_raw)
        .map_err(|e| anyhow!("invalid message_4 buffer: {e:?}"))?;

    let (mut initiator_done, _ead_4) = initiator
        .process_message_4(&message_4)
        .map_err(|e| anyhow!("process_message_4 failed: {e:?}"))?;

    let oscore_secret = initiator_done.edhoc_exporter(0u8, &[], 16);

    metrics.note = Some(format!(
        "derived_oscore_secret={}",
        hex::encode(oscore_secret)
    ));
    metrics.finalize(start.elapsed(), true);

    println!(
        "CLIENT METRICS -> Duration: {:?}, Sent: {} bytes, Received: {} bytes",
        start.elapsed(),
        metrics.bytes_sent,
        metrics.bytes_received
    );

    Ok(())
}