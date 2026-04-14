use anyhow::{anyhow, Result};
use hexlit::hex;
use lakers::{
    credential_check_or_fetch,
    generate_connection_identifier_cbor,
    Credential,
    CredentialTransfer,
    EDHOCMethod,
    EdhocMessageBuffer,
    EdhocResponder,
};
use rand::rngs::OsRng;
use std::time::Instant;
use tokio::net::TcpListener;

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
const CRED_R: &[u8] = &hex!(
    "A2026008A101A5010202410A2001215820BBC34960526EA4D32E940CAD2A234148DDC21791A12AFBCBAC93622046DD44F02258204519E257236B2A0CE2023F0931F1F386CA7AFDA64FCDE0108C224C51EABF6072"
);
const R: &[u8] = &hex!(
    "72cc4761dbd4c78f758931aa589d348d1ef874a7e303ede2f140dcf3e6aa4aac"
);

fn new_crypto() -> lakers_crypto::Crypto<OsRng> {
    lakers_crypto::Crypto::new(OsRng)
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();

    let bind_addr = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "0.0.0.0:5688".to_string());

    let listener = TcpListener::bind(&bind_addr).await?;
    println!("EDHOC/TCP server listening on {bind_addr}");

    loop {
        let (mut stream, peer_addr) = listener.accept().await?;

        tokio::spawn(async move {
            let start = Instant::now();
            let mut metrics = HandshakeMetrics::new("EDHOC/TCP", "server", &peer_addr.to_string());

            let result: Result<()> = async {
                let cred_r: Credential =
                    Credential::parse_ccs(CRED_R.try_into().unwrap()).unwrap();

                let responder = EdhocResponder::new(
                    new_crypto(),
                    EDHOCMethod::StatStat,
                    R.try_into().expect("Wrong length of responder private key"),
                    cred_r.clone(),
                );

                let message_1_raw =
                    recv_frame(&mut stream, &mut metrics.bytes_received, MAX_FRAME).await?;
                let message_1 = EdhocMessageBuffer::new_from_slice(&message_1_raw)
                    .map_err(|e| anyhow!("invalid message_1 buffer: {e:?}"))?;

                let (responder, _c_i, _ead_1) = responder
                    .process_message_1(&message_1)
                    .map_err(|e| anyhow!("process_message_1 failed: {e:?}"))?;

                let (responder, message_2) = responder
                    .prepare_message_2(CredentialTransfer::ByReference, None, &None)
                    .map_err(|e| anyhow!("prepare_message_2 failed: {e:?}"))?;

                send_frame(
                    &mut stream,
                    message_2.as_slice(),
                    &mut metrics.bytes_sent,
                )
                .await?;

                let message_3_raw =
                    recv_frame(&mut stream, &mut metrics.bytes_received, MAX_FRAME).await?;
                let message_3 = EdhocMessageBuffer::new_from_slice(&message_3_raw)
                    .map_err(|e| anyhow!("invalid message_3 buffer: {e:?}"))?;

                let (responder, id_cred_i, _ead_3) = responder
                    .parse_message_3(&message_3)
                    .map_err(|e| anyhow!("parse_message_3 failed: {e:?}"))?;

                let cred_i: Credential =
                    Credential::parse_ccs(CRED_I.try_into().unwrap()).unwrap();
                let valid_cred_i = credential_check_or_fetch(Some(cred_i), id_cred_i)
                    .map_err(|e| anyhow!("credential_check_or_fetch failed: {e:?}"))?;

                let (mut responder, _r_prk_out) = responder
                    .verify_message_3(valid_cred_i)
                    .map_err(|e| anyhow!("verify_message_3 failed: {e:?}"))?;

                let (_done, message_4) = responder
                    .prepare_message_4(&None)
                    .map_err(|e| anyhow!("prepare_message_4 failed: {e:?}"))?;

                send_frame(
                    &mut stream,
                    message_4.as_slice(),
                    &mut metrics.bytes_sent,
                )
                .await?;

                Ok(())
            }
            .await;

            match result {
                Ok(()) => {
                    metrics.finalize(start.elapsed(), true);
                    println!(
                        "SERVER METRICS -> {:?} Duration: {:?}, Sent: {} bytes, Received: {} bytes",
                        peer_addr,
                        start.elapsed(),
                        metrics.bytes_sent,
                        metrics.bytes_received
                    );
                }
                Err(e) => {
                    eprintln!("Server: request from {:?} failed: {}", peer_addr, e);
                }
            }
        });
    }
}