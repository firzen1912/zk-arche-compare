use anyhow::Result;
use rustls::{RootCertStore, ServerConfig};
use std::sync::Arc;
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

#[path = "../common/certs.rs"]
mod certs;
#[path = "../common/counting_stream.rs"]
mod counting_stream;

use certs::{load_certs, load_private_key};
use counting_stream::{CountingStream, IoCounters};

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();

    let bind_addr = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "0.0.0.0:7443".to_string());

    let server_cert = load_certs("certs/server.crt")?;
    let server_key = load_private_key("certs/server.key")?;
    let ca_cert = load_certs("certs/ca.crt")?;

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
    println!("mTLS server listening on {}", bind_addr);

    loop {
        let (tcp, peer_addr) = listener.accept().await?;
        let acceptor = acceptor.clone();

        tokio::spawn(async move {
            let counters = IoCounters::default();

            let result: Result<()> = async {
                tcp.set_nodelay(true)?;
                let counted_tcp = CountingStream::new(tcp, counters.clone());

                // Match ZK-ARCHE: start timer immediately before protocol processing.
                let start = Instant::now();

                let mut tls_stream = acceptor.accept(counted_tcp).await?;

                let (_, session) = tls_stream.get_ref();
                let peer_ok = session
                    .peer_certificates()
                    .map(|v| !v.is_empty())
                    .unwrap_or(false);

                if !peer_ok {
                    anyhow::bail!("client certificate missing");
                }

                let mut buf = [0u8; 5];
                tls_stream.read_exact(&mut buf).await?;
                tls_stream.write_all(b"world").await?;
                tls_stream.flush().await?;

                println!(
                    "SERVER METRICS -> {:?} Duration: {:?}, Sent: {} bytes, Received: {} bytes",
                    peer_addr,
                    start.elapsed(),
                    counters.sent(),
                    counters.recv()
                );

                let _ = tls_stream.shutdown().await;
                Ok(())
            }
            .await;

            if let Err(e) = result {
                eprintln!("Server: request from {:?} failed: {}", peer_addr, e);
            }
        });
    }
}