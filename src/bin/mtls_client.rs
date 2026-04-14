use anyhow::Result;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};
use std::sync::Arc;
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

#[path = "../common/certs.rs"]
mod certs;
#[path = "../common/counting_stream.rs"]
mod counting_stream;

use certs::{load_certs, load_private_key};
use counting_stream::{CountingStream, IoCounters};

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();

    let server_addr = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:7443".to_string());
    let server_name = std::env::args()
        .nth(2)
        .unwrap_or_else(|| "localhost".to_string());

    let ca_cert = load_certs("certs/ca.crt")?;
    let client_cert = load_certs("certs/client.crt")?;
    let client_key = load_private_key("certs/client.key")?;

    let mut roots = RootCertStore::empty();
    for cert in ca_cert {
        roots.add(cert)?;
    }

    let config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_client_auth_cert(client_cert, client_key)?;

    let connector = TlsConnector::from(Arc::new(config));

    let tcp = TcpStream::connect(&server_addr).await?;
    tcp.set_nodelay(true)?;

    let counters = IoCounters::default();
    let counted_tcp = CountingStream::new(tcp, counters.clone());

    let dns_name = ServerName::try_from(server_name)?.to_owned();

    // Match ZK-ARCHE: start timer immediately before first protocol bytes.
    let start = Instant::now();

    let mut tls = connector.connect(dns_name, counted_tcp).await?;

    // Tiny explicit post-handshake confirmation, similar in spirit to final auth completion.
    tls.write_all(b"hello").await?;
    tls.flush().await?;

    let mut buf = [0u8; 5];
    tls.read_exact(&mut buf).await?;

    println!(
        "CLIENT METRICS -> Duration: {:?}, Sent: {} bytes, Received: {} bytes",
        start.elapsed(),
        counters.sent(),
        counters.recv()
    );

    let _ = tls.shutdown().await;
    Ok(())
}