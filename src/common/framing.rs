use anyhow::{anyhow, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

pub async fn send_frame(
    stream: &mut TcpStream,
    payload: &[u8],
    sent_counter: &mut usize,
) -> Result<()> {
    let len = payload.len() as u32;
    stream.write_all(&len.to_be_bytes()).await?;
    stream.write_all(payload).await?;
    stream.flush().await?;
    *sent_counter += 4 + payload.len();
    Ok(())
}

pub async fn recv_frame(
    stream: &mut TcpStream,
    recv_counter: &mut usize,
    max_len: usize,
) -> Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > max_len {
        return Err(anyhow!("frame too large: {len}"));
    }
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).await?;
    *recv_counter += 4 + len;
    Ok(buf)
}
