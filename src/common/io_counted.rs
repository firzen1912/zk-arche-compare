use std::io::{Read, Write};

pub fn send_all(stream: &mut impl Write, buf: &[u8], sent: &mut usize) -> std::io::Result<()> {
    *sent += buf.len();
    stream.write_all(buf)
}

pub fn recv_exact(stream: &mut impl Read, buf: &mut [u8], recv: &mut usize) -> std::io::Result<()> {
    stream.read_exact(buf)?;
    *recv += buf.len();
    Ok(())
}

pub fn recv_u8(stream: &mut impl Read, recv: &mut usize) -> std::io::Result<u8> {
    let mut b = [0u8; 1];
    recv_exact(stream, &mut b, recv)?;
    Ok(b[0])
}

pub fn send_blob(stream: &mut impl Write, buf: &[u8], sent: &mut usize) -> std::io::Result<()> {
    send_all(stream, &(buf.len() as u32).to_le_bytes(), sent)?;
    if !buf.is_empty() {
        send_all(stream, buf, sent)?;
    }
    Ok(())
}

pub fn recv_blob(
    stream: &mut impl Read,
    recv: &mut usize,
    max_len: usize,
) -> std::io::Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    recv_exact(stream, &mut len_buf, recv)?;
    let rx_len = u32::from_le_bytes(len_buf) as usize;
    if rx_len > max_len {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("payload too large: {rx_len} bytes (max {max_len})"),
        ));
    }
    let mut buf = vec![0u8; rx_len];
    recv_exact(stream, &mut buf, recv)?;
    Ok(buf)
}
