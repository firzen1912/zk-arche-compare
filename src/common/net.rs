use std::net::TcpStream;
use std::time::Duration;

pub const IO_TIMEOUT: Duration = Duration::from_secs(5);

pub fn configure_stream(stream: &TcpStream) -> std::io::Result<()> {
    stream.set_nodelay(true)?;
    stream.set_read_timeout(Some(IO_TIMEOUT))?;
    stream.set_write_timeout(Some(IO_TIMEOUT))?;
    Ok(())
}
