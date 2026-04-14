use std::time::{Duration, Instant};

pub struct PhaseMetrics {
    start: Instant,
    pub sent: usize,
    pub recv: usize,
}

impl PhaseMetrics {
    pub fn new() -> Self {
        Self {
            start: Instant::now(),
            sent: 0,
            recv: 0,
        }
    }

    pub fn elapsed(&self) -> Duration {
        self.start.elapsed()
    }

    pub fn print_client(&self) {
        println!(
            "CLIENT METRICS -> Duration: {:?}, Sent: {} bytes, Received: {} bytes",
            self.elapsed(),
            self.sent,
            self.recv
        );
    }

    pub fn print_server<T: std::fmt::Debug>(&self, peer: T) {
        println!(
            "SERVER METRICS -> {:?} Duration: {:?}, Sent: {} bytes, Received: {} bytes",
            peer,
            self.elapsed(),
            self.sent,
            self.recv
        );
    }
}

#[derive(Debug, Clone, Default)]
pub struct HandshakeMetrics {
    pub protocol: String,
    pub role: String,
    pub peer: String,
    pub bytes_sent: usize,
    pub bytes_received: usize,
    pub total_bytes: usize,
    pub handshake_duration_ms: f64,
    pub success: bool,
    pub note: Option<String>,
}

impl HandshakeMetrics {
    pub fn new(protocol: &str, role: &str, peer: &str) -> Self {
        Self {
            protocol: protocol.to_string(),
            role: role.to_string(),
            peer: peer.to_string(),
            bytes_sent: 0,
            bytes_received: 0,
            total_bytes: 0,
            handshake_duration_ms: 0.0,
            success: false,
            note: None,
        }
    }

    pub fn finalize(&mut self, elapsed: Duration, success: bool) {
        self.total_bytes = self.bytes_sent + self.bytes_received;
        self.handshake_duration_ms = elapsed.as_secs_f64() * 1000.0;
        self.success = success;
    }

    pub fn print_client(&self, elapsed: Duration) {
        println!(
            "CLIENT METRICS -> Duration: {:?}, Sent: {} bytes, Received: {} bytes",
            elapsed,
            self.bytes_sent,
            self.bytes_received
        );
    }

    pub fn print_server<T: std::fmt::Debug>(&self, peer: T, elapsed: Duration) {
        println!(
            "SERVER METRICS -> {:?} Duration: {:?}, Sent: {} bytes, Received: {} bytes",
            peer,
            elapsed,
            self.bytes_sent,
            self.bytes_received
        );
    }
}