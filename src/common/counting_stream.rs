use std::pin::Pin;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

#[derive(Clone, Default)]
pub struct IoCounters {
    sent: Arc<AtomicUsize>,
    recv: Arc<AtomicUsize>,
}

impl IoCounters {
    pub fn sent(&self) -> usize {
        self.sent.load(Ordering::Relaxed)
    }

    pub fn recv(&self) -> usize {
        self.recv.load(Ordering::Relaxed)
    }
}

pub struct CountingStream<S> {
    inner: S,
    counters: IoCounters,
}

impl<S> CountingStream<S> {
    pub fn new(inner: S, counters: IoCounters) -> Self {
        Self { inner, counters }
    }

    pub fn counters(&self) -> IoCounters {
        self.counters.clone()
    }

    pub fn into_inner(self) -> S {
        self.inner
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for CountingStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let poll = Pin::new(&mut self.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = &poll {
            let after = buf.filled().len();
            let n = after.saturating_sub(before);
            self.counters.recv.fetch_add(n, Ordering::Relaxed);
        }
        poll
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for CountingStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let poll = Pin::new(&mut self.inner).poll_write(cx, data);
        if let Poll::Ready(Ok(n)) = &poll {
            self.counters.sent.fetch_add(*n, Ordering::Relaxed);
        }
        poll
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}