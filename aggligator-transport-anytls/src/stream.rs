// Derived from shoes (https://github.com/cfal/shoes), src/anytls/anytls_stream.rs,
// commit 60ed3838b346268615c81e4eace4e15e717da23e.
// Copyright (c) 2021-2023 Alex Lau <github@alau.ca>.
// Licensed under the MIT License; see the NOTICE file of this crate.

//! Read and write halves of an AnyTLS stream.

use bytes::Bytes;
use std::{
    io,
    pin::Pin,
    task::{Context, Poll, ready},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::mpsc,
};
use tokio_util::sync::{CancellationToken, PollSender};

use crate::frame::MAX_DATA_SIZE;

/// Capacity, in frames, of the per-stream read and write queues.
pub(crate) const STREAM_QUEUE: usize = 16;

/// Read half of a stream, fed by the session reader.
pub(crate) struct StreamRead {
    rx: mpsc::Receiver<io::Result<Bytes>>,
    buf: Bytes,
    eof: bool,
}

impl StreamRead {
    pub(crate) fn new(rx: mpsc::Receiver<io::Result<Bytes>>) -> Self {
        Self { rx, buf: Bytes::new(), eof: false }
    }
}

impl AsyncRead for StreamRead {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context, buf: &mut ReadBuf) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            if !this.buf.is_empty() {
                let n = this.buf.len().min(buf.remaining());
                buf.put_slice(&this.buf.split_to(n));
                return Poll::Ready(Ok(()));
            }

            if this.eof {
                return Poll::Ready(Ok(()));
            }

            match ready!(this.rx.poll_recv(cx)) {
                Some(Ok(data)) => this.buf = data,
                Some(Err(err)) => {
                    this.eof = true;
                    return Poll::Ready(Err(err));
                }
                None => this.eof = true,
            }
        }
    }
}

/// Write half of a stream.
///
/// Data goes into a bounded queue drained by the stream's forwarding task.
/// When the queue is full, writing returns [`Poll::Pending`].
/// Closing or dropping this half lets the forwarding task send FIN after the queued data.
pub(crate) struct StreamWrite {
    tx: PollSender<Bytes>,
    dead: CancellationToken,
}

impl StreamWrite {
    pub(crate) fn new(tx: mpsc::Sender<Bytes>, dead: CancellationToken) -> Self {
        Self { tx: PollSender::new(tx), dead }
    }
}

fn closed() -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, "AnyTLS stream closed")
}

impl AsyncWrite for StreamWrite {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context, buf: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.dead.is_cancelled() {
            return Poll::Ready(Err(closed()));
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        match ready!(this.tx.poll_reserve(cx)) {
            Ok(()) => {
                let n = buf.len().min(MAX_DATA_SIZE);
                match this.tx.send_item(Bytes::copy_from_slice(&buf[..n])) {
                    Ok(()) => Poll::Ready(Ok(n)),
                    Err(_) => Poll::Ready(Err(closed())),
                }
            }
            Err(_) => Poll::Ready(Err(closed())),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context) -> Poll<io::Result<()>> {
        if self.dead.is_cancelled() { Poll::Ready(Err(closed())) } else { Poll::Ready(Ok(())) }
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context) -> Poll<io::Result<()>> {
        self.get_mut().tx.close();
        Poll::Ready(Ok(()))
    }
}
