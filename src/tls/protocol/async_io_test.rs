use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, ReadBuf};

pub struct PassThroughReader<'a, T : AsyncRead + Unpin> {
    inner: &'a mut T,
}

impl<'a, T : AsyncRead + Unpin> PassThroughReader<'a, T> {
    pub fn new(inner: &'a mut T) -> PassThroughReader<'a, T> {
        PassThroughReader { inner }
    }
}

impl<'a, T : AsyncRead + Unpin> AsyncRead for PassThroughReader<'a, T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>
    ) -> Poll<Result<(), std::io::Error>> {
        let old_filled = buf.filled().len();
        match AsyncRead::poll_read(Pin::new(self.inner), cx, buf) {
            Poll::Ready(Err(e)) => {
                println!("PassThroughReader: error: {}", e);
                Poll::Ready(Err(e))
            }
            Poll::Ready(Ok(())) => {
                let new_filled = buf.filled().len();
                let delta_filled = new_filled - old_filled;
                println!("PassThroughReader: ok: got {} bytes", delta_filled);
                Poll::Ready(Ok(()))
            }
            Poll::Pending => {
                println!("PassThroughReader: pending");
                Poll::Pending
            }
        }
    }
}

pub struct FixedSizeReader<'a, T : AsyncRead + Unpin> {
    inner: &'a mut T,
    nbytes: usize,
}

impl<'a, T : AsyncRead + Unpin> FixedSizeReader<'a, T> {
    pub fn new(inner: &'a mut T, nbytes: usize) -> FixedSizeReader<'a, T> {
        FixedSizeReader { inner, nbytes }
    }
}

impl<'a, T : AsyncRead + Unpin> AsyncRead for FixedSizeReader<'a, T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        xbuf: &mut ReadBuf<'_>
    ) -> Poll<Result<(), std::io::Error>> {
        if xbuf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }

        let amt = std::cmp::min(self.nbytes, xbuf.remaining());
        let mut our_data = vec![0; amt];

        let mut our_buf = ReadBuf::new(&mut our_data);

        let old_filled = our_buf.filled().len();
        match AsyncRead::poll_read(Pin::new(&mut self.inner), cx, &mut our_buf) {
            Poll::Ready(Err(e)) => {
                println!("FixedSizeReader: error: {}", e);
                Poll::Ready(Err(e))
            }
            Poll::Ready(Ok(())) => {
                let new_filled = our_buf.filled().len();
                let delta_filled = new_filled - old_filled;

                if old_filled != 0 || new_filled != self.nbytes {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::Other, "unexpected buffer content")));
                }

                xbuf.put_slice(our_buf.filled());

                println!("FixedSizeReader: ok: got {} bytes", delta_filled);
                Poll::Ready(Ok(()))
            }
            Poll::Pending => {
                println!("FixedSizeReader: pending");
                Poll::Pending
            }
        }
    }
}
