use std::io;
use std::pin::Pin;
use std::collections::HashMap;
use std::task::{Context, Poll, Waker};
use std::future::Future;
use std::sync::{Arc, Mutex};
use bytes::{Buf};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use super::frame::{StreamId, Frame, FrameOp, FrameStream};
use crate::util::io::AsyncStream;

struct InternalReader {
    waker: Option<Waker>,
}

struct InternalWriter {
}

impl InternalReader {
    fn new() -> Self {
        InternalReader {
            waker: None,
        }
    }
}

impl InternalWriter {
    fn new() -> Self {
        InternalWriter {
        }
    }
}

struct MplexStreams {
    accept_waker: Option<Waker>,
    readers: HashMap<StreamId, InternalReader>,
    writers: HashMap<StreamId, InternalWriter>,
}

impl MplexStreams {
    fn new() -> Self {
        MplexStreams {
            accept_waker: None,
            readers: HashMap::new(),
            writers: HashMap::new(),
        }
    }

    fn wake_accept(&mut self) {
        if let Some(w) = self.accept_waker.take() {
            w.wake()
        }
    }

    fn set_accept_waker(&mut self, waker: Waker) {
        self.accept_waker = Some(waker);
    }

    fn wake_reader(&mut self, stream_id: &StreamId) {
        if let Some(reader) = self.readers.get_mut(stream_id) {
            if let Some(w) = reader.waker.take() {
                w.wake()
            }
        }
    }

    fn set_read_waker(&mut self, stream_id: &StreamId, waker: Waker) {
        if let Some(reader) = self.readers.get_mut(stream_id) {
            reader.waker = Some(waker);
        }
    }

    fn wake_all_readers(&mut self) {
        self.wake_accept();
        for (_, reader) in self.readers.iter_mut() {
            if let Some(w) = reader.waker.take() {
                w.wake()
            }
        }
    }

    fn add(&mut self, stream_id: &StreamId) {
        let reader = InternalReader::new();
        let writer = InternalWriter::new();
        self.readers.insert(stream_id.clone(), reader);
        self.writers.insert(stream_id.clone(), writer);
        self.print_readers_writers();
    }

    fn remove_reader(&mut self, stream_id: &StreamId) {
        self.readers.remove(stream_id);
        self.wake_all_readers();
        self.print_readers_writers();
    }

    fn remove_writer(&mut self, stream_id: &StreamId) {
        self.writers.remove(stream_id);
        self.print_readers_writers();
    }

    fn have_reader(&self, stream_id: &StreamId) -> bool {
        self.readers.contains_key(stream_id)
    }

    // fn have_writer(&self, stream_id: &StreamId) -> bool {
    //     self.writers.contains_key(stream_id)
    // }

    fn print_readers_writers(&self) {
        // print!("**** stream readers:");
        // for (sid, _) in self.readers.iter() {
        //     print!(" {:?}", sid);
        // }
        // println!();
        // print!("**** stream writers:");
        // for (sid, _) in self.readers.iter() {
        //     print!(" {:?}", sid);
        // }
        // println!();
    }
}

struct MplexShared {
    frames: FrameStream,
    no_more_frames: bool,
    incoming_frame: Option<Frame>,
    next_stream_num: u64,
    closed: bool,
    streams: MplexStreams,
}

impl MplexShared {
    fn new(transport: Pin<Box<dyn AsyncStream>>) -> Self
    {
        MplexShared {
            frames: FrameStream::new(transport),
            no_more_frames: false,
            incoming_frame: None,
            next_stream_num: 33,
            closed: false,
            streams: MplexStreams::new(),
        }
    }

    fn want_another_frame(&mut self) {
        self.incoming_frame = None;
        self.streams.wake_all_readers();
    }

    fn poll_accept_id(&mut self, cx: &mut Context<'_>) -> Poll<Result<Option<StreamId>, io::Error>> {
        match self.poll_fill_incoming(cx) {
            Poll::Pending => {
                self.streams.set_accept_waker(cx.waker().clone());
                return Poll::Pending;
            }
            Poll::Ready(Err(e)) => {
                return Poll::Ready(Err(e));
            }
            Poll::Ready(Ok(())) => {
                // continue
            }
        }

        match &self.incoming_frame {
            Some(frame) if frame.op == FrameOp::New => {
                let stream_id = frame.stream_id.clone();
                self.streams.add(&stream_id);
                self.want_another_frame();
                Poll::Ready(Ok(Some(stream_id)))
            }
            Some(_) => {
                self.streams.set_accept_waker(cx.waker().clone());
                Poll::Pending
            }
            None => {
                Poll::Ready(Ok(None))
            }
        }
    }

    fn poll_read(
        &mut self,
        stream_id: &StreamId,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<Result<(), io::Error>> {
        match self.poll_fill_incoming(cx) {
            Poll::Pending => {
                // There may be multiple read futures waiting for incoming data, and we can only
                // rely on poll_fill_incoming() to store the waker from the context it was most
                // recently called with. To cater for the possibility that another poll_read()
                // or poll_accept() for a different stream may occur before data is ready, store a
                // waker for this specific stream id.
                self.streams.set_read_waker(stream_id, cx.waker().clone());
                return Poll::Pending;
            }
            Poll::Ready(Err(e)) => {
                return Poll::Ready(Err(e));
            }
            Poll::Ready(Ok(())) => {
                // continue
            },
        }

        match &mut self.incoming_frame {
            Some(frame) if frame.stream_id == *stream_id => {
                if frame.op == FrameOp::Close {
                    self.want_another_frame();
                    return Poll::Ready(Ok(()));
                }

                let amt = std::cmp::min(frame.data.remaining(), buf.remaining());
                buf.put_slice(&frame.data[0..amt]);
                frame.data.advance(amt);
                if frame.data.is_empty() {
                    self.want_another_frame();
                }
                Poll::Ready(Ok(()))
            }
            Some(_) => {
                self.streams.set_read_waker(stream_id, cx.waker().clone());
                Poll::Pending
            }
            None => {
                Poll::Ready(Ok(()))
            }
        }
    }

    fn poll_fill_incoming(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        loop {
            if self.closed {
                return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
            }

            match &self.incoming_frame {
                Some(frame) if frame.op == FrameOp::New => {
                    return Poll::Ready(Ok(()));
                }
                Some(frame) if self.streams.have_reader(&frame.stream_id) => {
                    return Poll::Ready(Ok(()));
                }
                Some(_) => {
                    self.incoming_frame = None;
                    // continue
                }
                None => {
                    // continue
                }
            }

            match self.frames.poll_read_frame(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(None)) => {
                    self.no_more_frames = true;
                    self.streams.wake_all_readers();
                    return Poll::Ready(Ok(()));
                }
                Poll::Ready(Ok(Some(frame))) => {
                    match frame.op {
                        FrameOp::New => self.streams.wake_accept(),
                        _ => {
                            self.streams.wake_reader(&frame.stream_id);
                        }
                    }
                    self.incoming_frame = Some(frame);
                }
            }
        }
    }

    fn append_new(
        &mut self,
        name: Option<String>,
    ) -> StreamId {
        let num = self.next_stream_num;
        self.next_stream_num += 1;
        let stream_id = StreamId::Receiver(num);
        self.streams.add(&stream_id);
        self.frames.append_new(num, name);
        stream_id
    }
}

pub struct Accept<'a> {
    acceptor: &'a mut Acceptor,
}

impl<'a> Future for Accept<'a> {
    type Output = Result<Option<Stream>, io::Error>;
    fn poll(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>
    ) -> Poll<Self::Output> {
        Pin::into_inner(self).acceptor.poll_accept_stream(cx)
    }
}

pub struct Connect<'a> {
    connector: &'a mut Connector,
    name: Option<String>,
    stream_id: Option<StreamId>,
}

impl<'a> Future for Connect<'a> {
    type Output = Result<Stream, io::Error>;
    fn poll(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>
    ) -> Poll<Self::Output> {
        let mut iself = Pin::into_inner(self);
        let stream_id = match &iself.stream_id {
            None => {
                let stream_id = iself.connector.shared.lock().unwrap().append_new(iself.name.clone());
                iself.stream_id = Some(stream_id.clone());
                stream_id
            }
            Some(stream_id) => {
                stream_id.clone()
            }
        };

        match iself.connector.shared.lock().unwrap().frames.poll_drain(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Ready(Ok(())) => {}, // continue
        };
        Poll::Ready(Ok(Stream::new(stream_id, iself.connector.shared.clone())))
    }
}

pub struct Acceptor {
    shared: Arc<Mutex<MplexShared>>,
}

impl Acceptor {
    pub fn accept(&mut self) -> Accept {
        Accept { acceptor: self }
    }

    fn poll_accept_stream(&mut self, cx: &mut Context<'_>) -> Poll<Result<Option<Stream>, io::Error>> {
        match self.shared.lock().unwrap().poll_accept_id(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Ready(Ok(None)) => Poll::Ready(Ok(None)),
            Poll::Ready(Ok(Some(stream_id))) => Poll::Ready(Ok(Some(Stream::new(
                stream_id,
                self.shared.clone())))),
        }
    }
}

pub struct Connector {
    shared: Arc<Mutex<MplexShared>>,
}

impl Connector {
    pub fn connect(&mut self, name: Option<&str>) -> Connect {
        let name = name.map(String::from);
        Connect { connector: self, stream_id: None, name }
    }
}

pub struct Mplex {
    shared: Arc<Mutex<MplexShared>>,
}

impl Mplex {
    pub fn new(transport: Pin<Box<dyn AsyncStream>>) -> Self {
        Mplex {
            shared: Arc::new(Mutex::new(MplexShared::new(transport))),
        }
    }

    pub fn split(self) -> (Acceptor, Connector) {
        let acceptor = Acceptor { shared: self.shared.clone() };
        let connector = Connector { shared: self.shared };
        (acceptor, connector)
    }

    pub fn set_logging_enabled(&mut self, b: bool) {
        self.shared.lock().unwrap().frames.set_logging_enabled(b);
    }
}

////////////////////////////////////////////////////////////////////////////////////////////////////
//                                                                                                //
//                                          StreamReader                                          //
//                                                                                                //
////////////////////////////////////////////////////////////////////////////////////////////////////

pub struct StreamReader {
    stream_id: StreamId,
    shared: Arc<Mutex<MplexShared>>,
}

impl Drop for StreamReader {
    fn drop(&mut self) {
        // println!("drop stream reader {:?}", self.stream_id);
        self.shared.lock().unwrap().streams.remove_reader(&self.stream_id);
    }
}

impl AsyncRead for StreamReader {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>
    ) -> Poll<Result<(), io::Error>> {
        let iself = Pin::into_inner(self);
        iself.shared.lock().unwrap().poll_read(&iself.stream_id, cx, buf)
    }
}

////////////////////////////////////////////////////////////////////////////////////////////////////
//                                                                                                //
//                                          StreamWriter                                          //
//                                                                                                //
////////////////////////////////////////////////////////////////////////////////////////////////////

pub struct StreamWriter {
    stream_id: StreamId,
    shared: Arc<Mutex<MplexShared>>,
    write_error: Option<io::ErrorKind>,
}

impl StreamWriter {
    fn poll_drain(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        if let Some(e) = self.write_error {
            return Poll::Ready(Err(io::Error::from(e)));
        }

        let mut shared = self.shared.lock().unwrap();
        match shared.frames.poll_drain(cx) {
            Poll::Pending => {
                Poll::Pending
            }
            Poll::Ready(Ok(())) => {
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(e)) => {
                self.write_error = Some(e.kind());
                Poll::Ready(Err(e))
            }
        }
    }
}

impl Drop for StreamWriter {
    fn drop(&mut self) {
        // println!("drop stream writer {:?}", self.stream_id);
        self.shared.lock().unwrap().streams.remove_writer(&self.stream_id);
    }
}

impl AsyncWrite for StreamWriter {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8]
    ) -> Poll<Result<usize, io::Error>> {
        let iself = Pin::into_inner(self);
        match iself.poll_drain(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Ready(Ok(())) => {}, // continue
        }

        iself.shared.lock().unwrap().frames.append_message(&iself.stream_id.inverse(), buf);
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>
    ) -> Poll<Result<(), io::Error>> {
        Pin::into_inner(self).poll_drain(cx)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>
    ) -> Poll<Result<(), io::Error>> {
        let iself = Pin::into_inner(self);
        match iself.poll_drain(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Ready(Ok(())) => {}, // continue
        }

        iself.shared.lock().unwrap().frames.append_close(&iself.stream_id.inverse());
        iself.write_error = Some(io::ErrorKind::BrokenPipe);
        Poll::Ready(Ok(()))
    }
}

////////////////////////////////////////////////////////////////////////////////////////////////////
//                                                                                                //
//                                             Stream                                             //
//                                                                                                //
////////////////////////////////////////////////////////////////////////////////////////////////////

pub struct Stream {
    reader: StreamReader,
    writer: StreamWriter,
}

impl Stream {
    fn new(stream_id: StreamId, shared: Arc<Mutex<MplexShared>>) -> Self {
        Stream {
            reader: StreamReader {
                stream_id: stream_id.clone(),
                shared: shared.clone(),
            },
            writer: StreamWriter {
                stream_id,
                shared,
                write_error: None,
            }
        }
    }
}

impl AsyncRead for Stream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>
    ) -> Poll<Result<(), io::Error>> {
        let iself = Pin::into_inner(self);
        Pin::new(&mut iself.reader).poll_read(cx, buf)
    }
}

impl AsyncWrite for Stream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8]
    ) -> Poll<Result<usize, io::Error>> {
        let iself = Pin::into_inner(self);
        Pin::new(&mut iself.writer).poll_write(cx, buf)
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>
    ) -> Poll<Result<(), io::Error>> {
        let iself = Pin::into_inner(self);
        Pin::new(&mut iself.writer).poll_flush(cx)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>
    ) -> Poll<Result<(), io::Error>> {
        let iself = Pin::into_inner(self);
        Pin::new(&mut iself.writer).poll_shutdown(cx)
    }
}
