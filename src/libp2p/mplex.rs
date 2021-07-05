#![allow(unused_variables)]
#![allow(dead_code)]
#![allow(unused_mut)]
#![allow(unused_assignments)]
#![allow(unused_imports)]
#![allow(unused_macros)]

use std::fmt;
use std::io;
use std::error::Error;
use std::pin::Pin;
use std::collections::HashMap;
use std::collections::HashSet;
use std::task::{Context, Poll, Waker};
use std::future::Future;
use std::sync::{Arc, Mutex};
use bytes::{Bytes, BytesMut, Buf, BufMut};
use tokio::io::{AsyncRead, AsyncWrite, AsyncReadExt, AsyncWriteExt, ReadBuf};
use crate::io::AsyncStream;
use super::io::{
    read_varint,
    write_varint,
    read_length_prefixed_data,
    write_length_prefixed_data,
};
use crate::util::{escape_string, vec_with_len, Indent, DebugHexDump};
use crate::protobuf::VarInt;

const MAX_OUTSTANDING_DATA: usize = 65536;

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
        self.accept_waker.take().map(|w| w.wake());
    }

    fn set_accept_waker(&mut self, waker: Waker) {
        self.accept_waker = Some(waker);
    }

    fn wake_reader(&mut self, stream_id: &StreamId) {
        if let Some(reader) = self.readers.get_mut(stream_id) {
            reader.waker.take().map(|w| w.wake());
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
            reader.waker.take().map(|w| w.wake());
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

    fn have_writer(&self, stream_id: &StreamId) -> bool {
        self.writers.contains_key(stream_id)
    }

    fn print_readers_writers(&self) {
        print!("**** stream readers:");
        for (sid, _) in self.readers.iter() {
            print!(" {:?}", sid);
        }
        println!();
        print!("**** stream writers:");
        for (sid, _) in self.readers.iter() {
            print!(" {:?}", sid);
        }
        println!();
    }
}

struct MplexShared {
    transport: Box<dyn AsyncStream>,
    incoming_data: BytesMut,
    outgoing_data: BytesMut,
    incoming_frame: Option<Frame>,
    next_stream_num: u64,
    read_eof: bool,
    closed: bool,
    logging_enabled: bool,
    streams: MplexStreams,
}

fn extract_varint_u64(p_incoming_data: &mut BytesMut, p_offset: &mut usize) -> Option<u64> {
    let start_offset = *p_offset;
    loop {
        if *p_offset >= p_incoming_data.len() {
            return None;
        }
        if p_incoming_data[*p_offset] & 0x80 == 0 {
            let res = Some(VarInt(&p_incoming_data[start_offset..*p_offset + 1]).to_u64());
            *p_offset += 1;
            return res;
        }
        *p_offset += 1;
    }
}

impl MplexShared {
    fn new<T: 'static>(transport: T) -> Self
        where T : AsyncRead + AsyncWrite + Unpin + Send {
        MplexShared {
            transport: Box::new(transport),
            incoming_data: BytesMut::new(),
            outgoing_data: BytesMut::new(),
            incoming_frame: None,
            next_stream_num: 33,
            read_eof: false,
            closed: false,
            logging_enabled: false,
            streams: MplexStreams::new(),
        }
    }

    fn want_another_frame(&mut self) {
        self.incoming_frame = None;
        self.streams.wake_all_readers();
    }

    fn poll_accept_id(&mut self, cx: &mut Context<'_>) -> Poll<Result<StreamId, io::Error>> {
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
                Poll::Ready(Ok(stream_id))
            }
            _ => {
                self.streams.set_accept_waker(cx.waker().clone());
                Poll::Pending
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
                    // println!("poll_read; have close frame {:?}", stream_id);
                    return Poll::Ready(Ok(()));
                }

                let amt = std::cmp::min(frame.data.remaining(), buf.remaining());
                buf.put_slice(&frame.data[0..amt]);
                frame.data.advance(amt);
                if frame.data.len() == 0 {
                    self.want_another_frame();
                }
                Poll::Ready(Ok(()))
            }
            _ => {
                self.streams.set_read_waker(stream_id, cx.waker().clone());
                Poll::Pending
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
                _ => {
                    // continue
                }
            }

            match self.poll_read_frame(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(None)) => return Poll::Ready(Ok(())),
                Poll::Ready(Ok(Some(frame))) => {
                    match frame.op {
                        FrameOp::New => self.streams.wake_accept(),
                        _ => self.streams.wake_reader(&frame.stream_id),
                    }
                    self.log_incoming_frame(&frame);
                    self.incoming_frame = Some(frame);
                    // Poll::Ready(Ok(()))
                }
            }
        }
    }

    fn log_incoming_frame(&self, frame: &Frame) {
        if self.logging_enabled {
            println!("[mplex] <<<< {:?} {:?} <{} bytes>", frame.stream_id, frame.op, frame.data.len());
            println!("{:#?}", Indent(&DebugHexDump(&frame.data)));
        }
    }

    fn log_outgoing_frame(&self, stream_id: &StreamId, op: FrameOp, data: &[u8]) {
        if self.logging_enabled {
            println!("[mplex] >>>> {:?} {:?} <{} bytes>", stream_id, op, data.len());
            println!("{:#?}", Indent(&DebugHexDump(&data)));
        }
    }

    fn log_drain_error(&self, e: &io::Error) {
        if self.logging_enabled {
            println!("[mplex] >>>> drain error: {}", e);
        }
    }

    fn log_drain_ok(&self) {
        if self.logging_enabled {
            println!("[mplex] >>>> drained");
        }
    }

    fn poll_read_frame(&mut self, cx: &mut Context<'_>) -> Poll<Result<Option<Frame>, io::Error>> {
        loop {
            // Check if we already have all the data comprising a frame in incoming_data. If so,
            // return the frame and don't attempt to read any more data from the underlying
            // transport.
            let mut offset = 0;
            if let Some(header) = extract_varint_u64(&mut self.incoming_data, &mut offset) {
                let num = (header as u64) >> 3;
                let flag = Flag::from_raw((header as u8) & 0x7)?;
                if let Some(payload_len) = extract_varint_u64(&mut self.incoming_data, &mut offset) {
                    if self.incoming_data.len() >= offset + (payload_len as usize) {
                        self.incoming_data.advance(offset);
                        let payload = self.incoming_data.split_to(payload_len as usize);

                        let data = Bytes::from(payload);
                        return Poll::Ready(Ok(Some(Frame::from_message_parts(num, flag, data))));
                    }
                }
            }

            // If we've encountered EOF on a previous read, this means there are no more frames
            // avaialble (otherwise the above check would have succeeded). If incoming_data is
            // empty, this suggests the transport was closed cleanly, and we indicate an end of
            // stream. If incoming_data is not empty, this suggests the transport was not closed
            // cleanly, which we consider an error condition (albeit not a serious one; it could
            // be safely ignored).
            if self.read_eof {
                if self.incoming_data.len() > 0 {
                    return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
                }
                else {
                    return Poll::Ready(Ok(None));
                }
            }

            // Try to read more data for the next frame. We may get only a partial frame, in which
            // case we loop again.
            let mut recv_data: Vec<u8> = vec![0; 1024];
            let mut recv_buf = ReadBuf::new(&mut recv_data);
            let old_filled = recv_buf.filled().len();
            match Pin::new(&mut self.transport).poll_read(cx, &mut recv_buf) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(())) => {
                    if recv_buf.filled().len() == 0 {
                        self.read_eof = true; // will be picked up on next loop iteration
                        self.streams.wake_all_readers();
                    }
                    else {
                        self.incoming_data.extend_from_slice(recv_buf.filled());
                    }
                    // repeat loop
                }
            }
        }
    }

    fn poll_drain(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        while self.outgoing_data.len() > 0 {
            // match AsyncWrite::poll_write(Pin::new(&mut self.transport), cx, &self.outgoing_data) {
            match Pin::new(&mut self.transport).poll_write(cx, &self.outgoing_data) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(w)) => self.outgoing_data.advance(w),
            }
        }
        match Pin::new(&mut self.transport).poll_flush(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => {
                self.log_drain_error(&e);
                Poll::Ready(Err(e))
            }
            Poll::Ready(Ok(())) => {
                self.log_drain_ok();
                Poll::Ready(Ok(()))
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
        self.log_outgoing_frame(&stream_id, FrameOp::New, &[]);
        let header: u64 = (num << 3) | (Flag::NewStream.to_raw() as u64);
        self.outgoing_data.extend_from_slice(&VarInt::encode_u64(header));
        let name_bytes: Vec<u8> = match name {
            Some(name) => Vec::from(name.as_bytes()),
            None => Vec::new(),
        };
        self.outgoing_data.extend_from_slice(&VarInt::encode_usize(name_bytes.len()));
        self.outgoing_data.extend_from_slice(&name_bytes);
        self.streams.add(&stream_id);
        stream_id
    }

    fn append_message(
        &mut self,
        stream_id: &StreamId,
        data: &[u8],
    ) {
        self.log_outgoing_frame(&stream_id, FrameOp::Message, data);
        let header: u64 = match stream_id {
            StreamId::Receiver(num) => (num << 3) | (Flag::MessageReceiver.to_raw() as u64),
            StreamId::Initiator(num) => (num << 3) | (Flag::MessageInitiator.to_raw() as u64),
        };
        self.outgoing_data.extend_from_slice(&VarInt::encode_u64(header));
        self.outgoing_data.extend_from_slice(&VarInt::encode_usize(data.len()));
        self.outgoing_data.extend_from_slice(&data);
    }

    fn append_close(
        &mut self,
        stream_id: &StreamId
    ) {
        self.log_outgoing_frame(&stream_id, FrameOp::Close, &[]);
        let header: u64 = match stream_id {
            StreamId::Receiver(num) => (num << 3) | (Flag::CloseReceiver.to_raw() as u64),
            StreamId::Initiator(num) => (num << 3) | (Flag::CloseInitiator.to_raw() as u64),
        };
        self.outgoing_data.extend_from_slice(&VarInt::encode_u64(header));
        self.outgoing_data.extend_from_slice(&VarInt::encode_usize(0));
    }
}

pub struct Accept<'a> {
    acceptor: &'a mut MplexAcceptor,
}

impl<'a> Future for Accept<'a> {
    type Output = Result<Stream, io::Error>;
    fn poll(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>
    ) -> Poll<Self::Output> {
        let mut iself = Pin::into_inner(self);
        iself.acceptor.poll_accept_stream(cx)
    }
}

pub struct Connect<'a> {
    connector: &'a mut MplexConnector,
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

        match iself.connector.shared.lock().unwrap().poll_drain(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Ready(Ok(())) => {}, // continue
        };
        Poll::Ready(Ok(Stream::new(stream_id, iself.connector.shared.clone())))
    }
}

pub struct MplexAcceptor {
    shared: Arc<Mutex<MplexShared>>,
}

impl MplexAcceptor {
    pub fn accept(&mut self) -> Accept {
        Accept { acceptor: self }
    }

    fn poll_accept_stream(&mut self, cx: &mut Context<'_>) -> Poll<Result<Stream, io::Error>> {
        match self.shared.lock().unwrap().poll_accept_id(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Ready(Ok(stream_id)) => Poll::Ready(Ok(Stream::new(
                stream_id,
                self.shared.clone()))),
        }
    }
}

pub struct MplexConnector {
    shared: Arc<Mutex<MplexShared>>,
}

impl MplexConnector {
    pub fn connect(&mut self, name: Option<&str>) -> Connect {
        let name: Option<String> = match name {
            Some(name) => Some(String::from(name)),
            None => None,
        };
        Connect { connector: self, stream_id: None, name: name }
    }
}

pub struct Mplex {
    shared: Arc<Mutex<MplexShared>>,
}

impl Mplex {
    pub fn new<T: 'static>(transport: T) -> Self
        where T : AsyncRead + AsyncWrite + Unpin + Send
    {
        Mplex {
            shared: Arc::new(Mutex::new(MplexShared::new(transport))),
        }
    }

    pub fn split(self) -> (MplexAcceptor, MplexConnector) {
        let acceptor = MplexAcceptor { shared: self.shared.clone() };
        let connector = MplexConnector { shared: self.shared.clone() };
        (acceptor, connector)
    }

    pub fn set_logging_enabled(&mut self, b: bool) {
        self.shared.lock().unwrap().logging_enabled = b;
    }
}

#[derive(Clone, Debug, PartialEq)]
enum FrameOp {
    New,
    Message,
    Close,
    Reset,
}

#[derive(Clone, Debug, PartialEq)]
struct Frame {
    stream_id: StreamId,
    op: FrameOp,
    data: Bytes,
}

impl Frame {
    fn from_message_parts(num: u64, flag: Flag, data: Bytes) -> Self {
        match flag {
            Flag::NewStream => Frame {
                stream_id: StreamId::Initiator(num),
                op: FrameOp::New,
                data: Bytes::new(),
            },
            Flag::MessageReceiver => Frame {
                stream_id: StreamId::Receiver(num),
                op: FrameOp::Message,
                data: data,
            },
            Flag::MessageInitiator => Frame {
                stream_id: StreamId::Initiator(num),
                op: FrameOp::Message,
                data: data,
            },
            Flag::CloseReceiver => Frame {
                stream_id: StreamId::Receiver(num),
                op: FrameOp::Close,
                data: data,
            },
            Flag::CloseInitiator => Frame {
                stream_id: StreamId::Initiator(num),
                op: FrameOp::Close,
                data: data,
            },
            Flag::ResetReceiver => Frame {
                stream_id: StreamId::Receiver(num),
                op: FrameOp::Reset,
                data: data,
            },
            Flag::ResetInitiator => Frame {
                stream_id: StreamId::Initiator(num),
                op: FrameOp::Reset,
                data: data,
            },
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
enum StreamId {
    Receiver(u64),
    Initiator(u64),
}

impl StreamId {
    fn inverse(&self) -> StreamId {
        match self {
            StreamId::Receiver(num) => StreamId::Initiator(*num),
            StreamId::Initiator(num) => StreamId::Receiver(*num),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
enum Flag {
    NewStream, // 0
    MessageReceiver, // 1
    MessageInitiator, // 2
    CloseReceiver, // 3
    CloseInitiator, // 4
    ResetReceiver, // 5
    ResetInitiator, // 6
}

impl Flag {
    fn to_raw(&self) -> u8 {
        match &self {
            Flag::NewStream => 0,
            Flag::MessageReceiver => 1,
            Flag::MessageInitiator => 2,
            Flag::CloseReceiver => 3,
            Flag::CloseInitiator => 4,
            Flag::ResetReceiver => 5,
            Flag::ResetInitiator => 6,
        }
    }

    fn from_raw(num: u8) -> Result<Self, io::Error> {
        match num {
            0 => Ok(Flag::NewStream),
            1 => Ok(Flag::MessageReceiver),
            2 => Ok(Flag::MessageInitiator),
            3 => Ok(Flag::CloseReceiver),
            4 => Ok(Flag::CloseInitiator),
            5 => Ok(Flag::ResetReceiver),
            6 => Ok(Flag::ResetInitiator),
            _ => Err(io::ErrorKind::InvalidData.into()),
        }
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
        println!("drop stream reader {:?}", self.stream_id);
        self.shared.lock().unwrap().streams.remove_reader(&self.stream_id);
    }
}

impl AsyncRead for StreamReader {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>
    ) -> Poll<Result<(), io::Error>> {
        let mut iself = Pin::into_inner(self);
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
        match shared.poll_drain(cx) {
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
        println!("drop stream writer {:?}", self.stream_id);
        self.shared.lock().unwrap().streams.remove_writer(&self.stream_id);
    }
}

impl AsyncWrite for StreamWriter {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8]
    ) -> Poll<Result<usize, io::Error>> {
        let mut iself = Pin::into_inner(self);
        match iself.poll_drain(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Ready(Ok(())) => {}, // continue
        }

        iself.shared.lock().unwrap().append_message(&iself.stream_id.inverse(), buf);
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>
    ) -> Poll<Result<(), io::Error>> {
        let mut iself = Pin::into_inner(self);
        iself.poll_drain(cx)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>
    ) -> Poll<Result<(), io::Error>> {
        let mut iself = Pin::into_inner(self);
        match iself.poll_drain(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Ready(Ok(())) => {}, // continue
        }

        iself.shared.lock().unwrap().append_close(&iself.stream_id.inverse());
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
                stream_id: stream_id.clone(),
                shared: shared.clone(),
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
        let mut iself = Pin::into_inner(self);
        Pin::new(&mut iself.reader).poll_read(cx, buf)
    }
}

impl AsyncWrite for Stream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8]
    ) -> Poll<Result<usize, io::Error>> {
        let mut iself = Pin::into_inner(self);
        Pin::new(&mut iself.writer).poll_write(cx, buf)
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>
    ) -> Poll<Result<(), io::Error>> {
        let mut iself = Pin::into_inner(self);
        Pin::new(&mut iself.writer).poll_flush(cx)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>
    ) -> Poll<Result<(), io::Error>> {
        let mut iself = Pin::into_inner(self);
        Pin::new(&mut iself.writer).poll_shutdown(cx)
    }
}
