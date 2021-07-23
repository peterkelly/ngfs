use std::io;
use std::pin::Pin;
use bytes::{Bytes, BytesMut, Buf};
use crate::io::AsyncStream;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use std::task::{Context, Poll};
use crate::protobuf::VarInt;
use crate::util::{Indent, DebugHexDump};

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum StreamId {
    Receiver(u64),
    Initiator(u64),
}

impl StreamId {
    pub fn inverse(&self) -> StreamId {
        match self {
            StreamId::Receiver(num) => StreamId::Initiator(*num),
            StreamId::Initiator(num) => StreamId::Receiver(*num),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
enum Flag {
    NewStream,        // 0
    MessageReceiver,  // 1
    MessageInitiator, // 2
    CloseReceiver,    // 3
    CloseInitiator,   // 4
    ResetReceiver,    // 5
    ResetInitiator,   // 6
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

#[derive(Clone, Debug, PartialEq)]
pub enum FrameOp {
    New,
    Message,
    Close,
    Reset,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Frame {
    pub stream_id: StreamId,
    pub op: FrameOp,
    pub data: Bytes,
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

pub struct FrameStream {
    transport: Box<dyn AsyncStream>,
    incoming_data: BytesMut,
    outgoing_data: BytesMut,
    read_eof: bool,
    logging_enabled: bool,
}

impl FrameStream {
    pub fn set_logging_enabled(&mut self, b: bool) {
        self.logging_enabled = b;
    }

    pub fn new<T: 'static>(transport: T) -> Self
        where T : AsyncRead + AsyncWrite + Unpin + Send
    {
        FrameStream {
            transport: Box::new(transport),
            incoming_data: BytesMut::new(),
            outgoing_data: BytesMut::new(),
            read_eof: false,
            logging_enabled: false,
        }
    }

    // Returns Ok(None) on EOF (i.e. when the underlying transport is closed)
    pub fn poll_read_frame(&mut self, cx: &mut Context<'_>) -> Poll<Result<Option<Frame>, io::Error>> {
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
                        let frame = Frame::from_message_parts(num, flag, data);
                        self.log_incoming_frame(&frame);
                        return Poll::Ready(Ok(Some(frame)));
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
                    let filled = recv_buf.filled().len() - old_filled;
                    if filled == 0 {
                        self.read_eof = true; // will be picked up on next loop iteration
                    }
                    else {
                        self.incoming_data.extend_from_slice(recv_buf.filled());
                    }
                    // repeat loop
                }
            }
        }
    }

    pub fn poll_drain(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        while self.outgoing_data.len() > 0 {
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

    pub fn append_new(&mut self, num: u64, name: Option<String>) {
        let stream_id = StreamId::Receiver(num);
        let header: u64 = (num << 3) | (Flag::NewStream.to_raw() as u64);
        match name {
            Some(name) => {
                self.log_outgoing_frame(&stream_id, FrameOp::New, name.as_bytes());
                self.append_frame(header, name.as_bytes());
            }
            None => {
                self.log_outgoing_frame(&stream_id, FrameOp::New, &[]);
                self.append_frame(header, &[]);
            }
        };
    }

    pub fn append_message(
        &mut self,
        stream_id: &StreamId,
        data: &[u8],
    ) {
        self.log_outgoing_frame(&stream_id, FrameOp::Message, data);
        let header: u64 = match stream_id {
            StreamId::Receiver(num) => (num << 3) | (Flag::MessageReceiver.to_raw() as u64),
            StreamId::Initiator(num) => (num << 3) | (Flag::MessageInitiator.to_raw() as u64),
        };
        self.append_frame(header, data);
    }

    pub fn append_close(
        &mut self,
        stream_id: &StreamId
    ) {
        self.log_outgoing_frame(&stream_id, FrameOp::Close, &[]);
        let header: u64 = match stream_id {
            StreamId::Receiver(num) => (num << 3) | (Flag::CloseReceiver.to_raw() as u64),
            StreamId::Initiator(num) => (num << 3) | (Flag::CloseInitiator.to_raw() as u64),
        };
        self.append_frame(header, &[]);
    }

    fn append_frame(&mut self, header: u64, data: &[u8]) {
        self.outgoing_data.extend_from_slice(&VarInt::encode_u64(header));
        self.outgoing_data.extend_from_slice(&VarInt::encode_usize(data.len()));
        self.outgoing_data.extend_from_slice(&data);
    }

    fn log_incoming_frame(&self, frame: &Frame) {
        if self.logging_enabled {
            println!("[mplex] <<<< {:?} {:?} <{} bytes>",
                frame.stream_id, frame.op, frame.data.len());
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
