use bytes::Bytes;
use super::ids::StreamId;

/// Abruptly terminates the sending part of a stream.
/// ([Section 19.4](https://www.rfc-editor.org/rfc/rfc9000.html#name-reset_stream-frames))
///
/// An endpoint uses a `RESET_STREAM` frame to abruptly terminate the sending part of a stream.
///
/// After sending a `RESET_STREAM`, an endpoint ceases transmission and retransmission of
/// [`STREAM`](StreamFrame) frames on the identified stream. A receiver of `RESET_STREAM` can
/// discard any data that it already received on that stream.
///
/// An endpoint that receives a `RESET_STREAM` frame for a send-only stream **MUST** terminate the
/// connection with error [StreamStateError](TransportError::StreamStateError).
#[derive(Debug, Clone)]
pub struct ResetStreamFrame {
    /// A variable-length integer encoding of the stream ID of the stream being terminated.
    pub stream_id: StreamId,
    /// A variable-length integer containing the application protocol error code (see
    /// [Section 20.2](https://www.rfc-editor.org/rfc/rfc9000.html#app-error-codes)) that indicates
    /// why the stream is being closed.
    pub app_error_code: u64,
    /// A variable-length integer indicating the final size of the stream by the `RESET_STREAM`
    /// sender, in units of bytes; see
    /// [Section 4.5](https://www.rfc-editor.org/rfc/rfc9000.html#final-size).
    pub final_size: u64,
}

/// Implicitly create a stream and carry stream data
/// ([Section 19.8](https://www.rfc-editor.org/rfc/rfc9000.html#name-stream-frames))
#[derive(Debug, Clone)]
pub struct StreamFrame {
    pub stream_id: StreamId,
    pub offset: u64,
    pub data: Bytes,
}

/// Used in flow control to inform the peer of the maximum amount of data that can be sent on the
/// connection as a whole
/// ([Section 19.9](https://www.rfc-editor.org/rfc/rfc9000.html#name-max_data-frames))
///
/// All data sent in [STREAM](StreamFrame) frames counts toward this limit. The sum of the final
/// sizes on all streams -- including streams in terminal states -- **MUST NOT** exceed the value
/// advertised by a receiver. An endpoint **MUST** terminate a connection with an error of type
/// [FLOW_CONTROL_ERROR](TransportError::FlowControlError) if it receives more data than the maximum
/// data value that it has sent. This includes violations of remembered limits in Early Data; see
/// [Section 7.4.1](https://www.rfc-editor.org/rfc/rfc9000.html#zerortt-parameters).
#[derive(Debug, Clone)]
pub struct MaxDataFrame {
    /// variable-length integer indicating the maximum amount of data that can be sent on the entire
    /// connection, in units of bytes.
    pub max_data: u64,
}

/// Used in flow control to inform a peer of the maximum amount of data that can be sent on a stream
/// ([Section 19.10](https://www.rfc-editor.org/rfc/rfc9000.html#name-max_stream_data-frames))
///
/// A `MAX_STREAM_DATA` frame can be sent for streams in the "Recv" state; see
/// [Section 3.2](https://www.rfc-editor.org/rfc/rfc9000.html#stream-recv-states). Receiving a
/// `MAX_STREAM_DATA` frame for a locally initiated stream that has not yet been created **MUST** be
/// treated as a connection error of type [`StreamStateError`](TransportError::StreamStateError).
/// An endpoint that receives a `MAX_STREAM_DATA` frame for a receive-only stream **MUST** terminate
/// the connection with error [`StreamStateError`](TransportError::StreamStateError).
///
/// When counting data toward this limit, an endpoint accounts for the largest received offset of
/// data that is sent or received on the stream. Loss or reordering can mean that the largest
/// received offset on a stream can be greater than the total size of data received on that stream.
/// Receiving [STREAM](StreamFrame) frames might not increase the largest received offset.
///
/// The data sent on a stream **MUST NOT** exceed the largest maximum stream data value advertised
/// by the receiver. An endpoint **MUST** terminate a connection with an error of type
/// [`FlowControlError`](TransportError::FlowControlError) if it receives more data than the largest
/// maximum stream data that it has sent for the affected stream. This includes violations of
/// remembered limits in Early Data; see
/// [Section 7.4.1](https://www.rfc-editor.org/rfc/rfc9000.html#zerortt-parameters).
#[derive(Debug, Clone)]
pub struct MaxStreamDataFrame {
    /// The stream ID of the affected stream, encoded as a variable-length integer
    pub stream_id: StreamId,
    /// A variable-length integer indicating the maximum amount of data that can be sent on the
    /// identified stream, in units of bytes
    pub max_stream_data: u64,
}

/// Frame types from QUIC
/// [Section 19](https://www.rfc-editor.org/rfc/rfc9000.html#name-frame-types-and-formats)
#[derive(Debug, Clone)]
pub enum Frame {
    Padding,                           // 0x00
    Ping,                              // 0x01
    Ack,                               // 0x02 and 0x03
    ResetStream(ResetStreamFrame),     // 0x04
    StopSending,                       // 0x05
    Crypto,                            // 0x06
    NewToken,                          // 0x07
    Stream(StreamFrame),               // 0x08 to 0x0f
    MaxData(MaxDataFrame),             // 0x10
    MaxStreamData(MaxStreamDataFrame), // 0x11
    MaxStreams,                        // 0x12 or 0x13
    DataBlocked,                       // 0x14
    StreamDataBlocked,                 // 0x15
    StreamsBlocked,                    // 0x16 or 0x17
    NewConnectionId,                   // 0x18
    RetireConnectionId,                // 0x19
    PathChallenge,                     // 0x1a
    PathResponse,                      // 0x1b
    ConnectionClose,                   // 0x1c or 0x1d
    HandshakeDone,                     // 0x1e
}
