/// Error codes from QUIC [Section 20](https://www.rfc-editor.org/rfc/rfc9000.html#name-error-codes)
#[derive(Debug, Clone, Copy)]
pub enum TransportError {
    /// An endpoint uses this with `CONNECTION_CLOSE` to signal that the connection
    /// is being closed abruptly in the absence of any error.
    NoError,                 // 0x00

    /// The endpoint encountered an internal error and cannot continue with
    /// the connection.
    InternalError,           // 0x01

    /// The server refused to accept a new connection
    ConnectionRefused,       // 0x02

    /// An endpoint received more data than it permitted in its advertised data limits; see
    /// [Section 4](https://www.rfc-editor.org/rfc/rfc9000.html#flow-control).
    FlowControlError,        // 0x03

    /// An endpoint received a frame for a stream identifier that exceeded its advertised stream
    /// limit for the corresponding stream type.
    StreamLimitError,        // 0x04

    /// An endpoint received a frame for a stream that was not in a state that permitted that frame;
    /// see [Section 3](https://www.rfc-editor.org/rfc/rfc9000.html#stream-states).
    StreamStateError,        // 0x05

    /// 1. An endpoint received a `STREAM` frame containing data that exceeded the previously
    /// established final size,
    /// 2. an endpoint received a `STREAM` frame or a `RESET_STREAM` frame
    /// containing a final size that was lower than the size of stream data that was already
    /// received, or
    /// 3. an endpoint received a `STREAM` frame or a `RESET_STREAM` frame containing
    /// a different final size to the one already established.
    FinalSizeError,          // 0x06

    /// An endpoint received a frame that was badly formatted -- for instance, a frame of an unknown
    /// type or an `ACK` frame that has more acknowledgment ranges than the remainder of the packet
    /// could carry.
    FrameEncodingError,      // 0x07

    /// An endpoint received transport parameters that were badly formatted, included an invalid
    /// value, omitted a mandatory transport parameter, included a forbidden transport parameter,
    /// or were otherwise in error.
    TransportParameterError, // 0x08

    /// The number of connection IDs provided by the peer exceeds the advertised
    /// `active_connection_id_limit`.
    ConnectionIdLimitError,  // 0x09

    /// An endpoint detected an error with protocol compliance that was not covered by more specific
    /// error codes.
    ProtocolViolation,       // 0x0a

    /// A server received a client Initial that contained an invalid Token field.
    InvalidToken,            // 0x0b

    /// The application or application protocol caused the connection to be closed.
    ApplicationError,        // 0x0c

    /// An endpoint has received more data in `CRYPTO` frames than it can buffer.
    CryptoBufferExceeded,    // 0x0d

    /// An endpoint detected errors in performing key updates; see
    /// [Section 6](https://www.rfc-editor.org/rfc/rfc9001#section-6) of
    /// [QUIC-TLS](https://www.rfc-editor.org/rfc/rfc9001.html).
    KeyUpdateError,          // 0x0e

    /// An endpoint has reached the confidentiality or integrity limit for the AEAD algorithm used
    /// by the given connection.
    AeadLimitReached,        // 0x0f

    /// An endpoint has determined that the network path is incapable of supporting QUIC. An
    /// endpoint is unlikely to receive a `CONNECTION_CLOSE` frame carrying this code except when
    /// the path does not support a large enough MTU.
    NoViablePath,            // 0x10

    /// The cryptographic handshake failed. A range of 256 values is reserved for carrying error
    /// codes specific to the cryptographic handshake that is used. Codes for errors occurring when
    /// TLS is used for the cryptographic handshake are described in
    /// [Section 4.8](https://www.rfc-editor.org/rfc/rfc9001#section-4.8) of
    /// [QUIC-TLS](https://www.rfc-editor.org/rfc/rfc9001.html).
    CryptoError,             // 0x100-0x01ff
}

// 20.2. Application Protocol Error Codes
//
// The management of application error codes is left to application protocols. Application protocol
// error codes are used for the RESET_STREAM frame (Section 19.4), the STOP_SENDING frame (Section
// 19.5), and the CONNECTION_CLOSE frame with a type of 0x1d (Section 19.19).
