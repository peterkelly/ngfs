use tokio::io::{AsyncRead, AsyncWrite};

pub trait AsyncStream: AsyncRead + AsyncWrite + Send {}

impl<T> AsyncStream for T where T: AsyncRead + AsyncWrite + Send {}
