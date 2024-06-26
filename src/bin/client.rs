// https://tokio.rs/docs/getting-started/hello-world/

use tokio::net::TcpStream;
use tokio::io::AsyncWriteExt;

#[tokio::main]
async fn main() {
    let mut stream = TcpStream::connect("127.0.0.1:6142").await.unwrap();
    println!("created stream");

    let result = stream.write(b"hello world\n").await;
    println!("wrote to stream; success={:?}", result.is_ok());
}
