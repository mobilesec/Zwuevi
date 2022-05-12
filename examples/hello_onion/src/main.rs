use tokio::{io::AsyncWriteExt, net::TcpListener};
use zwuevi::Zwuevi;

#[tokio::main]
async fn main() {
    // create local listener
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    // create onion service
    let mut zwuevi = Zwuevi::default().await.unwrap();
    let onion_addr = zwuevi
        .add_onion_v3(&Zwuevi::generate_key(), [(80, ("127.0.0.1", port))], None)
        .await
        .unwrap();

    println!("echo-onion: {}.onion", onion_addr);

    // response to every connection
    loop {
        let (mut stream, _addr) = listener.accept().await.unwrap();
        let _ = stream.write_all(b"hello world").await;
        let _ = stream.flush().await;
    }
}
