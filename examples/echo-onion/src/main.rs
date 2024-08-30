use tokio::net::TcpListener;
use zwuevi::Zwuevi;

/// Create an echo onion server
///
/// The onion address will be printed to stdout.
/// You can connect with a simple curl command to test it:
/// ```sh
/// nc -X5 -xlocalhost:9050 <echo-onion-address> 80
/// ```
/// Be aware that this only works with the openbsd version of netcat.
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

    // accept new connections and echoing requests
    loop {
        let (stream, _addr) = listener.accept().await.unwrap();
        tokio::spawn(async move {
            let (mut reader, mut writer) = stream.into_split();
            let _ = tokio::io::copy(&mut reader, &mut writer).await;
        });
    }
}
