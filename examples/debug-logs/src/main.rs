use zwuevi::{AsyncEventKind, Zwuevi};

/// Connect to the default Tor control socket and print debug messages
#[tokio::main]
async fn main() {
    // create controller and set event listener
    let (tx, rx) = std::sync::mpsc::channel();
    let mut zwuevi = Zwuevi::default().await.unwrap();

    let _handle = zwuevi
        .add_event_handler(AsyncEventKind::LogMessagesDebug, move |event| {
            event
                .into_iter()
                .for_each(|line| tx.send(line).expect("Could not send log"));
        })
        .await;

    // receive event
    while let Ok(line) = rx.recv() {
        println!("{line}");
    }
}
