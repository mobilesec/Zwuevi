use zwuevi::{AsyncEventKind, Zwuevi};

#[tokio::main]
async fn main() {
    // create controller and set event listener
    let mut zwuevi = Zwuevi::new(
        9051,
        Some(&|result| match result {
            Ok((event, lines)) => print!(
                "{}: {}",
                event,
                lines.into_iter().fold(String::new(), |mut acc, line| {
                    acc.push_str(&format!("{}\n", line));
                    acc
                })
            ),
            Err(err) => eprintln!("error: {}", err),
        }),
    )
    .await
    .unwrap();

    // set for debug events
    zwuevi
        .set_events([AsyncEventKind::LogMessagesDebug])
        .await
        .unwrap();

    // create some log messages by creating and deleting an onion service
    let onion = zwuevi
        .add_onion_v3(&Zwuevi::generate_key(), [(80, ("127.0.0.1", 3000))], None)
        .await
        .unwrap();
    zwuevi.delete_onion(&onion).await.unwrap();
}
