use crate::*;

/// Create a default controller connection on port 9050
#[tokio::test]
async fn default_zwuevi_controller() {
    Zwuevi::default().await.unwrap();
}

/// Create two event handler and remove them one by one
#[tokio::test]
async fn async_event_handlers() {
    let mut zwuevi = Zwuevi::default().await.unwrap();
    let (tx_1, rx_1) = std::sync::mpsc::channel();
    let (tx_2, rx_2) = std::sync::mpsc::channel();

    let handler_1 = zwuevi
        .add_event_handler(AsyncEventKind::LogMessagesDebug, move |event| {
            tx_1.send(event).unwrap();
        })
        .await
        .unwrap();
    // somehow ensure the second is launched afterwards
    tokio::time::sleep(std::time::Duration::from_millis(10)).await;

    let handler_2 = zwuevi
        .add_event_handler(AsyncEventKind::LogMessagesDebug, move |event| {
            tx_2.send(event).unwrap();
        })
        .await
        .unwrap();

    // gather some messages
    tokio::time::sleep(std::time::Duration::from_secs(1)).await;

    // sync so it starts with the same message
    let first = rx_2.recv().unwrap();
    while first.ne(&rx_1.recv().unwrap()) {}

    // compare messages (all should be equal)
    while let Ok(msg) = rx_1.try_recv() {
        let dup = rx_2.recv().unwrap();
        assert_eq!(msg, dup);
    }

    // remove one handler and gather some more messgaes
    drop(handler_2);
    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    assert!(rx_2.recv().is_err());

    // remove all messages
    while let Ok(_msg) = rx_1.try_recv() {}

    // remove last handler and gather new messages - there should be none
    drop(handler_1);
    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    assert!(rx_1.recv().is_err());
}

/// Create onion service
#[tokio::test]
async fn add_onion_v3() {
    let mut zwuevi = Zwuevi::default().await.unwrap();
    let _onion = zwuevi
        .add_onion_v3(&Zwuevi::generate_key(), [(80, ("127.0.0.1", 3000))], None)
        .await
        .unwrap();
}

/// Create and delete onion service
#[tokio::test]
async fn delete_onion_v3() {
    let mut zwuevi = Zwuevi::default().await.unwrap();

    let onion = zwuevi
        .add_onion_v3(&Zwuevi::generate_key(), [(80, ("127.0.0.1", 3000))], None)
        .await
        .unwrap();

    zwuevi.delete_onion(&onion).await.unwrap();
}

/// Create async event listener for `Info` log messages
#[tokio::test]
async fn set_event_info_log() {
    let (tx, mut rx) = tokio::sync::mpsc::channel(64);
    let mut zwuevi = Zwuevi::default().await.unwrap();

    let _handle = zwuevi
        .add_event_handler(AsyncEventKind::LogMessagesInfo, move |event| {
            event
                .into_iter()
                .for_each(|line| tx.try_send(line).unwrap());
        })
        .await;

    let data = rx.recv().await.unwrap();
    assert!(!data.is_empty());
}

/// Create async event listener for `Debug` log messages
#[tokio::test]
async fn set_event_debug_log() {
    let (tx, mut rx) = tokio::sync::mpsc::channel(64);
    let mut zwuevi = Zwuevi::default().await.unwrap();

    let _handle = zwuevi
        .add_event_handler(AsyncEventKind::LogMessagesDebug, move |event| {
            event
                .into_iter()
                .for_each(|line| tx.try_send(line).unwrap());
        })
        .await;

    let data = rx.recv().await.unwrap();
    assert!(!data.is_empty());
}

/// Test raw command to receive version
#[tokio::test]
async fn get_info_version() {
    let mut zwuevi = Zwuevi::default().await.unwrap();
    let response = zwuevi.raw_command("GETINFO version").await.unwrap();

    assert!(response.data.iter().any(|line| line.contains("version")));
}
