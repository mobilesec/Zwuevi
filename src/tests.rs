use crate::{AsyncEventKind, Zwuevi};
use tokio::runtime::Runtime;

async fn create_logs(zwuevi: &mut Zwuevi) {
    let onion = zwuevi
        .add_onion_v3(&Zwuevi::generate_key(), [(80, ("127.0.0.1", 3000))], None)
        .await
        .unwrap();

    zwuevi.delete_onion(&onion).await.unwrap();
}

#[test]
fn controll_tor_connection() {
    let rt = Runtime::new().unwrap();

    // block until finished
    rt.block_on(async move {
        Zwuevi::default().await.unwrap();
    });
}

#[test]
fn add_onion_v3() {
    let rt = Runtime::new().unwrap();

    // block until finished
    rt.block_on(async move {
        let mut zwuevi = Zwuevi::default().await.unwrap();
        let _onion = zwuevi
            .add_onion_v3(&Zwuevi::generate_key(), [(80, ("127.0.0.1", 3000))], None)
            .await
            .unwrap();
    });
}

#[test]
fn delete_onion_v3() {
    let rt = Runtime::new().unwrap();

    // block until finished
    rt.block_on(async move {
        let mut zwuevi = Zwuevi::default().await.unwrap();

        let onion = zwuevi
            .add_onion_v3(&Zwuevi::generate_key(), [(80, ("127.0.0.1", 3000))], None)
            .await
            .unwrap();

        zwuevi.delete_onion(&onion).await.unwrap();
    });
}

#[test]
fn set_event_info_log() {
    let rt = Runtime::new().unwrap();

    // block until finished
    rt.block_on(async move {
        let mut zwuevi = Zwuevi::new(
            9051,
            Some(&|result| {
                let (event, _) = result.unwrap();
                assert_eq!(event, AsyncEventKind::LogMessagesInfo);
            }),
        )
        .await
        .unwrap();
        zwuevi
            .set_events([AsyncEventKind::LogMessagesInfo])
            .await
            .unwrap();

        create_logs(&mut zwuevi).await;
    });
}

#[test]
fn set_event_debug_log() {
    let rt = Runtime::new().unwrap();

    // block until finished
    rt.block_on(async move {
        let mut zwuevi = Zwuevi::new(
            9051,
            Some(&|result| {
                let (event, _) = result.unwrap();
                assert_eq!(event, AsyncEventKind::LogMessagesDebug);
            }),
        )
        .await
        .unwrap();
        zwuevi
            .set_events([AsyncEventKind::LogMessagesDebug])
            .await
            .unwrap();

        create_logs(&mut zwuevi).await;
    });
}

#[test]
fn event_handler() {
    let rt = Runtime::new().unwrap();

    // block until finished
    rt.block_on(async move {
        let mut zwuevi = Zwuevi::new(
            9051,
            Some(&|_| {
                panic!("Got event without registering for one");
            }),
        )
        .await
        .unwrap();

        create_logs(&mut zwuevi).await;

        // unset events
        zwuevi.remove_event_handler().await.unwrap();

        // listen for debug events
        zwuevi
            .set_events([AsyncEventKind::LogMessagesDebug])
            .await
            .unwrap();

        create_logs(&mut zwuevi).await;

        // listen for debug events
        zwuevi.set_events([]).await.unwrap();

        zwuevi
            .set_event_handler(&|_| {
                panic!("Got event after unset all events");
            })
            .await
            .unwrap();

        create_logs(&mut zwuevi).await;
    });
}

#[test]
fn remove_event_handler() {
    let rt = Runtime::new().unwrap();

    // block until finished
    rt.block_on(async move {
        let mut zwuevi = Zwuevi::new(
            9051,
            Some(&|_| panic!("Got event after removing event handler")),
        )
        .await
        .unwrap();

        zwuevi.remove_event_handler().await.unwrap();
        zwuevi
            .set_events([AsyncEventKind::LogMessagesDebug])
            .await
            .unwrap();

        create_logs(&mut zwuevi).await;
    });
}

#[test]
fn set_event_handler() {
    let rt = Runtime::new().unwrap();

    // block until finished
    rt.block_on(async move {
        let mut zwuevi = Zwuevi::default().await.unwrap();

        zwuevi
            .set_events([AsyncEventKind::LogMessagesDebug])
            .await
            .unwrap();

        zwuevi
            .set_event_handler(&|result| {
                let (event, _) = result.unwrap();
                assert_eq!(AsyncEventKind::LogMessagesDebug, event)
            })
            .await
            .unwrap();
        create_logs(&mut zwuevi).await;
    });
}

#[test]
fn get_info_version() {
    let rt = Runtime::new().unwrap();

    // block until finished
    rt.block_on(async move {
        let mut zwuevi = Zwuevi::default().await.unwrap();
        let response = zwuevi.raw_command("GETINFO version").await.unwrap();

        assert!(response.iter().any(|line| line.contains("version")))
    });
}
