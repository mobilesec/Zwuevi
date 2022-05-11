use rand::thread_rng;
use sha3::{Digest, Sha3_256};
use std::collections::HashSet;
use std::fmt::Display;
use std::io::{Error, ErrorKind};
use std::net::ToSocketAddrs;
use std::str::FromStr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;
use tokio::sync::Mutex;

const TOR_PORT_CONTROL: u16 = 9051;
const MAX_SINGLE_RECV_BYTES: usize = 1024 * 1024 * 1; // 1MB

#[derive(Debug, PartialEq, Eq)]
pub enum AsyncEventKind {
    CircuitStatusChanged,
    StreamStatusChanged,
    ConnectionStatusChanged,
    BandwidthUsedInTheLastSecond,

    // 4.1.5. there are three constant strings after 650 code
    LogMessagesDebug,
    LogMessagesInfo,
    LogMessagesNotice,
    LogMessagesWarn,
    LogMessagesErr,

    NewDescriptorsAvailable,
    NewAddressMapping,
    DescriptorsUploadedToUsInOurRoleAsAuthoritativeServer,
    OurDescriptorChanged,

    // 4.1.10 there are three constant strings after 650 code
    StatusGeneral,
    StatusClient,
    StatusServer,

    OurSetOfGuardNodesHasChanged,
    NetworkStatusHasChanged,
    BandwidthUsedOnApplicationStream,
    PerCountryClientStats,
    NewConsensusNetworkStatusHasArrived,
    NewCircuitBuildTimeHasBeenSet,
    SignalReceived,
    ConfigurationChanged,
    CircuitStatusChangedSlightly,
    PluggableTransportLaunched,
    BandwidthUsedOnOROrDirOrExitConnection,
    BandwidthUsedByAllStreamsAttachedToACircuit,
    PerCircuitCellStatus,
    TokenBucketsRefilled,
    HiddenServiceDescriptors,
    HiddenServiceDescriptorsContent,
    NetworkLivenessHasChanged,
    PluggableTransportLogs,
    PluggableTransportStatus,
}

impl From<&str> for AsyncEventKind {
    fn from(event: &str) -> Self {
        match event {
            "DEBUG" => AsyncEventKind::LogMessagesDebug,
            "INFO" => AsyncEventKind::LogMessagesInfo,
            "NOTICE" => AsyncEventKind::LogMessagesNotice,
            "WARN" => AsyncEventKind::LogMessagesWarn,
            "ERR" => AsyncEventKind::LogMessagesErr,
            _ => AsyncEventKind::StatusGeneral,
        }
    }
}

impl Display for AsyncEventKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let event = match self {
            AsyncEventKind::LogMessagesDebug => "DEBUG",
            AsyncEventKind::LogMessagesInfo => "INFO",
            AsyncEventKind::LogMessagesNotice => "NOTICE",
            AsyncEventKind::LogMessagesWarn => "WARN",
            AsyncEventKind::LogMessagesErr => "ERR",
            _ => "UNKNOWN",
        };

        f.write_str(event)
    }
}

struct Connection {
    sender: OwnedWriteHalf,
    //TODO event_handler needs to also handle errors like if there was some issues from the
    //tor-binary side! all errors should be handled via the event_handler
    event_handler:
        Arc<Mutex<Option<&'static (dyn Fn((AsyncEventKind, Vec<String>)) + Send + Sync)>>>,
    event_receiver: tokio::sync::mpsc::Receiver<Result<(u16, Vec<String>), Error>>,
}

impl Connection {
    async fn new(
        port: u16,
        event_handler: Option<&'static (dyn Fn((AsyncEventKind, Vec<String>)) + Send + Sync)>,
    ) -> Result<Connection, Error> {
        let stream = TcpStream::connect(&format!("127.0.0.1:{}", port)).await?;
        let (rx, sender) = stream.into_split();

        let event_handler = Arc::new(Mutex::new(event_handler));

        // create async loop
        let (event_sender, event_receiver) = tokio::sync::mpsc::channel(100);
        let handler = event_handler.clone();
        tokio::spawn(async move { Connection::event_loop(rx, event_sender, handler).await });

        Ok(Self {
            sender,
            event_handler,
            event_receiver,
        })
    }

    async fn authenticate(&mut self) -> Result<(), Error> {
        self.write(b"AUTHENTICATE\r\n").await?;
        let (code, _) = self.receive().await?;

        if code != 250 {
            return Err(Error::new(
                ErrorKind::Unsupported,
                format!("Invalid response code: {}", code),
            ));
        }

        Ok(())
    }

    async fn event_loop(
        mut rx: OwnedReadHalf,
        queue: tokio::sync::mpsc::Sender<Result<(u16, Vec<String>), Error>>,
        event_handler: Arc<
            Mutex<Option<&'static (dyn Fn((AsyncEventKind, Vec<String>)) + Send + Sync)>>,
        >,
    ) {
        loop {
            let mut lines = Vec::new();
            let mut response_code = None;

            let mut state = 0;

            let mut current_line_buffer = Vec::new();
            let mut bytes_read = 0;
            let mut char_buffer = [0u8; 1];

            loop {
                if bytes_read >= MAX_SINGLE_RECV_BYTES {
                    // FIXME: need to empty all bytes from queue?
                    eprintln!("More data sent as allowed: DoS / OOM protection");
                    break;
                }
                let b = {
                    if let Err(err) = rx.read_exact(&mut char_buffer[..]).await {
                        eprintln!("read error: {}", err);
                        break;
                    }
                    char_buffer[0]
                };

                bytes_read += 1;

                // is this check valid?
                // is all data valid ascii?
                if !b.is_ascii() {
                    eprintln!("Non ASCII character");
                    break;
                }

                if state == 0 {
                    if !b.is_ascii_digit() {
                        eprintln!("Invalid character");
                        break;
                    }
                    current_line_buffer.push(b);

                    // we found response code!
                    if current_line_buffer.len() == 3 {
                        let text = std::str::from_utf8(&current_line_buffer)
                            .map_err(|err| Error::new(ErrorKind::InvalidData, err))
                            .unwrap(); //FIXME
                        let parsed_response_code = u16::from_str(text)
                            .map_err(|err| Error::new(ErrorKind::InvalidData, err))
                            .unwrap(); //FIXME

                        // some fancy behaviour of from str may occur(?)
                        // let's leave this assert even for prod use
                        assert!(parsed_response_code < 1000, "Invalid response code");

                        if let Some(response_code) = response_code {
                            if response_code != parsed_response_code {
                                eprintln!("Response code mismatch");
                                break;
                            }
                        } else {
                            response_code = Some(parsed_response_code);
                        }
                        state = 1;
                        current_line_buffer.clear();
                    }
                } else if state == 1 {
                    debug_assert!(current_line_buffer.is_empty());
                    debug_assert!(response_code.is_some());
                    match b {
                        // last line
                        b' ' => {
                            state = 2;
                        }
                        // some of many lines
                        b'-' => {
                            state = 3;
                        }
                        // multiline mode trigger
                        b'+' => {
                            state = 4;
                        }
                        // other characters are not allowed
                        _ => {
                            eprintln!("Found invalid character");
                            break;
                        }
                    }
                } else if state == 2 || state == 3 {
                    // as the docs says:
                    // Tor, however, MUST NOT generate LF instead of CRLF.
                    current_line_buffer.push(b);
                    let length = current_line_buffer.len();
                    if length >= 2 && current_line_buffer[length - 2..] == b"\r\n"[..] {
                        current_line_buffer.truncate(length - 2);

                        let res = {
                            let mut line_buffer = Vec::new();
                            std::mem::swap(&mut current_line_buffer, &mut line_buffer);
                            String::from_utf8(line_buffer)
                        };
                        // only valid ascii remember?
                        // if so it's valid utf8
                        debug_assert!(res.is_ok());
                        let text = res
                            .map_err(|err| Error::new(ErrorKind::InvalidData, err))
                            .unwrap(); //FIXME
                        lines.push(text);

                        // if it's last line break loop
                        if state == 2 {
                            break;
                        } else {
                            state = 0;
                        }
                    }
                } else if state == 4 {
                    // multiline read mode reads lines until it eventually found \r\n.\r\n sequence
                    current_line_buffer.push(b);
                    let length = current_line_buffer.len();
                    if length >= 5 && current_line_buffer[length - 5..] == b"\r\n.\r\n"[..] {
                        current_line_buffer.truncate(length - 5);

                        let res = {
                            let mut line_buffer = Vec::new();
                            std::mem::swap(&mut current_line_buffer, &mut line_buffer);
                            String::from_utf8(line_buffer)
                        };

                        // only valid ascii remember?
                        // if so it's valid utf8
                        debug_assert!(res.is_ok());
                        let text = res
                            .map_err(|err| Error::new(ErrorKind::InvalidData, err))
                            .unwrap(); // FIXME
                        lines.push(text);

                        // there may be more lines incoming after this one
                        state = 0;
                    }
                } else {
                    unreachable!("Invalid state!");
                }
            }
            let response_code = match response_code {
                Some(response_code) => response_code,
                None => {
                    eprintln!("Invalid format");
                    break;
                }
            };

            // check if its an async event
            if response_code == 650 {
                if let Some(event_handler) = *event_handler.lock().await {
                    let first_line = lines.pop().unwrap();
                    let (event, data) = first_line.split_once(' ').unwrap();
                    let event = event.to_owned();
                    let mut data = vec![data.to_owned()];
                    data.extend(lines.into_iter());

                    // make event handler call async
                    tokio::spawn(async move {
                        (*event_handler)((AsyncEventKind::from(event.as_str()), data))
                    });
                }
                continue;
            }

            queue
                .send(Ok((response_code, lines)))
                .await
                .expect("Could not send data from the event loop"); // FIXME: ok?
        }
    }

    async fn receive(&mut self) -> Result<(u16, Vec<String>), Error> {
        match self.event_receiver.recv().await {
            Some(result) => result,
            None => Err(Error::new(ErrorKind::Other, "Issue")),
        }
    }

    async fn write(&mut self, data: &[u8]) -> Result<(), Error> {
        self.sender.write_all(data).await?;
        self.sender.flush().await?;

        Ok(())
    }

    async fn set_event_handler(
        &mut self,
        event_handler: &'static (dyn Fn((AsyncEventKind, Vec<String>)) + Send + Sync),
    ) -> Result<(), Error> {
        let mut handler = self.event_handler.lock().await;
        handler.replace(event_handler);

        Ok(())
    }

    async fn remove_event_handler(&mut self) -> Result<(), Error> {
        let mut handler = self.event_handler.lock().await;
        let _ = handler.take();

        Ok(())
    }
}

pub struct Zwuevi {
    connection: Connection,
}

impl Zwuevi {
    pub async fn default() -> Result<Zwuevi, Error> {
        let mut connection = Connection::new(TOR_PORT_CONTROL, None).await?;

        // authenticate
        connection.authenticate().await?;

        Ok(Self { connection })
    }

    pub async fn new(
        port: u16,
        event_handler: Option<&'static (dyn Fn((AsyncEventKind, Vec<String>)) + Send + Sync)>,
    ) -> Result<Zwuevi, Error> {
        let mut connection = Connection::new(port, event_handler).await?;

        // authenticate
        connection.authenticate().await?;

        Ok(Self { connection })
    }

    pub async fn set_events(
        &mut self,
        kinds: impl IntoIterator<Item = AsyncEventKind>,
    ) -> Result<(), Error> {
        let mut req = String::from("SETEVENTS");
        for k in kinds {
            req.push_str(&format!(" {}", k));
        }

        req.push_str("\r\n");
        self.connection.write(req.as_bytes()).await?;
        let (code, _) = self.connection.receive().await?;
        if code != 250 {
            return Err(Error::new(
                ErrorKind::Unsupported,
                format!("Invalid response code: {}", code),
            ));
        }
        Ok(())
    }

    pub async fn set_event_handler(
        &mut self,
        event_handler: &'static (dyn Fn((AsyncEventKind, Vec<String>)) + Send + Sync),
    ) -> Result<(), Error> {
        self.connection.set_event_handler(event_handler).await
    }

    pub async fn remove_event_handler(&mut self) -> Result<(), Error> {
        self.connection.remove_event_handler().await
    }

    pub async fn raw_command(&mut self, raw: &str) -> Result<(), Error> {
        self.connection
            .write(format!("{}\r\n", raw).as_bytes())
            .await?;

        let (code, _) = self.connection.receive().await?;
        if code != 250 {
            return Err(Error::new(
                ErrorKind::Unsupported,
                format!("Invalid response code: {}", code),
            ));
        }
        Ok(())
    }

    pub async fn add_onion_v3<S: ToSocketAddrs, I: IntoIterator<Item = (u16, S)>>(
        &mut self,
        secret_key: &[u8; 32],
        listeners: I,
        flags: Option<Vec<&str>>,
    ) -> Result<String, Error> {
        let sk = ed25519_dalek::SecretKey::from_bytes(secret_key).unwrap();
        let esk = ed25519_dalek::ExpandedSecretKey::from(&sk);

        let mut command = format!("ADD_ONION ED25519-V3:{} ", base64::encode(&esk.to_bytes()));

        if let Some(flags) = flags {
            if !flags.is_empty() {
                command.push_str(&format!("Flags={} ", &flags.join(",")));
            }
        }

        let mut service_listeners = HashSet::new();
        let mut listeners = listeners.into_iter();
        for (port, address) in listeners.by_ref() {
            if !service_listeners.is_empty() {
                command.push(' ');
            }
            if service_listeners.contains(&port) {
                return Err(Error::new(ErrorKind::Unsupported, "Invalid listeners"));
            }
            service_listeners.insert(port);
            let addr = address.to_socket_addrs().unwrap().next().unwrap();
            command.push_str(&format!("Port={},{}", port, addr));
        }

        // zero iterations of above loop has ran
        if service_listeners.is_empty() {
            return Err(Error::new(
                ErrorKind::Unsupported,
                "Invalid listener specification",
            ));
        }
        command.push_str("\r\n");

        self.connection.write(command.as_bytes()).await?;

        // we do not really care about contents of response
        // we can derive all the data from tor's objects at the torut level
        let (code, _) = self.connection.receive().await?;
        if code != 250 {
            return Err(Error::new(
                ErrorKind::Unsupported,
                format!("Invalid response code: {}", code),
            ));
        }

        Ok(Self::get_onion_address(&Self::get_public_key(secret_key)?))
    }

    pub async fn delete_onion(&mut self, onion_address: &str) -> Result<(), Error> {
        let onion_address = onion_address.trim_end_matches(".onion");
        if !onion_address.chars().all(|c| {
            // limit to safe chars, so there is no injection
            matches!(c, 'a'..='z' | 'A'..='Z' | '0'..='9' | '/' | '=')
        }) {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "Wrong characters in onion address",
            ));
        }
        self.connection
            .write(format!("DEL_ONION {}\r\n", onion_address).as_bytes())
            .await?;

        let (code, _) = self.connection.receive().await?;
        if code != 250 {
            return Err(Error::new(
                ErrorKind::Unsupported,
                format!("Invalid response code: {}", code),
            ));
        }

        Ok(())
    }

    pub fn get_public_key(secret_key: &[u8; 32]) -> Result<[u8; 32], Error> {
        let sk = ed25519_dalek::SecretKey::from_bytes(secret_key)
            .map_err(|err| Error::new(ErrorKind::Other, err))?;
        let pk = ed25519_dalek::PublicKey::from(&sk);

        Ok(pk.to_bytes())
    }

    pub fn get_onion_address(public_key: &[u8; 32]) -> String {
        let mut buf = [0u8; 35];
        public_key.iter().copied().enumerate().for_each(|(i, b)| {
            buf[i] = b;
        });

        let mut h = Sha3_256::new();
        h.update(b".onion checksum");
        h.update(&public_key);
        h.update(b"\x03");

        let res_vec = h.finalize().to_vec();
        buf[32] = res_vec[0];
        buf[33] = res_vec[1];
        buf[34] = 3;

        base32::encode(base32::Alphabet::RFC4648 { padding: false }, &buf).to_ascii_lowercase()
    }

    pub fn generate_key() -> [u8; 32] {
        let sk = ed25519_dalek::SecretKey::generate(&mut thread_rng());
        sk.to_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::{AsyncEventKind, Zwuevi};
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
                Some(&|(event, _)| {
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
                Some(&|(event, _)| {
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
                .set_event_handler(&|(event, _)| {
                    assert_eq!(AsyncEventKind::LogMessagesDebug, event)
                })
                .await
                .unwrap();
            create_logs(&mut zwuevi).await;
        });
    }
}
