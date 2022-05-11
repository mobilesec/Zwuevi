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
    event_handler: Arc<
        Mutex<
            Option<&'static (dyn Fn(Result<(AsyncEventKind, Vec<String>), Error>) + Send + Sync)>,
        >,
    >,
    event_receiver: tokio::sync::mpsc::Receiver<Result<(u16, Vec<String>), Error>>,
}

impl Connection {
    async fn new(
        port: u16,
        event_handler: Option<
            &'static (dyn Fn(Result<(AsyncEventKind, Vec<String>), Error>) + Send + Sync),
        >,
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

    async fn read_until(rx: &mut OwnedReadHalf, pattern: &[u8]) -> Result<String, Error> {
        let mut line = Vec::new();
        let mut byte = [0u8; 1];
        let length = pattern.len();

        loop {
            rx.read_exact(&mut byte).await?;
            line.push(byte[0]);

            let l = line.len();
            if l >= length && line[l - length..] == pattern[..] {
                line.truncate(l - length);
                let line = String::from_utf8(line)
                    .map_err(|err| Error::new(ErrorKind::InvalidData, err))?;
                return Ok(line);
            }
        }
    }

    async fn clean_line(rx: &mut OwnedReadHalf) -> String {
        match Self::read_until(rx, b"\r\n").await {
            Ok(line) => line,
            Err(err) => format!("not parsable: {}", err),
        }
    }

    async fn event_loop(
        mut rx: OwnedReadHalf,
        queue: tokio::sync::mpsc::Sender<Result<(u16, Vec<String>), Error>>,
        event_handler: Arc<
            Mutex<
                Option<
                    &'static (dyn Fn(Result<(AsyncEventKind, Vec<String>), Error>) + Send + Sync),
                >,
            >,
        >,
    ) {
        loop {
            let mut response_code;
            let mut lines = Vec::new();

            let data = 'lines: loop {
                // read the 3 digit response code
                // if we do not get a valid response code, we dont care about the line because we
                // would not know what we do with it (response or event?)
                let mut raw_response_code = [0u8; 3];
                if let Err(err) = rx.read_exact(&mut raw_response_code).await {
                    if err.kind().eq(&ErrorKind::UnexpectedEof) {
                        return;
                    }

                    let line = Self::clean_line(&mut rx).await;
                    eprintln!(
                        "Could not read valid response code (raw: {:?}): {} [{}]",
                        raw_response_code, err, line
                    );
                    continue 'lines;
                }

                let raw = match String::from_utf8(raw_response_code.into()) {
                    Ok(raw) => raw,
                    Err(err) => {
                        let line = Self::clean_line(&mut rx).await;
                        eprintln!(
                            "Could not parse valid utf8 from response code (raw: {:?}): {} [{}]",
                            raw_response_code, err, line
                        );
                        continue 'lines;
                    }
                };

                match u16::from_str(&raw) {
                    Ok(response) => response_code = response,
                    Err(err) => {
                        let line = Self::clean_line(&mut rx).await;
                        eprintln!(
                            "Could not parse valid response code (raw: {:?}): {} [{}]",
                            raw, err, line
                        );
                        continue 'lines;
                    }
                }

                // get next character to determine further process
                let mut byte = [0u8; 1];
                if let Err(err) = rx.read_exact(&mut byte).await {
                    let line = Self::clean_line(&mut rx).await;
                    break 'lines Err(Error::new(
                        ErrorKind::Other,
                        format!("Cant read the line mode we are in: {} [{}]", err, line),
                    ));
                }

                match byte[0] {
                    b' ' | b'-' => {
                        // ' ': last line - read until end
                        // '-': one of multiple - read line and continue
                        let line = match Self::read_until(&mut rx, b"\r\n").await {
                            Ok(line) => line,
                            Err(err) => {
                                let line = Self::clean_line(&mut rx).await;
                                break 'lines Err(Error::new(
                                    ErrorKind::Other,
                                    format!("Cant read the this line: {} [{}]", err, line),
                                ));
                            }
                        };

                        lines.push(line);

                        if byte[0] == b' ' {
                            break 'lines Ok((response_code, lines)); // found end of last line
                        } else {
                            continue 'lines; // resume with more lines
                        }
                    }
                    b'+' => {
                        // multiline mode
                        let multiline = match Self::read_until(&mut rx, b"\r\n.\r\n").await {
                            Ok(line) => line,
                            Err(err) => {
                                let line = Self::clean_line(&mut rx).await;
                                break 'lines Err(Error::new(
                                    ErrorKind::Other,
                                    format!("Cant read the this multiline: {} [{}]", err, line),
                                ));
                            }
                        };

                        lines.push(multiline);
                        continue 'lines; // resume with more lines
                    }
                    mode => {
                        let line = Self::clean_line(&mut rx).await;
                        break 'lines Err(Error::new(
                            ErrorKind::Other,
                            format!("Unsupported mode: {} [{}]", mode, line),
                        ));
                    }
                }
            };

            // check if its an async event
            if response_code == 650 {
                if let Some(event_handler) = *event_handler.lock().await {
                    let result = match data {
                        Ok((_, mut data)) => {
                            let first_line = data.pop().unwrap_or_default();
                            let (event, line) = first_line
                                .split_once(' ')
                                .unwrap_or(("INVALID EVENT PARSE", ""));
                            let event = event.to_owned();
                            let mut lines = vec![line.to_owned()];
                            lines.extend(data.into_iter());

                            Ok((AsyncEventKind::from(event.as_str()), lines))
                        }
                        Err(err) => Err(err),
                    };

                    // make event handler call async
                    tokio::spawn(async move { (*event_handler)(result) });
                }
            } else {
                queue
                    .send(data)
                    .await
                    .expect("Could not send data from the event loop"); // FIXME: ok?
            }
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
        event_handler: &'static (dyn Fn(Result<(AsyncEventKind, Vec<String>), Error>)
                      + Send
                      + Sync),
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
        event_handler: Option<
            &'static (dyn Fn(Result<(AsyncEventKind, Vec<String>), Error>) + Send + Sync),
        >,
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
        event_handler: &'static (dyn Fn(Result<(AsyncEventKind, Vec<String>), Error>)
                      + Send
                      + Sync),
    ) -> Result<(), Error> {
        self.connection.set_event_handler(event_handler).await
    }

    pub async fn remove_event_handler(&mut self) -> Result<(), Error> {
        self.connection.remove_event_handler().await
    }

    pub async fn raw_command(&mut self, raw: &str) -> Result<Vec<String>, Error> {
        self.connection
            .write(format!("{}\r\n", raw).as_bytes())
            .await?;

        let (code, data) = self.connection.receive().await?;
        if code != 250 {
            return Err(Error::new(
                ErrorKind::Unsupported,
                format!("Invalid response code: {}", code),
            ));
        }
        Ok(data)
    }

    pub async fn add_onion_v3<S: ToSocketAddrs, I: IntoIterator<Item = (u16, S)>>(
        &mut self,
        secret_key: &[u8; 32],
        listeners: I,
        flags: Option<Vec<&str>>,
    ) -> Result<String, Error> {
        let sk = ed25519_dalek::SecretKey::from_bytes(secret_key)
            .map_err(|err| Error::new(ErrorKind::Other, err))?;
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
            let addr = address.to_socket_addrs()?.next().ok_or(Error::new(
                ErrorKind::Other,
                "Could not parse valid socket address",
            ))?;
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
}
