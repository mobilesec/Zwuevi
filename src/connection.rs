use crate::AsyncEventKind;
use std::io::{Error, ErrorKind};
use std::str::FromStr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;
use tokio::sync::Mutex;

// Representation of an event handler for async events
pub(crate) type EventHandler =
    &'static (dyn Fn(Result<(AsyncEventKind, Vec<String>), Error>) + Send + Sync);

// Handling the async events, send and receive return value of commands
pub(crate) struct Connection {
    sender: OwnedWriteHalf,
    event_handler: Arc<Mutex<Option<EventHandler>>>,
    event_receiver: tokio::sync::mpsc::Receiver<Result<(u16, Vec<String>), Error>>,
}

impl Connection {
    // Create a new connection to the TOR control socket
    pub(crate) async fn new(
        port: u16,
        event_handler: Option<EventHandler>,
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

    // Authenticate with the simplest authentication command
    pub(crate) async fn authenticate(&mut self) -> Result<(), Error> {
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

    // Read from the socket until the provided `pattern`
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

    // Remove a complete line - used to clean if an error occurs
    async fn clean_line(rx: &mut OwnedReadHalf) -> String {
        match Self::read_until(rx, b"\r\n").await {
            Ok(line) => line,
            Err(err) => format!("not parsable: {}", err),
        }
    }

    // The event loop that is handling async events as well as responses on commands sent
    async fn event_loop(
        mut rx: OwnedReadHalf,
        queue: tokio::sync::mpsc::Sender<Result<(u16, Vec<String>), Error>>,
        event_handler: Arc<Mutex<Option<EventHandler>>>,
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
                    .expect("Could not send data to the event queue");
            }
        }
    }

    // Recieve a response from the TOR controller after a command was pushed
    pub(crate) async fn receive(&mut self) -> Result<(u16, Vec<String>), Error> {
        match self.event_receiver.recv().await {
            Some(result) => result,
            None => Err(Error::new(ErrorKind::Other, "Issue")),
        }
    }

    // Send a command to the TOR controller
    pub(crate) async fn write(&mut self, data: &[u8]) -> Result<(), Error> {
        self.sender.write_all(data).await?;
        self.sender.flush().await?;

        Ok(())
    }

    // Set a new event handler
    pub(crate) async fn set_event_handler(
        &mut self,
        event_handler: EventHandler,
    ) -> Result<(), Error> {
        let mut handler = self.event_handler.lock().await;
        handler.replace(event_handler);

        Ok(())
    }

    // Remove an existing event handler
    pub(crate) async fn remove_event_handler(&mut self) -> Result<(), Error> {
        let mut handler = self.event_handler.lock().await;
        let _ = handler.take();

        Ok(())
    }

    // Wait until Tor is connected.
    pub(crate) async fn wait_until_ready(&mut self) -> Result<(), Error> {
        loop {
            self.write(b"GETINFO status/circuit-established\r\n")
                .await?;
            let (code, value) = self.receive().await?;

            if code != 250 {
                return Err(Error::new(
                    ErrorKind::Unsupported,
                    format!("Invalid response code: {}", code),
                ));
            }

            // check status
            if value.contains(&String::from("status/circuit-established=1")) {
                return Ok(());
            }

            tokio::time::sleep(core::time::Duration::from_secs(1)).await;
        }
    }
}
