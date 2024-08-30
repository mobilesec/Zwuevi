use crate::misc::{Message, Response};
use crate::AsyncEventKind;
use log::{debug, warn};
use std::collections::HashMap;
use std::io::{Error, ErrorKind};
use std::str::FromStr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::task::JoinHandle;

// Handling the async events, send and receive return value of commands
pub(crate) struct Connection {
    sender: tokio::sync::mpsc::Sender<Message>,
    event_handler: JoinHandle<()>,
}

impl Drop for Connection {
    fn drop(&mut self) {
        self.event_handler.abort();
    }
}

impl Connection {
    // Read until end of line (as specified in Tor protocol)
    fn line_end(buffer: &[u8]) -> Option<usize> {
        buffer
            .windows(2)
            .position(|w| w.eq(b"\r\n"))
            .map(|end| end + 2)
    }

    // Read until end of multi-line (as specified in Tor protocol)
    fn line_multi_end(buffer: &[u8]) -> Option<usize> {
        buffer
            .windows(5)
            .position(|w| w.eq(b"\r\n.\r\n"))
            .map(|end| end + 5)
    }

    // Split buffer at specific index and remove prefix and suffix as specified by byte len
    fn split_off_string(buffer: &mut Vec<u8>, at: usize, prefix: usize, suffix: usize) -> String {
        let mut new = buffer.split_off(at);
        core::mem::swap(buffer, &mut new);

        String::from_utf8_lossy(&new[prefix..at - suffix]).into_owned()
    }

    // parse buffer and split off a string if the information is valid
    fn parse(buffer: &mut Vec<u8>) -> Option<(bool, u16, String)> {
        // if buffer is smaller than 8, we wait for more information
        //  -> minimum reply message might have at least 8 bytes:
        //  0-2:    return code
        //  3:      space
        //  4-5:    'OK'
        //  6-7:    '\r\n'
        if buffer.len() < 8 {
            return None;
        }

        // read the 3 digit response code
        let raw = match std::str::from_utf8(&buffer[..3]) {
            Ok(raw) => raw,
            Err(err) => {
                // if we already have a line in the buffer - we remove it
                // otherwise we keep it and might remove it the next iteration
                if let Some(end) = Self::line_end(buffer) {
                    let line = Self::split_off_string(buffer, end, 3, 2);
                    warn!(
                        "Could not parse valid utf8 from response code (raw: {:?}): {err} [{line}]",
                        &buffer[..3]
                    );
                }

                return None;
            }
        };

        let response_code = match u16::from_str(raw) {
            Ok(response) => response,
            Err(err) => {
                // if we already have a line in the buffer - we remove it
                // otherwise we keep it and might remove it the next iteration
                if let Some(end) = Self::line_end(buffer) {
                    let line = Self::split_off_string(buffer, end, 3, 2);
                    warn!(
                        "Could not parse valid response code (raw: {:?}): {err} [{line}]",
                        &buffer[..3]
                    );
                }

                return None;
            }
        };

        // get next character to determine further process
        match buffer[3] {
            b' ' => {
                // ' ': last line - read until newline
                let line = if let Some(end) = Self::line_end(buffer) {
                    Self::split_off_string(buffer, end, 4, 2)
                } else {
                    // no line end found - wait for more data
                    debug!("no end of end-line found yet - continue to read");
                    return None;
                };

                Some((true, response_code, line))
            }
            b'-' => {
                // '-': one of multiple - read line and continue
                let line = if let Some(end) = Self::line_end(buffer) {
                    Self::split_off_string(buffer, end, 4, 2)
                } else {
                    // no line end found - wait for more data
                    debug!("no end of mid-line found yet - continue to read");
                    return None;
                };

                Some((false, response_code, line))
            }
            b'+' => {
                // multiline mode
                let multiline = if let Some(end) = Self::line_multi_end(buffer) {
                    Self::split_off_string(buffer, end, 4, 5)
                } else {
                    // no multi-line end found - wait for more data
                    debug!("no end of data-line found yet - continue to read");
                    return None;
                };

                Some((true, response_code, multiline))
            }
            mode => {
                if let Some(end) = Self::line_multi_end(buffer) {
                    let line = Self::split_off_string(buffer, end, 3, 2);
                    warn!("invalid code: {mode}: forget line: {line}");
                }
                None
            }
        }
    }

    // Parse incoming messages from the buffer
    fn parse_message(buffer: &mut Vec<u8>, lines: &mut Vec<String>) -> Option<Response> {
        // while we get valid lines from buffer
        while let Some((complete, code, line)) = Self::parse(buffer) {
            // put data into vec
            lines.push(line);

            if !complete {
                // this was part of a multi-line message, there is still data missing
                continue;
            };

            // swap buffer
            let mut data = Vec::new();
            core::mem::swap(lines, &mut data);

            return Some(Response { code, data });
        }

        None
    }

    // Create the control command to set all currently active async event kinds
    fn active_async_event_kinds(
        handlers: &HashMap<AsyncEventKind, Vec<tokio::sync::mpsc::Sender<Response>>>,
    ) -> Vec<u8> {
        let event_kinds: Vec<&AsyncEventKind> = handlers.keys().collect();
        let mut req = String::from("SETEVENTS");
        for e in event_kinds {
            req.push_str(&format!(" {e}"));
        }
        req.push_str("\r\n");

        req.as_bytes().to_owned()
    }
}

impl Connection {
    // The event loop that is handling async events as well as responses of commands sent
    async fn event_loop(
        mut stream: TcpStream,
        mut command_receiver: tokio::sync::mpsc::Receiver<Message>,
    ) {
        let mut lines = Vec::new();
        let mut buffer = Vec::new();
        let mut handlers = HashMap::new();

        loop {
            // handle either command or receive from stream
            tokio::select! {
                // receive command
                message = command_receiver.recv() => {
                    // write a command to the control stream
                    let sender = Self::handle_command(&mut stream, message.expect("Cannot receive commands anymore: channel closed"), &mut handlers).await;

                    // parse messages until we get sync message
                    let message = Self::parse_until_sync_message(&mut buffer, &mut lines, &mut handlers, &mut stream).await;

                    // return message
                    sender
                        .send(message)
                        .await
                        .expect("Could not return sync response message");
                }
                // receive events
                _len = Self::read_to_buffer(&mut stream, &mut buffer) => {
                    while let Some(response) = Self::parse_message(&mut buffer,&mut lines) {
                        // this should always be async messages
                        if response.code == 650 {
                            // handle async messages
                            if Self::send_async_messages(&mut handlers, response).await {
                                // clean up event subscriptions
                                let cmd = Self::active_async_event_kinds(&handlers);

                                // send message to controller
                                stream
                                    .write_all(&cmd)
                                    .await
                                    .expect("Cannot write to controller");

                                // parse messages until we get sync message
                                let response: Response = Self::parse_until_sync_message(&mut buffer, &mut lines, &mut handlers, &mut stream)
                                    .await
                                    .try_into()
                                    .expect("Could not convert into Response");

                                if response.code != 250 {
                                    warn!("Could not adjust async event registrations: {response:?}");
                                }
                            }
                        }else{
                            // got a sync message
                            warn!("Received a sync message but did not expect one: {response:?}");
                        }
                    }
                }
            }
        }
    }

    // Parse all messages until we get a sync message
    // Because async messages can arrive at any time, we have to handle them as well
    async fn parse_until_sync_message(
        buffer: &mut Vec<u8>,
        lines: &mut Vec<String>,
        handlers: &mut HashMap<AsyncEventKind, Vec<tokio::sync::mpsc::Sender<Response>>>,
        stream: &mut TcpStream,
    ) -> Message {
        // parse messages until we get sync message
        loop {
            let mut message = None;
            while let Some(response) = Self::parse_message(buffer, lines) {
                // check if we got a async message
                if response.code == 650 {
                    // ignore clean ups here - if events are come in regulary we can
                    // handle them in the async section
                    let _ = Self::send_async_messages(handlers, response).await;
                } else {
                    // got sync message
                    message = Some(Message::Response(response.code, response.data));
                }
            }

            // after finishing all messages form the buffer check if we are done
            if let Some(message) = message {
                return message;
            }

            // there is no data left in the buffer and we did not receive sync message yet
            // read into buffer
            let _ = Self::read_to_buffer(stream, buffer).await;
        }
    }

    // Send async messages to the registered event listeners
    // This will return true if its needed to re-register the current event listeners
    async fn send_async_messages(
        handlers: &mut HashMap<AsyncEventKind, Vec<tokio::sync::mpsc::Sender<Response>>>,
        mut response: Response,
    ) -> bool {
        // try to get async-event-kind
        let kind = response.data.first_mut().and_then(|line| {
            line.find(' ').map(|idx| {
                let raw_kind = line.drain(..=idx).collect::<String>();
                AsyncEventKind::from(raw_kind.trim_end())
            })
        });

        if let Some(kind) = kind {
            // get listeners
            let remove = if let Some(senders) = handlers.get_mut(&kind) {
                // this should be fine as we checked previously that data is Ok
                let mut failed = Vec::new();

                // skip first to avoid clone
                for (idx, sender) in senders.iter_mut().enumerate().skip(1) {
                    if let Err(err) = sender.send(response.clone()).await {
                        debug!("Handler error: {err}");
                        failed.push(idx);
                    }
                }

                // send it to first listener
                if let Some(sender) = senders.iter_mut().next() {
                    if let Err(err) = sender.send(response).await {
                        debug!("Handler error: {err}");
                        failed.push(0);
                    }
                }

                // clean closed handlers
                while let Some(idx) = failed.pop() {
                    debug!("Remove handler {kind}:{idx}");
                    let _ = senders.remove(idx);
                }

                // check if we need to refresh our event subscriptions
                senders.is_empty()
            } else {
                // got an event where we do not have a subscription - need to reset events
                warn!("Got unhandled event");
                true
            };

            // clean up
            if remove {
                let _ = handlers.remove(&kind);
                return true;
            }
        } else {
            warn!("Cannot parse async-event-kind from {response:?}");
        }

        false
    }

    // Read new data to the buffer
    // This might panic - but we cannot recover if the control connection is lost!
    async fn read_to_buffer(stream: &mut TcpStream, buffer: &mut Vec<u8>) -> usize {
        match stream.read_buf(buffer).await {
            Ok(0) => panic!("Control connection closed - EOF"),
            Ok(len) => len,
            Err(err) => panic!("Control connection was closed: {err}"),
        }
    }

    // Handle our internal commands we are supporting
    async fn handle_command(
        stream: &mut TcpStream,
        message: Message,
        handlers: &mut HashMap<AsyncEventKind, Vec<tokio::sync::mpsc::Sender<Response>>>,
    ) -> tokio::sync::mpsc::Sender<Message> {
        match message {
            Message::Authenticate(cmd, sender)
            | Message::Raw(cmd, sender)
            | Message::AddOnionService(cmd, sender)
            | Message::DeleteOnionService(cmd, sender) => {
                // send message to controller
                stream
                    .write_all(&cmd)
                    .await
                    .expect("Cannot write to controller");

                sender
            }
            Message::AddEventHandler(kind, sender, event_handler) => {
                // add event handler
                match handlers.get_mut(&kind) {
                    Some(senders) => senders.push(event_handler),
                    None => {
                        handlers.insert(kind, vec![event_handler]);
                    }
                }

                // register events
                let cmd = Self::active_async_event_kinds(handlers);

                // send message to controller
                stream
                    .write_all(&cmd)
                    .await
                    .expect("Cannot write to controller");

                sender
            }
            msg => panic!("Got invalid command message: {msg:?}"),
        }
    }

    // Send a command to the Tor controller
    pub(crate) async fn send(&mut self, command: Message) -> Result<(), Error> {
        self.sender
            .send(command)
            .await
            .map_err(|err| Error::new(ErrorKind::Other, err))
    }

    // Set a new event handler
    pub(crate) async fn add_event_handler(
        &mut self,
        event_kind: AsyncEventKind,
        response_handler: tokio::sync::mpsc::Sender<Message>,
        event_handler: tokio::sync::mpsc::Sender<Response>,
    ) -> Result<(), Error> {
        self.send(Message::AddEventHandler(
            event_kind,
            response_handler,
            event_handler,
        ))
        .await
    }
}

impl Connection {
    // Create a new connection to the Tor control socket
    pub(crate) async fn new(port: u16) -> Result<Connection, Error> {
        let stream = TcpStream::connect(&format!("127.0.0.1:{port}")).await?;

        // create command loop channels
        let (sender, receiver) = tokio::sync::mpsc::channel(1024);

        // spawn event-handler
        let event_handler = tokio::spawn(Connection::event_loop(stream, receiver));

        Ok(Self {
            sender,
            event_handler,
        })
    }

    // Authenticate with the simplest authentication command
    pub(crate) async fn authenticate(&mut self) -> Result<(), Error> {
        let (sender, mut receiver) = tokio::sync::mpsc::channel(1024);
        self.send(Message::Authenticate(b"AUTHENTICATE\r\n".to_vec(), sender))
            .await?;
        let response: Response = match receiver.recv().await {
            Some(result) => result
                .try_into()
                .map_err(|err| Error::new(ErrorKind::Other, err)),
            None => Err(Error::new(ErrorKind::Other, "Event-channel was closed")),
        }?;

        if response.code != 250 {
            return Err(Error::new(
                ErrorKind::Unsupported,
                format!(
                    "Invalid response code {}: {:?}",
                    response.code, response.data
                ),
            ));
        }

        Ok(())
    }
}
