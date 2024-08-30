//! Simple Tor controller to create ephemeral onion services
//!
//! # Usage
//! Create [`Zwuevi`] to connect to the Tor controller.
//! It is assumed that there is already a correctly configured Tor instance running.
//! By default port `9051` is used for the connection.
//!
//! ## Create an ephemeral onion service
//! To create a new onion service it is necessary to create an onion servcie key first by using the
//! function [`Zwuevi::generate_key`].
//! Afterwards the controller can be initialized and the function [`Zwuevi::add_onion_v3`] can be used to
//! create a new onion service.
//! ```
//! use zwuevi::Zwuevi;
//!
//! #[tokio::main]
//! async fn main() {
//!     let key = Zwuevi::generate_key();
//!     let mut zwuevi = Zwuevi::default().await.unwrap();
//!     let onion = zwuevi.add_onion_v3(&key, [(80, ("127.0.0.1", 8000))], None).await.unwrap();
//!     println!("addr: {onion}");
//! }
//! ```
//! The second parameters describing the mapping between a TCP socket and the listening port of the
//! onion service.
//! In this case, `80` refers to the onion service port, which is the standard HTTP port and thus
//! does not need to be defined explicitly when opened in a browser.
//! The second part `("127.0.0.1", 8000)` is the TCP socket running locally on port `8000`.
//!
//! When [`Zwuevi`] gets dropped, all created onion services will be deleted.
//!
//! There is also a simple example `echo-onion` which creates a new onion service and echoing all
//! incoming data back.
//!
//! ## Listen to Tor events
//! Internally [`Zwuevi`] uses asynchronous event listeners to determine the state at the creation
//! of the control connection.
//! This interface is exposed with the [`Zwuevi::add_event_handler`] function which will invoke a given
//! handler each time the specified asynchronous event was fired.
//!
//! The example `debug-logs` shows how it can be used to listen for debug log entries of Tor.
//!
//! ## Send raw control commands
//! It's also possible to send control commands directly to the control connection.
//! The function [`Zwuevi::raw_command`] will take any character sequence and return the response from Tor.
//!
//! # Panics
//! If the connection to the controller socket gets interrupted the controller will panic.
use base64::Engine;
use connection::Connection;
use log::{debug, info, warn};
use misc::Message;
use rand::thread_rng;
use sha3::{Digest, Sha3_256};
use std::collections::HashSet;
use std::io::{Error, ErrorKind};
use std::net::ToSocketAddrs;

mod connection;
mod misc;

pub use misc::{AsyncEventHandle, AsyncEventKind, Response};

#[cfg(test)]
mod tests;

// Standard Tor control port
const TOR_PORT_CONTROL: u16 = 9051;

// Wait for all uploads to be confirmed
const UPLOAD_CONFIRMATIONS: usize = 5;

// Maximum events queued
const EVENT_QUEUE_SIZE: usize = 1024;

/// Tor controller
///
/// Create a Tor control connection and handle async events.
pub struct Zwuevi {
    sender: tokio::sync::mpsc::Sender<Message>,
    receiver: tokio::sync::mpsc::Receiver<Message>,
    connection: Connection,
}

impl Zwuevi {
    /// Create a new control connection to the default Tor control port `9051`
    ///
    /// After successful connecting to the control socket, it will block until Tor is ready to be
    /// used.
    ///
    /// # Errors
    /// This will return an Error if it cannot establish a connection to a running Tor instance or
    /// Tor cannot connect to the network.
    pub async fn default() -> Result<Zwuevi, Error> {
        Self::new(TOR_PORT_CONTROL).await
    }

    /// Create a new control connection to a non-standard port
    ///
    /// This will return an error if the connection cannot be established a connection to the Tor
    /// control port.
    ///
    /// # Arguments
    ///  * `control_port` - Control port of the running Tor instance
    ///
    /// # Errors
    /// If no connection can be established this will return an Error.
    ///
    /// # Example:
    /// ```
    /// use zwuevi::Zwuevi;
    ///
    /// #[tokio::main]
    /// async fn main() {
    ///     let _zwuevi = Zwuevi::new(9051).await.unwrap();
    /// }
    /// ```
    pub async fn new(control_port: u16) -> Result<Zwuevi, Error> {
        let mut connection = Connection::new(control_port).await?;

        // authenticate
        connection.authenticate().await?;
        let (sender, receiver) = tokio::sync::mpsc::channel(1024);
        let mut zwuevi = Self {
            sender,
            receiver,
            connection,
        };

        // listen on status-changes before we check status so we don't miss anything until we are
        // connected to the Tor network
        let (tx, mut rx) = tokio::sync::mpsc::channel(EVENT_QUEUE_SIZE);
        zwuevi
            .connection
            .add_event_handler(AsyncEventKind::StatusClient, zwuevi.sender.clone(), tx)
            .await?;

        let response = zwuevi.receive().await?;
        if response.code != 250 {
            return Err(Error::new(
                ErrorKind::Unsupported,
                format!(
                    "Invalid response code {}: {:?}",
                    response.code, response.data
                ),
            ));
        }

        // check if we are dormant and change it if we can
        if !zwuevi
            .raw_command("GETINFO dormant")
            .await
            .map(|response| {
                response
                    .data
                    .into_iter()
                    .any(|line| line.contains("dormant=0"))
            })?
        {
            warn!("Tor is currently dormant - try to activate Tor again");
            warn!("THIS MIGHT NOT WORK");
            let _ = zwuevi.raw_command("SIGNAL active").await?;
        }

        // check if we already have an established connection
        if zwuevi
            .raw_command("GETINFO status/circuit-established")
            .await
            .map(|response| {
                response
                    .data
                    .into_iter()
                    .any(|line| line.contains("circuit-established=0"))
            })?
        {
            // loop until we get `CIRCUIT_ESTABLISHED` from the events
            while match rx.recv().await {
                Some(output) => !std::convert::TryInto::<Response>::try_into(output)
                    .map_err(|err| {
                        Error::new(
                            ErrorKind::Other,
                            format!("Could not convert Message into Response: {err}"),
                        )
                    })?
                    .data
                    .into_iter()
                    .any(|line| line.contains("CIRCUIT_ESTABLISHED")),
                _ => true,
            } {
                info!("Waiting for Tor to establish a connection");
            }
        }

        Ok(zwuevi)
    }

    /// Add `AsyncEventKind` handler
    ///
    /// Creates a new event handler that receive the specified event kind.
    /// Returns a handle on success which terminates the event listening if it gets dropped.
    ///
    /// # Errors
    /// This will return an error if the event handler cannot be registered.
    ///
    /// # Example
    /// ```
    /// use zwuevi::Zwuevi;
    /// use zwuevi::AsyncEventKind;
    ///
    /// #[tokio::main]
    /// async fn main() {
    ///     let mut zwuevi = Zwuevi::default().await.unwrap();
    ///     // register event handler
    ///     let handle = zwuevi.add_event_handler(AsyncEventKind::LogMessagesDebug,
    ///         |event| event.into_iter().for_each(|line| println!("{line}"))
    ///     )
    ///     .await
    ///     .unwrap();
    ///
    ///     // drop handle to remove event-handler
    ///     drop(handle);
    /// }
    /// ```
    pub async fn add_event_handler(
        &mut self,
        event_kind: AsyncEventKind,
        func: impl Fn(Vec<String>) + Send + 'static,
    ) -> Result<AsyncEventHandle, Error> {
        let (tx, mut rx) = tokio::sync::mpsc::channel(EVENT_QUEUE_SIZE);
        self.connection
            .add_event_handler(event_kind, self.sender.clone(), tx)
            .await?;

        let response = self.receive().await?;
        if response.code != 250 {
            return Err(Error::new(
                ErrorKind::Unsupported,
                format!(
                    "Invalid response code {}: {:?}",
                    response.code, response.data
                ),
            ));
        }

        let handle = tokio::spawn(async move {
            while let Some(response) = rx.recv().await {
                (func)(response.data);
            }
        });

        Ok(AsyncEventHandle::from(handle))
    }

    /// Send raw command to the Tor controller
    ///
    /// The command will not be validated.
    /// On success, the return value contains the response message as a `Response` which includes
    /// the response code and the returned data per line.
    ///
    /// # Arguments
    ///  * `command` - Raw command
    ///
    /// # Errors
    /// This will return an error if it cannot send the command to the control connection.
    ///
    /// # Example:
    /// ```
    /// use zwuevi::Zwuevi;
    ///
    /// #[tokio::main]
    /// async fn main() {
    ///     let mut zwuevi = Zwuevi::default().await.unwrap();
    ///     let response = zwuevi.raw_command("GETINFO version")
    ///     .await
    ///     .unwrap();
    ///
    ///     assert!(response.code == 250);
    ///     println!("version: {:?}", response.data.first().unwrap().split_once('=').unwrap().1);
    /// }
    /// ```
    pub async fn raw_command(&mut self, command: &str) -> Result<Response, Error> {
        self.send(Message::Raw(
            format!("{command}\r\n").into(),
            self.sender.clone(),
        ))
        .await?;

        self.receive().await
    }

    /// Create a new onion service
    ///
    /// This will create a new v3 onion service with an existing secret key.
    /// On success, the onion address will be returned without the `.onion`.
    ///
    /// # Arguments
    ///  * `secret_key` - The secret key of the onion service
    ///  * `listeners` - List of listeners the onion service can connect to
    ///  * `flags` - Optional additional flags
    ///
    /// # Errors
    /// This will return an error if the new onion service could not be created.
    ///
    /// # Example:
    /// ```
    /// use zwuevi::Zwuevi;
    ///
    /// #[tokio::main]
    /// async fn main() {
    ///     let mut zwuevi = Zwuevi::default().await.unwrap();
    ///     let addr = zwuevi.add_onion_v3(&Zwuevi::generate_key(), [(80, ("127.0.0.1", 3000))], None)
    ///     .await
    ///     .unwrap();
    ///     println!("{addr}.onion");
    /// }
    /// ```
    pub async fn add_onion_v3<S: ToSocketAddrs, I: IntoIterator<Item = (u16, S)>>(
        &mut self,
        secret_key: &[u8; 32],
        listeners: I,
        flags: Option<Vec<&str>>,
    ) -> Result<String, Error> {
        // prepare parameters
        let sk = *secret_key as ed25519_dalek::SecretKey;
        let esk = ed25519_dalek::hazmat::ExpandedSecretKey::from(&sk);
        let esk = [esk.scalar.to_bytes(), esk.hash_prefix].concat();

        let addr = Self::get_onion_address(&Self::get_public_key(secret_key)?);
        let mut command = format!(
            "ADD_ONION ED25519-V3:{} ",
            base64::prelude::BASE64_STANDARD.encode(esk)
        );

        if let Some(flags) = flags {
            if !flags.is_empty() {
                command.push_str(&format!("Flags={} ", &flags.join(",")));
            }
        }

        // check listeners
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
            let addr = address.to_socket_addrs()?.next().ok_or_else(|| {
                Error::new(ErrorKind::Other, "Could not parse valid socket address")
            })?;
            command.push_str(&format!("Port={port},{addr}"));
        }

        // assert that there is at least one listener
        if service_listeners.is_empty() {
            return Err(Error::new(
                ErrorKind::Unsupported,
                "Invalid listener specification",
            ));
        }
        command.push_str("\r\n");

        // wait until service is published
        let (tx, mut rx) = tokio::sync::mpsc::channel(EVENT_QUEUE_SIZE);
        self.send(Message::AddEventHandler(
            AsyncEventKind::HiddenServiceDescriptors,
            self.sender.clone(),
            tx,
        ))
        .await?;

        // check if the response was successful
        let response = self.receive().await?;
        if response.code != 250 {
            return Err(Error::new(
                ErrorKind::Unsupported,
                format!(
                    "Invalid response code {}: {:?}",
                    response.code, response.data
                ),
            ));
        }

        // create service
        self.send(Message::AddOnionService(
            command.into(),
            self.sender.clone(),
        ))
        .await?;

        // check if the response was successful
        let response = self.receive().await?;
        if response.code != 250 {
            return Err(Error::new(
                ErrorKind::Unsupported,
                format!(
                    "Invalid response code {}: {:?}",
                    response.code, response.data
                ),
            ));
        }

        // loop until we get all required uploads
        let mut uploads = 0;
        while uploads < UPLOAD_CONFIRMATIONS {
            debug!("Got {uploads} confirmations");
            if let Some(response) = rx.recv().await {
                if response.code == 650
                    && response
                        .data
                        .into_iter()
                        .any(|line| line.contains("UPLOADED") && line.contains(&addr))
                {
                    uploads += 1;
                }
            } else {
                return Err(Error::new(
                    ErrorKind::UnexpectedEof,
                    "Cannot receive any more confirmation events because channel was closed",
                ));
            }
        }

        // return the onion address
        Ok(addr)
    }

    /// Delete an onion service
    ///
    /// This will remove an existing onino service.
    ///
    /// # Arguments
    ///  * `onion_address` - Onion address with or without '.onion'
    ///
    /// # Errors
    /// This will return an error if the onion service could not be deleted.
    pub async fn delete_onion(&mut self, onion_address: &str) -> Result<(), Error> {
        let onion_address = onion_address.trim_end_matches(".onion");
        if !onion_address.chars().all(|c| {
            // limit to safe chars, so there is no injection
            matches!(c, 'a'..='z' | 'A'..='Z' | '2'..='7' )
        }) {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "Wrong characters in onion address",
            ));
        }
        self.send(Message::DeleteOnionService(
            format!("DEL_ONION {onion_address}\r\n").into(),
            self.sender.clone(),
        ))
        .await?;

        // check if response was successful
        let response = self.receive().await?;
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

    /// Get the public key from the secret key
    ///
    /// This will return the public key from the given secret key.
    ///
    /// # Arguments
    ///  * `secret_key` - Secret key from an onion service
    ///
    /// # Errors
    /// This will return an error if the key is invalid.
    pub fn get_public_key(secret_key: &[u8; 32]) -> Result<[u8; 32], Error> {
        let sk = ed25519_dalek::SigningKey::from_bytes(secret_key);
        let pk = ed25519_dalek::VerifyingKey::from(&sk);

        Ok(pk.to_bytes())
    }

    /// Return the onion address from an onion service
    ///
    /// Create the onion address from the public key of an onion service.
    /// There is no validation check if the public key is valid.
    pub fn get_onion_address(public_key: &[u8; 32]) -> String {
        let mut buf = [0u8; 35];
        public_key.iter().copied().enumerate().for_each(|(i, b)| {
            buf[i] = b;
        });

        let mut h = Sha3_256::new();
        h.update(b".onion checksum");
        h.update(public_key);
        h.update(b"\x03");

        let res_vec = h.finalize().to_vec();
        buf[32] = res_vec[0];
        buf[33] = res_vec[1];
        buf[34] = 3;

        base32::encode(base32::Alphabet::Rfc4648 { padding: false }, &buf).to_ascii_lowercase()
    }

    /// Generate a new onion service key
    ///
    /// Return a fresh secret key for a new onion service.
    pub fn generate_key() -> [u8; 32] {
        let sk = ed25519_dalek::SigningKey::generate(&mut thread_rng());
        sk.to_bytes()
    }

    // Recieve a response from the Tor controller after a command was pushed
    async fn receive(&mut self) -> Result<Response, Error> {
        match self.receiver.recv().await {
            Some(result) => result
                .try_into()
                .map_err(|err| Error::new(ErrorKind::Other, err)),
            None => Err(Error::new(ErrorKind::Other, "Event-channel was closed")),
        }
    }

    // Send a command to the Tor controller
    async fn send(&mut self, command: Message) -> Result<(), Error> {
        self.connection
            .send(command)
            .await
            .map_err(|err| Error::new(ErrorKind::Other, err))
    }
}
