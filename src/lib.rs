use connection::{Connection, EventHandler};
use rand::thread_rng;
use sha3::{Digest, Sha3_256};
use std::collections::HashSet;
use std::io::{Error, ErrorKind};
use std::net::ToSocketAddrs;

mod connection;
mod misc;

pub use misc::AsyncEventKind;

#[cfg(test)]
mod tests;

// Standard TOR control port
const TOR_PORT_CONTROL: u16 = 9051;

/// TOR controller
///
/// Create a TOR control connection and handle async events.
pub struct Zwuevi {
    connection: Connection,
}

impl Zwuevi {
    /// Create a new control connection to the default TOR control port `9051`
    ///
    /// After successful connection to the control port, it will wait until TOR is ready.
    /// Returns an error if there cannot be established a connection to the TOR control port.
    pub async fn default() -> Result<Zwuevi, Error> {
        let mut connection = Connection::new(TOR_PORT_CONTROL, None).await?;

        // authenticate
        connection.authenticate().await?;
        connection.wait_until_ready().await?;

        Ok(Self { connection })
    }

    /// Create a new control connection to a non-standard port
    ///
    /// This will return an error if there cannot be established a connection to the TOR control
    /// port.
    ///
    /// # Arguments
    ///  * `control_port` - Control port of the running TOR instance
    ///  * `event_handler` - If provided, hold the event handler for async events
    ///
    /// # Example:
    /// ```
    /// use zwuevi::Zwuevi;
    ///
    /// #[tokio::main]
    /// async fn main() {
    ///     let _ = Zwuevi::new(
    ///         9051,
    ///         Some(&|result| match result {
    ///             Ok((event, _lines)) => print!("{}", event),
    ///             Err(err) => eprintln!("error: {}", err),
    ///         }),
    ///     )
    ///     .await
    ///     .unwrap();
    /// }
    /// ```
    pub async fn new(
        control_port: u16,
        event_handler: Option<EventHandler>,
    ) -> Result<Zwuevi, Error> {
        let mut connection = Connection::new(control_port, event_handler).await?;

        // authenticate
        connection.authenticate().await?;

        Ok(Self { connection })
    }

    /// Set `AsyncEventKind`
    ///
    /// This should only fail if the control connection fails.
    ///
    /// # Arguments
    ///  * `async_events` - All asnyc events the controller will listen to
    pub async fn set_events(
        &mut self,
        async_events: impl IntoIterator<Item = AsyncEventKind>,
    ) -> Result<(), Error> {
        let mut req = String::from("SETEVENTS");
        for e in async_events {
            req.push_str(&format!(" {}", e));
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

    /// Set an event handler for async events
    ///
    /// Will replace an existing event handler if any.
    /// This should never fail.
    ///
    /// # Arguments
    ///  * `event_handler` - Async event handler
    ///
    /// # Example:
    /// ```
    /// use zwuevi::Zwuevi;
    ///
    /// #[tokio::main]
    /// async fn main() {
    ///     let mut zwuevi = Zwuevi::default().await.unwrap();
    ///     zwuevi.set_event_handler(
    ///         &|result| match result {
    ///             Ok((event, _lines)) => print!("{}", event),
    ///             Err(err) => eprintln!("error: {}", err),
    ///         },
    ///     )
    ///     .await
    ///     .unwrap();
    /// }
    /// ```
    pub async fn set_event_handler(&mut self, event_handler: EventHandler) -> Result<(), Error> {
        self.connection.set_event_handler(event_handler).await
    }

    /// Remove an existing event handler
    ///
    /// This should never fail.
    pub async fn remove_event_handler(&mut self) -> Result<(), Error> {
        self.connection.remove_event_handler().await
    }

    /// Send raw command to the TOR controller
    ///
    /// The command will not be validated.
    /// On success, the return value contains the response lines, error description otherwise.
    ///
    /// # Arguments
    ///  * `command` - Raw command
    ///
    /// # Example:
    /// ```
    /// use zwuevi::Zwuevi;
    ///
    /// #[tokio::main]
    /// async fn main() {
    ///     let mut zwuevi = Zwuevi::default().await.unwrap();
    ///     let version = zwuevi.raw_command("GETINFO version")
    ///     .await
    ///     .unwrap();
    ///
    ///     println!("{:?}", version.first().unwrap().split_once('=').unwrap().1);
    /// }
    /// ```
    pub async fn raw_command(&mut self, command: &str) -> Result<Vec<String>, Error> {
        self.connection
            .write(format!("{}\r\n", command).as_bytes())
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
    /// # Example:
    /// ```
    /// use zwuevi::Zwuevi;
    ///
    /// #[tokio::main]
    /// async fn main() {
    ///     let mut zwuevi = Zwuevi::default().await.unwrap();
    ///     zwuevi.add_onion_v3(&Zwuevi::generate_key(), [(80, ("127.0.0.1", 3000))], None)
    ///     .await
    ///     .unwrap();
    /// }
    /// ```
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
            let addr = address.to_socket_addrs()?.next().ok_or_else(|| {
                Error::new(ErrorKind::Other, "Could not parse valid socket address")
            })?;
            command.push_str(&format!("Port={},{}", port, addr));
        }

        // assert that there is at least one listener
        if service_listeners.is_empty() {
            return Err(Error::new(
                ErrorKind::Unsupported,
                "Invalid listener specification",
            ));
        }
        command.push_str("\r\n");

        self.connection.write(command.as_bytes()).await?;

        // check if the response was successful
        let (code, _) = self.connection.receive().await?;
        if code != 250 {
            return Err(Error::new(
                ErrorKind::Unsupported,
                format!("Invalid response code: {}", code),
            ));
        }

        // return the onion address
        Ok(Self::get_onion_address(&Self::get_public_key(secret_key)?))
    }

    /// Delete an onion service
    ///
    /// This will remove an existing onino service.
    ///
    /// # Arguments
    ///  * `onion_address` - Onion address without `.onion`
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

        // check if response was successful
        let (code, _) = self.connection.receive().await?;
        if code != 250 {
            return Err(Error::new(
                ErrorKind::Unsupported,
                format!("Invalid response code: {}", code),
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
    pub fn get_public_key(secret_key: &[u8; 32]) -> Result<[u8; 32], Error> {
        let sk = ed25519_dalek::SecretKey::from_bytes(secret_key)
            .map_err(|err| Error::new(ErrorKind::Other, err))?;
        let pk = ed25519_dalek::PublicKey::from(&sk);

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
        h.update(&public_key);
        h.update(b"\x03");

        let res_vec = h.finalize().to_vec();
        buf[32] = res_vec[0];
        buf[33] = res_vec[1];
        buf[34] = 3;

        base32::encode(base32::Alphabet::RFC4648 { padding: false }, &buf).to_ascii_lowercase()
    }

    /// Generate a new onion service key
    ///
    /// Return a fresh secret key for a new onion service.
    pub fn generate_key() -> [u8; 32] {
        let sk = ed25519_dalek::SecretKey::generate(&mut thread_rng());
        sk.to_bytes()
    }
}
