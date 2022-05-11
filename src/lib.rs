use connection::Connection;
use misc::AsyncEventKind;
use rand::thread_rng;
use sha3::{Digest, Sha3_256};
use std::collections::HashSet;
use std::io::{Error, ErrorKind};
use std::net::ToSocketAddrs;

mod connection;
mod misc;

#[cfg(test)]
mod tests;

const TOR_PORT_CONTROL: u16 = 9051;

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
