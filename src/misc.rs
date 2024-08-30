use std::fmt::Display;

/// Sync response from sending a command to the control socket
#[derive(Debug, Clone)]
pub struct Response {
    /// Response code
    pub code: u16,
    /// Responded data parsed by line
    pub data: Vec<String>,
}

// Internal messages to send commands to control connection as well as handling the response
// messages
#[derive(Debug)]
pub(crate) enum Message {
    // Authentication request
    Authenticate(Vec<u8>, tokio::sync::mpsc::Sender<Message>),
    // Raw command
    Raw(Vec<u8>, tokio::sync::mpsc::Sender<Message>),
    // Add async event handler
    AddEventHandler(
        AsyncEventKind,
        tokio::sync::mpsc::Sender<Message>,
        tokio::sync::mpsc::Sender<Response>,
    ),
    // New onion service
    AddOnionService(Vec<u8>, tokio::sync::mpsc::Sender<Message>),
    // Delete onion service
    DeleteOnionService(Vec<u8>, tokio::sync::mpsc::Sender<Message>),
    // Response message from control connection
    Response(u16, Vec<String>),
}

impl TryInto<Response> for Message {
    type Error = std::io::Error;

    fn try_into(self) -> Result<Response, Self::Error> {
        match self {
            Message::Response(code, data) => Ok(Response { code, data }),
            msg => Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("cannot convert to a response: {msg:?}"),
            )),
        }
    }
}

/// Async event handle
///
/// As long as this handle exists, it's associated `AsyncEventKind`'s are handled.
pub struct AsyncEventHandle {
    handle: tokio::task::JoinHandle<()>,
}

impl Drop for AsyncEventHandle {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

impl From<tokio::task::JoinHandle<()>> for AsyncEventHandle {
    fn from(handle: tokio::task::JoinHandle<()>) -> Self {
        Self { handle }
    }
}

/// Available async events
///
/// All async events this library supports.
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub enum AsyncEventKind {
    CircuitStatusChanged,
    StreamStatusChanged,
    ConnectionStatusChanged,
    BandwidthUsedInTheLastSecond,
    LogMessagesDebug,
    LogMessagesInfo,
    LogMessagesNotice,
    LogMessagesWarn,
    LogMessagesErr,
    NewDescriptorsAvailable,
    NewAddressMapping,
    DescriptorsUploadedToUsInOurRoleAsAuthoritativeServer,
    OurDescriptorChanged,
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
    Unknown,
}

impl From<&str> for AsyncEventKind {
    fn from(event: &str) -> Self {
        match event {
            "CIRC" => AsyncEventKind::CircuitStatusChanged,
            "STREAM" => AsyncEventKind::StreamStatusChanged,
            "ORCONN" => AsyncEventKind::ConnectionStatusChanged,
            "BW" => AsyncEventKind::BandwidthUsedInTheLastSecond,
            "DEBUG" => AsyncEventKind::LogMessagesDebug,
            "INFO" => AsyncEventKind::LogMessagesInfo,
            "NOTICE" => AsyncEventKind::LogMessagesNotice,
            "WARN" => AsyncEventKind::LogMessagesWarn,
            "ERR" => AsyncEventKind::LogMessagesErr,
            "NEWDESC" => AsyncEventKind::NewDescriptorsAvailable,
            "ADDRMAP" => AsyncEventKind::NewAddressMapping,
            "AUTHDIR_NEWDESCS" => {
                AsyncEventKind::DescriptorsUploadedToUsInOurRoleAsAuthoritativeServer
            }
            "DESCCHANGED" => AsyncEventKind::OurDescriptorChanged,
            "STATUS_GENERAL" => AsyncEventKind::StatusGeneral,
            "STATUS_CLIENT" => AsyncEventKind::StatusClient,
            "STATUS_SERVER" => AsyncEventKind::StatusServer,
            "GUARD" => AsyncEventKind::OurSetOfGuardNodesHasChanged,
            "NS" => AsyncEventKind::NetworkStatusHasChanged,
            "STREAM_BW" => AsyncEventKind::BandwidthUsedOnApplicationStream,
            "CLIENTS_SEEN" => AsyncEventKind::PerCountryClientStats,
            "NEWCONSENSUS" => AsyncEventKind::NewConsensusNetworkStatusHasArrived,
            "BUILDTIMEOUT_SET" => AsyncEventKind::NewCircuitBuildTimeHasBeenSet,
            "SIGNAL" => AsyncEventKind::SignalReceived,
            "CONF_CHANGED" => AsyncEventKind::ConfigurationChanged,
            "CIRC_MINOR" => AsyncEventKind::CircuitStatusChangedSlightly,
            "TRANSPORT_LAUNCHED" => AsyncEventKind::PluggableTransportLaunched,
            "CONN_BW" => AsyncEventKind::BandwidthUsedOnOROrDirOrExitConnection,
            "CIRC_BW" => AsyncEventKind::BandwidthUsedByAllStreamsAttachedToACircuit,
            "CELL_STATS" => AsyncEventKind::PerCircuitCellStatus,
            "TB_EMPTY" => AsyncEventKind::TokenBucketsRefilled,
            "HS_DESC" => AsyncEventKind::HiddenServiceDescriptors,
            "HS_DESC_CONTENT" => AsyncEventKind::HiddenServiceDescriptorsContent,
            "NETWORK_LIVENESS" => AsyncEventKind::NetworkLivenessHasChanged,
            "PT_LOG" => AsyncEventKind::PluggableTransportLogs,
            "PT_STATUS" => AsyncEventKind::PluggableTransportStatus,

            _ => AsyncEventKind::Unknown,
        }
    }
}

impl Display for AsyncEventKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let event = match self {
            AsyncEventKind::CircuitStatusChanged => "CIRC",
            AsyncEventKind::StreamStatusChanged => "STREAM",
            AsyncEventKind::ConnectionStatusChanged => "ORCONN",
            AsyncEventKind::BandwidthUsedInTheLastSecond => "BW",
            AsyncEventKind::LogMessagesDebug => "DEBUG",
            AsyncEventKind::LogMessagesInfo => "INFO",
            AsyncEventKind::LogMessagesNotice => "NOTICE",
            AsyncEventKind::LogMessagesWarn => "WARN",
            AsyncEventKind::LogMessagesErr => "ERR",
            AsyncEventKind::NewDescriptorsAvailable => "NEWDESC",
            AsyncEventKind::NewAddressMapping => "ADDRMAP",
            AsyncEventKind::DescriptorsUploadedToUsInOurRoleAsAuthoritativeServer => {
                "AUTHDIR_NEWDESCS"
            }
            AsyncEventKind::OurDescriptorChanged => "DESCCHANGED",
            AsyncEventKind::StatusGeneral => "STATUS_GENERAL",
            AsyncEventKind::StatusClient => "STATUS_CLIENT",
            AsyncEventKind::StatusServer => "STATUS_SERVER",
            AsyncEventKind::OurSetOfGuardNodesHasChanged => "GUARD",
            AsyncEventKind::NetworkStatusHasChanged => "NS",
            AsyncEventKind::BandwidthUsedOnApplicationStream => "STREAM_BW",
            AsyncEventKind::PerCountryClientStats => "CLIENTS_SEEN",
            AsyncEventKind::NewConsensusNetworkStatusHasArrived => "NEWCONSENSUS",
            AsyncEventKind::NewCircuitBuildTimeHasBeenSet => "BUILDTIMEOUT_SET",
            AsyncEventKind::SignalReceived => "SIGNAL",
            AsyncEventKind::ConfigurationChanged => "CONF_CHANGED",
            AsyncEventKind::CircuitStatusChangedSlightly => "CIRC_MINOR",
            AsyncEventKind::PluggableTransportLaunched => "TRANSPORT_LAUNCHED",
            AsyncEventKind::BandwidthUsedOnOROrDirOrExitConnection => "CONN_BW",
            AsyncEventKind::BandwidthUsedByAllStreamsAttachedToACircuit => "CIRC_BW",
            AsyncEventKind::PerCircuitCellStatus => "CELL_STATS",
            AsyncEventKind::TokenBucketsRefilled => "TB_EMPTY",
            AsyncEventKind::HiddenServiceDescriptors => "HS_DESC",
            AsyncEventKind::HiddenServiceDescriptorsContent => "HS_DESC_CONTENT",
            AsyncEventKind::NetworkLivenessHasChanged => "NETWORK_LIVENESS",
            AsyncEventKind::PluggableTransportLogs => "PT_LOG",
            AsyncEventKind::PluggableTransportStatus => "PT_STATUS",

            AsyncEventKind::Unknown => "UNKNOWN",
        };

        f.write_str(event)
    }
}
