use std::fmt::Display;

/// Available async events
///
/// All async events this library supports.
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
