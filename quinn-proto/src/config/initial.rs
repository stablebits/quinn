use std::net::{IpAddr, SocketAddr};

use crate::Instant;

/// Synchronous policy for Initial packets not already routed to a connection.
///
/// Callbacks run in the endpoint receive path, potentially under its lock. They must
/// be cheap, must not block, and must not re-enter the endpoint. They may see repeated
/// Initials. Address validation is not authentication of an application identity.
pub trait InitialFilter: Send + Sync {
    /// Admit a new Initial before token authentication or Initial-key derivation.
    ///
    /// Returning false silently drops it without a response or incoming state.
    /// This applies equally to absent, forged, and valid tokens. Metadata is
    /// unauthenticated. The default imposes no limit; override to bound work with
    /// a global budget. Per-source limits alone do not bound spoofed-source traffic.
    ///
    /// Some admitted Initials never reach [`Self::decide`]: those with a malformed header, and
    /// those carrying a Retry token that decrypts but is invalid for the packet, e.g. expired
    /// or issued for another address. As without a filter, they are refused with an encrypted
    /// CONNECTION_CLOSE, costing Initial-key derivation and a response, so only a budget here
    /// bounds them.
    fn allow_initial(&self, _metadata: &InitialMetadata) -> bool {
        true
    }

    /// Choose a disposition after the token has been decoded and validated, before Initial keys
    /// are derived or incoming state is created.
    ///
    /// A valid NEW_TOKEN has already been recorded in the replay log when this runs, so
    /// returning [`InitialDecision::Ignore`] can use it up: the client's retransmissions carry
    /// the same token, and a replay log that detects the reuse makes them unvalidated.
    ///
    /// Address validation only shows that the client receives packets at its address. Retry
    /// tokens are not single-use: within their lifetime a client can present the same token on
    /// any number of new Initials. Keep a budget on [`InitialDecision::Proceed`], the expensive
    /// path, for validated peers too.
    fn decide(&self, context: &InitialContext) -> InitialDecision;
}

/// Disposition of an admitted Initial.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
#[non_exhaustive]
pub enum InitialDecision {
    /// Continue normal processing and create an Incoming if the packet is valid.
    Proceed,
    /// Silently drop, without Initial keys or incoming state, after token processing.
    Ignore,
}

/// Unauthenticated metadata available before token processing.
#[derive(Debug, Copy, Clone)]
pub struct InitialMetadata {
    pub(crate) remote: SocketAddr,
    pub(crate) local_ip: Option<IpAddr>,
    pub(crate) received_at: Instant,
    pub(crate) datagram_len: usize,
}

impl InitialMetadata {
    /// Source address, which may be spoofed.
    pub fn remote_address(&self) -> SocketAddr {
        self.remote
    }
    /// Destination IP, when reported by the platform.
    pub fn local_ip(&self) -> Option<IpAddr> {
        self.local_ip
    }
    /// Endpoint receive timestamp, suitable for admission budgets.
    pub fn received_at(&self) -> Instant {
        self.received_at
    }
    /// Size of the UDP datagram containing the Initial.
    pub fn datagram_len(&self) -> usize {
        self.datagram_len
    }
}

/// Metadata and token-validation results for an admitted Initial.
#[derive(Debug, Copy, Clone)]
pub struct InitialContext {
    pub(crate) metadata: InitialMetadata,
    pub(crate) validated: bool,
    pub(crate) may_retry: bool,
}

impl InitialContext {
    /// Metadata observed before token validation.
    pub fn metadata(&self) -> &InitialMetadata {
        &self.metadata
    }
    /// Source address of the packet.
    pub fn remote_address(&self) -> SocketAddr {
        self.metadata.remote
    }
    /// Destination IP, when reported by the platform.
    pub fn local_ip(&self) -> Option<IpAddr> {
        self.metadata.local_ip
    }
    /// Whether a token validated the address.
    ///
    /// NEW_TOKEN validates the IP only; Retry tokens bind both IP and port.
    pub fn remote_address_validated(&self) -> bool {
        self.validated
    }
    /// Whether another Retry is permitted (false after a valid Retry token).
    pub fn may_retry(&self) -> bool {
        self.may_retry
    }
}
