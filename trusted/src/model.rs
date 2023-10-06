use crate::StdError;
use alloc::boxed::Box;
use alloc::vec::Vec;
use core::fmt;
use core::option::Option;
use core::result::Result;
use slog::Logger;

/// Enumerates actor induced errors. Note that all errors indicate that
/// actor cannot continue to operate and must be terminated.
#[derive(Debug)]
pub enum ActorError {
    /// An internal error.
    Internal,
    /// Failed to load actor configuration.
    ConfigLoading,
    /// Failed to load serialized actor snapshot.
    SnapshotLoading,
}

impl StdError for ActorError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        None
    }
}

impl fmt::Display for ActorError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            ActorError::Internal => write!(f, "Intern error"),
            ActorError::ConfigLoading => write!(f, "Failed to load config"),
            ActorError::SnapshotLoading => write!(f, "Failed to load snapshot"),
        }
    }
}

/// Represents an actor context that acts as a accessor for the underlying
/// consensus module and the trusted host.
pub trait ActorContext {
    /// Gets logger to send entries through the trusted host to the untrusted launcher.
    fn logger(&self) -> &Logger;

    /// Gets the identity of the underyling consensus module node in the consensus
    /// cluster.
    fn id(&self) -> u64;

    /// Gets a measurement of a monotonically nondecreasing clock provided by
    /// the untrusted launcher to the trusted host. The resolution of the instant is
    /// mesured in milliseconds. Instants are opaque that can only be compared to one
    /// another. In other words the absolute value must not be interpretted as wall
    /// clock time or time since the trusted application start.
    fn instant(&self) -> u64;

    /// Gets serialized configuration that stays immutable through the lifetime of
    /// the trusted application.
    fn config(&self) -> Vec<u8>;

    /// Checks if the underlying consensus module is currently executing under leader
    /// role.
    fn leader(&self) -> bool;

    /// Proposes an even to the underlying consensus module for replication. Returns
    /// error if underlying consensus module is not currently executing under leader
    /// role.
    fn propose_event(&mut self, event: Vec<u8>) -> Result<(), ActorError>;

    /// Sends message through the trusted host to the untrusted launcher.
    fn send_message(&mut self, message: Vec<u8>);
}

/// Represents a stateful actor backed by replicated state machine.
pub trait Actor {
    /// Handles actor initialization. If error is returned the actor is considered
    /// in unknown state and is destroyed.
    fn on_init(&mut self, context: Box<dyn ActorContext>) -> Result<(), ActorError>;

    /// Handles actor shutdown. After this method call completes the actor
    /// is destroyed.
    fn on_shutdown(&mut self);

    /// Handles creation of the actor state snapshot. If error is returned the actor
    /// is considered is unknown state and is destroyed.
    fn on_save_snapshot(&mut self) -> Result<Vec<u8>, ActorError>;

    /// Handles restoration of the actor state from snapshot. If error is returned the actor
    /// is considered is unknown state and is destroyed.
    fn on_load_snapshot(&mut self, snapshot: &[u8]) -> Result<(), ActorError>;

    /// Handles processing of command by the actor. Command represents an intent of a
    /// consumer (e.g. request to update staet) and may result in event proposal.
    /// Events are then replicated by the consensus module.
    fn on_process_command(&mut self, command: &[u8]) -> Result<(), ActorError>;

    /// Handles committed events by applying them to the actor state. Event represents
    /// a state transition of the actor and may result in messages being sent to the
    /// consumer (e.g. response to the command that generated this event).
    fn on_apply_event(&mut self, index: u64, event: &[u8]) -> Result<(), ActorError>;
}
