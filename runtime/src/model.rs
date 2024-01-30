// Copyright 2024 The Trusted Computations Platform Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use crate::StdError;
use alloc::boxed::Box;
use core::fmt;
use core::option::Option;
use core::result::Result;
use prost::bytes::Bytes;
use slog::Logger;

/// Enumerates actor induced errors. Note that all errors indicate that
/// actor cannot continue to operate and must be terminated.
#[derive(Debug, PartialEq)]
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
    fn config(&self) -> Bytes;

    /// Checks if the underlying consensus module is currently executing under leader
    /// role.
    fn leader(&self) -> bool;
}

// Represents an outcome of command processing.
pub enum CommandOutcome {
    // Command has been processed immediately and resulted in serialized response.
    Response(Bytes),

    // Command will be processed once the serialized event is committed and applied.
    Event(Bytes),
}

// Represents an outcome of event application.
pub enum EventOutcome {
    // Response to the send to the consumer after event has been applied to the actor.
    Response(Bytes),

    // Nothing to send.
    None,
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
    fn on_save_snapshot(&mut self) -> Result<Bytes, ActorError>;

    /// Handles restoration of the actor state from snapshot. If error is returned the actor
    /// is considered is unknown state and is destroyed.
    fn on_load_snapshot(&mut self, snapshot: Bytes) -> Result<(), ActorError>;

    /// Handles processing of a command by the actor. Command represents an intent of a
    /// consumer (e.g. request to update actor state). The command processing logic may
    /// decide to immediately respond (e.g. the command validation failed and cannot be
    /// executed) or to propose an event for replication by the consensus module (e.g. the
    /// event to update actor state once replicated).
    fn on_process_command(&mut self, command: Bytes) -> Result<CommandOutcome, ActorError>;

    /// Handles committed events by applying them to the actor state. Event represents
    /// a state transition of the actor and may result in messages being sent to the
    /// consumer (e.g. response to the command that generated this event).
    fn on_apply_event(&mut self, index: u64, event: Bytes) -> Result<EventOutcome, ActorError>;
}
