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
use alloc::vec;
use alloc::vec::Vec;
use core::fmt;
use core::option::Option;
use core::result::Result;
use prost::bytes::Bytes;
use prost::Message;
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

/// Represents an application level command sent to or from an actor. Command is split
/// into lightweight unencrypted header and typically more heavyweight encrypted payload.
/// Command header is deserialized by actor or untrusted host to decide how to process
/// the command. Command payload processing depends on the command header contents.
#[derive(Default, PartialEq, Debug, Clone)]
pub struct ActorCommand {
    // Correlation id that actor may use to match request and response commands.
    pub correlation_id: u64,

    /// Serialized but not encrypted contents of the application command header.
    pub header: Bytes,

    /// Serialized and encrypted payload of the application command.
    pub payload: Bytes,
}

impl ActorCommand {
    /// Creates actor message with only header populated with the serialized proto.
    pub fn with_header<H: Message + Sized>(correlation_id: u64, header: &H) -> ActorCommand {
        ActorCommand {
            correlation_id,
            header: header.encode_to_vec().into(),
            payload: Bytes::new(),
        }
    }
}

/// Represents an application level replicated event.
#[derive(Default, PartialEq, Debug, Clone)]
pub struct ActorEvent {
    pub correlation_id: u64,

    /// Serialized contents of the event.
    pub contents: Bytes,
}

impl ActorEvent {
    pub fn with_bytes(correlation_id: u64, contents: Bytes) -> Self {
        ActorEvent {
            correlation_id,
            contents,
        }
    }

    pub fn with_proto<E: Message + Sized>(correlation_id: u64, proto: &E) -> Self {
        ActorEvent {
            correlation_id,
            contents: proto.encode_to_vec().into(),
        }
    }
}

/// Represents an outcome of application command processing, which may result
/// in a number of application commands requested to be sent out and an event
/// requested to be replicated.
#[derive(Default, PartialEq, Debug, Clone)]
pub struct CommandOutcome {
    /// Application messages that are requested to be sent out.
    pub commands: Vec<ActorCommand>,
    /// Event that is requested to be replicated.
    pub event: Option<ActorEvent>,
}

impl CommandOutcome {
    /// Creates an outcome with a single command to be sent out.
    pub fn with_command(command: ActorCommand) -> CommandOutcome {
        CommandOutcome {
            commands: vec![command],
            event: None,
        }
    }

    /// Creates an outcome with an event to be replicated.
    pub fn with_event(event: ActorEvent) -> CommandOutcome {
        CommandOutcome {
            commands: vec![],
            event: Some(event),
        }
    }

    /// Creates an outcome with a single command to be sent out and an event to be replicated.
    pub fn with_message_and_event(command: ActorCommand, event: ActorEvent) -> CommandOutcome {
        CommandOutcome {
            commands: vec![command],
            event: Some(event),
        }
    }
}

/// Represents an outcome of replicated event processing, which may result
/// in a number of application commands requested to be sent out.
#[derive(Default, PartialEq)]
pub struct EventOutcome {
    /// Application messages that are requested to be sent out.
    pub commands: Vec<ActorCommand>,
}

impl EventOutcome {
    /// Creates an outcome with no commands to be sent out.
    pub fn with_none() -> EventOutcome {
        EventOutcome::default()
    }

    /// Creates an outcome with a single command to be sent out.
    pub fn with_command(command: ActorCommand) -> EventOutcome {
        EventOutcome {
            commands: vec![command],
        }
    }

    /// Creates an outcome with a number of commands to be sent out.
    pub fn with_commands(commands: Vec<ActorCommand>) -> EventOutcome {
        EventOutcome { commands }
    }
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
    fn on_process_command(&mut self, command: ActorCommand) -> Result<CommandOutcome, ActorError>;

    /// Handles committed events by applying them to the actor state. Event represents
    /// a state transition of the actor and may result in messages being sent to the
    /// consumer (e.g. response to the command that generated this event).
    fn on_apply_event(&mut self, index: u64, event: ActorEvent)
        -> Result<EventOutcome, ActorError>;
}
