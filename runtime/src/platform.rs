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

//! This module expresses a simple abstraction layer between the trusted host and
//! trusted application it runs. The main goal is to abstract away details of the
//! trusted hosting and support mutiple host implementations. The host implementations
//! differ in their capabilities with some imposing significant restrictions but
//! offering better security and privacy guarantees. Hence the abstraction layer
//! focuses on the most restricted host and assumes restricted kernel.
//!
//! Restricted kernel limits the execution model to processing signals (or rather
//! messages) received from the untrusted launcher over a communication channel. Given
//! this limitation the abstraction layer assumes that the trusted application performs
//! processing in response to the signal from the untrusted launcher which can be
//! either a message or a clock tick. In other words the abstraction layer defines
//! a poll based execution model driven by a signal generating loop in untrusted
//! launcher.
//!
//! [Application] trait must be implemented by a concrete trusted application to
//! receive signals from the trusted host originating from untrusted launcher.
//!
//! [Host] trait must be implemented by a concrete trusted host to expose its capabilities
//! to the trusted application.

use crate::StdError;
use alloc::vec::Vec;
use core::fmt;
use core::result::Result;
use tcp_proto::runtime::endpoint::{InMessage, OutMessage};

// Unrecoverable errors that lead to program termination.
#[derive(Debug, PartialEq)]
pub enum PalError {
    Internal,
    InvalidOperation,
    Raft,
    Actor,
}

impl StdError for PalError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        None
    }
}

impl fmt::Display for PalError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            PalError::Internal => write!(f, "Intern error"),
            PalError::InvalidOperation => write!(f, "Invalid operation"),
            PalError::Actor => write!(f, "Actor unrecoverable error"),
            PalError::Raft => write!(f, "Raft unrecoverable error"),
        }
    }
}

/// Represents a trusted host, abstracting away the details of how trusted
/// application is hosted (e.g. trusted host can be restricted kernel bare
/// metal based encrypted virtual machine or a linux kernel docker based
/// encrypted virtual machine).
pub trait Host {
    /// Sends messages through the communication channel that connects the trusted
    /// application to the untrusted launcher.
    ///
    /// # Argumnets
    ///
    /// * `messages` - A set of messages to send through the channel.
    ///
    /// # Panics
    ///
    /// If the communication channel is irrepairably broken, a success otherise.
    fn send_messages(&mut self, messages: Vec<OutMessage>);

    /// Gets serialized public key used for signing by the trusted application.
    /// The signing key is generated at the start of the trusted application and
    /// remains unchanged through the lifetime.
    ///
    /// # Note
    ///
    /// Public signing key can be used to derive a trusted application identity.
    /// For example, a trusted application that represents a node in Raft cluster
    /// running inside of a group trusted hosts, it is important that Raft node
    /// identity cannot be forged, does not require coordination to pick one and
    /// has low collision chance. Hash of the public signing key is an identity
    /// mechanism that is compliant with these requirements.
    fn public_signing_key(&self) -> Vec<u8>;
}

/// Represents a trusted application running inside a trusted host. The trusted
/// application is considered passive and performs execution in response to
/// receiving messages through the communication channel that connects the trusted
/// application to the untrusted launcher. In the absence of messages to be processed
/// the trusted application will receive periodically empty set of messages to allow
/// trusted application to make progress based on time change.
pub trait Application {
    /// Receives messages to process by the trusted application. Conceptually represents
    /// a computation slice. A set of messages may be empty.
    ///
    /// # Arguments
    ///
    /// * `host` - Trusted host that is responsible the trusted application. Provides
    /// access to message sending and attestation capabilities.
    /// * `instant` - A measurement of a monotonically nondecreasing clock provided by
    /// the untrusted launcher to the trusted host. The resolution of the instant is
    /// mesured in milliseconds. Instants are opaque that can only be compared to one
    /// another. In other words the absolute value must not be interpretted as wall
    /// clock time or time since the trusted application start.
    /// * `opt_message` - A potentially empty message received from the untrusted
    /// launcher for the trusted application to process.
    ///
    /// # Returns
    ///
    /// Error if the trusted application encountered an unrecoverable error and must
    /// be terminated, a success otherwise. The application level recoverable errors
    /// are represented and communicated using messages.
    fn receive_message(
        &mut self,
        host: &mut impl Host,
        instant: u64,
        opt_message: Option<InMessage>,
    ) -> Result<(), PalError>;
}
