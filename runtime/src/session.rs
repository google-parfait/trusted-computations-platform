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

use alloc::boxed::Box;
use alloc::vec::Vec;
use anyhow::Result;
use oak_proto_rust::oak::session::v1::{SessionRequest, SessionResponse};
use oak_session::attestation::AttestationType;
use oak_session::config::SessionConfig;
use oak_session::handshake::HandshakeType;
use oak_session::session::{ClientSession, ServerSession, Session};
use oak_session::ProtocolEngine;

// Factory class for creating instances of `OakClientSession` and `OakServerSession`
// traits.
pub trait OakSessionFactory {
    // Returns OakClientSession, responsible for initiating handshake between 2 raft
    // replicas using Noise protocol.
    fn get_oak_client_session(&self) -> Result<Box<dyn OakClientSession>>;
    // Returns OakServerSession, recipient of the handshake message from the client.
    fn get_oak_server_session(&self) -> Result<Box<dyn OakServerSession>>;
}

/// Session representing an end-to-end encrypted bidirectional streaming session
/// between two raft peers.
pub trait OakSession<I, O> {
    /// Puts a message received from the peer into the state-machine changing
    /// its state.
    fn put_incoming_message(&mut self, incoming_message: &I) -> Result<Option<()>>;

    /// Gets the next message that needs to be sent to the peer.
    fn get_outgoing_message(&mut self) -> Result<Option<O>>;

    /// Checks whether session is ready to send and receive encrypted messages.
    fn is_open(&self) -> bool;

    /// Encrypts `plaintext` and stashes it to be sent to the peer later.
    fn write(&mut self, plaintext: &[u8]) -> Result<()>;

    /// Reads an encrypted message from the peer and decrypts it.
    fn read(&mut self) -> Result<Option<Vec<u8>>>;
}

pub trait OakClientSession = OakSession<SessionResponse, SessionRequest>;
pub trait OakServerSession = OakSession<SessionRequest, SessionResponse>;

// Default implementation of `OakSessionFactory`.
pub struct DefaultOakSessionFactory {}

impl OakSessionFactory for DefaultOakSessionFactory {
    fn get_oak_client_session(&self) -> Result<Box<dyn OakClientSession>> {
        let client_session = DefaultOakClientSession::create()?;
        Ok(Box::new(client_session))
    }

    fn get_oak_server_session(&self) -> Result<Box<dyn OakServerSession>> {
        let server_session = DefaultOakServerSession::create()?;
        Ok(Box::new(server_session))
    }
}

// Default implementation of `OakClientSession`.
pub struct DefaultOakClientSession {
    inner: ClientSession,
}

impl DefaultOakClientSession {
    pub fn create() -> Result<Self> {
        // TODO: Revisit config parameters.
        Ok(Self {
            inner: ClientSession::create(
                SessionConfig::builder(AttestationType::Bidirectional, HandshakeType::NoiseNN)
                    .build(),
            )?,
        })
    }
}

impl OakSession<SessionResponse, SessionRequest> for DefaultOakClientSession {
    fn get_outgoing_message(&mut self) -> Result<Option<SessionRequest>> {
        self.inner.get_outgoing_message()
    }

    fn put_incoming_message(&mut self, incoming_message: &SessionResponse) -> Result<Option<()>> {
        self.inner.put_incoming_message(incoming_message)
    }

    fn is_open(&self) -> bool {
        self.inner.is_open()
    }

    fn write(&mut self, plaintext: &[u8]) -> Result<()> {
        self.inner.write(plaintext)
    }

    fn read(&mut self) -> Result<Option<Vec<u8>>> {
        self.inner.read()
    }
}

// Default implementation of `OakServerSession`.
pub struct DefaultOakServerSession {
    inner: ServerSession,
}

impl DefaultOakServerSession {
    pub fn create() -> Result<Self> {
        Ok(Self {
            inner: ServerSession::new(
                SessionConfig::builder(AttestationType::Bidirectional, HandshakeType::NoiseNN)
                    .build(),
            ),
        })
    }
}

impl OakSession<SessionRequest, SessionResponse> for DefaultOakServerSession {
    fn get_outgoing_message(&mut self) -> Result<Option<SessionResponse>> {
        self.inner.get_outgoing_message()
    }

    fn put_incoming_message(&mut self, incoming_message: &SessionRequest) -> Result<Option<()>> {
        self.inner.put_incoming_message(incoming_message)
    }

    fn is_open(&self) -> bool {
        self.inner.is_open()
    }

    fn write(&mut self, plaintext: &[u8]) -> Result<()> {
        self.inner.write(plaintext)
    }

    fn read(&mut self) -> Result<Option<Vec<u8>>> {
        self.inner.read()
    }
}
