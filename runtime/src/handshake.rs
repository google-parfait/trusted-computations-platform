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

use crate::platform::PalError;

use alloc::boxed::Box;
use core::mem;
use tcp_proto::runtime::endpoint::*;

// Role associated with a HandshakeSession.
#[derive(Debug, PartialEq)]
pub enum Role {
    // Initiator of the handshake.
    Initiator,
    // Recipient of the handshake.
    Recipient,
}

/// Returns a HandshakeSession for a given role.
pub trait HandshakeSessionProvider {
    /// Get a HandshakeSession object for a given role.
    fn get(
        &self,
        self_replica_id: u64,
        peer_replica_id: u64,
        role: Role,
    ) -> Box<dyn HandshakeSession>;
}

/// Responsible for establishing a handshake between two raft replicas.
/// This includes performing mutual attestation and using noise protocol
/// to exchange symmetric keys which can be later used for encrypting/decrypting
/// payloads.
pub trait HandshakeSession {
    // Process an incoming SecureChanneHandshake message.
    fn process_message(&mut self, message: &SecureChannelHandshake) -> Result<(), PalError>;

    // Take out any pending handshake messages that need to be sent out for this session.
    // Returns None if no such message exists.
    fn take_out_message(&mut self) -> Option<SecureChannelHandshake>;

    // Returns true if this handshake session is now complete.
    fn is_completed(&self) -> bool;
}

pub struct DefaultHandshakeSessionProvider {}

impl HandshakeSessionProvider for DefaultHandshakeSessionProvider {
    fn get(
        &self,
        self_replica_id: u64,
        peer_replica_id: u64,
        role: Role,
    ) -> Box<dyn HandshakeSession> {
        match role {
            Role::Initiator => Box::new(ClientHandshakeSession::new(
                self_replica_id,
                peer_replica_id,
            )),
            Role::Recipient => Box::new(ServerHandshakeSession::new(
                self_replica_id,
                peer_replica_id,
            )),
        }
    }
}

pub struct ClientHandshakeSession {
    _self_replica_id: u64,
    _peer_replica_id: u64,
    pending_message: Option<SecureChannelHandshake>,
}

impl ClientHandshakeSession {
    fn new(self_replica_id: u64, peer_replica_id: u64) -> Self {
        // Initialize the first handshake message that should be sent out by the client.
        let pending_message = Some(SecureChannelHandshake {
            recipient_replica_id: peer_replica_id,
            sender_replica_id: self_replica_id,
            encryption: None,
        });
        Self {
            _self_replica_id: self_replica_id,
            _peer_replica_id: peer_replica_id,
            pending_message,
        }
    }
}
impl HandshakeSession for ClientHandshakeSession {
    fn process_message(&mut self, _message: &SecureChannelHandshake) -> Result<(), PalError> {
        Ok(())
    }

    fn take_out_message(&mut self) -> Option<SecureChannelHandshake> {
        mem::take(&mut self.pending_message)
    }

    fn is_completed(&self) -> bool {
        self.pending_message.is_none()
    }
}

pub struct ServerHandshakeSession {
    self_replica_id: u64,
    peer_replica_id: u64,
    pending_message: Option<SecureChannelHandshake>,
}

impl ServerHandshakeSession {
    fn new(self_replica_id: u64, peer_replica_id: u64) -> Self {
        Self {
            self_replica_id,
            peer_replica_id,
            pending_message: None,
        }
    }
}
impl HandshakeSession for ServerHandshakeSession {
    fn process_message(&mut self, _message: &SecureChannelHandshake) -> Result<(), PalError> {
        // Stash a handshake response.
        self.pending_message = Some(SecureChannelHandshake {
            recipient_replica_id: self.peer_replica_id,
            sender_replica_id: self.self_replica_id,
            encryption: None,
        });
        Ok(())
    }

    fn take_out_message(&mut self) -> Option<SecureChannelHandshake> {
        mem::take(&mut self.pending_message)
    }

    fn is_completed(&self) -> bool {
        self.pending_message.is_none()
    }
}

#[cfg(all(test, feature = "std"))]
mod test {
    use crate::handshake::{DefaultHandshakeSessionProvider, HandshakeSessionProvider};
    use handshake::Role;
    use tcp_proto::runtime::endpoint::*;

    fn create_secure_channel_handshake(
        sender_replica_id: u64,
        recipient_replica_id: u64,
    ) -> SecureChannelHandshake {
        SecureChannelHandshake {
            recipient_replica_id,
            sender_replica_id,
            encryption: None,
        }
    }

    #[test]
    fn test_client_session() {
        let self_replica_id = 11111;
        let peer_replica_id = 22222;
        let handshake_message = create_secure_channel_handshake(self_replica_id, peer_replica_id);
        let handshake_session_provider = DefaultHandshakeSessionProvider {};
        let mut client_handshake_session =
            handshake_session_provider.get(self_replica_id, peer_replica_id, Role::Initiator);

        assert_eq!(
            Some(handshake_message.clone()),
            client_handshake_session.take_out_message()
        );
        assert_eq!(
            Ok(()),
            client_handshake_session.process_message(&handshake_message)
        );
        assert_eq!(true, client_handshake_session.is_completed());
    }

    #[test]
    fn test_server_session() {
        let self_replica_id = 11111;
        let peer_replica_id = 22222;
        let handshake_message = create_secure_channel_handshake(self_replica_id, peer_replica_id);
        let handshake_session_provider = DefaultHandshakeSessionProvider {};
        let mut server_handshake_session =
            handshake_session_provider.get(self_replica_id, peer_replica_id, Role::Recipient);

        assert_eq!(
            Ok(()),
            server_handshake_session.process_message(&handshake_message)
        );
        assert_eq!(
            Some(handshake_message.clone()),
            server_handshake_session.take_out_message()
        );
        assert_eq!(true, server_handshake_session.is_completed());
    }
}
