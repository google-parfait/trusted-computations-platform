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

use core::any::Any;

use crate::{logger::log::create_logger, platform::PalError};
use alloc::vec::Vec;
use hashbrown::HashMap;
use slog::{warn, Logger};
use tcp_proto::runtime::endpoint::*;

/// Responsible for managing communication between raft replicas such as
/// initiating a handshake with replicas seen for the first time and encrypting/
/// decrypting messages for replica-replica communication if replicas have
/// successfully negotiated a handshake.
pub trait CommunicationModule {
    /// Initializes the ReplicaCommunicationManager for the given replica id.
    ///
    /// The ReplicaCommunicationManager must be initialized before first use.
    fn init(&mut self, replica_id: u64);

    /// Process an outgoing message to a replica.
    ///
    /// If handshake with the given replica is already succesfully completed, then
    /// this method encrypts and stashes the outgoing message which can be retrieved
    /// later.
    /// If this is the first time a message is being sent to the replica, then modifies
    /// internal state to initiate a handshake and stashes unencrypted messages which
    /// will be encrypted later once handshake has successfully completed.
    ///
    /// Callers must invoke `take_out_messages` to extract any stashed messages that
    /// are ready to be sent.
    fn process_out_message(&mut self, message: out_message::Msg) -> Result<(), PalError>;

    /// Process an incoming message from another replica.
    ///
    /// If handshake with the given replica is already successfully completed, then
    /// this method returns the decrypted message that can be processed by the caller.
    ///
    /// If this is the first time a message is received from this replica, then it must be
    /// the handshake message in which case this method verifies the attestation report,
    /// stashes a handshake response (if needed) and returns None since there are no decrypted
    /// messages that need to be processed by the caller.
    fn process_in_message(
        &mut self,
        message: in_message::Msg,
    ) -> Result<Option<in_message::Msg>, PalError>;

    /// Take out stashed messages to be sent to other replicas.
    ///
    /// This can include encrypted raft messages and/or handshake messages if this is
    /// the first time talking to a peer replica.
    fn take_out_messages(&mut self) -> Vec<out_message::Msg>;
}

// Default implementation of CommunicationModule.
pub struct DefaultCommunicationModule {
    logger: Logger,
    // Per replica state by replica_id.
    replicas: HashMap<u64, CommunicationState>,
    // Self replica_id.
    replica_id: u64,
}

impl DefaultCommunicationModule {
    pub fn new() -> Self {
        Self {
            logger: create_logger(),
            replicas: HashMap::new(),
            replica_id: 0,
        }
    }

    fn check_initialized(&self) -> Result<(), PalError> {
        if self.replica_id == 0 {
            return Err(PalError::InvalidOperation);
        }
        Ok(())
    }
}

impl CommunicationModule for DefaultCommunicationModule {
    fn init(&mut self, id: u64) {
        self.replica_id = id
    }

    fn process_out_message(&mut self, message: out_message::Msg) -> Result<(), PalError> {
        self.check_initialized()?;

        let peer_replica_id = match &message {
            out_message::Msg::DeliverMessage(deliver_message) => {
                deliver_message.recipient_replica_id
            }
            out_message::Msg::DeliverSnapshotRequest(deliver_snapshot_request) => {
                deliver_snapshot_request.recipient_replica_id
            }
            out_message::Msg::DeliverSnapshotResponse(deliver_snapshot_response) => {
                deliver_snapshot_response.recipient_replica_id
            }
            _ => {
                warn!(
                    self.logger,
                    "Message type {:?} is not supported.",
                    &message.type_id()
                );
                return Err(PalError::InvalidArgument);
            }
        };

        let replica_state =
            self.replicas
                .entry(peer_replica_id)
                .or_insert(CommunicationState::new(
                    self.logger.clone(),
                    self.replica_id,
                    peer_replica_id,
                ));
        replica_state.process_out_message(message)
    }

    fn process_in_message(
        &mut self,
        message: in_message::Msg,
    ) -> Result<Option<in_message::Msg>, PalError> {
        Ok(None)
    }

    fn take_out_messages(&mut self) -> Vec<out_message::Msg> {
        Vec::new()
    }
}

// Manages communication with a given peer replica.
pub struct CommunicationState {
    logger: Logger,
    peer_replica_id: u64,
    self_replica_id: u64,
    handshake_state: HandshakeState,
    // Stashed messages that will be sent out once handshake completes.
    stashed_messages: Vec<out_message::Msg>,
}

enum HandshakeState {
    Unknown,
    Initiated,
    Completed,
    Failed,
}

impl CommunicationState {
    // Create the ReplicaCommunicationState. This happens the first time a
    // message is sent to or received from a peer replica.
    fn new(logger: Logger, self_replica_id: u64, peer_replica_id: u64) -> Self {
        Self {
            logger,
            self_replica_id,
            peer_replica_id,
            handshake_state: HandshakeState::Unknown,
            stashed_messages: Vec::new(),
        }
    }

    fn process_out_message(&mut self, message: out_message::Msg) -> Result<(), PalError> {
        Ok(())
    }

    fn process_in_message(
        &mut self,
        message: in_message::Msg,
    ) -> Result<Option<in_message::Msg>, PalError> {
        Ok(None)
    }

    fn take_out_messages(&mut self) -> Vec<out_message::Msg> {
        Vec::new()
    }
}

#[cfg(all(test, feature = "std"))]
mod test {
    use prost::bytes::Bytes;
    use tcp_proto::runtime::endpoint::*;

    use crate::{
        communication::{CommunicationModule, DefaultCommunicationModule},
        platform::PalError,
    };

    fn create_deliver_message_response(
        sender_replica_id: u64,
        recipient_replica_id: u64,
    ) -> out_message::Msg {
        out_message::Msg::DeliverMessage(DeliverMessage {
            recipient_replica_id,
            sender_replica_id,
            message_contents: Bytes::new(),
        })
    }

    fn create_deliver_snapshot_request(
        sender_replica_id: u64,
        recipient_replica_id: u64,
    ) -> out_message::Msg {
        out_message::Msg::DeliverSnapshotRequest(DeliverSnapshotRequest {
            recipient_replica_id,
            sender_replica_id,
            delivery_id: 0,
            payload_contents: Bytes::new(),
        })
    }

    fn create_deliver_snapshot_response(
        sender_replica_id: u64,
        recipient_replica_id: u64,
    ) -> out_message::Msg {
        out_message::Msg::DeliverSnapshotResponse(DeliverSnapshotResponse {
            recipient_replica_id,
            sender_replica_id,
            delivery_id: 0,
            payload_contents: Bytes::new(),
        })
    }

    fn create_unsupported_message() -> out_message::Msg {
        out_message::Msg::StartReplica(StartReplicaResponse { replica_id: 0 })
    }

    #[test]
    fn test_process_out_message() {
        let mut communication_module = DefaultCommunicationModule::new();
        let sender_replica_id = 11111;
        let recipient_replica_id_a = 88888;
        let recipient_replica_id_b = 99999;

        // Invoking `process_out_message` before `init` should fail.
        assert_eq!(
            Err(PalError::InvalidOperation),
            communication_module.process_out_message(create_deliver_message_response(
                sender_replica_id,
                recipient_replica_id_a
            ))
        );

        communication_module.init(sender_replica_id);

        assert_eq!(
            Ok(()),
            communication_module.process_out_message(create_deliver_message_response(
                sender_replica_id,
                recipient_replica_id_a
            ))
        );
        assert_eq!(
            Ok(()),
            communication_module.process_out_message(create_deliver_snapshot_request(
                sender_replica_id,
                recipient_replica_id_a
            ))
        );
        assert_eq!(
            Ok(()),
            communication_module.process_out_message(create_deliver_snapshot_response(
                sender_replica_id,
                recipient_replica_id_a
            ))
        );
        assert_eq!(
            Ok(()),
            communication_module.process_out_message(create_deliver_message_response(
                sender_replica_id,
                recipient_replica_id_b
            ))
        );
        assert_eq!(
            Err(PalError::InvalidArgument),
            communication_module.process_out_message(create_unsupported_message())
        );
    }
}
