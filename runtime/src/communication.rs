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

use core::mem;

use crate::{logger::log::create_logger, platform::PalError};
use alloc::vec;
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
    /// this method stashes the unencrypted outgoing message which can be retrieved later
    /// in encrypted form.
    ///
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

    /// Take out stashed messages (in encrypted form) to be sent to other replicas.
    ///
    /// This can include encrypted raft messages and/or handshake messages if this is
    /// the first time talking to a peer replica.
    fn take_out_messages(&mut self) -> Vec<OutMessage>;
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
            out_message::Msg::DeliverSystemMessage(deliver_system_message) => {
                deliver_system_message.recipient_replica_id
            }
            out_message::Msg::DeliverSnapshotRequest(deliver_snapshot_request) => {
                deliver_snapshot_request.recipient_replica_id
            }
            out_message::Msg::DeliverSnapshotResponse(deliver_snapshot_response) => {
                deliver_snapshot_response.recipient_replica_id
            }
            _ => {
                warn!(self.logger, "Message type {:?} is not supported.", message);
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
        self.check_initialized()?;

        let peer_replica_id = match &message {
            in_message::Msg::SecureChannelHandshake(secure_channel_handshake) => {
                secure_channel_handshake.sender_replica_id
            }
            in_message::Msg::DeliverSystemMessage(deliver_system_message) => {
                deliver_system_message.sender_replica_id
            }
            in_message::Msg::DeliverSnapshotRequest(deliver_snapshot_request) => {
                deliver_snapshot_request.sender_replica_id
            }
            in_message::Msg::DeliverSnapshotResponse(deliver_snapshot_response) => {
                deliver_snapshot_response.sender_replica_id
            }
            _ => {
                warn!(self.logger, "Message type {:?} is not supported.", message);
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
        replica_state.process_in_message(message)
    }

    fn take_out_messages(&mut self) -> Vec<OutMessage> {
        let mut messages = Vec::new();
        for (_, replica_state) in self.replicas.iter_mut() {
            messages.append(&mut replica_state.take_out_messages())
        }
        messages
    }
}

// Manages communication with a given peer replica.
pub struct CommunicationState {
    logger: Logger,
    peer_replica_id: u64,
    self_replica_id: u64,
    handshake_state: HandshakeState,
    pending_handshake_message: Option<SecureChannelHandshake>,
    // Unencrypted stashed messages that will be encrypted and sent out once
    // handshake completes.
    unencrypted_messages: Vec<OutMessage>,
}

#[derive(PartialEq)]
enum HandshakeState {
    // Handshake not performed yet.
    Unknown,
    // Handshake has been initiated. Waiting for a response.
    Initiated,
    // Handshake successfully completed and attestation verified.
    Completed,
    // Handshake failed due to internal errors or failed attestation.
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
            pending_handshake_message: None,
            unencrypted_messages: Vec::new(),
        }
    }

    fn set_handshake_message(&mut self) {
        if self.pending_handshake_message == None {
            self.pending_handshake_message = Some(SecureChannelHandshake {
                recipient_replica_id: self.peer_replica_id,
                sender_replica_id: self.self_replica_id,
                encryption: None,
            });
        }
    }

    fn process_out_message(&mut self, message: out_message::Msg) -> Result<(), PalError> {
        match &self.handshake_state {
            HandshakeState::Unknown => {
                self.set_handshake_message();
                self.unencrypted_messages
                    .push(OutMessage { msg: Some(message) });
                self.handshake_state = HandshakeState::Initiated;
                Ok(())
            }
            HandshakeState::Initiated => {
                self.unencrypted_messages
                    .push(OutMessage { msg: Some(message) });
                Ok(())
            }
            HandshakeState::Completed => {
                self.unencrypted_messages
                    .push(OutMessage { msg: Some(message) });
                Ok(())
            }
            HandshakeState::Failed => {
                warn!(
                    self.logger,
                    "Handshake failed with peer {}", self.peer_replica_id
                );
                return Err(PalError::Internal);
            }
        }
    }

    fn process_in_message(
        &mut self,
        message: in_message::Msg,
    ) -> Result<Option<in_message::Msg>, PalError> {
        match &self.handshake_state {
            HandshakeState::Unknown => {
                match message {
                    // First message must be a handshake message.
                    in_message::Msg::SecureChannelHandshake(_) => {
                        // TODO: Verify attestation report.
                        self.set_handshake_message();
                        // Transition from Unknown->Completed state on the recipient side
                        // since a handshake request was successfully received and verified,
                        // and a handshake response has been set to be sent back to the sender.
                        self.handshake_state = HandshakeState::Completed;
                        Ok(None)
                    }
                    _ => {
                        warn!(
                            self.logger,
                            "First message must be SecureChannelHandshake but found {:?}", message
                        );
                        self.handshake_state = HandshakeState::Failed;
                        return Err(PalError::Internal);
                    }
                }
            }
            HandshakeState::Initiated => {
                match message {
                    // First message must be a handshake message.
                    in_message::Msg::SecureChannelHandshake(_) => {
                        // TODO: Verify attestation report.
                        self.handshake_state = HandshakeState::Completed;
                        Ok(None)
                    }
                    _ => {
                        warn!(
                            self.logger,
                            "First message must be SecureChannelHandshake but found {:?}", message
                        );
                        self.handshake_state = HandshakeState::Failed;
                        return Err(PalError::Internal);
                    }
                }
            }
            HandshakeState::Completed => {
                // TODO: Decrypt message.
                Ok(Some(message))
            }
            HandshakeState::Failed => {
                warn!(
                    self.logger,
                    "Handshake failed with peer {}", self.peer_replica_id
                );
                return Err(PalError::Internal);
            }
        }
    }

    fn take_out_messages(&mut self) -> Vec<OutMessage> {
        let mut messages = Vec::new();
        if let Some(pending_handshake_message) = self.pending_handshake_message.take() {
            messages = vec![OutMessage {
                msg: Some(out_message::Msg::SecureChannelHandshake(
                    pending_handshake_message,
                )),
            }];
        } else if self.handshake_state == HandshakeState::Completed {
            // TODO: Encrypt message.
            messages = mem::take(&mut self.unencrypted_messages);
        }
        messages
    }
}

#[cfg(all(test, feature = "std"))]
mod test {
    use crate::{
        communication::{CommunicationModule, DefaultCommunicationModule},
        platform::PalError,
    };
    use alloc::vec;
    use alloc::vec::Vec;
    use prost::bytes::Bytes;
    use tcp_proto::runtime::endpoint::*;

    fn create_deliver_system_message(
        sender_replica_id: u64,
        recipient_replica_id: u64,
    ) -> DeliverSystemMessage {
        DeliverSystemMessage {
            recipient_replica_id,
            sender_replica_id,
            message_contents: Bytes::new(),
        }
    }

    fn create_deliver_snapshot_request(
        sender_replica_id: u64,
        recipient_replica_id: u64,
    ) -> DeliverSnapshotRequest {
        DeliverSnapshotRequest {
            recipient_replica_id,
            sender_replica_id,
            delivery_id: 0,
            payload_contents: Bytes::new(),
        }
    }

    fn create_deliver_snapshot_response(
        sender_replica_id: u64,
        recipient_replica_id: u64,
    ) -> DeliverSnapshotResponse {
        DeliverSnapshotResponse {
            recipient_replica_id,
            sender_replica_id,
            delivery_id: 0,
            payload_contents: Bytes::new(),
        }
    }

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

    fn create_unsupported_out_message() -> out_message::Msg {
        out_message::Msg::StartReplica(StartReplicaResponse { replica_id: 0 })
    }

    fn create_unsupported_in_message() -> in_message::Msg {
        in_message::Msg::StartReplica(StartReplicaRequest {
            is_leader: true,
            replica_id_hint: 0,
            raft_config: None,
            app_config: Bytes::new(),
            attestation_config: None,
        })
    }

    #[test]
    fn test_process_out_message() {
        let mut communication_module = DefaultCommunicationModule::new();
        let self_replica_id = 11111;
        let peer_replica_id_a = 88888;
        let peer_replica_id_b = 99999;
        let handshake_message_a = OutMessage {
            msg: Some(out_message::Msg::SecureChannelHandshake(
                SecureChannelHandshake {
                    recipient_replica_id: peer_replica_id_a,
                    sender_replica_id: self_replica_id,
                    encryption: None,
                },
            )),
        };
        let handshake_message_b = OutMessage {
            msg: Some(out_message::Msg::SecureChannelHandshake(
                SecureChannelHandshake {
                    recipient_replica_id: peer_replica_id_b,
                    sender_replica_id: self_replica_id,
                    encryption: None,
                },
            )),
        };

        // Invoking `process_out_message` before `init` should fail.
        assert_eq!(
            Err(PalError::InvalidOperation),
            communication_module.process_out_message(out_message::Msg::DeliverSystemMessage(
                create_deliver_system_message(self_replica_id, peer_replica_id_a)
            ))
        );

        communication_module.init(self_replica_id);

        assert_eq!(
            Ok(()),
            communication_module.process_out_message(out_message::Msg::DeliverSystemMessage(
                create_deliver_system_message(self_replica_id, peer_replica_id_a)
            ))
        );
        assert_eq!(
            Ok(()),
            communication_module.process_out_message(out_message::Msg::DeliverSnapshotRequest(
                create_deliver_snapshot_request(self_replica_id, peer_replica_id_a)
            ))
        );
        assert_eq!(
            Ok(()),
            communication_module.process_out_message(out_message::Msg::DeliverSnapshotResponse(
                create_deliver_snapshot_response(self_replica_id, peer_replica_id_a)
            ))
        );
        assert_eq!(
            Ok(()),
            communication_module.process_out_message(out_message::Msg::DeliverSystemMessage(
                create_deliver_system_message(self_replica_id, peer_replica_id_b)
            ))
        );
        assert_eq!(
            Err(PalError::InvalidArgument),
            communication_module.process_out_message(create_unsupported_out_message())
        );
        assert_eq!(
            vec![handshake_message_a, handshake_message_b],
            communication_module.take_out_messages()
        );
    }

    #[test]
    fn test_process_in_message() {
        let mut communication_module = DefaultCommunicationModule::new();
        let peer_replica_id_a = 11111;
        let peer_replica_id_b = 22222;
        let self_replica_id = 88888;
        let handshake_message_a = OutMessage {
            msg: Some(out_message::Msg::SecureChannelHandshake(
                SecureChannelHandshake {
                    recipient_replica_id: peer_replica_id_a,
                    sender_replica_id: self_replica_id,
                    encryption: None,
                },
            )),
        };
        let handshake_message_b = OutMessage {
            msg: Some(out_message::Msg::SecureChannelHandshake(
                SecureChannelHandshake {
                    recipient_replica_id: peer_replica_id_b,
                    sender_replica_id: self_replica_id,
                    encryption: None,
                },
            )),
        };

        // Invoking `process_in_message` before `init` should fail.
        assert_eq!(
            Err(PalError::InvalidOperation),
            communication_module.process_in_message(in_message::Msg::DeliverSystemMessage(
                create_deliver_system_message(peer_replica_id_a, self_replica_id)
            ))
        );

        communication_module.init(self_replica_id);

        assert_eq!(
            Ok(None),
            communication_module.process_in_message(in_message::Msg::SecureChannelHandshake(
                create_secure_channel_handshake(peer_replica_id_a, self_replica_id)
            ))
        );
        assert_eq!(
            Ok(Some(in_message::Msg::DeliverSystemMessage(
                create_deliver_system_message(peer_replica_id_a, self_replica_id)
            ))),
            communication_module.process_in_message(in_message::Msg::DeliverSystemMessage(
                create_deliver_system_message(peer_replica_id_a, self_replica_id)
            ))
        );
        assert_eq!(
            Ok(Some(in_message::Msg::DeliverSnapshotRequest(
                create_deliver_snapshot_request(peer_replica_id_a, self_replica_id)
            ))),
            communication_module.process_in_message(in_message::Msg::DeliverSnapshotRequest(
                create_deliver_snapshot_request(peer_replica_id_a, self_replica_id)
            ))
        );
        assert_eq!(
            Ok(Some(in_message::Msg::DeliverSnapshotResponse(
                create_deliver_snapshot_response(peer_replica_id_a, self_replica_id)
            ))),
            communication_module.process_in_message(in_message::Msg::DeliverSnapshotResponse(
                create_deliver_snapshot_response(peer_replica_id_a, self_replica_id)
            ))
        );
        assert_eq!(
            Ok(None),
            communication_module.process_in_message(in_message::Msg::SecureChannelHandshake(
                create_secure_channel_handshake(peer_replica_id_b, self_replica_id)
            ))
        );
        assert_eq!(
            Err(PalError::InvalidArgument),
            communication_module.process_in_message(create_unsupported_in_message())
        );
        assert_eq!(
            vec![handshake_message_a, handshake_message_b],
            communication_module.take_out_messages()
        );
    }

    #[test]
    fn test_mutual_handshake_success() {
        let mut communication_module_a = DefaultCommunicationModule::new();
        let mut communication_module_b = DefaultCommunicationModule::new();
        let peer_replica_id_a = 11111;
        let peer_replica_id_b = 22222;
        let handshake_message_a_to_b = SecureChannelHandshake {
            sender_replica_id: peer_replica_id_a,
            recipient_replica_id: peer_replica_id_b,
            encryption: None,
        };
        let handshake_message_b_to_a = SecureChannelHandshake {
            sender_replica_id: peer_replica_id_b,
            recipient_replica_id: peer_replica_id_a,
            encryption: None,
        };
        let deliver_system_message =
            create_deliver_system_message(peer_replica_id_a, peer_replica_id_b);
        let deliver_snapshot_request =
            create_deliver_snapshot_request(peer_replica_id_a, peer_replica_id_b);

        communication_module_a.init(peer_replica_id_a);
        communication_module_b.init(peer_replica_id_b);

        // Handshake initiated from a to b.
        assert_eq!(
            Ok(()),
            communication_module_a.process_out_message(out_message::Msg::DeliverSystemMessage(
                deliver_system_message.clone()
            ))
        );
        assert_eq!(
            vec![OutMessage {
                msg: Some(out_message::Msg::SecureChannelHandshake(
                    handshake_message_a_to_b.clone()
                ))
            }],
            communication_module_a.take_out_messages()
        );
        // Taking out messages again should return empty since handshake has not completed.
        assert_eq!(
            Vec::<OutMessage>::new(),
            communication_module_a.take_out_messages()
        );

        // Handshake response from b to a.
        assert_eq!(
            Ok(None),
            communication_module_b.process_in_message(in_message::Msg::SecureChannelHandshake(
                handshake_message_a_to_b.clone()
            ))
        );
        assert_eq!(
            vec![OutMessage {
                msg: Some(out_message::Msg::SecureChannelHandshake(
                    handshake_message_b_to_a.clone()
                ))
            }],
            communication_module_b.take_out_messages()
        );

        // Handshake response received by a. It should now be ok to return previously
        // stashed messages.
        assert_eq!(
            Ok(None),
            communication_module_a.process_in_message(in_message::Msg::SecureChannelHandshake(
                handshake_message_b_to_a.clone()
            ))
        );
        assert_eq!(
            Ok(()),
            communication_module_a.process_out_message(out_message::Msg::DeliverSnapshotRequest(
                deliver_snapshot_request.clone()
            ))
        );
        assert_eq!(
            vec![
                OutMessage {
                    msg: Some(out_message::Msg::DeliverSystemMessage(
                        deliver_system_message.clone()
                    ))
                },
                OutMessage {
                    msg: Some(out_message::Msg::DeliverSnapshotRequest(
                        deliver_snapshot_request.clone()
                    ))
                }
            ],
            communication_module_a.take_out_messages()
        );

        assert_eq!(
            Ok(Some(in_message::Msg::DeliverSystemMessage(
                deliver_system_message.clone()
            ))),
            communication_module_b.process_in_message(in_message::Msg::DeliverSystemMessage(
                deliver_system_message.clone()
            ))
        );
    }

    #[test]
    fn test_invalid_handshake_message_fails() {
        let mut communication_module_a = DefaultCommunicationModule::new();
        let mut communication_module_b = DefaultCommunicationModule::new();
        let peer_replica_id_a = 11111;
        let peer_replica_id_b = 22222;
        let deliver_system_message_a_to_b =
            create_deliver_system_message(peer_replica_id_a, peer_replica_id_b);
        let deliver_system_message_b_to_a =
            create_deliver_system_message(peer_replica_id_b, peer_replica_id_a);

        communication_module_a.init(peer_replica_id_a);
        communication_module_b.init(peer_replica_id_b);

        assert_eq!(
            Ok(()),
            communication_module_a.process_out_message(out_message::Msg::DeliverSystemMessage(
                deliver_system_message_a_to_b.clone()
            ))
        );
        assert_eq!(
            Err(PalError::Internal),
            communication_module_b.process_in_message(in_message::Msg::DeliverSystemMessage(
                deliver_system_message_a_to_b.clone()
            ))
        );
        assert_eq!(
            Err(PalError::Internal),
            communication_module_a.process_in_message(in_message::Msg::DeliverSystemMessage(
                deliver_system_message_b_to_a.clone()
            ))
        );
        // Both a and b are in Failed state, so receiving or sending any subsequent messages should
        // fail.
        assert_eq!(
            Err(PalError::Internal),
            communication_module_a.process_in_message(in_message::Msg::DeliverSystemMessage(
                deliver_system_message_b_to_a.clone()
            ))
        );
        assert_eq!(
            Err(PalError::Internal),
            communication_module_b.process_in_message(in_message::Msg::DeliverSystemMessage(
                deliver_system_message_a_to_b.clone()
            ))
        );
        assert_eq!(
            Err(PalError::Internal),
            communication_module_a.process_out_message(out_message::Msg::DeliverSystemMessage(
                deliver_system_message_a_to_b.clone()
            ))
        );
        assert_eq!(
            Err(PalError::Internal),
            communication_module_b.process_out_message(out_message::Msg::DeliverSystemMessage(
                deliver_system_message_b_to_a.clone()
            ))
        );
    }
}
