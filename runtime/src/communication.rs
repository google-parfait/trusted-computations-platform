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

use crate::{
    encryptor::Encryptor,
    handshake::{HandshakeSession, HandshakeSessionProvider, Role},
    logger::log::create_logger,
    platform::PalError,
};
use alloc::vec::Vec;
use alloc::{boxed::Box, vec};
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

    // Processes change in the cluster state by cleaning up resources for replicas
    // that are no longer part of the cluster.
    // `new_replica_ids` contains a list of all replica_ids currently part of the Raft
    // cluster.
    fn process_cluster_change(&mut self, new_replica_ids: &[u64]);
}

// Default implementation of CommunicationModule.
pub struct DefaultCommunicationModule {
    logger: Logger,
    // Per replica state by replica_id.
    replicas: HashMap<u64, CommunicationState>,
    // Self replica_id.
    replica_id: u64,
    handshake_session_provider: Box<dyn HandshakeSessionProvider>,
}

impl DefaultCommunicationModule {
    pub fn new(handshake_session_provider: Box<dyn HandshakeSessionProvider>) -> Self {
        Self {
            logger: create_logger(),
            replicas: HashMap::new(),
            replica_id: 0,
            handshake_session_provider,
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

        // We need to store references in local variables below to avoid immutably borrowing "self"
        // in the closure passed to "or_insert_with". "self" is mutably borrowed in
        // "self.replicas.entry(...)" so it cannot be immutably borrowed in the closure again.
        let logger = &self.logger;
        let handshake_provider = &self.handshake_session_provider;
        let replica_id = self.replica_id;
        let replica_state = self.replicas.entry(peer_replica_id).or_insert_with(|| {
            CommunicationState::new(
                logger.clone(),
                handshake_provider.get(replica_id, peer_replica_id, Role::Initiator),
            )
        });
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

        // We need to store references in local variables below to avoid immutably borrowing "self"
        // in the closure passed to "or_insert_with". "self" is mutably borrowed in
        // "self.replicas.entry(...)" so it cannot be immutably borrowed in the closure again.
        let logger = &self.logger;
        let handshake_provider = &self.handshake_session_provider;
        let replica_id = self.replica_id;
        let replica_state = self.replicas.entry(peer_replica_id).or_insert_with(|| {
            CommunicationState::new(
                logger.clone(),
                handshake_provider.get(replica_id, peer_replica_id, Role::Recipient),
            )
        });
        replica_state.process_in_message(message)
    }

    fn take_out_messages(&mut self) -> Vec<OutMessage> {
        let mut messages = Vec::new();
        for (_, replica_state) in self.replicas.iter_mut() {
            messages.append(&mut replica_state.take_out_messages())
        }
        messages
    }

    fn process_cluster_change(&mut self, new_replica_ids: &[u64]) {
        // If replica is no longer part of cluster, clear all state.
        if !new_replica_ids.contains(&self.replica_id) {
            self.replicas.clear();
            return;
        }

        // Remove replicas that are no longer part of the raft cluster.
        // Any new replicas part of `new_replica_ids` that weren't previously part of the
        // cluster will be added to `self.replicas` list on demand when communication is first
        // initiatiated with that replica.
        self.replicas
            .retain(|&key, _| new_replica_ids.contains(&key));
    }
}

// Manages communication with a given peer replica.
pub struct CommunicationState {
    logger: Logger,
    handshake_state: HandshakeState,
    pending_handshake_message: Option<SecureChannelHandshake>,
    handshake_session: Option<Box<dyn HandshakeSession>>,
    // Unencrypted stashed messages that will be encrypted and sent out once
    // handshake completes.
    unencrypted_messages: Vec<out_message::Msg>,
    encryptor: Option<Box<dyn Encryptor>>,
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
    fn new(logger: Logger, handshake_session: Box<dyn HandshakeSession>) -> Self {
        Self {
            logger,
            handshake_state: HandshakeState::Unknown,
            pending_handshake_message: None,
            handshake_session: Some(handshake_session),
            unencrypted_messages: Vec::new(),
            encryptor: None,
        }
    }

    fn process_out_message(&mut self, message: out_message::Msg) -> Result<(), PalError> {
        match &self.handshake_state {
            HandshakeState::Unknown => {
                self.pending_handshake_message = self
                    .handshake_session
                    .as_mut()
                    .unwrap()
                    .take_out_message()?;
                if self.pending_handshake_message.is_none() {
                    warn!(self.logger, "No initial handshake message found.");
                    return Err(PalError::Internal);
                }
                self.unencrypted_messages.push(message);
                self.handshake_state = HandshakeState::Initiated;
                Ok(())
            }
            HandshakeState::Initiated | HandshakeState::Completed => {
                self.unencrypted_messages.push(message);
                Ok(())
            }
            HandshakeState::Failed => {
                warn!(self.logger, "HandshakeState Failed.");
                return Err(PalError::Internal);
            }
        }
    }

    fn process_in_message(
        &mut self,
        message: in_message::Msg,
    ) -> Result<Option<in_message::Msg>, PalError> {
        match &self.handshake_state {
            HandshakeState::Unknown | HandshakeState::Initiated => {
                match message {
                    // Messages in Unknown/Initiated state must be handshake messages.
                    in_message::Msg::SecureChannelHandshake(handshake_message) => {
                        self.handshake_session
                            .as_mut()
                            .unwrap()
                            .process_message(&handshake_message)?;
                        self.pending_handshake_message = self
                            .handshake_session
                            .as_mut()
                            .unwrap()
                            .take_out_message()?;
                        if self.handshake_session.as_ref().unwrap().is_completed() {
                            // Consume `self.handshake_session`.
                            let handshake_session = self.handshake_session.take();
                            self.encryptor = handshake_session.unwrap().get_encryptor();
                            self.handshake_state = HandshakeState::Completed;
                        } else {
                            self.handshake_state = HandshakeState::Initiated;
                        }
                        Ok(None)
                    }
                    _ => {
                        warn!(
                            self.logger,
                            "Message must be SecureChannelHandshake but found {:?}", message
                        );
                        self.handshake_state = HandshakeState::Failed;
                        return Err(PalError::Internal);
                    }
                }
            }
            HandshakeState::Completed => Ok(self.decrypt_message(message)),
            HandshakeState::Failed => {
                warn!(self.logger, "HandshakeState Failed.");
                return Err(PalError::Internal);
            }
        }
    }

    fn decrypt_message(&self, message: in_message::Msg) -> Option<in_message::Msg> {
        let encryptor = self.encryptor.as_ref().unwrap();
        let result = match message {
            in_message::Msg::DeliverSystemMessage(mut msg) => encryptor
                .decrypt(&msg.message_contents)
                .and_then(|decrypted_msg| {
                    msg.message_contents = decrypted_msg.into();
                    Ok(in_message::Msg::DeliverSystemMessage(msg))
                }),
            in_message::Msg::DeliverSnapshotRequest(mut msg) => encryptor
                .decrypt(&msg.payload_contents)
                .and_then(|decrypted_msg| {
                    msg.payload_contents = decrypted_msg.into();
                    Ok(in_message::Msg::DeliverSnapshotRequest(msg))
                }),
            in_message::Msg::DeliverSnapshotResponse(mut msg) => encryptor
                .decrypt(&msg.payload_contents)
                .and_then(|decrypted_msg| {
                    msg.payload_contents = decrypted_msg.into();
                    Ok(in_message::Msg::DeliverSnapshotResponse(msg))
                }),
            _ => {
                warn!(
                    self.logger,
                    "Unexpected message encountered for decryption {:?}", message
                );
                Err(PalError::Internal)
            }
        };

        if result.is_err() {
            warn!(self.logger, "Failed to decrypt message {:?}", result.err());
            return None;
        }
        Some(result.unwrap())
    }

    fn take_encrypted_messages(&mut self) -> Vec<OutMessage> {
        let mut messages = Vec::new();
        let unencrypted_msgs = mem::take(&mut self.unencrypted_messages);
        let encryptor = self.encryptor.as_ref().unwrap();

        for unencrypted_message in unencrypted_msgs {
            let result = match unencrypted_message {
                out_message::Msg::DeliverSystemMessage(mut message) => encryptor
                    .encrypt(&message.message_contents)
                    .and_then(|encrypted_message| {
                        message.message_contents = encrypted_message.into();
                        messages.push(OutMessage {
                            msg: Some(out_message::Msg::DeliverSystemMessage(message)),
                        });
                        Ok(())
                    }),
                out_message::Msg::DeliverSnapshotRequest(mut message) => encryptor
                    .encrypt(&message.payload_contents)
                    .and_then(|encrypted_message| {
                        message.payload_contents = encrypted_message.into();
                        messages.push(OutMessage {
                            msg: Some(out_message::Msg::DeliverSnapshotRequest(message)),
                        });
                        Ok(())
                    }),
                out_message::Msg::DeliverSnapshotResponse(mut message) => encryptor
                    .encrypt(&message.payload_contents)
                    .and_then(|encrypted_message| {
                        message.payload_contents = encrypted_message.into();
                        messages.push(OutMessage {
                            msg: Some(out_message::Msg::DeliverSnapshotResponse(message)),
                        });
                        Ok(())
                    }),
                _ => {
                    warn!(
                        self.logger,
                        "Unexpected message encountered for encryption {:?}", unencrypted_message
                    );
                    Err(PalError::Internal)
                }
            };

            if result.is_err() {
                warn!(self.logger, "Failed to encrypt {:?}", result.err());
            }
        }
        messages
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
            messages = self.take_encrypted_messages();
        }

        messages
    }
}

#[cfg(all(test, feature = "std"))]
mod test {
    extern crate mockall;

    use self::mockall::predicate::eq;
    use crate::{
        communication::{CommunicationModule, DefaultCommunicationModule},
        platform::PalError,
    };
    use alloc::vec;
    use alloc::vec::Vec;
    use communication::mem;
    use handshake::Role;
    use mock::{MockEncryptor, MockHandshakeSession, MockHandshakeSessionProvider};
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

    fn create_deliver_system_message_with_contents(
        sender_replica_id: u64,
        recipient_replica_id: u64,
        message_contents: Bytes,
    ) -> DeliverSystemMessage {
        DeliverSystemMessage {
            recipient_replica_id,
            sender_replica_id,
            message_contents,
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

    fn create_deliver_snapshot_request_with_contents(
        sender_replica_id: u64,
        recipient_replica_id: u64,
        payload_contents: Bytes,
    ) -> DeliverSnapshotRequest {
        DeliverSnapshotRequest {
            recipient_replica_id,
            sender_replica_id,
            delivery_id: 0,
            payload_contents,
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

    fn create_deliver_snapshot_response_with_contents(
        sender_replica_id: u64,
        recipient_replica_id: u64,
        payload_contents: Bytes,
    ) -> DeliverSnapshotResponse {
        DeliverSnapshotResponse {
            recipient_replica_id,
            sender_replica_id,
            delivery_id: 0,
            payload_contents,
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

    struct HandshakeSessionProviderBuilder {
        mock_handshake_session_provider: MockHandshakeSessionProvider,
    }

    impl HandshakeSessionProviderBuilder {
        fn new() -> HandshakeSessionProviderBuilder {
            HandshakeSessionProviderBuilder {
                mock_handshake_session_provider: MockHandshakeSessionProvider::new(),
            }
        }

        fn expect_get(
            mut self,
            self_replica_id: u64,
            peer_replica_id: u64,
            role: Role,
            mock_handshake_session: MockHandshakeSession,
        ) -> HandshakeSessionProviderBuilder {
            self.mock_handshake_session_provider
                .expect_get()
                .with(eq(self_replica_id), eq(peer_replica_id), eq(role))
                .once()
                .return_once(move |_, _, _| Box::new(mock_handshake_session));
            self
        }

        fn take(mut self) -> MockHandshakeSessionProvider {
            mem::take(&mut self.mock_handshake_session_provider)
        }
    }

    struct HandshakeSessionBuilder {
        mock_handshake_session: MockHandshakeSession,
    }

    impl HandshakeSessionBuilder {
        fn new() -> HandshakeSessionBuilder {
            HandshakeSessionBuilder {
                mock_handshake_session: MockHandshakeSession::new(),
            }
        }

        fn expect_process_message(
            mut self,
            message: SecureChannelHandshake,
            result: Result<(), PalError>,
        ) -> HandshakeSessionBuilder {
            self.mock_handshake_session
                .expect_process_message()
                .with(eq(message))
                .once()
                .return_once(move |_| result);
            self
        }

        fn expect_take_out_message(
            mut self,
            message: Result<Option<SecureChannelHandshake>, PalError>,
        ) -> HandshakeSessionBuilder {
            self.mock_handshake_session
                .expect_take_out_message()
                .once()
                .return_once(move || message);

            self
        }

        fn expect_is_completed(mut self, is_completed: bool) -> HandshakeSessionBuilder {
            self.mock_handshake_session
                .expect_is_completed()
                .once()
                .return_const(is_completed);
            self
        }

        fn expect_get_encryptor(
            mut self,
            mock_encryptor: MockEncryptor,
        ) -> HandshakeSessionBuilder {
            self.mock_handshake_session
                .expect_get_encryptor()
                .once()
                .return_once(move || Some(Box::new(mock_encryptor)));
            self
        }

        fn take(mut self) -> MockHandshakeSession {
            mem::take(&mut self.mock_handshake_session)
        }
    }

    struct EncryptorBuilder {
        mock_encryptor: MockEncryptor,
    }

    impl EncryptorBuilder {
        fn new() -> EncryptorBuilder {
            EncryptorBuilder {
                mock_encryptor: MockEncryptor::new(),
            }
        }

        fn expect_encrypt(
            mut self,
            plaintext: Bytes,
            result: Result<Vec<u8>, PalError>,
        ) -> EncryptorBuilder {
            self.mock_encryptor
                .expect_encrypt()
                .with(eq(plaintext))
                .once()
                .return_once(move |_| result);
            self
        }

        fn expect_decrypt(
            mut self,
            ciphertext: Bytes,
            result: Result<Vec<u8>, PalError>,
        ) -> EncryptorBuilder {
            self.mock_encryptor
                .expect_decrypt()
                .with(eq(ciphertext))
                .once()
                .return_once(move |_| result);
            self
        }

        fn take(mut self) -> MockEncryptor {
            mem::take(&mut self.mock_encryptor)
        }
    }

    #[test]
    fn test_process_out_message() {
        let self_replica_id = 11111;
        let peer_replica_id_a = 88888;
        let peer_replica_id_b = 99999;
        let handshake_message_a =
            create_secure_channel_handshake(self_replica_id, peer_replica_id_a);
        let handshake_message_b =
            create_secure_channel_handshake(self_replica_id, peer_replica_id_b);
        let mock_handshake_session_a = HandshakeSessionBuilder::new()
            .expect_take_out_message(Ok(Some(handshake_message_a.clone())))
            .take();
        let mock_handshake_session_b = HandshakeSessionBuilder::new()
            .expect_take_out_message(Ok(Some(handshake_message_b.clone())))
            .take();
        let mock_handshake_session_provider = HandshakeSessionProviderBuilder::new()
            .expect_get(
                self_replica_id,
                peer_replica_id_a,
                Role::Initiator,
                mock_handshake_session_a,
            )
            .expect_get(
                self_replica_id,
                peer_replica_id_b,
                Role::Initiator,
                mock_handshake_session_b,
            )
            .take();
        let mut communication_module =
            DefaultCommunicationModule::new(Box::new(mock_handshake_session_provider));

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
            vec![
                OutMessage {
                    msg: Some(out_message::Msg::SecureChannelHandshake(
                        handshake_message_a.clone()
                    ))
                },
                OutMessage {
                    msg: Some(out_message::Msg::SecureChannelHandshake(
                        handshake_message_b.clone()
                    ))
                }
            ],
            communication_module.take_out_messages()
        );
    }

    #[test]
    fn test_process_in_message() {
        let peer_replica_id_a = 11111;
        let peer_replica_id_b = 22222;
        let self_replica_id = 88888;
        let handshake_message_a =
            create_secure_channel_handshake(peer_replica_id_a, self_replica_id);
        let handshake_message_b =
            create_secure_channel_handshake(peer_replica_id_b, self_replica_id);
        let deliver_sys_msg_encrypted = create_deliver_system_message_with_contents(
            peer_replica_id_a,
            self_replica_id,
            "sys_msg_ciphertext".into(),
        );
        let deliver_sys_msg_unencrypted = create_deliver_system_message_with_contents(
            peer_replica_id_a,
            self_replica_id,
            "sys_msg_plaintext".into(),
        );
        let deliver_snapshot_req_encrypted = create_deliver_snapshot_request_with_contents(
            peer_replica_id_a,
            self_replica_id,
            "snapshot_req_ciphertext".into(),
        );
        let deliver_snapshot_req_unencrypted = create_deliver_snapshot_request_with_contents(
            peer_replica_id_a,
            self_replica_id,
            "snapshot_req_plaintext".into(),
        );
        let deliver_snapshot_resp_encrypted = create_deliver_snapshot_response_with_contents(
            peer_replica_id_a,
            self_replica_id,
            "snapshot_resp_ciphertext".into(),
        );
        let deliver_snapshot_resp_unencrypted = create_deliver_snapshot_response_with_contents(
            peer_replica_id_a,
            self_replica_id,
            "snapshot_resp_plaintext".into(),
        );
        let mock_encryptor = EncryptorBuilder::new()
            .expect_decrypt(
                deliver_sys_msg_encrypted.message_contents.clone(),
                Ok(deliver_sys_msg_unencrypted.message_contents.to_vec()),
            )
            .expect_decrypt(
                deliver_snapshot_req_encrypted.payload_contents.clone(),
                Ok(deliver_snapshot_req_unencrypted.payload_contents.to_vec()),
            )
            .expect_decrypt(
                deliver_snapshot_resp_encrypted.payload_contents.clone(),
                Ok(deliver_snapshot_resp_unencrypted.payload_contents.to_vec()),
            )
            .take();
        let mock_handshake_session_a = HandshakeSessionBuilder::new()
            .expect_process_message(handshake_message_a.clone(), Ok(()))
            .expect_take_out_message(Ok(Some(handshake_message_a.clone())))
            .expect_is_completed(true)
            .expect_get_encryptor(mock_encryptor)
            .take();
        let mock_handshake_session_b = HandshakeSessionBuilder::new()
            .expect_process_message(handshake_message_b.clone(), Ok(()))
            .expect_take_out_message(Ok(Some(handshake_message_b.clone())))
            .expect_is_completed(true)
            .expect_get_encryptor(MockEncryptor::new())
            .take();
        let mock_handshake_session_provider = HandshakeSessionProviderBuilder::new()
            .expect_get(
                self_replica_id,
                peer_replica_id_a,
                Role::Recipient,
                mock_handshake_session_a,
            )
            .expect_get(
                self_replica_id,
                peer_replica_id_b,
                Role::Recipient,
                mock_handshake_session_b,
            )
            .take();
        let mut communication_module =
            DefaultCommunicationModule::new(Box::new(mock_handshake_session_provider));

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
                handshake_message_a.clone()
            ))
        );
        assert_eq!(
            Ok(Some(in_message::Msg::DeliverSystemMessage(
                deliver_sys_msg_unencrypted
            ))),
            communication_module.process_in_message(in_message::Msg::DeliverSystemMessage(
                deliver_sys_msg_encrypted
            ))
        );
        assert_eq!(
            Ok(Some(in_message::Msg::DeliverSnapshotRequest(
                deliver_snapshot_req_unencrypted
            ))),
            communication_module.process_in_message(in_message::Msg::DeliverSnapshotRequest(
                deliver_snapshot_req_encrypted
            ))
        );
        assert_eq!(
            Ok(Some(in_message::Msg::DeliverSnapshotResponse(
                deliver_snapshot_resp_unencrypted
            ))),
            communication_module.process_in_message(in_message::Msg::DeliverSnapshotResponse(
                deliver_snapshot_resp_encrypted
            ))
        );
        assert_eq!(
            Ok(None),
            communication_module.process_in_message(in_message::Msg::SecureChannelHandshake(
                handshake_message_b.clone()
            ))
        );
        assert_eq!(
            Err(PalError::InvalidArgument),
            communication_module.process_in_message(create_unsupported_in_message())
        );
        assert_eq!(
            vec![
                OutMessage {
                    msg: Some(out_message::Msg::SecureChannelHandshake(
                        handshake_message_a.clone()
                    ))
                },
                OutMessage {
                    msg: Some(out_message::Msg::SecureChannelHandshake(
                        handshake_message_b.clone()
                    ))
                }
            ],
            communication_module.take_out_messages()
        );
    }

    #[test]
    fn test_mutual_handshake_single_roundtrip_success() {
        let peer_replica_id_a = 11111;
        let peer_replica_id_b = 22222;
        let handshake_message_a_to_b =
            create_secure_channel_handshake(peer_replica_id_a, peer_replica_id_b);
        let handshake_message_b_to_a =
            create_secure_channel_handshake(peer_replica_id_b, peer_replica_id_a);
        let deliver_sys_msg_encrypted = create_deliver_system_message_with_contents(
            peer_replica_id_a,
            peer_replica_id_b,
            "sys_msg_ciphertext".into(),
        );
        let deliver_sys_msg_unencrypted = create_deliver_system_message_with_contents(
            peer_replica_id_a,
            peer_replica_id_b,
            "sys_msg_plaintext".into(),
        );
        let deliver_snapshot_req_encrypted = create_deliver_snapshot_request_with_contents(
            peer_replica_id_a,
            peer_replica_id_b,
            "snapshot_req_ciphertext".into(),
        );
        let deliver_snapshot_req_unencrypted = create_deliver_snapshot_request_with_contents(
            peer_replica_id_a,
            peer_replica_id_b,
            "snapshot_req_plaintext".into(),
        );
        let mock_encryptor_a = EncryptorBuilder::new()
            .expect_encrypt(
                deliver_sys_msg_unencrypted.message_contents.clone(),
                Ok(deliver_sys_msg_encrypted.message_contents.to_vec()),
            )
            .expect_encrypt(
                deliver_snapshot_req_unencrypted.payload_contents.clone(),
                Ok(deliver_snapshot_req_encrypted.payload_contents.to_vec()),
            )
            .take();
        let mock_encryptor_b = EncryptorBuilder::new()
            .expect_decrypt(
                deliver_sys_msg_encrypted.message_contents.clone(),
                Ok(deliver_sys_msg_unencrypted.message_contents.to_vec()),
            )
            .take();
        let mock_handshake_session_a = HandshakeSessionBuilder::new()
            .expect_take_out_message(Ok(Some(handshake_message_a_to_b.clone())))
            .expect_process_message(handshake_message_b_to_a.clone(), Ok(()))
            .expect_take_out_message(Ok(None))
            .expect_is_completed(true)
            .expect_get_encryptor(mock_encryptor_a)
            .take();
        let mock_handshake_session_b = HandshakeSessionBuilder::new()
            .expect_process_message(handshake_message_a_to_b.clone(), Ok(()))
            .expect_take_out_message(Ok(Some(handshake_message_b_to_a.clone())))
            .expect_is_completed(true)
            .expect_get_encryptor(mock_encryptor_b)
            .take();
        let mock_handshake_session_provider_a = HandshakeSessionProviderBuilder::new()
            .expect_get(
                peer_replica_id_a,
                peer_replica_id_b,
                Role::Initiator,
                mock_handshake_session_a,
            )
            .take();
        let mock_handshake_session_provider_b = HandshakeSessionProviderBuilder::new()
            .expect_get(
                peer_replica_id_b,
                peer_replica_id_a,
                Role::Recipient,
                mock_handshake_session_b,
            )
            .take();
        let mut communication_module_a =
            DefaultCommunicationModule::new(Box::new(mock_handshake_session_provider_a));
        let mut communication_module_b =
            DefaultCommunicationModule::new(Box::new(mock_handshake_session_provider_b));

        communication_module_a.init(peer_replica_id_a);
        communication_module_b.init(peer_replica_id_b);

        // Handshake initiated from a to b.
        assert_eq!(
            Ok(()),
            communication_module_a.process_out_message(out_message::Msg::DeliverSystemMessage(
                deliver_sys_msg_unencrypted.clone()
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
                deliver_snapshot_req_unencrypted.clone()
            ))
        );
        assert_eq!(
            vec![
                OutMessage {
                    msg: Some(out_message::Msg::DeliverSystemMessage(
                        deliver_sys_msg_encrypted.clone()
                    ))
                },
                OutMessage {
                    msg: Some(out_message::Msg::DeliverSnapshotRequest(
                        deliver_snapshot_req_encrypted.clone()
                    ))
                }
            ],
            communication_module_a.take_out_messages()
        );

        assert_eq!(
            Ok(Some(in_message::Msg::DeliverSystemMessage(
                deliver_sys_msg_unencrypted.clone()
            ))),
            communication_module_b.process_in_message(in_message::Msg::DeliverSystemMessage(
                deliver_sys_msg_encrypted.clone()
            ))
        );
    }

    #[test]
    fn test_mutual_handshake_multiple_roundtrips_success() {
        let peer_replica_id_a = 11111;
        let peer_replica_id_b = 22222;
        let handshake_message_a_to_b =
            create_secure_channel_handshake(peer_replica_id_a, peer_replica_id_b);
        let handshake_message_b_to_a =
            create_secure_channel_handshake(peer_replica_id_b, peer_replica_id_a);
        let deliver_sys_msg_encrypted = create_deliver_system_message_with_contents(
            peer_replica_id_a,
            peer_replica_id_b,
            "sys_msg_ciphertext".into(),
        );
        let deliver_sys_msg_unencrypted = create_deliver_system_message_with_contents(
            peer_replica_id_a,
            peer_replica_id_b,
            "sys_msg_plaintext".into(),
        );
        let deliver_snapshot_req_encrypted = create_deliver_snapshot_request_with_contents(
            peer_replica_id_a,
            peer_replica_id_b,
            "snapshot_req_ciphertext".into(),
        );
        let deliver_snapshot_req_unencrypted = create_deliver_snapshot_request_with_contents(
            peer_replica_id_a,
            peer_replica_id_b,
            "snapshot_req_plaintext".into(),
        );
        let mock_encryptor_a = EncryptorBuilder::new()
            .expect_encrypt(
                deliver_sys_msg_unencrypted.message_contents.clone(),
                Ok(deliver_sys_msg_encrypted.message_contents.to_vec()),
            )
            .expect_encrypt(
                deliver_snapshot_req_unencrypted.payload_contents.clone(),
                Ok(deliver_snapshot_req_encrypted.payload_contents.to_vec()),
            )
            .take();
        let mock_encryptor_b = EncryptorBuilder::new()
            .expect_decrypt(
                deliver_sys_msg_encrypted.message_contents.clone(),
                Ok(deliver_sys_msg_unencrypted.message_contents.to_vec()),
            )
            .take();
        let mock_handshake_session_a = HandshakeSessionBuilder::new()
            .expect_take_out_message(Ok(Some(handshake_message_a_to_b.clone())))
            .expect_process_message(handshake_message_b_to_a.clone(), Ok(()))
            .expect_take_out_message(Ok(Some(handshake_message_a_to_b.clone())))
            .expect_is_completed(false)
            .expect_process_message(handshake_message_b_to_a.clone(), Ok(()))
            .expect_take_out_message(Ok(None))
            .expect_is_completed(true)
            .expect_get_encryptor(mock_encryptor_a)
            .take();
        let mock_handshake_session_b = HandshakeSessionBuilder::new()
            .expect_process_message(handshake_message_a_to_b.clone(), Ok(()))
            .expect_take_out_message(Ok(Some(handshake_message_b_to_a.clone())))
            .expect_is_completed(false)
            .expect_process_message(handshake_message_a_to_b.clone(), Ok(()))
            .expect_take_out_message(Ok(Some(handshake_message_b_to_a.clone())))
            .expect_is_completed(true)
            .expect_get_encryptor(mock_encryptor_b)
            .take();
        let mock_handshake_session_provider_a = HandshakeSessionProviderBuilder::new()
            .expect_get(
                peer_replica_id_a,
                peer_replica_id_b,
                Role::Initiator,
                mock_handshake_session_a,
            )
            .take();
        let mock_handshake_session_provider_b = HandshakeSessionProviderBuilder::new()
            .expect_get(
                peer_replica_id_b,
                peer_replica_id_a,
                Role::Recipient,
                mock_handshake_session_b,
            )
            .take();
        let mut communication_module_a =
            DefaultCommunicationModule::new(Box::new(mock_handshake_session_provider_a));
        let mut communication_module_b =
            DefaultCommunicationModule::new(Box::new(mock_handshake_session_provider_b));

        communication_module_a.init(peer_replica_id_a);
        communication_module_b.init(peer_replica_id_b);

        // First round trip of handshake messages.
        assert_eq!(
            Ok(()),
            communication_module_a.process_out_message(out_message::Msg::DeliverSystemMessage(
                deliver_sys_msg_unencrypted.clone()
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
        assert_eq!(
            Ok(None),
            communication_module_a.process_in_message(in_message::Msg::SecureChannelHandshake(
                handshake_message_b_to_a.clone()
            ))
        );

        // Second roundtrip of handshake messages.
        assert_eq!(
            vec![OutMessage {
                msg: Some(out_message::Msg::SecureChannelHandshake(
                    handshake_message_a_to_b.clone()
                ))
            }],
            communication_module_a.take_out_messages()
        );
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
        assert_eq!(
            Ok(None),
            communication_module_a.process_in_message(in_message::Msg::SecureChannelHandshake(
                handshake_message_b_to_a.clone()
            ))
        );

        // Handshake complete so previously stashed messages can be sent out.
        assert_eq!(
            Ok(()),
            communication_module_a.process_out_message(out_message::Msg::DeliverSnapshotRequest(
                deliver_snapshot_req_unencrypted.clone()
            ))
        );
        assert_eq!(
            vec![
                OutMessage {
                    msg: Some(out_message::Msg::DeliverSystemMessage(
                        deliver_sys_msg_encrypted.clone()
                    ))
                },
                OutMessage {
                    msg: Some(out_message::Msg::DeliverSnapshotRequest(
                        deliver_snapshot_req_encrypted.clone()
                    ))
                }
            ],
            communication_module_a.take_out_messages()
        );

        assert_eq!(
            Ok(Some(in_message::Msg::DeliverSystemMessage(
                deliver_sys_msg_unencrypted.clone()
            ))),
            communication_module_b.process_in_message(in_message::Msg::DeliverSystemMessage(
                deliver_sys_msg_encrypted.clone()
            ))
        );
    }

    #[test]
    fn test_invalid_handshake_message_fails() {
        let peer_replica_id_a = 11111;
        let peer_replica_id_b = 22222;
        let mock_handshake_session_a = HandshakeSessionBuilder::new()
            .expect_take_out_message(Ok(Some(create_secure_channel_handshake(
                peer_replica_id_a,
                peer_replica_id_b,
            ))))
            .take();
        let mock_handshake_session_b = HandshakeSessionBuilder::new().take();
        let mock_handshake_session_provider_a = HandshakeSessionProviderBuilder::new()
            .expect_get(
                peer_replica_id_a,
                peer_replica_id_b,
                Role::Initiator,
                mock_handshake_session_a,
            )
            .take();
        let mock_handshake_session_provider_b = HandshakeSessionProviderBuilder::new()
            .expect_get(
                peer_replica_id_b,
                peer_replica_id_a,
                Role::Recipient,
                mock_handshake_session_b,
            )
            .take();
        let mut communication_module_a =
            DefaultCommunicationModule::new(Box::new(mock_handshake_session_provider_a));
        let mut communication_module_b =
            DefaultCommunicationModule::new(Box::new(mock_handshake_session_provider_b));

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

    #[test]
    fn test_process_cluster_change() {
        let peer_replica_id_a = 11111;
        let peer_replica_id_b = 22222;
        let handshake_message_a_to_b =
            create_secure_channel_handshake(peer_replica_id_a, peer_replica_id_b);
        let handshake_message_b_to_a =
            create_secure_channel_handshake(peer_replica_id_b, peer_replica_id_a);
        let deliver_system_message = create_deliver_system_message_with_contents(
            peer_replica_id_a,
            peer_replica_id_b,
            "foo".into(),
        );
        let mock_encryptor = EncryptorBuilder::new()
            .expect_encrypt(
                deliver_system_message.message_contents.clone(),
                Ok(deliver_system_message.message_contents.to_vec()),
            )
            .take();
        let mock_handshake_session_a1 = HandshakeSessionBuilder::new()
            .expect_take_out_message(Ok(Some(handshake_message_a_to_b.clone())))
            .take();
        let mock_handshake_session_a2 = HandshakeSessionBuilder::new()
            .expect_take_out_message(Ok(Some(handshake_message_a_to_b.clone())))
            .expect_process_message(handshake_message_b_to_a.clone(), Ok(()))
            .expect_take_out_message(Ok(None))
            .expect_is_completed(true)
            .expect_get_encryptor(mock_encryptor)
            .take();
        let mock_handshake_session_provider_a = HandshakeSessionProviderBuilder::new()
            .expect_get(
                peer_replica_id_a,
                peer_replica_id_b,
                Role::Initiator,
                mock_handshake_session_a1,
            )
            .expect_get(
                peer_replica_id_a,
                peer_replica_id_b,
                Role::Initiator,
                mock_handshake_session_a2,
            )
            .take();
        let mut communication_module_a =
            DefaultCommunicationModule::new(Box::new(mock_handshake_session_provider_a));

        communication_module_a.init(peer_replica_id_a);

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

        // Process cluster change such that `peer_replica_id_b` is no longer part of
        // cluster.
        communication_module_a.process_cluster_change(&vec![peer_replica_id_a]);

        // Handshake is re-initiated when talking to `peer_replica_id_b` again later.
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
        assert_eq!(
            Ok(None),
            communication_module_a.process_in_message(in_message::Msg::SecureChannelHandshake(
                handshake_message_b_to_a.clone()
            ))
        );
        assert_eq!(
            vec![OutMessage {
                msg: Some(out_message::Msg::DeliverSystemMessage(
                    deliver_system_message.clone()
                ))
            },],
            communication_module_a.take_out_messages()
        );
    }
}
