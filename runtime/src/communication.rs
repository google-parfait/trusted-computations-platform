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
//

use core::mem;

use crate::{
    encryptor::Encryptor,
    handshake::{HandshakeSession, HandshakeSessionProvider, Role},
    logger::log::create_logger,
    platform::PalError,
};
use alloc::format;
use alloc::sync::Arc;
use alloc::vec::Vec;
use alloc::{boxed::Box, vec};
use anyhow::anyhow;
use hashbrown::HashMap;
use oak_proto_rust::oak::attestation::v1::{Endorsements, ReferenceValues};
use oak_time::Clock;
use raft::prelude::MessageType;
use slog::{info, o, warn, Logger};
use tcp_proto::runtime::endpoint::*;

#[derive(PartialEq, Debug)]
// Configuration for the Communication Module.
pub struct CommunicationConfig {
    // Number of tick events that must pass before retrying handshake with a failed
    // replica.
    pub handshake_retry_tick: u64,
    // Maximum number of ticks to wait for a response once handshake has been initiated.
    pub handshake_initiated_tick_timeout: u32,
    // The Reference Values for the trusted app that this replica is allowed to communicate
    // with.
    pub reference_values: ReferenceValues,
    // Endorsements for the trusted app that this replica represents.
    pub endorsements: Endorsements,
}

#[derive(PartialEq, Debug)]
/// The type of OutgoingMessage handled by the communication module before being sent out to a replica.
pub enum OutgoingMessage {
    DeliverSystemMessage(DeliverSystemMessage, MessageType),
    DeliverSnapshotRequest(DeliverSnapshotRequest),
    DeliverSnapshotResponse(DeliverSnapshotResponse),
}

/// Responsible for managing communication between raft replicas such as
/// initiating a handshake with replicas seen for the first time and encrypting/
/// decrypting messages for replica-replica communication if replicas have
/// successfully negotiated a handshake.
pub trait CommunicationModule {
    /// Initializes the ReplicaCommunicationManager for the given replica id.
    ///
    /// The ReplicaCommunicationManager must be initialized before first use.
    fn init(
        &mut self,
        replica_id: u64,
        logger: Logger,
        clock: Arc<dyn Clock>,
        config: CommunicationConfig,
    );

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
    ///
    /// Returns `PalError` for unrecoverable errors which must lead to program termination.
    fn process_out_message(&mut self, message: OutgoingMessage) -> Result<(), PalError>;

    /// Process an incoming message from another replica.
    ///
    /// If handshake with the given replica is already successfully completed, then
    /// this method returns the decrypted message that can be processed by the caller.
    ///
    /// If this is the first time a message is received from this replica, then it must be
    /// the handshake message in which case this method verifies the attestation report,
    /// stashes a handshake response (if needed) and returns None since there are no decrypted
    /// messages that need to be processed by the caller.
    ///
    /// Returns `PalError` for unrecoverable errors which must lead to program termination.
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

    // Processes a new tick event and resets any internal failed state if enough ticks
    // have passed.
    fn make_tick(&mut self);
}

// Default implementation of CommunicationModule.
pub struct DefaultCommunicationModule {
    logger: Logger,
    // Per replica state by replica_id.
    replicas: HashMap<u64, CommunicationState>,
    // Self replica_id.
    replica_id: u64,
    handshake_session_provider: Box<dyn HandshakeSessionProvider>,
    config: CommunicationConfig,
}

impl DefaultCommunicationModule {
    pub fn new(handshake_session_provider: Box<dyn HandshakeSessionProvider>) -> Self {
        Self {
            logger: create_logger(),
            replicas: HashMap::new(),
            replica_id: 0,
            handshake_session_provider,
            config: CommunicationConfig {
                // System defaults.
                handshake_retry_tick: 1,
                handshake_initiated_tick_timeout: 10,
                reference_values: ReferenceValues::default(),
                endorsements: Endorsements::default(),
            },
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
    fn init(
        &mut self,
        id: u64,
        logger: Logger,
        clock: Arc<dyn Clock>,
        config: CommunicationConfig,
    ) {
        self.replica_id = id;
        self.logger = logger;
        self.config = config;
        self.handshake_session_provider.init(
            self.logger.new(o!("type" => "handshake")),
            clock,
            self.config.reference_values.clone(),
            self.config.endorsements.clone(),
        );
    }

    fn process_out_message(&mut self, message: OutgoingMessage) -> Result<(), PalError> {
        self.check_initialized()?;

        let peer_replica_id = match &message {
            OutgoingMessage::DeliverSystemMessage(deliver_system_message, _) => {
                deliver_system_message.recipient_replica_id
            }
            OutgoingMessage::DeliverSnapshotRequest(deliver_snapshot_request) => {
                deliver_snapshot_request.recipient_replica_id
            }
            OutgoingMessage::DeliverSnapshotResponse(deliver_snapshot_response) => {
                deliver_snapshot_response.recipient_replica_id
            }
        };

        // We need to store references in local variables below to avoid immutably borrowing "self"
        // in the closure passed to "or_insert_with". "self" is mutably borrowed in
        // "self.replicas.entry(...)" so it cannot be immutably borrowed in the closure again.
        let logger = &self.logger;
        let replica_state = self.replicas.entry(peer_replica_id).or_insert_with(|| {
            CommunicationState::new(logger.clone(), self.config.handshake_initiated_tick_timeout)
        });

        if !replica_state.is_initialized() {
            let handshake_session = self
                .handshake_session_provider
                .get(self.replica_id, peer_replica_id, Role::Initiator)
                .map_err(|err| {
                    warn!(logger, "Failed to get handshake_session {:?}", err);
                    PalError::Internal
                })?;
            replica_state.init(handshake_session)?;
        }

        // Failure to process message should not lead to program termination, so simply log and
        // return.
        let result = replica_state.process_out_message(message);
        if result.is_err() {
            warn!(
                self.logger,
                "Failed to process out_message {:?}",
                result.err()
            );
        }
        Ok(())
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
                return Err(PalError::InvalidOperation);
            }
        };

        // We need to store references in local variables below to avoid immutably borrowing "self"
        // in the closure passed to "or_insert_with". "self" is mutably borrowed in
        // "self.replicas.entry(...)" so it cannot be immutably borrowed in the closure again.
        let logger = &self.logger;
        let replica_state = self.replicas.entry(peer_replica_id).or_insert_with(|| {
            CommunicationState::new(logger.clone(), self.config.handshake_initiated_tick_timeout)
        });

        if !replica_state.is_initialized() {
            let handshake_session = self
                .handshake_session_provider
                .get(self.replica_id, peer_replica_id, Role::Recipient)
                .map_err(|err| {
                    warn!(logger, "Failed to get handshake_session {:?}", err);
                    PalError::Internal
                })?;
            replica_state.init(handshake_session)?;
        }

        // Failure to process message should not lead to program termination, so simply log and
        // return.
        let result = replica_state.process_in_message(message);
        if result.is_err() {
            warn!(
                self.logger,
                "Failed to process in_message {:?}",
                result.err()
            );
            return Ok(None);
        }
        Ok(result.unwrap())
    }

    fn take_out_messages(&mut self) -> Vec<OutMessage> {
        let mut messages = Vec::new();
        for (_, replica_state) in self.replicas.iter_mut() {
            messages.append(&mut replica_state.take_out_messages())
        }
        messages
    }

    fn process_cluster_change(&mut self, new_replica_ids: &[u64]) {
        info!(
            self.logger,
            "Updating cluster with replicas {:?}", new_replica_ids
        );
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

    fn make_tick(&mut self) {
        for replica in self.replicas.values_mut() {
            replica.make_tick();
            if let HandshakeState::Failed(ticks_since_failed) = replica.handshake_state
                && ticks_since_failed >= self.config.handshake_retry_tick
            {
                replica.reset_state_machine();
            }
        }
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
    unencrypted_messages: Vec<OutgoingMessage>,
    encryptor: Option<Box<dyn Encryptor>>,
    handshake_initiated_tick_timeout: u32,
}

#[derive(PartialEq)]
enum HandshakeState {
    // Handshake not performed yet.
    Unknown,
    // Handshake has been initialized.
    Initialized,
    // Handshake has been initiated. Waiting for a response.
    Initiated(u32),
    // Handshake successfully completed and attestation verified.
    Completed,
    // Handshake failed due to internal errors or failed attestation.
    Failed(u64),
}

impl CommunicationState {
    // Create the ReplicaCommunicationState. This happens the first time a
    // message is sent to or received from a peer replica.
    fn new(logger: Logger, handshake_initiated_tick_timeout: u32) -> Self {
        Self {
            logger,
            handshake_state: HandshakeState::Unknown,
            pending_handshake_message: None,
            handshake_session: None,
            unencrypted_messages: Vec::new(),
            encryptor: None,
            handshake_initiated_tick_timeout,
        }
    }

    fn init(&mut self, handshake_session: Box<dyn HandshakeSession>) -> Result<(), PalError> {
        if self.handshake_state != HandshakeState::Unknown {
            warn!(
                self.logger,
                "HandshakeState can only be initialized in Unknown state"
            );
            return Err(PalError::InvalidOperation);
        }
        self.handshake_session = Some(handshake_session);
        self.handshake_state = HandshakeState::Initialized;
        Ok(())
    }

    fn is_initialized(&self) -> bool {
        self.handshake_state != HandshakeState::Unknown
    }

    fn make_tick(&mut self) {
        match &self.handshake_state {
            HandshakeState::Failed(mut ticks_since_failed) => {
                ticks_since_failed += 1;
                self.handshake_state = HandshakeState::Failed(ticks_since_failed);
            }
            HandshakeState::Initiated(mut ticks_since_initiated) => {
                ticks_since_initiated += 1;
                if ticks_since_initiated >= self.handshake_initiated_tick_timeout {
                    info!(self.logger, "Handshake timed out in state Initiated.");
                    self.handshake_state = HandshakeState::Failed(0);
                } else {
                    self.handshake_state = HandshakeState::Initiated(ticks_since_initiated);
                }
            }
            _ => {}
        }
    }

    // Resets the state machine but preserves any messages not sent out yet.
    fn reset_state_machine(&mut self) {
        info!(self.logger, "Resetting state");
        self.handshake_state = HandshakeState::Unknown;
        self.pending_handshake_message = None;
        self.handshake_session = None;
        self.encryptor = None;
    }

    fn transition_to_failed(&mut self, err: &anyhow::Error) {
        warn!(self.logger, "{}", err);
        self.handshake_state = HandshakeState::Failed(0);
    }

    // Pushes a message to be sent. Deduplicating heartbeat messages by replacing the
    // previous version if it is still present.
    fn push_or_replace_unencrypted_message(&mut self, message: OutgoingMessage) {
        if let OutgoingMessage::DeliverSystemMessage(_, MessageType::MsgHeartbeat) = message {
            for message_in_place in &mut self.unencrypted_messages {
                if let OutgoingMessage::DeliverSystemMessage(_, MessageType::MsgHeartbeat) =
                    message_in_place
                {
                    *message_in_place = message;
                    return;
                }
            }
        }
        self.unencrypted_messages.push(message);
    }

    fn process_out_message(&mut self, message: OutgoingMessage) -> anyhow::Result<()> {
        match &self.handshake_state {
            HandshakeState::Unknown => {
                let err =
                    anyhow!("HandshakeState must be initialized before processing out_messages.");
                self.transition_to_failed(&err);
                return Err(err);
            }
            HandshakeState::Initialized => {
                self.pending_handshake_message = self
                    .handshake_session
                    .as_mut()
                    .unwrap()
                    .take_out_message()
                    .inspect_err(|err| {
                        self.transition_to_failed(&err);
                    })?;

                if self.pending_handshake_message.is_none() {
                    let err = anyhow!("No initial handshake message found.");
                    self.transition_to_failed(&err);
                    return Err(err);
                }
                self.push_or_replace_unencrypted_message(message);
                self.handshake_state = HandshakeState::Initiated(0);
                Ok(())
            }
            HandshakeState::Initiated(_) | HandshakeState::Completed => {
                self.push_or_replace_unencrypted_message(message);
                Ok(())
            }
            HandshakeState::Failed(_) => {
                // Keep buffering messages even in Failed state so that they can be
                // retried later.
                self.push_or_replace_unencrypted_message(message);
                warn!(self.logger, "HandshakeState Failed.");
                Ok(())
            }
        }
    }

    fn process_in_message(
        &mut self,
        message: in_message::Msg,
    ) -> anyhow::Result<Option<in_message::Msg>> {
        match &self.handshake_state {
            HandshakeState::Unknown => {
                let err =
                    anyhow!("HandshakeState must be initialized before processing in_messages.");
                self.transition_to_failed(&err);
                return Err(err);
            }
            HandshakeState::Initialized | HandshakeState::Initiated(_) => {
                match message {
                    // Messages in Initialized/Initiated state must be handshake messages.
                    in_message::Msg::SecureChannelHandshake(handshake_message) => {
                        self.handshake_session
                            .as_mut()
                            .unwrap()
                            .process_message(handshake_message)
                            .inspect_err(|err| {
                                self.transition_to_failed(&err);
                            })?;
                        self.pending_handshake_message = self
                            .handshake_session
                            .as_mut()
                            .unwrap()
                            .take_out_message()
                            .inspect_err(|err| {
                                self.transition_to_failed(&err);
                            })?;
                        if self.handshake_session.as_ref().unwrap().is_completed() {
                            // Consume `self.handshake_session`.
                            let handshake_session = self.handshake_session.take();
                            self.encryptor = handshake_session.unwrap().get_encryptor();
                            self.handshake_state = HandshakeState::Completed;
                        } else if self.handshake_state == HandshakeState::Initialized {
                            self.handshake_state = HandshakeState::Initiated(0);
                        }
                        Ok(None)
                    }
                    _ => {
                        let err = anyhow!(format!(
                            "Message must be SecureChannelHandshake but found {:?}",
                            message
                        ));
                        self.transition_to_failed(&err);
                        Err(err)
                    }
                }
            }
            HandshakeState::Completed => Ok(self.decrypt_message(message)),
            HandshakeState::Failed(_) => {
                warn!(self.logger, "HandshakeState Failed.");
                Ok(None)
            }
        }
    }

    fn decrypt_message(&mut self, message: in_message::Msg) -> Option<in_message::Msg> {
        let encryptor = self.encryptor.as_mut().unwrap();
        let result = match message {
            in_message::Msg::DeliverSystemMessage(mut msg) => encryptor
                .decrypt(msg.payload.as_ref().unwrap())
                .and_then(|decrypted_msg| {
                    msg.payload = Some(Payload {
                        contents: decrypted_msg.into(),
                        ..Default::default()
                    });
                    Ok(in_message::Msg::DeliverSystemMessage(msg))
                }),
            in_message::Msg::DeliverSnapshotRequest(mut msg) => encryptor
                .decrypt(msg.payload.as_ref().unwrap())
                .and_then(|decrypted_msg| {
                    msg.payload = Some(Payload {
                        contents: decrypted_msg.into(),
                        ..Default::default()
                    });
                    Ok(in_message::Msg::DeliverSnapshotRequest(msg))
                }),
            in_message::Msg::DeliverSnapshotResponse(mut msg) => encryptor
                .decrypt(msg.payload.as_ref().unwrap())
                .and_then(|decrypted_msg| {
                    msg.payload = Some(Payload {
                        contents: decrypted_msg.into(),
                        ..Default::default()
                    });
                    Ok(in_message::Msg::DeliverSnapshotResponse(msg))
                }),
            in_message::Msg::SecureChannelHandshake(_msg) => {
                // Receiving SecureChannelHandshake in Completed state indicates that the last
                // attempt likely failed on the other side.
                // Transition to error state so that handshake can be retried after enough ticks
                // have passed.
                let err = anyhow!(
                    "SecureChannelHandshake received in Completed state. Transitioning to Failed state to retry handshake later."
                );
                self.transition_to_failed(&err);
                return None;
            }
            _ => Err(anyhow!(format!(
                "Unexpected message encountered for decryption {:?}",
                message
            ))),
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
        let encryptor = self.encryptor.as_mut().unwrap();

        for unencrypted_message in unencrypted_msgs {
            let result = match unencrypted_message {
                OutgoingMessage::DeliverSystemMessage(mut message, _) => encryptor
                    .encrypt(&message.payload.as_ref().unwrap().contents)
                    .and_then(|encrypted_message| {
                        message.payload = Some(encrypted_message);
                        messages.push(OutMessage {
                            msg: Some(out_message::Msg::DeliverSystemMessage(message)),
                        });
                        Ok(())
                    }),
                OutgoingMessage::DeliverSnapshotRequest(mut message) => encryptor
                    .encrypt(&message.payload.as_ref().unwrap().contents)
                    .and_then(|encrypted_message| {
                        message.payload = Some(encrypted_message);
                        messages.push(OutMessage {
                            msg: Some(out_message::Msg::DeliverSnapshotRequest(message)),
                        });
                        Ok(())
                    }),
                OutgoingMessage::DeliverSnapshotResponse(mut message) => encryptor
                    .encrypt(&message.payload.as_ref().unwrap().contents)
                    .and_then(|encrypted_message| {
                        message.payload = Some(encrypted_message.into());
                        messages.push(OutMessage {
                            msg: Some(out_message::Msg::DeliverSnapshotResponse(message)),
                        });
                        Ok(())
                    }),
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

    use self::mockall::predicate::{always, eq};
    use crate::communication::{mem, OutgoingMessage};
    use crate::handshake::Role;
    use crate::logger::log::create_logger;
    use crate::mock::{MockEncryptor, MockHandshakeSession, MockHandshakeSessionProvider};
    use crate::{
        communication::{CommunicationConfig, CommunicationModule, DefaultCommunicationModule},
        platform::PalError,
    };
    use alloc::sync::Arc;
    use alloc::vec;
    use alloc::vec::Vec;
    use anyhow::anyhow;
    use googletest::{
        assert_that,
        matchers::{eq as gt_eq, unordered_elements_are},
    };
    use oak_proto_rust::oak::attestation::v1::{Endorsements, ReferenceValues};
    use oak_time::{clock::FixedClock, UNIX_EPOCH};
    use prost::bytes::Bytes;
    use raft::prelude::MessageType;
    use tcp_proto::runtime::endpoint::*;

    fn create_deliver_system_message(
        sender_replica_id: u64,
        recipient_replica_id: u64,
    ) -> DeliverSystemMessage {
        DeliverSystemMessage {
            recipient_replica_id,
            sender_replica_id,
            ..Default::default()
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
            payload: Some(Payload {
                contents: message_contents,
                ..Default::default()
            }),
            ..Default::default()
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
            ..Default::default()
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
            payload: Some(Payload {
                contents: payload_contents,
                ..Default::default()
            }),
            ..Default::default()
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
            ..Default::default()
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
            payload: Some(Payload {
                contents: payload_contents,
                ..Default::default()
            }),
            ..Default::default()
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

    fn create_unsupported_in_message() -> in_message::Msg {
        in_message::Msg::StartReplica(StartReplicaRequest {
            is_leader: true,
            replica_id_hint: 0,
            raft_config: None,
            app_config: Bytes::new(),
            is_ephemeral: false,
            ..Default::default()
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

        fn expect_init(
            mut self,
            reference_values: ReferenceValues,
            endorsements: Endorsements,
        ) -> HandshakeSessionProviderBuilder {
            self.mock_handshake_session_provider
                .expect_init()
                .with(always(), always(), eq(reference_values), eq(endorsements))
                .once()
                .return_const(());
            self
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
                .return_once(move |_, _, _| Ok(Box::new(mock_handshake_session)));
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
            result: anyhow::Result<()>,
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
            message: anyhow::Result<Option<SecureChannelHandshake>>,
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
            result: anyhow::Result<Payload>,
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
            payload: Payload,
            result: anyhow::Result<Vec<u8>>,
        ) -> EncryptorBuilder {
            self.mock_encryptor
                .expect_decrypt()
                .with(eq(payload))
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
            .expect_init(ReferenceValues::default(), Endorsements::default())
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
            communication_module.process_out_message(OutgoingMessage::DeliverSystemMessage(
                create_deliver_system_message(self_replica_id, peer_replica_id_a),
                MessageType::MsgHeartbeat,
            ))
        );
        let clock = FixedClock::at_instant(UNIX_EPOCH);
        communication_module.init(
            self_replica_id,
            create_logger(),
            Arc::new(clock),
            CommunicationConfig {
                reference_values: ReferenceValues::default(),
                endorsements: Endorsements::default(),
                handshake_retry_tick: 1,
                handshake_initiated_tick_timeout: 10,
            },
        );

        assert_eq!(
            Ok(()),
            communication_module.process_out_message(OutgoingMessage::DeliverSystemMessage(
                create_deliver_system_message(self_replica_id, peer_replica_id_a),
                MessageType::MsgHeartbeat,
            ))
        );
        assert_eq!(
            Ok(()),
            communication_module.process_out_message(OutgoingMessage::DeliverSnapshotRequest(
                create_deliver_snapshot_request(self_replica_id, peer_replica_id_a)
            ))
        );
        assert_eq!(
            Ok(()),
            communication_module.process_out_message(OutgoingMessage::DeliverSnapshotResponse(
                create_deliver_snapshot_response(self_replica_id, peer_replica_id_a)
            ))
        );
        assert_eq!(
            Ok(()),
            communication_module.process_out_message(OutgoingMessage::DeliverSystemMessage(
                create_deliver_system_message(self_replica_id, peer_replica_id_b),
                MessageType::MsgHeartbeat
            ))
        );
        assert_that!(
            communication_module.take_out_messages(),
            unordered_elements_are![
                gt_eq(OutMessage {
                    msg: Some(out_message::Msg::SecureChannelHandshake(
                        handshake_message_a.clone()
                    ))
                }),
                gt_eq(OutMessage {
                    msg: Some(out_message::Msg::SecureChannelHandshake(
                        handshake_message_b.clone()
                    ))
                })
            ],
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
                Payload {
                    contents: deliver_sys_msg_encrypted
                        .payload
                        .as_ref()
                        .unwrap()
                        .contents
                        .clone(),
                    ..Default::default()
                },
                Ok(deliver_sys_msg_unencrypted
                    .payload
                    .as_ref()
                    .unwrap()
                    .contents
                    .to_vec()),
            )
            .expect_decrypt(
                Payload {
                    contents: deliver_snapshot_req_encrypted
                        .payload
                        .as_ref()
                        .unwrap()
                        .contents
                        .clone(),
                    ..Default::default()
                },
                Ok(deliver_snapshot_req_unencrypted
                    .payload
                    .as_ref()
                    .unwrap()
                    .contents
                    .to_vec()),
            )
            .expect_decrypt(
                Payload {
                    contents: deliver_snapshot_resp_encrypted
                        .payload
                        .as_ref()
                        .unwrap()
                        .contents
                        .clone(),
                    ..Default::default()
                },
                Ok(deliver_snapshot_resp_unencrypted
                    .payload
                    .as_ref()
                    .unwrap()
                    .contents
                    .to_vec()),
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
            .expect_init(ReferenceValues::default(), Endorsements::default())
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
        let clock = FixedClock::at_instant(UNIX_EPOCH);
        communication_module.init(
            self_replica_id,
            create_logger(),
            Arc::new(clock),
            CommunicationConfig {
                reference_values: ReferenceValues::default(),
                endorsements: Endorsements::default(),
                handshake_retry_tick: 1,
                handshake_initiated_tick_timeout: 10,
            },
        );

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
            Err(PalError::InvalidOperation),
            communication_module.process_in_message(create_unsupported_in_message())
        );
        assert_that!(
            communication_module.take_out_messages(),
            unordered_elements_are![
                gt_eq(OutMessage {
                    msg: Some(out_message::Msg::SecureChannelHandshake(
                        handshake_message_a.clone()
                    ))
                }),
                gt_eq(OutMessage {
                    msg: Some(out_message::Msg::SecureChannelHandshake(
                        handshake_message_b.clone()
                    ))
                })
            ],
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
                deliver_sys_msg_unencrypted
                    .payload
                    .as_ref()
                    .unwrap()
                    .contents
                    .clone(),
                Ok(Payload {
                    contents: deliver_sys_msg_encrypted
                        .payload
                        .as_ref()
                        .unwrap()
                        .contents
                        .clone(),
                    ..Default::default()
                }),
            )
            .expect_encrypt(
                deliver_snapshot_req_unencrypted
                    .payload
                    .as_ref()
                    .unwrap()
                    .contents
                    .clone(),
                Ok(Payload {
                    contents: deliver_snapshot_req_encrypted
                        .payload
                        .as_ref()
                        .unwrap()
                        .contents
                        .clone(),
                    ..Default::default()
                }),
            )
            .take();
        let mock_encryptor_b = EncryptorBuilder::new()
            .expect_decrypt(
                Payload {
                    contents: deliver_sys_msg_encrypted
                        .payload
                        .as_ref()
                        .unwrap()
                        .contents
                        .clone(),
                    ..Default::default()
                },
                Ok(deliver_sys_msg_unencrypted
                    .payload
                    .as_ref()
                    .unwrap()
                    .contents
                    .to_vec()),
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
            .expect_init(ReferenceValues::default(), Endorsements::default())
            .expect_get(
                peer_replica_id_a,
                peer_replica_id_b,
                Role::Initiator,
                mock_handshake_session_a,
            )
            .take();
        let mock_handshake_session_provider_b = HandshakeSessionProviderBuilder::new()
            .expect_init(ReferenceValues::default(), Endorsements::default())
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
        let clock_a = FixedClock::at_instant(UNIX_EPOCH);
        let clock_b = FixedClock::at_instant(UNIX_EPOCH);
        communication_module_a.init(
            peer_replica_id_a,
            create_logger(),
            Arc::new(clock_a),
            CommunicationConfig {
                reference_values: ReferenceValues::default(),
                endorsements: Endorsements::default(),
                handshake_retry_tick: 1,
                handshake_initiated_tick_timeout: 10,
            },
        );
        communication_module_b.init(
            peer_replica_id_b,
            create_logger(),
            Arc::new(clock_b),
            CommunicationConfig {
                reference_values: ReferenceValues::default(),
                endorsements: Endorsements::default(),
                handshake_retry_tick: 1,
                handshake_initiated_tick_timeout: 10,
            },
        );

        // Handshake initiated from a to b.
        assert_eq!(
            Ok(()),
            communication_module_a.process_out_message(OutgoingMessage::DeliverSystemMessage(
                deliver_sys_msg_unencrypted.clone(),
                MessageType::MsgHeartbeat,
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
            communication_module_a.process_out_message(OutgoingMessage::DeliverSnapshotRequest(
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
                deliver_sys_msg_unencrypted
                    .payload
                    .as_ref()
                    .unwrap()
                    .contents
                    .clone(),
                Ok(Payload {
                    contents: deliver_sys_msg_encrypted
                        .payload
                        .as_ref()
                        .unwrap()
                        .contents
                        .clone(),
                    ..Default::default()
                }),
            )
            .expect_encrypt(
                deliver_snapshot_req_unencrypted
                    .payload
                    .as_ref()
                    .unwrap()
                    .contents
                    .clone(),
                Ok(Payload {
                    contents: deliver_snapshot_req_encrypted
                        .payload
                        .as_ref()
                        .unwrap()
                        .contents
                        .clone(),
                    ..Default::default()
                }),
            )
            .take();
        let mock_encryptor_b = EncryptorBuilder::new()
            .expect_decrypt(
                Payload {
                    contents: deliver_sys_msg_encrypted
                        .payload
                        .as_ref()
                        .unwrap()
                        .contents
                        .clone(),
                    ..Default::default()
                },
                Ok(deliver_sys_msg_unencrypted
                    .payload
                    .as_ref()
                    .unwrap()
                    .contents
                    .to_vec()),
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
            .expect_init(ReferenceValues::default(), Endorsements::default())
            .expect_get(
                peer_replica_id_a,
                peer_replica_id_b,
                Role::Initiator,
                mock_handshake_session_a,
            )
            .take();
        let mock_handshake_session_provider_b = HandshakeSessionProviderBuilder::new()
            .expect_init(ReferenceValues::default(), Endorsements::default())
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
        let clock_a = FixedClock::at_instant(UNIX_EPOCH);
        let clock_b = FixedClock::at_instant(UNIX_EPOCH);
        communication_module_a.init(
            peer_replica_id_a,
            create_logger(),
            Arc::new(clock_a),
            CommunicationConfig {
                reference_values: ReferenceValues::default(),
                endorsements: Endorsements::default(),
                handshake_retry_tick: 1,
                handshake_initiated_tick_timeout: 10,
            },
        );
        communication_module_b.init(
            peer_replica_id_b,
            create_logger(),
            Arc::new(clock_b),
            CommunicationConfig {
                reference_values: ReferenceValues::default(),
                endorsements: Endorsements::default(),
                handshake_retry_tick: 1,
                handshake_initiated_tick_timeout: 10,
            },
        );

        // First round trip of handshake messages.
        assert_eq!(
            Ok(()),
            communication_module_a.process_out_message(OutgoingMessage::DeliverSystemMessage(
                deliver_sys_msg_unencrypted.clone(),
                MessageType::MsgHeartbeat,
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
            communication_module_a.process_out_message(OutgoingMessage::DeliverSnapshotRequest(
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
            .expect_init(ReferenceValues::default(), Endorsements::default())
            .expect_get(
                peer_replica_id_a,
                peer_replica_id_b,
                Role::Initiator,
                mock_handshake_session_a,
            )
            .take();
        let mock_handshake_session_provider_b = HandshakeSessionProviderBuilder::new()
            .expect_init(ReferenceValues::default(), Endorsements::default())
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
        let clock_a = FixedClock::at_instant(UNIX_EPOCH);
        let clock_b = FixedClock::at_instant(UNIX_EPOCH);
        communication_module_a.init(
            peer_replica_id_a,
            create_logger(),
            Arc::new(clock_a),
            CommunicationConfig {
                reference_values: ReferenceValues::default(),
                endorsements: Endorsements::default(),
                handshake_retry_tick: 1,
                handshake_initiated_tick_timeout: 10,
            },
        );
        communication_module_b.init(
            peer_replica_id_b,
            create_logger(),
            Arc::new(clock_b),
            CommunicationConfig {
                reference_values: ReferenceValues::default(),
                endorsements: Endorsements::default(),
                handshake_retry_tick: 1,
                handshake_initiated_tick_timeout: 10,
            },
        );

        assert_eq!(
            Ok(()),
            communication_module_a.process_out_message(OutgoingMessage::DeliverSystemMessage(
                deliver_system_message_a_to_b.clone(),
                MessageType::MsgHeartbeat,
            ))
        );
        assert_eq!(
            Ok(None),
            communication_module_b.process_in_message(in_message::Msg::DeliverSystemMessage(
                deliver_system_message_a_to_b.clone()
            ))
        );
        assert_eq!(
            Ok(None),
            communication_module_a.process_in_message(in_message::Msg::DeliverSystemMessage(
                deliver_system_message_b_to_a.clone()
            ))
        );
        // Both a and b are in Failed state, so receiving or sending any subsequent messages should
        // be a no-op.
        assert_eq!(
            Ok(None),
            communication_module_a.process_in_message(in_message::Msg::DeliverSystemMessage(
                deliver_system_message_b_to_a.clone()
            ))
        );
        assert_eq!(
            Ok(None),
            communication_module_b.process_in_message(in_message::Msg::DeliverSystemMessage(
                deliver_system_message_a_to_b.clone()
            ))
        );
        assert_eq!(
            Ok(()),
            communication_module_a.process_out_message(OutgoingMessage::DeliverSystemMessage(
                deliver_system_message_a_to_b.clone(),
                MessageType::MsgHeartbeat,
            ))
        );
        assert_eq!(
            Ok(()),
            communication_module_b.process_out_message(OutgoingMessage::DeliverSystemMessage(
                deliver_system_message_b_to_a.clone(),
                MessageType::MsgHeartbeat,
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
                deliver_system_message
                    .payload
                    .as_ref()
                    .unwrap()
                    .contents
                    .clone(),
                Ok(Payload {
                    contents: deliver_system_message
                        .payload
                        .as_ref()
                        .unwrap()
                        .contents
                        .clone(),
                    ..Default::default()
                }),
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
            .expect_init(ReferenceValues::default(), Endorsements::default())
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
        let clock = FixedClock::at_instant(UNIX_EPOCH);
        communication_module_a.init(
            peer_replica_id_a,
            create_logger(),
            Arc::new(clock),
            CommunicationConfig {
                reference_values: ReferenceValues::default(),
                endorsements: Endorsements::default(),
                handshake_retry_tick: 1,
                handshake_initiated_tick_timeout: 10,
            },
        );

        // Handshake initiated from a to b.
        assert_eq!(
            Ok(()),
            communication_module_a.process_out_message(OutgoingMessage::DeliverSystemMessage(
                deliver_system_message.clone(),
                MessageType::MsgHeartbeat,
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
            communication_module_a.process_out_message(OutgoingMessage::DeliverSystemMessage(
                deliver_system_message.clone(),
                MessageType::MsgHeartbeat,
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

    #[test]
    fn test_handshake_retry() {
        let peer_replica_id_a = 11111;
        let peer_replica_id_b = 22222;
        let config = CommunicationConfig {
            handshake_retry_tick: 2,
            handshake_initiated_tick_timeout: 10,
            reference_values: ReferenceValues::default(),
            endorsements: Endorsements::default(),
        };
        let handshake_message_a_to_b =
            create_secure_channel_handshake(peer_replica_id_a, peer_replica_id_b);
        let handshake_message_b_to_a =
            create_secure_channel_handshake(peer_replica_id_b, peer_replica_id_a);
        let deliver_system_message_1 = create_deliver_system_message_with_contents(
            peer_replica_id_a,
            peer_replica_id_b,
            "foo".into(),
        );
        let deliver_system_message_2 = create_deliver_system_message_with_contents(
            peer_replica_id_a,
            peer_replica_id_b,
            "bar".into(),
        );
        let deliver_system_message_3 = create_deliver_system_message_with_contents(
            peer_replica_id_a,
            peer_replica_id_b,
            "baz".into(),
        );
        let mock_encryptor = EncryptorBuilder::new()
            .expect_encrypt(
                deliver_system_message_1
                    .payload
                    .as_ref()
                    .unwrap()
                    .contents
                    .clone(),
                Ok(Payload {
                    contents: deliver_system_message_1
                        .payload
                        .as_ref()
                        .unwrap()
                        .contents
                        .clone(),
                    ..Default::default()
                }),
            )
            .expect_encrypt(
                deliver_system_message_2
                    .payload
                    .as_ref()
                    .unwrap()
                    .contents
                    .clone(),
                Ok(Payload {
                    contents: deliver_system_message_2
                        .payload
                        .as_ref()
                        .unwrap()
                        .contents
                        .clone(),
                    ..Default::default()
                }),
            )
            .expect_encrypt(
                deliver_system_message_3
                    .payload
                    .as_ref()
                    .unwrap()
                    .contents
                    .clone(),
                Ok(Payload {
                    contents: deliver_system_message_3
                        .payload
                        .as_ref()
                        .unwrap()
                        .contents
                        .clone(),
                    ..Default::default()
                }),
            )
            .take();
        // Pretend that first handshake attempt failed.
        let mock_handshake_session_1 = HandshakeSessionBuilder::new()
            .expect_take_out_message(Ok(Some(handshake_message_a_to_b.clone())))
            .expect_process_message(handshake_message_b_to_a.clone(), Err(anyhow!("Error")))
            .take();
        let mock_handshake_session_2 = HandshakeSessionBuilder::new()
            .expect_take_out_message(Ok(Some(handshake_message_a_to_b.clone())))
            .expect_process_message(handshake_message_b_to_a.clone(), Ok(()))
            .expect_take_out_message(Ok(None))
            .expect_is_completed(true)
            .expect_get_encryptor(mock_encryptor)
            .take();

        // HandshakeSession is created twice total, once again when enough ticks have
        // passed.
        let mock_handshake_session_provider = HandshakeSessionProviderBuilder::new()
            .expect_init(ReferenceValues::default(), Endorsements::default())
            .expect_get(
                peer_replica_id_a,
                peer_replica_id_b,
                Role::Initiator,
                mock_handshake_session_1,
            )
            .expect_get(
                peer_replica_id_a,
                peer_replica_id_b,
                Role::Initiator,
                mock_handshake_session_2,
            )
            .take();

        let mut communication_module =
            DefaultCommunicationModule::new(Box::new(mock_handshake_session_provider));
        let clock = FixedClock::at_instant(UNIX_EPOCH);
        communication_module.init(peer_replica_id_a, create_logger(), Arc::new(clock), config);

        // Initiate handshake.
        assert_eq!(
            Ok(()),
            communication_module.process_out_message(OutgoingMessage::DeliverSystemMessage(
                deliver_system_message_1.clone(),
                MessageType::MsgHeartbeat,
            ))
        );
        assert_eq!(
            vec![OutMessage {
                msg: Some(out_message::Msg::SecureChannelHandshake(
                    handshake_message_a_to_b.clone()
                ))
            }],
            communication_module.take_out_messages()
        );
        // Processing below message will fail the state machine.
        assert_eq!(
            Ok(None),
            communication_module.process_in_message(in_message::Msg::SecureChannelHandshake(
                handshake_message_b_to_a.clone()
            ))
        );
        // Try sending messages in FAILED state which will be buffered.
        assert_eq!(
            Ok(()),
            communication_module.process_out_message(OutgoingMessage::DeliverSystemMessage(
                deliver_system_message_2.clone(),
                MessageType::MsgHeartbeatResponse,
            ))
        );
        // Taking out messages again should return empty since handshake has not completed.
        assert_eq!(
            Vec::<OutMessage>::new(),
            communication_module.take_out_messages()
        );
        // Make enough ticks to retry handshake.
        communication_module.make_tick();
        communication_module.make_tick();
        // Initiate handshake again and succeed.
        assert_eq!(
            Ok(()),
            communication_module.process_out_message(OutgoingMessage::DeliverSystemMessage(
                deliver_system_message_3.clone(),
                MessageType::MsgHup,
            ))
        );
        assert_eq!(
            vec![OutMessage {
                msg: Some(out_message::Msg::SecureChannelHandshake(
                    handshake_message_a_to_b.clone()
                ))
            }],
            communication_module.take_out_messages()
        );
        assert_eq!(
            Ok(None),
            communication_module.process_in_message(in_message::Msg::SecureChannelHandshake(
                handshake_message_b_to_a.clone()
            ))
        );
        assert_eq!(
            vec![
                OutMessage {
                    msg: Some(out_message::Msg::DeliverSystemMessage(
                        deliver_system_message_1.clone()
                    ))
                },
                OutMessage {
                    msg: Some(out_message::Msg::DeliverSystemMessage(
                        deliver_system_message_2.clone()
                    ))
                },
                OutMessage {
                    msg: Some(out_message::Msg::DeliverSystemMessage(
                        deliver_system_message_3.clone()
                    ))
                }
            ],
            communication_module.take_out_messages()
        );
    }

    #[test]
    fn test_handshake_initiated_tick_timeout() {
        let peer_replica_id_a = 11111;
        let peer_replica_id_b = 22222;
        let config = CommunicationConfig {
            handshake_retry_tick: 1,
            handshake_initiated_tick_timeout: 3,
            reference_values: ReferenceValues::default(),
            endorsements: Endorsements::default(),
        };
        let handshake_message_a_to_b =
            create_secure_channel_handshake(peer_replica_id_a, peer_replica_id_b);
        let handshake_message_b_to_a =
            create_secure_channel_handshake(peer_replica_id_b, peer_replica_id_a);
        let deliver_system_message_1 = create_deliver_system_message_with_contents(
            peer_replica_id_a,
            peer_replica_id_b,
            "foo".into(),
        );
        let deliver_system_message_2 = create_deliver_system_message_with_contents(
            peer_replica_id_a,
            peer_replica_id_b,
            "bar".into(),
        );
        let deliver_system_message_3 = create_deliver_system_message_with_contents(
            peer_replica_id_a,
            peer_replica_id_b,
            "baz".into(),
        );
        let mock_encryptor = EncryptorBuilder::new()
            .expect_encrypt(
                deliver_system_message_1
                    .payload
                    .as_ref()
                    .unwrap()
                    .contents
                    .clone(),
                Ok(Payload {
                    contents: deliver_system_message_1
                        .payload
                        .as_ref()
                        .unwrap()
                        .contents
                        .clone(),
                    ..Default::default()
                }),
            )
            .expect_encrypt(
                deliver_system_message_2
                    .payload
                    .as_ref()
                    .unwrap()
                    .contents
                    .clone(),
                Ok(Payload {
                    contents: deliver_system_message_2
                        .payload
                        .as_ref()
                        .unwrap()
                        .contents
                        .clone(),
                    ..Default::default()
                }),
            )
            .expect_encrypt(
                deliver_system_message_3
                    .payload
                    .as_ref()
                    .unwrap()
                    .contents
                    .clone(),
                Ok(Payload {
                    contents: deliver_system_message_3
                        .payload
                        .as_ref()
                        .unwrap()
                        .contents
                        .clone(),
                    ..Default::default()
                }),
            )
            .take();
        // Pretend that first handshake attempt timed out.
        let mock_handshake_session_1 = HandshakeSessionBuilder::new()
            .expect_take_out_message(Ok(Some(handshake_message_a_to_b.clone())))
            .take();
        let mock_handshake_session_2 = HandshakeSessionBuilder::new()
            .expect_take_out_message(Ok(Some(handshake_message_a_to_b.clone())))
            .expect_process_message(handshake_message_b_to_a.clone(), Ok(()))
            .expect_take_out_message(Ok(None))
            .expect_is_completed(true)
            .expect_get_encryptor(mock_encryptor)
            .take();

        // HandshakeSession is created twice total, once again when enough ticks have passed.
        let mock_handshake_session_provider = HandshakeSessionProviderBuilder::new()
            .expect_init(ReferenceValues::default(), Endorsements::default())
            .expect_get(
                peer_replica_id_a,
                peer_replica_id_b,
                Role::Initiator,
                mock_handshake_session_1,
            )
            .expect_get(
                peer_replica_id_a,
                peer_replica_id_b,
                Role::Initiator,
                mock_handshake_session_2,
            )
            .take();

        let mut communication_module =
            DefaultCommunicationModule::new(Box::new(mock_handshake_session_provider));
        let clock = FixedClock::at_instant(UNIX_EPOCH);
        communication_module.init(peer_replica_id_a, create_logger(), Arc::new(clock), config);

        // Initiate handshake.
        assert_eq!(
            Ok(()),
            communication_module.process_out_message(OutgoingMessage::DeliverSystemMessage(
                deliver_system_message_1.clone(),
                MessageType::MsgHeartbeat,
            ))
        );
        assert_eq!(
            vec![OutMessage {
                msg: Some(out_message::Msg::SecureChannelHandshake(
                    handshake_message_a_to_b.clone()
                ))
            }],
            communication_module.take_out_messages()
        );

        // Make enough ticks to timeout in Initiated state.
        communication_module.make_tick();
        communication_module.make_tick();
        communication_module.make_tick();
        // Try sending messages in FAILED state which will be buffered.
        assert_eq!(
            Ok(()),
            communication_module.process_out_message(OutgoingMessage::DeliverSystemMessage(
                deliver_system_message_2.clone(),
                MessageType::MsgHeartbeatResponse,
            ))
        );
        // Taking out messages should return empty since handshake has not completed.
        assert_eq!(
            Vec::<OutMessage>::new(),
            communication_module.take_out_messages()
        );
        // Make more ticks to retry FAILED handshake.
        communication_module.make_tick();
        // Initiate handshake again and succeed.
        assert_eq!(
            Ok(()),
            communication_module.process_out_message(OutgoingMessage::DeliverSystemMessage(
                deliver_system_message_3.clone(),
                MessageType::MsgHup,
            ))
        );
        assert_eq!(
            vec![OutMessage {
                msg: Some(out_message::Msg::SecureChannelHandshake(
                    handshake_message_a_to_b.clone()
                ))
            }],
            communication_module.take_out_messages()
        );
        assert_eq!(
            Ok(None),
            communication_module.process_in_message(in_message::Msg::SecureChannelHandshake(
                handshake_message_b_to_a.clone()
            ))
        );
        assert_eq!(
            vec![
                OutMessage {
                    msg: Some(out_message::Msg::DeliverSystemMessage(
                        deliver_system_message_1.clone()
                    ))
                },
                OutMessage {
                    msg: Some(out_message::Msg::DeliverSystemMessage(
                        deliver_system_message_2.clone()
                    ))
                },
                OutMessage {
                    msg: Some(out_message::Msg::DeliverSystemMessage(
                        deliver_system_message_3.clone()
                    ))
                }
            ],
            communication_module.take_out_messages()
        );
    }

    #[test]
    fn test_heartbeat_messages_are_deduplicated() {
        let peer_replica_id_a = 11111;
        let peer_replica_id_b = 22222;
        let handshake_message_a_to_b =
            create_secure_channel_handshake(peer_replica_id_a, peer_replica_id_b);
        let handshake_message_b_to_a =
            create_secure_channel_handshake(peer_replica_id_b, peer_replica_id_a);
        let deliver_sys_msg_1_encrypted = create_deliver_system_message_with_contents(
            peer_replica_id_a,
            peer_replica_id_b,
            "sys_msg_1_ciphertext".into(),
        );
        let deliver_sys_msg_1_unencrypted = create_deliver_system_message_with_contents(
            peer_replica_id_a,
            peer_replica_id_b,
            "sys_msg_1_plaintext".into(),
        );
        let deliver_sys_msg_2_encrypted = create_deliver_system_message_with_contents(
            peer_replica_id_a,
            peer_replica_id_b,
            "sys_msg_2_ciphertext".into(),
        );
        let deliver_sys_msg_2_unencrypted = create_deliver_system_message_with_contents(
            peer_replica_id_a,
            peer_replica_id_b,
            "sys_msg_2_plaintext".into(),
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
                deliver_snapshot_req_unencrypted
                    .payload
                    .as_ref()
                    .unwrap()
                    .contents
                    .clone(),
                Ok(Payload {
                    contents: deliver_snapshot_req_encrypted
                        .payload
                        .as_ref()
                        .unwrap()
                        .contents
                        .clone(),
                    ..Default::default()
                }),
            )
            .expect_encrypt(
                deliver_sys_msg_2_unencrypted
                    .payload
                    .as_ref()
                    .unwrap()
                    .contents
                    .clone(),
                Ok(Payload {
                    contents: deliver_sys_msg_2_encrypted
                        .payload
                        .as_ref()
                        .unwrap()
                        .contents
                        .clone(),
                    ..Default::default()
                }),
            )
            .take();
        let mock_handshake_session_a = HandshakeSessionBuilder::new()
            .expect_take_out_message(Ok(Some(handshake_message_a_to_b.clone())))
            .expect_process_message(handshake_message_b_to_a.clone(), Ok(()))
            .expect_take_out_message(Ok(None))
            .expect_is_completed(true)
            .expect_get_encryptor(mock_encryptor_a)
            .take();
        let mock_handshake_session_provider_a = HandshakeSessionProviderBuilder::new()
            .expect_init(ReferenceValues::default(), Endorsements::default())
            .expect_get(
                peer_replica_id_a,
                peer_replica_id_b,
                Role::Initiator,
                mock_handshake_session_a,
            )
            .take();
        let mut communication_module_a =
            DefaultCommunicationModule::new(Box::new(mock_handshake_session_provider_a));
        let clock_a = FixedClock::at_instant(UNIX_EPOCH);
        communication_module_a.init(
            peer_replica_id_a,
            create_logger(),
            Arc::new(clock_a),
            CommunicationConfig {
                reference_values: ReferenceValues::default(),
                endorsements: Endorsements::default(),
                handshake_retry_tick: 1,
                handshake_initiated_tick_timeout: 10,
            },
        );

        // Handshake initiated from a to b.
        assert_eq!(
            Ok(()),
            communication_module_a.process_out_message(OutgoingMessage::DeliverSystemMessage(
                deliver_sys_msg_1_unencrypted.clone(),
                MessageType::MsgHeartbeat,
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
            communication_module_a.process_out_message(OutgoingMessage::DeliverSnapshotRequest(
                deliver_snapshot_req_unencrypted.clone()
            ))
        );

        // This second heartbeat message should overwrite the first.
        assert_eq!(
            Ok(()),
            communication_module_a.process_out_message(OutgoingMessage::DeliverSystemMessage(
                deliver_sys_msg_2_unencrypted.clone(),
                MessageType::MsgHeartbeat,
            ))
        );
        assert_eq!(
            vec![
                OutMessage {
                    msg: Some(out_message::Msg::DeliverSystemMessage(
                        deliver_sys_msg_2_encrypted.clone()
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
    }
}
