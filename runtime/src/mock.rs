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

#![cfg(feature = "std")]

extern crate mockall;
extern crate tcp_proto;

use self::mockall::mock;
use crate::communication::{CommunicationConfig, CommunicationModule, OutgoingMessage};
use crate::consensus;
use crate::consensus::{Raft, RaftLightReady, RaftReady, Store};
use crate::encryptor::Encryptor;
use crate::handshake::{HandshakeSession, HandshakeSessionProvider, Role};
use crate::model::{
    Actor, ActorCommand, ActorContext, ActorError, ActorEvent, ActorEventContext, CommandOutcome,
    EventOutcome,
};
use crate::platform::{Host, PalError};
use crate::session::{OakClientSession, OakServerSession, OakSession, OakSessionFactory};
use crate::snapshot::{
    SnapshotError, SnapshotReceiver, SnapshotReceiverImpl, SnapshotSender, SnapshotSenderImpl,
};
use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use oak_attestation_verification_types::util::Clock;
use oak_proto_rust::oak::attestation::v1::{Endorsements, ReferenceValues};
use oak_proto_rust::oak::session::v1::{SessionRequest, SessionResponse};
use prost::bytes::Bytes;
use raft::{
    eraftpb::ConfChange as RaftConfigChange, eraftpb::ConfState as RaftConfigState,
    eraftpb::Entry as RaftEntry, eraftpb::HardState as RaftHardState,
    eraftpb::Message as RaftMessage, eraftpb::Snapshot as RaftSnapshot, Config as RaftConfig,
    Error as RaftError, GetEntriesContext as RaftGetEntriesContext,
    SnapshotStatus as RaftSnapshotStatus, Storage as RaftStorage,
};
use slog::Logger;
use tcp_proto::runtime::endpoint::{
    in_message, raft_config::SnapshotConfig, DeliverSnapshotRequest, DeliverSnapshotResponse,
    OutMessage, Payload, SecureChannelHandshake,
};

mock! {
    pub Actor {
    }

    impl Actor for Actor {
        fn on_init(&mut self, context: Box<dyn ActorContext>) -> Result<(), ActorError>;

        fn on_shutdown(&mut self);

        fn on_save_snapshot(&mut self) -> Result<Bytes, ActorError>;

        fn on_load_snapshot(&mut self, snapshot: Bytes) -> Result<(), ActorError>;

        fn on_process_command(&mut self, command: Option<ActorCommand>) -> Result<CommandOutcome, ActorError>;

        fn on_apply_event(&mut self, context: ActorEventContext, event: ActorEvent) -> Result<EventOutcome, ActorError>;

        fn get_reference_values(&self) -> ReferenceValues;
    }
}

mock! {
    pub ActorContext {}

    impl ActorContext for ActorContext {
        fn logger(&self) -> &Logger;

        fn id(&self) -> u64;

        fn instant(&self) -> u64;

        fn config(&self) -> Bytes;

        fn leader(&self) -> bool;
    }
}

mock! {
    pub Host {
    }

    impl Host for Host {
        fn send_messages(&mut self, messages: Vec<OutMessage>);

        fn public_signing_key(&self) -> Vec<u8>;
    }
}

mock! {
    pub Store {
    }

    impl Store for Store {
        fn set_hard_state(&mut self, state: RaftHardState);

        fn append_entries(&mut self, entries: &[RaftEntry]) -> Result<(), RaftError>;

        fn apply_snapshot(&mut self, snapshot: RaftSnapshot) -> Result<(), RaftError>;

        fn should_snapshot(&self, applied_index: u64, config_state: &RaftConfigState) -> bool;

        fn create_snapshot(
            &mut self,
            applied_index: u64,
            config_state: RaftConfigState,
            snapshot_data: Bytes,
        ) -> Result<(), RaftError>;

        fn latest_snapshot_size(&self) -> u64;
    }
}

impl RaftStorage for MockStore {
    fn initial_state(&self) -> Result<raft::RaftState, RaftError> {
        todo!()
    }

    fn entries(
        &self,
        _low: u64,
        _high: u64,
        _max_size: impl Into<Option<u64>>,
        _context: RaftGetEntriesContext,
    ) -> Result<Vec<RaftEntry>, RaftError> {
        todo!()
    }

    fn term(&self, _idx: u64) -> Result<u64, RaftError> {
        todo!()
    }

    fn first_index(&self) -> Result<u64, RaftError> {
        todo!()
    }

    fn last_index(&self) -> Result<u64, RaftError> {
        todo!()
    }

    fn snapshot(&self, _request_index: u64, _to: u64) -> Result<RaftSnapshot, RaftError> {
        todo!()
    }
}

mock! {
    pub Raft<S: Store> {
    }

    impl<S: Store + RaftStorage> Raft for Raft<S> {
        type S = S;

        fn initialized(&self) -> bool;

        fn state(&self) -> consensus::RaftState;

        fn leader(&self) -> bool;

        fn mut_store(&mut self) -> &mut S;

        fn init(&mut self, node_id: u64, config: &RaftConfig, snapshot: Bytes, leader: bool, store: S, logger: &Logger) -> Result<(), RaftError>;

        fn make_step(&mut self, message: RaftMessage) -> Result<(), RaftError>;

        fn make_proposal(&mut self, proposal: Bytes) -> Result<(), RaftError>;

        fn make_config_change_proposal(
            &mut self,
            config_change: RaftConfigChange,
        ) -> Result<(), RaftError>;

        fn make_tick(&mut self);

        fn apply_config_change(&mut self, config_change: &RaftConfigChange) -> Result<RaftConfigState, RaftError>;

        fn has_ready(&self) -> bool;

        fn get_ready(&mut self) -> RaftReady;

        fn advance_ready(&mut self, ready: RaftReady) -> RaftLightReady;

        fn advance_apply(&mut self);

        fn report_snapshot(&mut self, replica_id: u64, status: RaftSnapshotStatus);
    }
}

mock! {
    pub SnapshotReceiver {
    }

    impl SnapshotReceiverImpl for SnapshotReceiver {
        fn init(&mut self, logger: Logger, replica_id: u64);

        fn set_instant(&mut self, instant: u64);

        fn reset(&mut self);
    }

    impl SnapshotReceiver for SnapshotReceiver {
        fn process_request(&mut self, request: DeliverSnapshotRequest) -> DeliverSnapshotResponse;

        fn try_complete(&mut self) -> Option<Result<(u64, RaftSnapshot), SnapshotError>>;
    }
}

mock! {
    pub SnapshotSender {
    }

    impl SnapshotSenderImpl for SnapshotSender {
        fn init(&mut self, logger: Logger, replica_id: u64, snapshot_config: &Option<SnapshotConfig>);

        fn set_instant(&mut self, instant: u64);

        fn reset(&mut self) -> Vec<(u64, RaftSnapshotStatus)>;
    }

    impl SnapshotSender for SnapshotSender {
        fn start(&mut self, receiver_id: u64, snapshot: RaftSnapshot);

        fn next_request(&mut self) -> Option<DeliverSnapshotRequest>;

        fn process_response(
            &mut self,
            sender_id: u64,
            delivery_id: u64,
            response: Result<DeliverSnapshotResponse, SnapshotError>,
        );

        fn process_unexpected_request(&mut self, request: DeliverSnapshotRequest) -> DeliverSnapshotResponse;

        fn try_complete(&mut self) -> Option<(u64, RaftSnapshotStatus)>;
    }
}

mock! {
    pub CommunicationModule {
    }

    impl CommunicationModule for CommunicationModule {
        fn init(
            &mut self,
            replica_id: u64,
            logger: Logger,
            clock: Arc<dyn Clock>,
            config: CommunicationConfig);

        fn process_out_message(&mut self, message: OutgoingMessage) -> Result<(), PalError>;

        fn process_in_message(
            &mut self,
            message: in_message::Msg,
        ) -> Result<Option<in_message::Msg>, PalError>;

        fn take_out_messages(&mut self) -> Vec<OutMessage>;

        fn process_cluster_change(&mut self, new_replica_ids: &[u64]);

        fn make_tick(&mut self);
    }
}

mock! {
    pub HandshakeSessionProvider {
    }

    impl HandshakeSessionProvider for HandshakeSessionProvider {
        fn init(
            &mut self,
            logger: Logger,
            clock: Arc<dyn Clock>,
            reference_values: ReferenceValues,
            endorsements: Endorsements,
        );

        fn get(
            &self,
            self_replica_id: u64,
            peer_replica_id: u64,
            role: Role,
        ) -> anyhow::Result<Box<dyn HandshakeSession>>;
    }
}

mock! {
    pub HandshakeSession {
    }

    impl HandshakeSession for HandshakeSession {
        fn process_message(&mut self, message: SecureChannelHandshake) -> anyhow::Result<()>;

        fn take_out_message(&mut self) -> anyhow::Result<Option<SecureChannelHandshake>>;

        fn is_completed(&self) -> bool;

        fn get_encryptor(self: Box<Self>) -> Option<Box<dyn Encryptor>>;
    }
}

mock! {
    pub Encryptor {
    }

    impl Encryptor for Encryptor {
        fn encrypt(&mut self, plaintext: &[u8]) -> anyhow::Result<Payload>;

        fn decrypt(&mut self, payload: &Payload) -> anyhow::Result<Vec<u8>>;
    }
}

mock! {
    pub OakSessionFactory {
    }

    impl OakSessionFactory for OakSessionFactory {
        fn init(&mut self, clock: Arc<dyn Clock>, reference_values: ReferenceValues, endorsements: Endorsements);

        fn get_oak_client_session(&self) -> anyhow::Result<Box<dyn OakClientSession>>;

        fn get_oak_server_session(&self) -> anyhow::Result<Box<dyn OakServerSession>>;
    }
}

mock! {
    pub OakClientSession {
    }

    impl OakSession<SessionResponse, SessionRequest> for OakClientSession {
    fn put_incoming_message(&mut self, incoming_message: SessionResponse) -> anyhow::Result<Option<()>>;

    fn get_outgoing_message(&mut self) -> anyhow::Result<Option<SessionRequest>>;

    fn is_open(&self) -> bool;

    fn write(&mut self, plaintext: &[u8]) -> anyhow::Result<()>;

    fn read(&mut self) -> anyhow::Result<Option<Vec<u8>>>;
    }
}

mock! {
    pub OakServerSession {
    }

    impl OakSession<SessionRequest, SessionResponse> for OakServerSession {
    fn put_incoming_message(&mut self, incoming_message: SessionRequest) -> anyhow::Result<Option<()>>;

    fn get_outgoing_message(&mut self) -> anyhow::Result<Option<SessionResponse>>;

    fn is_open(&self) -> bool;

    fn write(&mut self, plaintext: &[u8]) -> anyhow::Result<()>;

    fn read(&mut self) -> anyhow::Result<Option<Vec<u8>>>;
    }
}

mock! {
    pub Clock {
    }

    impl Clock for Clock {
        fn get_milliseconds_since_epoch(&self) -> i64;
    }
}
