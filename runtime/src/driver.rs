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

#![allow(clippy::useless_conversion)]
use crate::communication::{CommunicationConfig, CommunicationModule, OutgoingMessage};
use crate::consensus::{Raft, RaftState, Store};
use crate::logger::log::create_remote_logger;
use crate::logger::{DrainOutput, EmptyDrainOutput};
use crate::model::{Actor, ActorCommand, ActorContext, ActorEvent, ActorEventContext};
use crate::platform::{Application, Host, PalError};
use crate::snapshot::{SnapshotError, SnapshotProcessor, SnapshotProcessorRole};
use crate::util::raft::{
    create_entry, create_raft_config_change, create_raft_message, deserialize_config_change,
    deserialize_raft_message, get_config_state, get_metadata, serialize_raft_message,
};
use alloc::boxed::Box;
use alloc::rc::Rc;
use alloc::sync::Arc;
use alloc::{vec, vec::Vec};
use core::convert::TryFrom;
use core::{
    cell::{RefCell, RefMut},
    cmp, mem,
    sync::atomic::{AtomicI64, Ordering},
};
use oak_attestation_verification_types::util::Clock;
use oak_proto_rust::oak::attestation::v1::{Endorsements, ReferenceValues};
use prost::{bytes::Bytes, Message};
use raft::{
    eraftpb::ConfChangeType as RaftConfigChangeType, eraftpb::ConfState as RaftConfigState,
    eraftpb::Entry as RaftEntry, eraftpb::EntryType as RaftEntryType,
    eraftpb::Message as RaftMessage, eraftpb::MessageType as RaftMessageType, eraftpb::MessageType,
    eraftpb::Snapshot as RaftSnapshot, Error as RaftError, SnapshotStatus as RaftSnapshotStatus,
    Storage as RaftStorage,
};
use slog::{debug, error, info, o, warn, Logger};
use tcp_proto::runtime::endpoint::*;

struct DriverContextCore {
    id: u64,
    instant: u64,
    config: Bytes,
    leader: bool,
    proposals: Vec<Bytes>,
}

impl DriverContextCore {
    fn new() -> DriverContextCore {
        DriverContextCore {
            id: 0,
            instant: 0,
            config: Bytes::new(),
            leader: false,
            proposals: Vec::new(),
        }
    }

    fn set_state(&mut self, instant: u64, leader: bool) {
        self.instant = instant;
        self.leader = leader;
    }

    fn set_immutable_state(&mut self, id: u64, config: Bytes) {
        self.id = id;
        self.config = config;
    }

    fn id(&self) -> u64 {
        self.id
    }

    fn instant(&self) -> u64 {
        self.instant
    }

    fn leader(&self) -> bool {
        self.leader
    }

    fn config(&self) -> Bytes {
        self.config.clone()
    }

    fn append_proposal(&mut self, proposal: Bytes) {
        self.proposals.push(proposal);
    }

    fn take_outputs(&mut self) -> Vec<Bytes> {
        mem::take(&mut self.proposals)
    }
}

struct DriverContext {
    core: Rc<RefCell<DriverContextCore>>,
    logger: Logger,
}

impl DriverContext {
    fn new(core: Rc<RefCell<DriverContextCore>>, logger: Logger) -> Self {
        DriverContext { core, logger }
    }
}

impl ActorContext for DriverContext {
    fn logger(&self) -> &Logger {
        &self.logger
    }

    fn id(&self) -> u64 {
        self.core.borrow().id()
    }

    fn instant(&self) -> u64 {
        self.core.borrow().instant()
    }

    fn config(&self) -> Bytes {
        self.core.borrow().config()
    }

    fn leader(&self) -> bool {
        self.core.borrow().leader()
    }
}

struct DefaultClock {
    instant: AtomicI64,
}

impl DefaultClock {
    fn set_instant(&self, instant: i64) {
        self.instant.store(instant, Ordering::Relaxed);
    }
}

impl Clock for DefaultClock {
    fn get_milliseconds_since_epoch(&self) -> i64 {
        self.instant.load(Ordering::Relaxed)
    }
}

#[derive(PartialEq, Eq)]
enum DriverState {
    Created,
    Started,
    Stopped,
}
#[derive(Default)]
struct DriverConfig {
    tick_period: u64,
    snapshot_count: u64,
}

struct RaftProgress {
    // Index of the last committed entry that has been applied to the actor.
    applied_index: u64,
    // The lastest configuration of the cluster that has been committed.
    config_state: RaftConfigState,
}

impl RaftProgress {
    fn new() -> RaftProgress {
        RaftProgress {
            applied_index: 0,
            config_state: RaftConfigState::default(),
        }
    }
}

pub struct Driver<R: Raft, S: Store, P: SnapshotProcessor, A: Actor, C: CommunicationModule> {
    core: Rc<RefCell<DriverContextCore>>,
    driver_config: DriverConfig,
    driver_state: DriverState,
    messages: Vec<OutMessage>,
    snapshots: Vec<RaftMessage>,
    id: u64,
    instant: u64,
    tick_instant: u64,
    logger: Logger,
    logger_output: Box<dyn DrainOutput>,
    raft: R,
    store: Box<dyn FnMut(Logger, u64) -> S>,
    snapshot: P,
    actor: A,
    raft_state: RaftState,
    prev_raft_state: RaftState,
    raft_progress: RaftProgress,
    communication: C,
    is_ephemeral: bool,
    default_clock: Arc<DefaultClock>,
    lameduck_mode: bool,
}

impl<
        R: Raft<S = S>,
        S: Store + RaftStorage,
        P: SnapshotProcessor,
        A: Actor,
        C: CommunicationModule,
    > Driver<R, S, P, A, C>
{
    pub fn new(
        raft: R,
        store: Box<dyn FnMut(Logger, u64) -> S>,
        snapshot: P,
        actor: A,
        communication: C,
        logger: Option<Logger>,
    ) -> Self {
        let (logger, logger_output) = match logger {
            Some(logger) => (
                logger,
                Box::new(EmptyDrainOutput {}) as Box<dyn DrainOutput>,
            ),
            None => create_remote_logger(),
        };
        Driver {
            core: Rc::new(RefCell::new(DriverContextCore::new())),
            driver_config: DriverConfig {
                tick_period: 100,
                snapshot_count: 1000,
            },
            driver_state: DriverState::Created,
            messages: Vec::new(),
            snapshots: Vec::new(),
            id: 0,
            instant: 0,
            tick_instant: 0,
            logger,
            logger_output,
            raft,
            store,
            snapshot,
            actor,
            raft_state: RaftState::new(),
            prev_raft_state: RaftState::new(),
            raft_progress: RaftProgress::new(),
            communication,
            is_ephemeral: false,
            default_clock: Arc::new(DefaultClock {
                instant: AtomicI64::new(0),
            }),
            lameduck_mode: false,
        }
    }

    fn mut_core(&mut self) -> RefMut<'_, DriverContextCore> {
        self.core.borrow_mut()
    }

    fn initialize_raft_node(
        &mut self,
        raft_config: &Option<RaftConfig>,
        snapshot: Bytes,
        leader: bool,
    ) -> Result<(), PalError> {
        let mut config = raft::Config {
            id: self.id,
            ..Default::default()
        };

        if let Some(raft_config) = raft_config {
            // Store driver relavant parts of the config.
            self.driver_config.tick_period = raft_config.tick_period;
            if let Some(snapshot_config) = &raft_config.snapshot_config {
                self.driver_config.snapshot_count = snapshot_config.snapshot_count;
            }

            // Update Raft native configuration.
            config.election_tick = raft_config.election_tick as usize;
            config.heartbeat_tick = raft_config.heartbeat_tick as usize;
            config.max_size_per_msg = raft_config.max_size_per_msg;
        }

        // Initialize Raft instance.
        self.raft
            .init(
                self.id,
                &config,
                snapshot,
                leader,
                (self.store)(
                    self.logger.new(o!("type" => "store")),
                    self.driver_config.snapshot_count,
                ),
                &self.logger,
            )
            .map_err(|e| {
                error!(self.logger, "Failed to create Raft node: {}", e);

                // Failure to create Raft node must lead to termination.
                PalError::Raft
            })?;

        // Initialize raft progress to match the current state of raft.
        // Note that we have non zero applied index only if the node has
        // been initialized as leader.
        if leader {
            self.raft_progress = RaftProgress {
                applied_index: 1,
                config_state: RaftConfigState {
                    voters: vec![self.id],
                    ..Default::default()
                },
            };
        }

        self.tick_instant = self.instant;
        // No need to initially report the state of the cluster, only after the changes.
        self.prev_raft_state = self.get_raft_state();

        Ok(())
    }

    fn check_raft_leadership(&self) -> bool {
        self.raft.leader()
    }

    fn get_raft_state(&self) -> RaftState {
        let mut raft_state = self.raft.state();
        // Report committed cluster config only if current replica is the leader.
        if raft_state.leader_replica_id == self.id {
            raft_state.committed_cluster_config = self.raft_progress.config_state.voters.clone();
        }
        raft_state
    }

    fn make_raft_step(
        &mut self,
        sender_replica_id: u64,
        recipient_replica_id: u64,
        message_contents: Bytes,
    ) -> Result<(), PalError> {
        match deserialize_raft_message(message_contents) {
            Err(e) => {
                warn!(
                    self.logger,
                    "Ignoring failed to deserialize Raft message: {}", e
                );

                Ok(())
            }
            Ok(message) => {
                if self.id != recipient_replica_id {
                    // Ignore incorrectly routed message
                    warn!(
                        self.logger,
                        "Ignoring incorectly routed Raft message: recipient id {}",
                        recipient_replica_id
                    );
                }
                if message.get_from() != sender_replica_id {
                    // Ignore malformed message
                    warn!(
                        self.logger,
                        "Ignoring malformed Raft message: sender id {}", sender_replica_id
                    );
                }

                // Advance Raft internal state by one step.
                match self.raft.make_step(message) {
                    Err(e) => {
                        error!(self.logger, "Raft experienced unrecoverable error: {}", e);

                        // Unrecoverable Raft errors must lead to termination.
                        Err(PalError::Raft)
                    }
                    Ok(_) => Ok(()),
                }
            }
        }
    }

    fn make_raft_proposal(&mut self, proposal_contents: Bytes) {
        debug!(self.logger, "Making Raft proposal");

        self.raft.make_proposal(proposal_contents).unwrap();
    }

    fn make_raft_config_change_proposal(
        &mut self,
        node_id: u64,
        change_type: RaftConfigChangeType,
    ) -> Result<ChangeClusterStatus, PalError> {
        debug!(self.logger, "Making Raft config change proposal");

        let config_change = create_raft_config_change(node_id, change_type);
        match self.raft.make_config_change_proposal(config_change) {
            Ok(_) => Ok(ChangeClusterStatus::ChangeStatusPending),
            Err(RaftError::ProposalDropped) => {
                warn!(self.logger, "Dropping Raft config change proposal");

                Ok(ChangeClusterStatus::ChangeStatusRejected)
            }
            Err(e) => {
                error!(self.logger, "Raft experienced unrecoverable error: {}", e);

                // Unrecoverable Raft errors must lead to termination.
                Err(PalError::Raft)
            }
        }
    }

    fn trigger_raft_tick(&mut self) {
        // Given that Raft is being driven from the outside and arbitrary amount of time can
        // pass between driver invocation we may need to produce multiple ticks.
        if self.instant - self.tick_instant >= self.driver_config.tick_period {
            self.tick_instant = self.instant;
            // invoke Raft tick to trigger timer based changes.
            self.raft.make_tick();
        }
    }

    fn apply_raft_committed_entries(
        &mut self,
        mut committed_entries: Vec<RaftEntry>,
    ) -> Result<(), PalError> {
        // Sort committed entries by entry index to make sure they are applied in order.
        committed_entries.sort_by(|a, b| a.index.cmp(&b.index));
        for committed_entry in committed_entries {
            // Remember progress of applying committed entries.
            self.raft_progress.applied_index = committed_entry.index;

            if committed_entry.data.is_empty() {
                // Empty entry is produced by the newly elected leader to commit entries
                // from the previous terms.
                continue;
            }
            // The entry may either be a config change or a normal proposal.
            if let RaftEntryType::EntryConfChange = committed_entry.get_entry_type() {
                // Make committed configuration effective.
                let config_change = match deserialize_config_change(&committed_entry.data) {
                    Ok(config_change) => config_change,
                    Err(e) => {
                        error!(
                            self.logger,
                            "Failed to deserialize Raft config change: {}", e
                        );
                        // Failure to deserialize Raft config change must lead to termination.
                        return Err(PalError::Raft);
                    }
                };

                debug!(
                    self.logger,
                    "Applying Raft config change entry: {:?}", config_change
                );

                match self.raft.apply_config_change(&config_change) {
                    Err(e) => {
                        error!(self.logger, "Failed to apply Raft config change: {}", e);
                        // Failure to apply Raft config change must lead to termination.
                        return Err(PalError::Raft);
                    }
                    Ok(config_state) => {
                        self.collect_config_state(config_state);
                    }
                };
            } else {
                debug!(
                    self.logger,
                    "Applying Raft entry #{}", committed_entry.index
                );
                // Recover the entry id so that original message can be correlated
                let entry = Entry::decode(committed_entry.get_data()).map_err(|e| {
                    error!(self.logger, "Failed to deserialize Raft entry: {}", e);
                    // Failure to deserialize Raft config change must lead to termination.
                    return PalError::Raft;
                })?;

                let entry_id = entry.entry_id.unwrap();

                // Pass committed entry to the actor to make effective.
                let event_outcome = self
                    .actor
                    .on_apply_event(
                        ActorEventContext {
                            index: committed_entry.index,
                            owned: entry_id.replica_id == self.id,
                        },
                        ActorEvent::with_bytes(entry_id.entry_id, entry.entry_contents),
                    )
                    .map_err(|e| {
                        error!(
                            self.logger,
                            "Failed to apply committed event to actor state: {}", e
                        );
                        // Failure to apply committed event to actor state must lead to termination.
                        PalError::Actor
                    })?;

                for actor_command in event_outcome.commands {
                    self.stash_message(out_message::Msg::DeliverAppMessage(DeliverAppMessage {
                        correlation_id: actor_command.correlation_id,
                        message_header: actor_command.header,
                        message_payload: actor_command.payload,
                    }));
                }
            }
        }

        Ok(())
    }

    fn send_raft_messages(&mut self, raft_messages: Vec<RaftMessage>) -> Result<(), PalError> {
        for raft_message in raft_messages {
            // Stash messages that contain snapshot to be sent out by the snapshot processor.
            if raft_message.msg_type
                == <MessageType as Into<i32>>::into(RaftMessageType::MsgSnapshot)
            {
                self.stash_snapshot(raft_message);
                continue;
            }

            self.communication
                .process_out_message(OutgoingMessage::DeliverSystemMessage(
                    DeliverSystemMessage {
                        recipient_replica_id: raft_message.to,
                        sender_replica_id: self.id,
                        payload: Some(Payload {
                            contents: serialize_raft_message(&raft_message).unwrap(),
                            ..Default::default()
                        }),
                        ..Default::default()
                    },
                    raft_message.msg_type(),
                ))?;
        }

        Ok(())
    }

    fn restore_raft_snapshot(&mut self, raft_snapshot: &mut RaftSnapshot) -> Result<(), PalError> {
        if raft_snapshot.is_empty() {
            // Nothing to restore if the snapshot is empty.
            return Ok(());
        }

        info!(
            self.logger,
            "Restoring Raft snappshot: {:?}",
            get_metadata(raft_snapshot)
        );

        self.collect_config_state(get_config_state(raft_snapshot).clone());

        // Persist unstable snapshot received from a peer into the stable storage.
        let apply_result = self.raft.mut_store().apply_snapshot(raft_snapshot.clone());
        if let Err(e) = apply_result {
            error!(
                self.logger,
                "Failed to apply Raft snapshot to storage: {}", e
            );
            // Failure to apply Raft snapshot to storage snapshot must lead to termination.
            return Err(PalError::Raft);
        }

        // Pass snapshot to the actor to restore.
        let snapshot = Bytes::from(raft_snapshot.take_data());
        self.actor.on_load_snapshot(snapshot).map_err(|e| {
            error!(self.logger, "Failed to load actor state snapshot: {}", e);
            // Failure to load actor snapshot must lead to termination.
            PalError::Actor
        })?;

        // Applied index is reset to the snapshot index.
        self.raft_progress.applied_index = get_metadata(raft_snapshot).index;

        Ok(())
    }

    fn maybe_create_raft_snapshot(&mut self) -> Result<(), PalError> {
        if !self.raft.mut_store().should_snapshot(
            self.raft_progress.applied_index,
            &self.raft_progress.config_state,
        ) {
            return Ok(());
        }

        let snapshot_data = self.actor.on_save_snapshot().map_err(|e| {
            error!(self.logger, "Failed to save actor state to snapshot: {}", e);
            // Failure to apply Raft snapshot to storage snapshot must lead to termination.
            PalError::Actor
        })?;

        let applied_index = self.raft_progress.applied_index;
        let config_state = self.raft_progress.config_state.clone();
        self.raft
            .mut_store()
            .create_snapshot(applied_index, config_state, snapshot_data)
            .map_err(|e| {
                error!(self.logger, "Failed to save actor state to snapshot: {}", e);
                // Failure to create Raft snapshot to storage snapshot must lead to termination.
                PalError::Actor
            })
    }

    fn advance_raft(&mut self) -> Result<(), PalError> {
        // Trigger raft ticks only when the replica is NOT in lameduck mode.
        // If this replica is a leader, in lameduck mode raft ticks are ignored which
        // would cause the leader to relinquish leadership by not triggering heartbeats.
        // If this replica is a follower, ignoring ticks will ensure no election is triggered
        // by this replica in lameduck mode.
        if !self.lameduck_mode {
            self.trigger_raft_tick();
        }

        if !self.raft.has_ready() {
            // There is nothing process.
            return Ok(());
        }

        let mut raft_ready = self.raft.get_ready();

        // Send out messages to the peers.
        self.send_raft_messages(raft_ready.take_messages())?;

        if let Some(raft_hard_state) = raft_ready.hard_state() {
            // Persist changed hard state into the stable storage.
            self.raft
                .mut_store()
                .set_hard_state(raft_hard_state.clone());
        }

        // If not empty persist snapshot to stable storage and apply it to the
        // actor.
        let mut snapshot = raft_ready.take_snapshot();
        self.restore_raft_snapshot(&mut snapshot)?;

        // Apply committed entries to the actor state machine.
        self.apply_raft_committed_entries(raft_ready.take_committed_entries())?;
        // Send out messages that had to await the persistence of the hard state, entries
        // and snapshot to the stable storage.
        self.send_raft_messages(raft_ready.take_persisted_messages())?;

        let entries = raft_ready.take_entries();
        if !entries.is_empty() {
            // Persist unstable entries into the stable storage.
            let append_result = self.raft.mut_store().append_entries(entries.as_ref());
            if let Err(e) = append_result {
                error!(
                    self.logger,
                    "Failed to append Raft entries to storage: {}", e
                );
                // Failure to append Raft entries to storage snapshot must lead to termination.
                return Err(PalError::Actor);
            }
        }

        // Advance Raft state after fully processing ready.
        let mut light_raft_ready = self.raft.advance_ready(raft_ready);

        // Send out messages to the peers.
        self.send_raft_messages(light_raft_ready.take_messages())?;
        // Apply all committed entries.
        self.apply_raft_committed_entries(light_raft_ready.take_committed_entries())?;
        // Advance the apply index.
        self.raft.advance_apply();

        Ok(())
    }

    fn reset_leader_state(&mut self) {
        self.prev_raft_state = RaftState::new();
    }

    fn collect_config_state(&mut self, config_state: RaftConfigState) {
        self.raft_progress.config_state = config_state;
    }

    fn stash_leader_state(&mut self) {
        self.raft_state = self.get_raft_state();

        if self.prev_raft_state == self.raft_state {
            return;
        }

        self.prev_raft_state = self.raft_state.clone();

        // Update snapshot processor with the latest raft cluster state.
        self.update_snapshot_cluster_change();

        // Update communication module with the latest set of known replicas.
        self.communication
            .process_cluster_change(&self.raft_progress.config_state.voters);

        // Sent out cluster check message with the update.
        self.stash_message(out_message::Msg::CheckCluster(CheckClusterResponse {
            leader_replica_id: self.raft_state.leader_replica_id,
            leader_term: self.raft_state.leader_term,
            cluster_replica_ids: self.raft_state.committed_cluster_config.clone(),
            has_pending_changes: self.raft_state.has_pending_change,
        }));
    }

    fn preset_state_machine(&mut self, instant: u64) {
        self.prev_raft_state = self.raft_state.clone();
        self.instant = cmp::max(self.instant, instant);
        let instant = self.instant;
        let leader = self.check_raft_leadership();
        self.mut_core().set_state(instant, leader);
        self.default_clock.set_instant(instant as i64);
    }

    fn check_driver_state(&self, state: DriverState) -> Result<(), PalError> {
        if self.driver_state != state {
            return Err(PalError::InvalidOperation);
        }

        Ok(())
    }

    fn check_driver_started(&self) -> Result<(), PalError> {
        self.check_driver_state(DriverState::Started)
    }

    fn check_non_ephemeral(&self) -> Result<(), PalError> {
        if self.is_ephemeral {
            return Err(PalError::InvalidOperation);
        }
        Ok(())
    }

    fn initialize_driver(&mut self, _app_signing_key: Vec<u8>, replica_id_hint: u64) {
        self.id = replica_id_hint;
        self.logger = self.logger.new(o!("raft_id" => self.id));
    }

    fn process_start_node(
        &mut self,
        start_replica_request: &mut StartReplicaRequest,
        app_signing_key: Vec<u8>,
    ) -> Result<(), PalError> {
        self.check_driver_state(DriverState::Created)?;

        self.initialize_driver(app_signing_key, start_replica_request.replica_id_hint);

        let id = self.id;
        let app_config = mem::take(&mut start_replica_request.app_config);
        self.mut_core().set_immutable_state(id, app_config);

        let actor_context = Box::new(DriverContext::new(
            Rc::clone(&self.core),
            self.logger.new(o!("type" => "actor")),
        ));

        self.actor.on_init(actor_context).map_err(|e| {
            error!(self.logger, "Failed to initialize actor: {}", e);

            // Failure to initialize actor must lead to termination.
            PalError::Actor
        })?;
        self.is_ephemeral = start_replica_request.is_ephemeral;

        // Initialize Raft and Snapshot only for non-ephemeral nodes.
        if !self.is_ephemeral {
            let snapshot = self.actor.on_save_snapshot().map_err(|e| {
                error!(self.logger, "Failed to save actor snapshot: {}", e);

                // Failure to save actor snapshot must lead to termination.
                PalError::Actor
            })?;

            // Initialize snapshot processor.
            let snapshot_config = match &start_replica_request.raft_config {
                Some(raft_config) => &raft_config.snapshot_config,
                None => &None,
            };
            self.snapshot.init(
                self.logger.new(o!("type" => "snapshot")),
                self.id,
                snapshot_config,
            );

            self.initialize_raft_node(
                &start_replica_request.raft_config,
                snapshot,
                start_replica_request.is_leader,
            )?;
        }

        let mut communication_config = match &start_replica_request.raft_config {
            Some(raft_config) => CommunicationConfig {
                handshake_retry_tick: raft_config.handshake_retry_tick,
                handshake_initiated_tick_timeout: raft_config.heartbeat_tick * 10,
                reference_values: ReferenceValues::default(),
                endorsements: Endorsements::default(),
            },
            None => CommunicationConfig {
                // System defaults.
                handshake_retry_tick: 1,
                handshake_initiated_tick_timeout: 10,
                reference_values: ReferenceValues::default(),
                endorsements: Endorsements::default(),
            },
        };
        communication_config.reference_values = self.actor.get_reference_values();
        communication_config.endorsements =
            start_replica_request.endorsements.as_ref().unwrap().clone();
        self.communication.init(
            self.id,
            self.logger.new(o!("type" => "communication")),
            self.actor
                .get_clock_override()
                .unwrap_or_else(|| self.default_clock.clone()),
            communication_config,
        );

        self.driver_state = DriverState::Started;

        self.stash_message(out_message::Msg::StartReplica(StartReplicaResponse {
            replica_id: self.id,
        }));

        Ok(())
    }

    fn process_stop_node(
        &mut self,
        _stop_replica_request: &StopReplicaRequest,
    ) -> Result<(), PalError> {
        if let DriverState::Stopped = self.driver_state {
            return Ok(());
        }

        self.actor.on_shutdown();

        self.driver_state = DriverState::Stopped;

        self.stash_message(out_message::Msg::StopReplica(StopReplicaResponse {}));

        Ok(())
    }

    fn process_change_cluster(
        &mut self,
        change_cluster_request: &ChangeClusterRequest,
    ) -> Result<(), PalError> {
        self.check_driver_started()?;
        self.check_non_ephemeral()?;

        let change_status = match ChangeClusterType::try_from(change_cluster_request.change_type) {
            Ok(ChangeClusterType::ChangeTypeAddReplica) => self.make_raft_config_change_proposal(
                change_cluster_request.replica_id,
                RaftConfigChangeType::AddNode,
            )?,
            Ok(ChangeClusterType::ChangeTypeRemoveReplica) => self
                .make_raft_config_change_proposal(
                    change_cluster_request.replica_id,
                    RaftConfigChangeType::RemoveNode,
                )?,
            _ => {
                warn!(self.logger, "Rejecting cluster change command: unknown");

                ChangeClusterStatus::ChangeStatusRejected
            }
        };

        self.stash_message(out_message::Msg::ChangeCluster(ChangeClusterResponse {
            change_id: change_cluster_request.change_id,
            change_status: change_status.into(),
        }));

        Ok(())
    }

    fn process_check_cluster(
        &mut self,
        _check_cluster_request: &CheckClusterRequest,
    ) -> Result<(), PalError> {
        self.check_driver_started()?;
        self.check_non_ephemeral()?;

        self.reset_leader_state();

        Ok(())
    }

    fn process_deliver_system_message(
        &mut self,
        deliver_system_message: DeliverSystemMessage,
    ) -> Result<(), PalError> {
        self.check_driver_started()?;
        self.check_non_ephemeral()?;

        let message =
            self.communication
                .process_in_message(in_message::Msg::DeliverSystemMessage(
                    deliver_system_message,
                ))?;

        if message.is_none() {
            return Ok(());
        }

        let message = message.unwrap();
        match message {
            in_message::Msg::DeliverSystemMessage(m) => self.make_raft_step(
                m.sender_replica_id,
                m.recipient_replica_id,
                m.payload.unwrap().contents,
            ),
            _ => {
                warn!(self.logger, "Unexpected message type {:?}", message);
                Err(PalError::Internal)
            }
        }
    }

    fn update_snapshot_cluster_change(&mut self) {
        if self.driver_state != DriverState::Started {
            return;
        }

        // Notify snapshot processor of the latest state of the cluster.
        let snapshot_updates = self.snapshot.process_cluster_change(
            self.raft_state.leader_replica_id,
            self.raft_state.leader_term,
            &self.raft_state.committed_cluster_config,
        );

        // Notify raft if any of the snapshot transfers has been cancelled.
        for (replica_id, snapshot_status) in snapshot_updates {
            self.raft.report_snapshot(replica_id, snapshot_status);
        }
    }

    fn process_deliver_snapshot_request(
        &mut self,
        deliver_snapshot_request: DeliverSnapshotRequest,
    ) -> Result<(), PalError> {
        self.check_non_ephemeral()?;
        let message =
            self.communication
                .process_in_message(in_message::Msg::DeliverSnapshotRequest(
                    deliver_snapshot_request,
                ))?;

        if message.is_none() {
            return Ok(());
        }

        let message = message.unwrap();
        match message {
            in_message::Msg::DeliverSnapshotRequest(m) => {
                let deliver_snapshot_response = match self.snapshot.mut_processor(self.instant) {
                    SnapshotProcessorRole::Sender(sender) => {
                        warn!(
                            self.logger,
                            "Node is in snapshot sending mode, unexpected deliver snapshot request"
                        );
                        sender.process_unexpected_request(m)
                    }
                    SnapshotProcessorRole::Receiver(receiver) => receiver.process_request(m),
                };
                self.communication
                    .process_out_message(OutgoingMessage::DeliverSnapshotResponse(
                        deliver_snapshot_response,
                    ))
            }
            _ => {
                warn!(self.logger, "Unexpected message type {:?}", message);
                Err(PalError::Internal)
            }
        }
    }

    fn process_deliver_snapshot_response(
        &mut self,
        deliver_snapshot_response: DeliverSnapshotResponse,
    ) -> Result<(), PalError> {
        self.check_non_ephemeral()?;
        let message =
            self.communication
                .process_in_message(in_message::Msg::DeliverSnapshotResponse(
                    deliver_snapshot_response,
                ))?;

        if message.is_none() {
            return Ok(());
        }

        let message = message.unwrap();
        match message {
            in_message::Msg::DeliverSnapshotResponse(m) => {
                match self.snapshot.mut_processor(self.instant) {
                    SnapshotProcessorRole::Sender(sender) => {
                        sender.process_response(m.sender_replica_id, m.delivery_id, Ok(m))
                    }
                    SnapshotProcessorRole::Receiver(_) => {
                        warn!(
                            self.logger,
                            "Node is snapshot receiving mode, unexpected deliver snapshot response"
                        );
                    }
                }
                Ok(())
            }
            _ => {
                warn!(self.logger, "Unexpected message type {:?}", message);
                Err(PalError::Internal)
            }
        }
    }

    fn process_deliver_snapshot_failure(
        &mut self,
        deliver_snapshot_failure: DeliverSnapshotFailure,
    ) -> Result<(), PalError> {
        self.check_non_ephemeral()?;
        match self.snapshot.mut_processor(self.instant) {
            SnapshotProcessorRole::Sender(sender) => sender.process_response(
                deliver_snapshot_failure.sender_replica_id,
                deliver_snapshot_failure.delivery_id,
                Err(SnapshotError::FailedDelivery),
            ),
            SnapshotProcessorRole::Receiver(_) => {
                warn!(
                    self.logger,
                    "Node is snapshot receiving mode, unexpected deliver snapshot failure"
                );
            }
        }

        Ok(())
    }

    fn process_snapshot_progress(&mut self) {
        if self.driver_state != DriverState::Started {
            return;
        }

        match self.snapshot.mut_processor(self.instant) {
            SnapshotProcessorRole::Sender(sender) => {
                if let Some((replica_id, snapshot_status)) = sender.try_complete() {
                    self.raft.report_snapshot(replica_id, snapshot_status);
                }
            }
            SnapshotProcessorRole::Receiver(receiver) => {
                if let Some(snapshot_result) = receiver.try_complete() {
                    match snapshot_result {
                        Ok((sender_replica_id, snapshot)) => {
                            let mut snapshot_message = create_raft_message(
                                sender_replica_id,
                                self.id,
                                RaftMessageType::MsgSnapshot,
                            );
                            snapshot_message.set_snapshot(snapshot);
                            if let Err(e) = self.raft.make_step(snapshot_message) {
                                error!(self.logger, "Raft experienced unrecoverable error: {}", e);
                            }
                        }
                        Err(_) => {
                            warn!(
                                self.logger,
                                "Snapshot has been received but failed validation"
                            );
                        }
                    }
                }
            }
        }
    }

    fn process_snapshot_sending(&mut self) -> Result<(), PalError> {
        let snapshot_messages = mem::take(&mut self.snapshots);

        let mut out_messages: Vec<OutgoingMessage> = Vec::new();
        match self.snapshot.mut_processor(self.instant) {
            SnapshotProcessorRole::Sender(sender) => {
                for snapshot_message in snapshot_messages {
                    sender.start(snapshot_message.to, snapshot_message.snapshot.unwrap());
                }

                while let Some(request) = sender.next_request() {
                    out_messages.push(OutgoingMessage::DeliverSnapshotRequest(request));
                }
            }
            SnapshotProcessorRole::Receiver(_) => {
                if !snapshot_messages.is_empty() {
                    warn!(
                        self.logger,
                        "Unexpected snapshot sending while playing receiver role"
                    );
                    for snapshot_message in snapshot_messages {
                        self.raft
                            .report_snapshot(snapshot_message.to, RaftSnapshotStatus::Failure);
                    }
                }
            }
        }

        for out_message in out_messages {
            self.communication.process_out_message(out_message)?;
        }

        Ok(())
    }

    fn process_deliver_app_message(
        &mut self,
        deliver_app_message: Option<DeliverAppMessage>,
    ) -> Result<(), PalError> {
        self.check_driver_started()?;

        let message_outcome = self
            .actor
            .on_process_command(deliver_app_message.map(|m| ActorCommand {
                correlation_id: m.correlation_id,
                header: m.message_header,
                payload: m.message_payload,
            }))
            .map_err(|e| {
                error!(self.logger, "Failed to process actor command: {}", e);

                // Failure to process actor command must lead to termination.
                PalError::Actor
            })?;

        for actor_message in message_outcome.commands {
            self.stash_message(out_message::Msg::DeliverAppMessage(DeliverAppMessage {
                correlation_id: actor_message.correlation_id,
                message_header: actor_message.header,
                message_payload: actor_message.payload,
            }));
        }

        if let Some(actor_event) = message_outcome.event {
            if self.is_ephemeral {
                // For ephemeral replica, apply the event immediately since it is not replicated.
                let event_outcome = self
                    .actor
                    .on_apply_event(
                        ActorEventContext {
                            index: 0,
                            owned: true,
                        },
                        actor_event,
                    )
                    .map_err(|e| {
                        error!(self.logger, "Failed to apply event to actor state: {}", e);
                        // Failure to apply event to actor state must lead to termination.
                        PalError::Actor
                    })?;

                for actor_command in event_outcome.commands {
                    self.stash_message(out_message::Msg::DeliverAppMessage(DeliverAppMessage {
                        correlation_id: actor_command.correlation_id,
                        message_header: actor_command.header,
                        message_payload: actor_command.payload,
                    }));
                }
            } else {
                let entry = create_entry(
                    EntryId {
                        entry_id: actor_event.correlation_id,
                        replica_id: self.id,
                    },
                    actor_event.contents,
                );
                self.mut_core()
                    .append_proposal(entry.encode_to_vec().into())
            }
        }

        Ok(())
    }

    fn process_get_replica_state(
        &mut self,
        _get_replica_state_request: &GetReplicaStateRequest,
    ) -> Result<(), PalError> {
        self.check_driver_started()?;

        if self.is_ephemeral {
            self.stash_message(out_message::Msg::GetReplicaState(
                GetReplicaStateResponse::default(),
            ));
        } else {
            let latest_snapshot_size = self.raft.mut_store().latest_snapshot_size();
            self.stash_message(out_message::Msg::GetReplicaState(GetReplicaStateResponse {
                applied_index: self.raft_progress.applied_index,
                latest_snapshot_size,
            }));
        }

        Ok(())
    }

    fn process_secure_channel_handshake(
        &mut self,
        secure_channel_handshake: SecureChannelHandshake,
    ) -> Result<(), PalError> {
        self.check_driver_started()?;

        self.communication
            .process_in_message(in_message::Msg::SecureChannelHandshake(
                secure_channel_handshake,
            ))?;
        Ok(())
    }

    fn process_actor_raft_proposals(&mut self) {
        let proposals = self.mut_core().take_outputs();

        for proposal in proposals {
            self.make_raft_proposal(proposal);
        }
    }

    fn process_state_machine(&mut self) -> Result<(), PalError> {
        if self.raft.initialized() {
            // Advance Raft internal state.
            self.advance_raft()?;

            // Maybe create a snashot of the actor to reduce the size of the log.
            self.maybe_create_raft_snapshot()?;

            // If the leader state has changed send it out for observability.
            self.stash_leader_state();
        }

        Ok(())
    }

    fn take_out_messages(&mut self) -> Vec<OutMessage> {
        // Take messages to be sent out.
        mem::take(&mut self.messages)
    }

    fn stash_log_entries(&mut self) {
        for log_message in self.logger_output.take_entries() {
            self.stash_message(out_message::Msg::Log(log_message));
        }
    }

    fn stash_comms_module_entries(&mut self) {
        self.messages
            .append(&mut self.communication.take_out_messages());
    }

    fn stash_message(&mut self, message: out_message::Msg) {
        self.messages.push(OutMessage { msg: Some(message) });
    }

    fn stash_snapshot(&mut self, snapshot_message: RaftMessage) {
        self.snapshots.push(snapshot_message);
    }
}

impl<
        R: Raft<S = S>,
        S: Store + RaftStorage,
        P: SnapshotProcessor,
        A: Actor,
        C: CommunicationModule,
    > Application for Driver<R, S, P, A, C>
{
    /// Handles messages received from the trusted host.
    fn receive_message(
        &mut self,
        host: &mut impl Host,
        instant: u64,
        opt_message: Option<InMessage>,
    ) -> Result<(), PalError> {
        // Update state of the context that will remain unchanged while messages are
        // dispatched for processing.
        self.preset_state_machine(instant);

        let mut deliver_app_message_opt = None;
        // Dispatch incoming message for processing.
        if let Some(deserialized_message) = opt_message {
            match deserialized_message.msg {
                None => {
                    warn!(self.logger, "Rejecting message: unknown");
                    // Ignore unknown message.
                    return Ok(());
                }
                Some(mut message) => {
                    match message {
                        in_message::Msg::StartReplica(ref mut start_node_request) => {
                            self.process_start_node(start_node_request, host.public_signing_key())
                        }
                        in_message::Msg::StopReplica(ref stop_node_request) => {
                            self.process_stop_node(stop_node_request)
                        }
                        in_message::Msg::EnterLameduckMode(ref _enter_lameduck_mode) => {
                            info!(self.logger, "Entering lameduck mode");
                            self.lameduck_mode = true;
                            Ok(())
                        }
                        in_message::Msg::ChangeCluster(ref change_cluster_request) => {
                            self.process_change_cluster(change_cluster_request)
                        }
                        in_message::Msg::CheckCluster(ref check_cluster_request) => {
                            self.process_check_cluster(check_cluster_request)
                        }
                        in_message::Msg::DeliverSystemMessage(deliver_system_message) => {
                            self.process_deliver_system_message(deliver_system_message)
                        }
                        in_message::Msg::DeliverSnapshotRequest(deliver_snapshot_request) => {
                            self.process_deliver_snapshot_request(deliver_snapshot_request)
                        }
                        in_message::Msg::DeliverSnapshotResponse(deliver_snapshot_response) => {
                            self.process_deliver_snapshot_response(deliver_snapshot_response)
                        }
                        in_message::Msg::DeliverSnapshotFailure(deliver_snapshot_failure) => {
                            self.process_deliver_snapshot_failure(deliver_snapshot_failure)
                        }
                        in_message::Msg::GetReplicaState(ref get_replica_state_request) => {
                            self.process_get_replica_state(get_replica_state_request)
                        }
                        in_message::Msg::SecureChannelHandshake(secure_channel_handshake) => {
                            self.process_secure_channel_handshake(secure_channel_handshake)
                        }
                        in_message::Msg::DeliverAppMessage(deliver_app_message) => {
                            deliver_app_message_opt = Some(deliver_app_message);
                            Ok(())
                        }
                    }?;
                }
            };
        }
        if self.driver_state == DriverState::Started {
            self.process_deliver_app_message(deliver_app_message_opt)?;
            self.communication.make_tick();
        }

        if !self.is_ephemeral {
            // Processes outputs from the actor to make raft proposals.
            self.process_actor_raft_proposals();

            // Process snapshot transfer completion or failures.
            self.process_snapshot_progress();

            // Advance the Raft and collect results messages.
            self.process_state_machine()?;

            // Initiate if needed snapshot sending.
            self.process_snapshot_sending()?;
        }

        self.stash_log_entries();
        self.stash_comms_module_entries();

        // Send messages to Raft peers and consumers through the trusted host.
        host.send_messages(self.take_out_messages());

        Ok(())
    }
}

#[cfg(all(test, feature = "std"))]
mod test {
    extern crate mockall;
    extern crate spin;

    use crate::{
        consensus::{RaftLightReady, RaftReady},
        mock::{MockSnapshotReceiver, MockSnapshotSender},
        model::{CommandOutcome, EventOutcome},
        snapshot::DefaultSnapshotProcessor,
        util::raft::{
            create_empty_raft_entry, create_entry_id, create_raft_config_state, create_raft_entry,
            create_raft_message, create_raft_snapshot, create_raft_snapshot_metadata,
            serialize_config_change,
        },
    };

    use self::mockall::predicate::{always, eq};
    use super::*;
    use crate::mock::{MockActor, MockCommunicationModule, MockHost, MockRaft, MockStore};
    use crate::model::ActorError;
    use oak_proto_rust::oak::attestation::v1::ReferenceValues;
    use raft::eraftpb::{
        ConfChange as RaftConfigChange, EntryType as RaftEntryType, MessageType as RaftMessageType,
    };
    use tcp_proto::runtime::endpoint::raft_config::SnapshotConfig;

    const REPLICA_1: u64 = 1;
    const REPLICA_2: u64 = 2;
    const REPLICA_3: u64 = 3;

    fn create_default_parameters() -> (u64, u64, RaftConfig) {
        let node_id = REPLICA_1;
        let instant = 100;

        let raft_config = RaftConfig {
            tick_period: 100,
            election_tick: 20,
            heartbeat_tick: 2,
            max_size_per_msg: 0,
            snapshot_config: Some(SnapshotConfig {
                snapshot_count: 10,
                chunk_size: 20,
                max_pending_chunks: 2,
            }),
            handshake_retry_tick: 1,
        };

        (node_id, instant, raft_config)
    }

    fn create_default_raft_state(node_id: u64) -> RaftState {
        RaftState {
            leader_replica_id: node_id,
            leader_term: 1,
            committed_cluster_config: vec![node_id],
            has_pending_change: false,
        }
    }

    fn create_raft_state(leader_replica_id: u64, committed_cluster_config: Vec<u64>) -> RaftState {
        RaftState {
            leader_replica_id,
            leader_term: 1,
            committed_cluster_config,
            has_pending_change: false,
        }
    }

    fn create_start_replica_request(
        raft_config: RaftConfig,
        leader: bool,
        replica_id_hint: u64,
        app_config: Bytes,
    ) -> InMessage {
        let envelope = InMessage {
            msg: Some(in_message::Msg::StartReplica(StartReplicaRequest {
                is_leader: leader,
                replica_id_hint,
                raft_config: Some(raft_config),
                app_config: app_config,
                is_ephemeral: false,
                endorsements: Some(Endorsements::default()),
                ..Default::default()
            })),
        };
        envelope
    }

    fn create_start_replica_response(replica_id: u64) -> out_message::Msg {
        out_message::Msg::StartReplica(StartReplicaResponse { replica_id })
    }

    fn create_stop_replica_request() -> InMessage {
        let envelope = InMessage {
            msg: Some(in_message::Msg::StopReplica(StopReplicaRequest {})),
        };
        envelope
    }

    fn create_stop_replica_response() -> out_message::Msg {
        out_message::Msg::StopReplica(StopReplicaResponse {})
    }

    fn create_in_deliver_app_message(correlation_id: u64, message_header: Bytes) -> InMessage {
        let envelope = InMessage {
            msg: Some(in_message::Msg::DeliverAppMessage(DeliverAppMessage {
                correlation_id,
                message_header,
                message_payload: Bytes::new(),
            })),
        };
        envelope
    }

    fn create_out_deliver_app_message(
        correlation_id: u64,
        message_header: Bytes,
    ) -> out_message::Msg {
        out_message::Msg::DeliverAppMessage(DeliverAppMessage {
            correlation_id,
            message_header,
            message_payload: Bytes::new(),
        })
    }

    fn create_change_cluster_request(replica_id: u64, change_type: ChangeClusterType) -> InMessage {
        let envelope = InMessage {
            msg: Some(in_message::Msg::ChangeCluster(ChangeClusterRequest {
                change_id: 1,
                replica_id,
                change_type: change_type.into(),
            })),
        };
        envelope
    }

    fn create_change_cluster_response(change_status: ChangeClusterStatus) -> out_message::Msg {
        out_message::Msg::ChangeCluster(ChangeClusterResponse {
            change_id: 1,
            change_status: change_status.into(),
        })
    }

    fn create_check_cluster_request() -> InMessage {
        let envelope = InMessage {
            msg: Some(in_message::Msg::CheckCluster(CheckClusterRequest {})),
        };
        envelope
    }

    fn create_check_cluster_response(raft_state: &RaftState) -> out_message::Msg {
        out_message::Msg::CheckCluster(CheckClusterResponse {
            leader_replica_id: raft_state.leader_replica_id,
            leader_term: raft_state.leader_term,
            cluster_replica_ids: raft_state.committed_cluster_config.clone(),
            has_pending_changes: raft_state.has_pending_change,
        })
    }

    fn create_get_replica_state_request() -> InMessage {
        let envelope = InMessage {
            msg: Some(in_message::Msg::GetReplicaState(GetReplicaStateRequest {})),
        };
        envelope
    }

    fn create_get_replica_state_response(
        applied_index: u64,
        latest_snapshot_size: u64,
    ) -> out_message::Msg {
        out_message::Msg::GetReplicaState(GetReplicaStateResponse {
            applied_index,
            latest_snapshot_size,
        })
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

    fn create_deliver_system_message_request(raft_message: &RaftMessage) -> InMessage {
        let envelope = InMessage {
            msg: Some(in_message::Msg::DeliverSystemMessage(
                DeliverSystemMessage {
                    recipient_replica_id: raft_message.to,
                    sender_replica_id: raft_message.from,
                    payload: Some(Payload {
                        contents: serialize_raft_message(raft_message).unwrap(),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
            )),
        };
        envelope
    }

    fn create_deliver_system_message_response(raft_message: &RaftMessage) -> OutgoingMessage {
        OutgoingMessage::DeliverSystemMessage(
            DeliverSystemMessage {
                recipient_replica_id: raft_message.to,
                sender_replica_id: raft_message.from,
                payload: Some(Payload {
                    contents: serialize_raft_message(raft_message).unwrap(),
                    ..Default::default()
                }),
                ..Default::default()
            },
            raft_message.get_msg_type(),
        )
    }

    fn create_send_messages_matcher(
        expected: Vec<out_message::Msg>,
    ) -> impl Fn(&Vec<OutMessage>) -> bool {
        move |envelopes: &Vec<OutMessage>| {
            let actual: Vec<out_message::Msg> = envelopes
                .iter()
                .map(|m| m.msg.clone().unwrap())
                .filter(|m| {
                    if let out_message::Msg::Log(_) = m {
                        return false;
                    };
                    true
                })
                .collect();
            expected.iter().all(|e| actual.contains(e)) && expected.len() == actual.len()
        }
    }

    fn wrap_deliver_snapshot_request_out(request: DeliverSnapshotRequest) -> out_message::Msg {
        out_message::Msg::DeliverSnapshotRequest(request)
    }

    fn wrap_deliver_snapshot_request_in(request: DeliverSnapshotRequest) -> InMessage {
        InMessage {
            msg: Some(in_message::Msg::DeliverSnapshotRequest(request)),
        }
    }

    fn create_deliver_snapshot_request(
        recipient_id: u64,
        sender_id: u64,
        delivery_id: u64,
    ) -> DeliverSnapshotRequest {
        DeliverSnapshotRequest {
            recipient_replica_id: recipient_id,
            sender_replica_id: sender_id,
            delivery_id,
            payload: Some(Payload {
                contents: vec![4, 5, 6, 7, 8, 9].into(),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    fn wrap_deliver_snapshot_response_out(response: DeliverSnapshotResponse) -> out_message::Msg {
        out_message::Msg::DeliverSnapshotResponse(response)
    }

    fn wrap_deliver_snapshot_response_in(response: DeliverSnapshotResponse) -> InMessage {
        InMessage {
            msg: Some(in_message::Msg::DeliverSnapshotResponse(response)),
        }
    }

    fn create_deliver_snapshot_response(
        recipient_id: u64,
        sender_id: u64,
        delivery_id: u64,
    ) -> DeliverSnapshotResponse {
        DeliverSnapshotResponse {
            recipient_replica_id: recipient_id,
            sender_replica_id: sender_id,
            delivery_id,
            payload: Some(Payload {
                contents: vec![6, 7, 8, 9].into(),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    fn wrap_deliver_snapshot_failure_in(failure: DeliverSnapshotFailure) -> InMessage {
        InMessage {
            msg: Some(in_message::Msg::DeliverSnapshotFailure(failure)),
        }
    }

    fn create_deliver_snapshot_failure(sender_id: u64, delivery_id: u64) -> DeliverSnapshotFailure {
        DeliverSnapshotFailure {
            sender_replica_id: sender_id,
            delivery_id,
        }
    }

    fn get_default_comm_config(raft_config: RaftConfig) -> CommunicationConfig {
        CommunicationConfig {
            handshake_retry_tick: raft_config.handshake_retry_tick,
            handshake_initiated_tick_timeout: raft_config.heartbeat_tick * 10,
            reference_values: ReferenceValues::default(),
            endorsements: Endorsements::default(),
        }
    }

    const DELIVERY_1: u64 = 1;
    const DELIVERY_2: u64 = 2;

    struct MockHostBuilder {
        mock_host: MockHost,
    }

    impl MockHostBuilder {
        fn new() -> MockHostBuilder {
            MockHostBuilder {
                mock_host: MockHost::new(),
            }
        }

        fn expect_public_signing_key(
            &mut self,
            public_signing_key: Vec<u8>,
        ) -> &mut MockHostBuilder {
            self.mock_host
                .expect_public_signing_key()
                .return_once(move || public_signing_key);
            self
        }

        fn expect_send_messages(
            &mut self,
            sent_messages: Vec<out_message::Msg>,
        ) -> &mut MockHostBuilder {
            self.mock_host
                .expect_send_messages()
                .withf(create_send_messages_matcher(sent_messages))
                .return_const(());

            self
        }

        fn take(&mut self) -> MockHost {
            mem::take(&mut self.mock_host)
        }
    }

    struct RaftBuilder {
        mock_store: MockStore,
        mock_raft: MockRaft<MockStore>,
    }

    impl RaftBuilder {
        fn new() -> RaftBuilder {
            RaftBuilder {
                mock_store: MockStore::new(),
                mock_raft: MockRaft::new(),
            }
        }

        fn expect_leader(mut self, leader: bool) -> RaftBuilder {
            self.mock_raft.expect_leader().return_const(leader);

            self
        }

        fn expect_init(
            mut self,
            handler: impl Fn(u64, &raft::Config, Bytes, bool, MockStore, &Logger) -> Result<(), RaftError>
                + 'static,
        ) -> RaftBuilder {
            self.mock_raft.expect_init().return_once_st(handler);
            self.mock_raft.expect_initialized().returning(|| true);

            self
        }

        fn expect_should_snapshot(mut self, should_snapshot: bool) -> RaftBuilder {
            self.mock_store
                .expect_should_snapshot()
                .return_const(should_snapshot);
            self
        }

        fn expect_latest_snapshot_size(mut self, latest_snapshot_size: u64) -> RaftBuilder {
            self.mock_store
                .expect_latest_snapshot_size()
                .return_const(latest_snapshot_size);
            self
        }

        fn expect_apply_snapshot(
            mut self,
            snapshot: RaftSnapshot,
            handler: impl Fn(RaftSnapshot) -> Result<(), RaftError> + 'static,
        ) -> RaftBuilder {
            self.mock_store
                .expect_apply_snapshot()
                .with(eq(snapshot))
                .return_once_st(handler);
            self
        }

        fn expect_append_entries(
            mut self,
            entries: Vec<RaftEntry>,
            handler: impl Fn(&[RaftEntry]) -> Result<(), RaftError> + 'static,
        ) -> RaftBuilder {
            self.mock_store
                .expect_append_entries()
                .with(eq(entries))
                .return_once_st(handler);
            self
        }

        fn expect_create_snapshot(
            mut self,
            applied_index: u64,
            config_state: RaftConfigState,
            snapshot_data: Bytes,
            result: Result<(), RaftError>,
        ) -> RaftBuilder {
            self.mock_store
                .expect_create_snapshot()
                .with(eq(applied_index), eq(config_state), eq(snapshot_data))
                .return_once_st(|_, _, _| result);
            self
        }

        fn expect_make_tick(mut self) -> RaftBuilder {
            self.mock_raft.expect_make_tick().once().return_const(());
            self
        }

        fn expect_make_step(
            mut self,
            raft_message: &RaftMessage,
            result: Result<(), RaftError>,
        ) -> RaftBuilder {
            self.mock_raft
                .expect_make_step()
                .with(eq(raft_message.clone()))
                .return_once_st(move |_| result);
            self
        }

        fn expect_has_ready(mut self, has_ready: bool) -> RaftBuilder {
            self.mock_raft
                .expect_has_ready()
                .once()
                .return_const(has_ready);
            self
        }

        fn expect_state(mut self, raft_state: &RaftState) -> RaftBuilder {
            self.mock_raft
                .expect_state()
                .return_const(raft_state.clone());
            self
        }

        fn expect_state_once(mut self, raft_state: &RaftState) -> RaftBuilder {
            self.mock_raft
                .expect_state()
                .once()
                .return_const(raft_state.clone());
            self
        }

        fn expect_make_proposal(
            mut self,
            proposal: Entry,
            handler: impl Fn(Bytes) -> Result<(), RaftError> + 'static,
        ) -> RaftBuilder {
            self.mock_raft
                .expect_make_proposal()
                .with(eq(Bytes::from(proposal.encode_to_vec())))
                .returning_st(handler);

            self
        }

        fn expect_make_config_change_proposal(
            mut self,
            config_change: RaftConfigChange,
            handler: impl Fn(RaftConfigChange) -> Result<(), RaftError> + 'static,
        ) -> RaftBuilder {
            self.mock_raft
                .expect_make_config_change_proposal()
                .with(eq(config_change))
                .returning_st(handler);

            self
        }

        fn expect_ready(mut self, ready: &RaftReady) -> RaftBuilder {
            let ready = ready.clone();
            self.mock_raft
                .expect_get_ready()
                .once()
                .return_once(move || ready);
            self
        }

        fn expect_apply_config_change(
            mut self,
            config_change: &RaftConfigChange,
            result: Result<RaftConfigState, RaftError>,
        ) -> RaftBuilder {
            let config_change = config_change.clone();
            self.mock_raft
                .expect_apply_config_change()
                .with(eq(config_change))
                .once()
                .return_once_st(move |_| result);
            self
        }

        fn expect_advance_ready(
            mut self,
            ready_number: u64,
            light_ready: RaftLightReady,
        ) -> RaftBuilder {
            self.mock_raft
                .expect_advance_ready()
                .withf_st(move |ready| ready.number() == ready_number)
                .return_const(light_ready);
            self
        }

        fn expect_advance_apply(mut self) -> RaftBuilder {
            self.mock_raft.expect_advance_apply().return_const(());
            self
        }

        fn expect_report_snapshot(
            mut self,
            replica_id: u64,
            status: RaftSnapshotStatus,
        ) -> RaftBuilder {
            self.mock_raft
                .expect_report_snapshot()
                .with(eq(replica_id), eq(status))
                .once()
                .return_const(());
            self
        }

        fn take(&mut self) -> (MockStore, MockRaft<MockStore>) {
            (
                mem::take(&mut self.mock_store),
                mem::take(&mut self.mock_raft),
            )
        }
    }

    struct SnapshotBuilder {
        mock_snapshot_sender: MockSnapshotSender,
        mock_snapshot_receiver: MockSnapshotReceiver,
    }

    impl SnapshotBuilder {
        fn new() -> SnapshotBuilder {
            SnapshotBuilder {
                mock_snapshot_sender: MockSnapshotSender::new(),
                mock_snapshot_receiver: MockSnapshotReceiver::new(),
            }
        }

        fn expect_init(mut self, replica_id: u64) -> SnapshotBuilder {
            let (_, _, raft_config) = create_default_parameters();
            self.mock_snapshot_sender
                .expect_init()
                .with(always(), eq(replica_id), eq(raft_config.snapshot_config))
                .return_const(());

            self.mock_snapshot_receiver
                .expect_init()
                .with(always(), eq(replica_id))
                .return_const(());

            self
        }

        fn expect_receiver_set_instant(mut self) -> SnapshotBuilder {
            self.mock_snapshot_receiver
                .expect_set_instant()
                .return_const(());

            self
        }

        fn expect_receiver_try_complete(
            mut self,
            result: Option<Result<(u64, RaftSnapshot), SnapshotError>>,
        ) -> SnapshotBuilder {
            self.mock_snapshot_receiver
                .expect_try_complete()
                .once()
                .return_once(|| result);

            self
        }

        fn expect_receiver_process_request(
            mut self,
            request: DeliverSnapshotRequest,
            response: DeliverSnapshotResponse,
        ) -> SnapshotBuilder {
            self.mock_snapshot_receiver
                .expect_process_request()
                .with(eq(request))
                .once()
                .return_const(response);

            self
        }

        fn expect_receiver_reset(mut self) -> SnapshotBuilder {
            self.mock_snapshot_receiver.expect_reset().return_const(());

            self
        }

        fn expect_sender_set_instant(mut self) -> SnapshotBuilder {
            self.mock_snapshot_sender
                .expect_set_instant()
                .return_const(());

            self
        }

        fn expect_sender_process_response(
            mut self,
            sender_id: u64,
            delivery_id: u64,
            response: Result<DeliverSnapshotResponse, SnapshotError>,
        ) -> SnapshotBuilder {
            self.mock_snapshot_sender
                .expect_process_response()
                .with(eq(sender_id), eq(delivery_id), eq(response))
                .once()
                .return_const(());
            self
        }

        fn expect_sender_next_request(
            mut self,
            request: Option<DeliverSnapshotRequest>,
        ) -> SnapshotBuilder {
            self.mock_snapshot_sender
                .expect_next_request()
                .once()
                .return_once(|| request);

            self
        }

        fn expect_sender_try_complete(
            mut self,
            result: Option<(u64, RaftSnapshotStatus)>,
        ) -> SnapshotBuilder {
            self.mock_snapshot_sender
                .expect_try_complete()
                .once()
                .return_once(move || result);

            self
        }

        fn expect_sender_start(
            mut self,
            recipient_id: u64,
            snapshot: RaftSnapshot,
        ) -> SnapshotBuilder {
            self.mock_snapshot_sender
                .expect_start()
                .with(eq(recipient_id), eq(snapshot))
                .once()
                .return_const(());

            self
        }

        fn take(mut self) -> (MockSnapshotSender, MockSnapshotReceiver) {
            (
                mem::take(&mut self.mock_snapshot_sender),
                mem::take(&mut self.mock_snapshot_receiver),
            )
        }
    }

    struct CommunicationBuilder {
        mock_communication_module: MockCommunicationModule,
    }

    impl CommunicationBuilder {
        fn new() -> CommunicationBuilder {
            CommunicationBuilder {
                mock_communication_module: MockCommunicationModule::new(),
            }
        }

        fn expect_init(
            mut self,
            replica_id: u64,
            config: CommunicationConfig,
        ) -> CommunicationBuilder {
            self.mock_communication_module
                .expect_init()
                .with(eq(replica_id), always(), always(), eq(config))
                .once()
                .return_const(());

            self
        }

        fn expect_make_tick(mut self) -> CommunicationBuilder {
            self.mock_communication_module
                .expect_make_tick()
                .once()
                .return_const(());
            self
        }

        fn expect_process_out_message(
            mut self,
            message: OutgoingMessage,
            result: Result<(), PalError>,
        ) -> CommunicationBuilder {
            self.mock_communication_module
                .expect_process_out_message()
                .with(eq(message))
                .return_once_st(|_| result);

            self
        }

        fn expect_process_in_message(
            mut self,
            message: in_message::Msg,
            result: Result<Option<in_message::Msg>, PalError>,
        ) -> CommunicationBuilder {
            self.mock_communication_module
                .expect_process_in_message()
                .with(eq(message))
                .return_once_st(|_| result);

            self
        }

        fn expect_take_out_messages(mut self, messages: Vec<OutMessage>) -> CommunicationBuilder {
            self.mock_communication_module
                .expect_take_out_messages()
                .once()
                .return_const(messages);

            self
        }

        fn expect_process_cluster_change(mut self, replicas: Vec<u64>) -> CommunicationBuilder {
            self.mock_communication_module
                .expect_process_cluster_change()
                .with(eq(replicas))
                .once()
                .return_const(());
            self
        }

        fn take(mut self) -> MockCommunicationModule {
            mem::take(&mut self.mock_communication_module)
        }
    }

    struct DriverBuilder {
        mock_actor: MockActor,
    }

    impl DriverBuilder {
        fn new() -> DriverBuilder {
            DriverBuilder {
                mock_actor: MockActor::new(),
            }
        }

        fn expect_on_init(
            &mut self,
            init_handler: impl Fn(Box<dyn ActorContext>) -> Result<(), ActorError> + 'static,
        ) -> &mut DriverBuilder {
            self.mock_actor
                .expect_on_init()
                .return_once_st(init_handler);

            self
        }

        fn expect_on_shutdown(&mut self) -> &mut DriverBuilder {
            self.mock_actor.expect_on_shutdown().once().return_const(());

            self
        }

        fn expect_get_reference_values(
            &mut self,
            reference_values: ReferenceValues,
        ) -> &mut DriverBuilder {
            self.mock_actor
                .expect_get_reference_values()
                .once()
                .return_once(|| reference_values);

            self
        }

        fn expect_on_process_command(
            &mut self,
            command: Option<ActorCommand>,
            result: Result<CommandOutcome, ActorError>,
        ) -> &mut DriverBuilder {
            self.mock_actor
                .expect_on_process_command()
                .with(eq(command))
                .returning(move |_| result.clone());

            self
        }

        fn expect_on_load_snapshot(
            &mut self,
            snapshot: Bytes,
            result: Result<(), ActorError>,
        ) -> &mut DriverBuilder {
            self.mock_actor
                .expect_on_load_snapshot()
                .with(eq(snapshot))
                .return_once(|_| result);
            self
        }

        fn expect_on_save_snapshot(
            &mut self,
            result: Result<Bytes, ActorError>,
        ) -> &mut DriverBuilder {
            self.mock_actor
                .expect_on_save_snapshot()
                .return_once(|| result);
            self
        }

        fn expect_on_apply_event(
            &mut self,
            context: ActorEventContext,
            event: ActorEvent,
            result: Result<EventOutcome, ActorError>,
        ) -> &mut DriverBuilder {
            self.mock_actor
                .expect_on_apply_event()
                .with(eq(context), eq(event))
                .return_once(|_, _| result);

            self
        }

        fn take(
            &mut self,
            mut raft_builder: RaftBuilder,
            snapshot_builder: SnapshotBuilder,
            communication_builder: CommunicationBuilder,
        ) -> Driver<
            MockRaft<MockStore>,
            MockStore,
            DefaultSnapshotProcessor,
            MockActor,
            MockCommunicationModule,
        > {
            let (mock_store, mut mock_raft) = raft_builder.take();
            let mock_actor = mem::take(&mut self.mock_actor);
            let (mock_snapshot_sender, mock_snapshot_receiver) = snapshot_builder.take();
            let mock_communication_module = communication_builder.take();

            mock_raft.expect_mut_store().return_var(mock_store);

            Driver::new(
                mock_raft,
                Box::new(|_, _| MockStore::new()),
                DefaultSnapshotProcessor::new(
                    Box::new(mock_snapshot_sender),
                    Box::new(mock_snapshot_receiver),
                ),
                mock_actor,
                mock_communication_module,
                /*logger=*/ None,
            )
        }
    }

    #[test]
    fn test_driver_start_node_request() {
        let (node_id, instant, raft_config) = create_default_parameters();
        let init_snapshot = Bytes::from(vec![2, 3, 4]);

        let mut mock_host = MockHostBuilder::new()
            .expect_public_signing_key(vec![])
            .expect_send_messages(vec![create_start_replica_response(node_id)])
            .take();

        let exp_raft_config = raft_config.clone();
        let exp_init_snapshot = init_snapshot.clone();
        let raft_builder = RaftBuilder::new()
            .expect_leader(false)
            .expect_init(move |id, config, snapshot, leader, _, _| {
                assert_eq!(node_id, config.id);
                assert_eq!(exp_raft_config.election_tick as usize, config.election_tick);
                assert_eq!(
                    exp_raft_config.heartbeat_tick as usize,
                    config.heartbeat_tick
                );
                assert_eq!(exp_raft_config.max_size_per_msg, config.max_size_per_msg);
                assert_eq!(node_id, id);
                assert_eq!(exp_init_snapshot, snapshot);
                assert!(leader);
                Ok(())
            })
            .expect_has_ready(false)
            .expect_should_snapshot(false)
            .expect_state(&create_default_raft_state(node_id));

        let snapshot_builder = SnapshotBuilder::new()
            .expect_init(node_id)
            .expect_receiver_set_instant()
            .expect_receiver_try_complete(None);

        let communication_builder = CommunicationBuilder::new()
            .expect_init(node_id, get_default_comm_config(raft_config.clone()))
            .expect_make_tick()
            .expect_take_out_messages(Vec::new());

        let mut driver = DriverBuilder::new()
            .expect_on_init(|_| Ok(()))
            .expect_get_reference_values(ReferenceValues::default())
            .expect_on_save_snapshot(Ok(init_snapshot.clone()))
            .expect_on_process_command(None, Ok(CommandOutcome::with_none()))
            .take(raft_builder, snapshot_builder, communication_builder);

        assert_eq!(
            Ok(()),
            driver.receive_message(
                &mut mock_host,
                instant,
                Some(create_start_replica_request(
                    raft_config.clone(),
                    true,
                    node_id,
                    Bytes::new()
                )),
            )
        );
    }

    #[test]
    fn test_driver_stop_node_request() {
        let (node_id, instant, raft_config) = create_default_parameters();
        let init_snapshot = Bytes::from(vec![2, 3, 4]);

        let mut mock_host = MockHostBuilder::new()
            .expect_public_signing_key(vec![])
            .expect_send_messages(vec![create_start_replica_response(node_id)])
            .expect_send_messages(vec![create_stop_replica_response()])
            .take();

        let raft_builder = RaftBuilder::new()
            .expect_leader(false)
            .expect_init(|_, _, _, _, _, _| Ok(()))
            .expect_has_ready(false)
            .expect_has_ready(false)
            .expect_should_snapshot(false)
            .expect_state(&create_default_raft_state(node_id));

        let snapshot_builder = SnapshotBuilder::new()
            .expect_init(node_id)
            .expect_receiver_set_instant()
            .expect_receiver_try_complete(None);

        let communication_builder = CommunicationBuilder::new()
            .expect_init(node_id, get_default_comm_config(raft_config.clone()))
            .expect_make_tick()
            .expect_take_out_messages(Vec::new())
            .expect_take_out_messages(Vec::new());

        let mut driver = DriverBuilder::new()
            .expect_on_init(|_| Ok(()))
            .expect_get_reference_values(ReferenceValues::default())
            .expect_on_save_snapshot(Ok(init_snapshot.clone()))
            .expect_on_process_command(None, Ok(CommandOutcome::with_none()))
            .expect_on_shutdown()
            .take(raft_builder, snapshot_builder, communication_builder);

        assert_eq!(
            Ok(()),
            driver.receive_message(
                &mut mock_host,
                instant,
                Some(create_start_replica_request(
                    raft_config.clone(),
                    true,
                    node_id,
                    Bytes::new()
                )),
            )
        );

        assert_eq!(
            Ok(()),
            driver.receive_message(
                &mut mock_host,
                instant + 10,
                Some(create_stop_replica_request()),
            )
        );
    }

    #[test]
    fn test_driver_deliver_app_message_request() {
        let (node_id, instant, raft_config) = create_default_parameters();
        let init_snapshot = Bytes::from(vec![2, 3, 4]);
        let proposal_contents_1 = Bytes::from(vec![1, 2, 3]);
        let proposal_contents_2 = Bytes::from(vec![4, 5, 6]);
        let proposal_result_2 = vec![4, 4, 6];
        let correlation_id_1 = 1;
        let correlation_id_2 = 2;
        let entry_id_1 = create_entry_id(node_id, correlation_id_1);

        let mut mock_host = MockHostBuilder::new()
            .expect_public_signing_key(vec![])
            .expect_send_messages(vec![create_start_replica_response(node_id)])
            .expect_send_messages(vec![])
            .expect_send_messages(vec![create_out_deliver_app_message(
                correlation_id_2,
                proposal_result_2.clone().into(),
            )])
            .take();

        let proposal_entry_1 = Entry {
            entry_id: Some(entry_id_1.clone()),
            entry_contents: proposal_contents_1.clone().into(),
        };

        let raft_builder = RaftBuilder::new()
            .expect_leader(false)
            .expect_init(|_, _, _, _, _, _| Ok(()))
            .expect_has_ready(false)
            .expect_has_ready(false)
            .expect_has_ready(false)
            .expect_make_proposal(proposal_entry_1, |_| Ok(()))
            .expect_should_snapshot(false)
            .expect_state(&create_default_raft_state(node_id));

        let snapshot_builder = SnapshotBuilder::new()
            .expect_init(node_id)
            .expect_receiver_set_instant()
            .expect_receiver_try_complete(None)
            .expect_receiver_try_complete(None)
            .expect_receiver_try_complete(None);

        let communication_builder = CommunicationBuilder::new()
            .expect_init(node_id, get_default_comm_config(raft_config.clone()))
            .expect_make_tick()
            .expect_make_tick()
            .expect_make_tick()
            .expect_take_out_messages(Vec::new())
            .expect_take_out_messages(Vec::new())
            .expect_take_out_messages(Vec::new());

        let mut driver = DriverBuilder::new()
            .expect_on_init(|_| Ok(()))
            .expect_get_reference_values(ReferenceValues::default())
            .expect_on_save_snapshot(Ok(init_snapshot.clone()))
            .expect_on_process_command(None, Ok(CommandOutcome::with_none()))
            .expect_on_process_command(
                Some(ActorCommand {
                    correlation_id: correlation_id_1,
                    header: proposal_contents_1.clone(),
                    payload: Bytes::new(),
                }),
                Ok(CommandOutcome::with_event(ActorEvent {
                    correlation_id: correlation_id_1,
                    contents: proposal_contents_1.clone().into(),
                })),
            )
            .expect_on_process_command(
                Some(ActorCommand {
                    correlation_id: correlation_id_2,
                    header: proposal_contents_2.clone(),
                    payload: Bytes::new(),
                }),
                Ok(CommandOutcome::with_command(ActorCommand {
                    correlation_id: correlation_id_2,
                    header: proposal_result_2.clone().into(),
                    payload: Bytes::new(),
                })),
            )
            .take(raft_builder, snapshot_builder, communication_builder);

        assert_eq!(
            Ok(()),
            driver.receive_message(
                &mut mock_host,
                instant,
                Some(create_start_replica_request(
                    raft_config.clone(),
                    true,
                    node_id,
                    Bytes::new()
                )),
            )
        );

        assert_eq!(
            Ok(()),
            driver.receive_message(
                &mut mock_host,
                instant + 10,
                Some(create_in_deliver_app_message(
                    correlation_id_1,
                    proposal_contents_1.clone().into()
                )),
            )
        );

        assert_eq!(
            Ok(()),
            driver.receive_message(
                &mut mock_host,
                instant + 10,
                Some(create_in_deliver_app_message(
                    correlation_id_2,
                    proposal_contents_2.clone().into()
                )),
            )
        );
    }

    #[test]
    fn test_driver_actor_context() {
        let (node_id, instant, raft_config) = create_default_parameters();
        let init_snapshot = Bytes::from(vec![2, 3, 4]);
        let self_config = vec![1, 2, 3];

        let mut mock_host = MockHostBuilder::new()
            .expect_public_signing_key(vec![])
            .expect_send_messages(vec![create_start_replica_response(node_id)])
            .take();

        let raft_builder = RaftBuilder::new()
            .expect_leader(false)
            .expect_init(|_, _, _, _, _, _| Ok(()))
            .expect_has_ready(false)
            .expect_should_snapshot(false)
            .expect_state(&create_default_raft_state(node_id));

        let snapshot_builder = SnapshotBuilder::new()
            .expect_init(node_id)
            .expect_receiver_set_instant()
            .expect_receiver_try_complete(None);

        let communication_builder = CommunicationBuilder::new()
            .expect_init(node_id, get_default_comm_config(raft_config.clone()))
            .expect_make_tick()
            .expect_take_out_messages(Vec::new());

        let exp_self_config = self_config.clone();
        let mut driver = DriverBuilder::new()
            .expect_on_init(move |actor_context| {
                assert_eq!(node_id, actor_context.id());
                assert_eq!(instant, actor_context.instant());
                assert_eq!(exp_self_config, actor_context.config());
                assert!(!actor_context.leader());

                Ok(())
            })
            .expect_get_reference_values(ReferenceValues::default())
            .expect_on_save_snapshot(Ok(init_snapshot.clone()))
            .expect_on_process_command(None, Ok(CommandOutcome::with_none()))
            .take(raft_builder, snapshot_builder, communication_builder);

        assert_eq!(
            Ok(()),
            driver.receive_message(
                &mut mock_host,
                instant,
                Some(create_start_replica_request(
                    raft_config.clone(),
                    true,
                    node_id,
                    self_config.into()
                )),
            )
        );
    }

    #[test]
    fn test_driver_ephemeral_replica() {
        let (node_id, instant, raft_config) = create_default_parameters();
        let self_config = vec![1, 2, 3];
        let correlation_id = 1;
        let proposal_contents = Bytes::from(vec![1, 2, 3]);
        let actor_command_1 = ActorCommand {
            correlation_id,
            header: proposal_contents.clone(),
            payload: Bytes::new(),
        };
        let actor_event = ActorEvent {
            correlation_id,
            contents: proposal_contents.clone(),
        };
        let proposal_result = vec![4, 4, 6];
        let actor_command_2 = ActorCommand {
            correlation_id,
            header: proposal_result.clone().into(),
            payload: Bytes::new(),
        };

        let mut mock_host = MockHostBuilder::new()
            .expect_public_signing_key(vec![])
            .expect_send_messages(vec![create_start_replica_response(node_id)])
            .expect_send_messages(vec![
                create_out_deliver_app_message(correlation_id, proposal_contents.clone().into()),
                create_out_deliver_app_message(correlation_id, proposal_result.clone().into()),
            ])
            .expect_send_messages(vec![create_stop_replica_response()])
            .take();

        let raft_builder = RaftBuilder::new().expect_leader(false);
        let snapshot_builder = SnapshotBuilder::new();
        let communication_builder = CommunicationBuilder::new()
            .expect_init(node_id, get_default_comm_config(raft_config.clone()))
            .expect_make_tick()
            .expect_make_tick()
            .expect_take_out_messages(Vec::new())
            .expect_take_out_messages(Vec::new())
            .expect_take_out_messages(Vec::new());

        let exp_self_config = self_config.clone();

        let mut driver = DriverBuilder::new()
            .expect_on_init(move |actor_context| {
                assert_eq!(node_id, actor_context.id());
                assert_eq!(instant, actor_context.instant());
                assert_eq!(exp_self_config, actor_context.config());
                assert!(!actor_context.leader());

                Ok(())
            })
            .expect_get_reference_values(ReferenceValues::default())
            .expect_on_process_command(None, Ok(CommandOutcome::with_none()))
            .expect_on_process_command(
                Some(actor_command_1.clone()),
                Ok(CommandOutcome::with_command_and_event(
                    actor_command_1.clone(),
                    actor_event.clone(),
                )),
            )
            .expect_on_apply_event(
                ActorEventContext {
                    index: 0,
                    owned: true,
                },
                actor_event.clone(),
                Ok(EventOutcome::with_command(actor_command_2.clone())),
            )
            .expect_on_shutdown()
            .take(raft_builder, snapshot_builder, communication_builder);

        assert_eq!(
            Ok(()),
            driver.receive_message(
                &mut mock_host,
                instant,
                Some(InMessage {
                    msg: Some(in_message::Msg::StartReplica(StartReplicaRequest {
                        is_leader: false,
                        replica_id_hint: node_id,
                        raft_config: Some(raft_config),
                        app_config: self_config.into(),
                        is_ephemeral: true,
                        endorsements: Some(Endorsements::default()),
                        ..Default::default()
                    })),
                }),
            )
        );

        assert_eq!(
            Ok(()),
            driver.receive_message(
                &mut mock_host,
                instant + 10,
                Some(create_in_deliver_app_message(
                    correlation_id,
                    proposal_contents.clone().into()
                )),
            )
        );

        assert_eq!(
            Ok(()),
            driver.receive_message(
                &mut mock_host,
                instant + 20,
                Some(create_stop_replica_request()),
            )
        );
    }

    #[test]
    fn test_driver_change_cluster_request() {
        let (node_id, instant, raft_config) = create_default_parameters();
        let init_snapshot = Bytes::from(vec![2, 3, 4]);
        let peer_id = 2;

        let mut mock_host = MockHostBuilder::new()
            .expect_public_signing_key(vec![])
            .expect_send_messages(vec![create_start_replica_response(node_id)])
            .expect_send_messages(vec![create_change_cluster_response(
                ChangeClusterStatus::ChangeStatusPending,
            )])
            .take();

        let raft_builder = RaftBuilder::new()
            .expect_leader(false)
            .expect_init(|_, _, _, _, _, _| Ok(()))
            .expect_has_ready(false)
            .expect_has_ready(false)
            .expect_should_snapshot(false)
            .expect_state(&create_default_raft_state(node_id))
            .expect_make_config_change_proposal(
                create_raft_config_change(peer_id, RaftConfigChangeType::AddNode),
                |_| Ok(()),
            );

        let snapshot_builder = SnapshotBuilder::new()
            .expect_init(node_id)
            .expect_receiver_set_instant()
            .expect_receiver_try_complete(None)
            .expect_receiver_try_complete(None);

        let communication_builder = CommunicationBuilder::new()
            .expect_init(node_id, get_default_comm_config(raft_config.clone()))
            .expect_make_tick()
            .expect_make_tick()
            .expect_take_out_messages(Vec::new())
            .expect_take_out_messages(Vec::new());

        let mut driver = DriverBuilder::new()
            .expect_on_init(|_| Ok(()))
            .expect_get_reference_values(ReferenceValues::default())
            .expect_on_save_snapshot(Ok(init_snapshot.clone()))
            .expect_on_process_command(None, Ok(CommandOutcome::with_none()))
            .take(raft_builder, snapshot_builder, communication_builder);

        assert_eq!(
            Ok(()),
            driver.receive_message(
                &mut mock_host,
                instant,
                Some(create_start_replica_request(
                    raft_config.clone(),
                    true,
                    node_id,
                    Bytes::new()
                )),
            )
        );

        assert_eq!(
            Ok(()),
            driver.receive_message(
                &mut mock_host,
                instant + 10,
                Some(create_change_cluster_request(
                    peer_id,
                    ChangeClusterType::ChangeTypeAddReplica
                )),
            )
        );
    }

    #[test]
    fn test_driver_check_cluster_request() {
        let (node_id, instant, raft_config) = create_default_parameters();
        let init_snapshot = Bytes::from(vec![2, 3, 4]);
        let peer_id = 2;

        let raft_state = create_default_raft_state(node_id);

        let mut mock_host = MockHostBuilder::new()
            .expect_public_signing_key(vec![])
            .expect_send_messages(vec![create_start_replica_response(node_id)])
            .expect_send_messages(vec![create_check_cluster_response(&raft_state)])
            .take();

        let raft_builder = RaftBuilder::new()
            .expect_leader(false)
            .expect_init(|_, _, _, _, _, _| Ok(()))
            .expect_has_ready(false)
            .expect_has_ready(false)
            .expect_should_snapshot(false)
            .expect_state(&raft_state)
            .expect_make_config_change_proposal(
                create_raft_config_change(peer_id, RaftConfigChangeType::AddNode),
                |_| Ok(()),
            );

        let snapshot_builder = SnapshotBuilder::new()
            .expect_init(node_id)
            .expect_receiver_set_instant()
            .expect_receiver_try_complete(None)
            .expect_receiver_try_complete(None)
            .expect_receiver_reset()
            .expect_sender_set_instant()
            .expect_sender_next_request(None);

        let communication_builder = CommunicationBuilder::new()
            .expect_init(node_id, get_default_comm_config(raft_config.clone()))
            .expect_make_tick()
            .expect_take_out_messages(Vec::new())
            .expect_process_cluster_change(vec![node_id])
            .expect_make_tick()
            .expect_take_out_messages(Vec::new());

        let mut driver = DriverBuilder::new()
            .expect_on_init(|_| Ok(()))
            .expect_get_reference_values(ReferenceValues::default())
            .expect_on_save_snapshot(Ok(init_snapshot.clone()))
            .expect_on_process_command(None, Ok(CommandOutcome::with_none()))
            .take(raft_builder, snapshot_builder, communication_builder);

        assert_eq!(
            Ok(()),
            driver.receive_message(
                &mut mock_host,
                instant,
                Some(create_start_replica_request(
                    raft_config.clone(),
                    true,
                    node_id,
                    Bytes::new()
                )),
            )
        );

        assert_eq!(
            Ok(()),
            driver.receive_message(
                &mut mock_host,
                instant + 10,
                Some(create_check_cluster_request()),
            )
        );
    }

    #[test]
    fn test_driver_raft_ready() {
        let (node_id, instant, raft_config) = create_default_parameters();
        let init_snapshot = Bytes::from(vec![2, 3, 4]);
        let peer_id = 2;

        let raft_state = RaftState::default();

        let message_a = create_raft_message(node_id, peer_id, RaftMessageType::MsgBeat);
        let messages = vec![message_a.clone()];

        let message_b = create_raft_message(node_id, peer_id, RaftMessageType::MsgAppend);
        let persisted_messages: Vec<RaftMessage> = vec![message_b.clone()];

        let entries = vec![create_empty_raft_entry(3, 2)];

        let proposal_result = vec![4, 5, 6];
        let entry_id = create_entry_id(node_id, 1);
        let entry = create_entry(entry_id.clone(), proposal_result.clone().into());
        let committed_normal_entry = create_raft_entry(
            2,
            2,
            RaftEntryType::EntryNormal,
            entry.encode_to_vec().into(),
        );

        let config_change = create_raft_config_change(peer_id, RaftConfigChangeType::AddNode);
        let config_state = create_raft_config_state(vec![node_id, peer_id]);
        let committed_config_entry = create_raft_entry(
            3,
            2,
            RaftEntryType::EntryConfChange,
            serialize_config_change(&config_change).unwrap(),
        );
        let committed_entries = vec![
            committed_normal_entry.clone(),
            committed_config_entry.clone(),
        ];

        let snapshot = create_raft_snapshot(
            create_raft_snapshot_metadata(1, 1, create_raft_config_state(vec![node_id, peer_id])),
            vec![1, 2, 3].into(),
        );

        let ready = RaftReady::new(
            messages,
            persisted_messages,
            entries.clone(),
            committed_entries,
            None,
            snapshot.clone(),
            1,
        );

        let light_ready = RaftLightReady::default();

        let mut mock_host = MockHostBuilder::new()
            .expect_public_signing_key(vec![])
            .expect_send_messages(vec![create_start_replica_response(node_id)])
            .expect_send_messages(vec![
                out_message::Msg::SecureChannelHandshake(create_secure_channel_handshake(
                    node_id, peer_id,
                )),
                create_out_deliver_app_message(entry_id.entry_id, proposal_result.clone().into()),
            ])
            .take();

        let raft_builder = RaftBuilder::new()
            .expect_leader(false)
            .expect_init(|_, _, _, _, _, _| Ok(()))
            .expect_should_snapshot(false)
            .expect_state(&raft_state)
            .expect_has_ready(false)
            .expect_has_ready(true)
            .expect_ready(&ready)
            .expect_advance_ready(ready.number(), light_ready)
            .expect_advance_apply()
            .expect_apply_snapshot(snapshot.clone(), |_| Ok(()))
            .expect_append_entries(entries, |_| Ok(()))
            .expect_apply_config_change(&config_change, Ok(config_state.clone()));

        let snapshot_builder = SnapshotBuilder::new()
            .expect_init(node_id)
            .expect_receiver_set_instant()
            .expect_receiver_try_complete(None)
            .expect_receiver_try_complete(None);

        let communication_builder = CommunicationBuilder::new()
            .expect_init(node_id, get_default_comm_config(raft_config.clone()))
            .expect_make_tick()
            .expect_take_out_messages(Vec::new())
            .expect_process_out_message(create_deliver_system_message_response(&message_a), Ok(()))
            .expect_process_out_message(create_deliver_system_message_response(&message_b), Ok(()))
            .expect_make_tick()
            .expect_take_out_messages(vec![OutMessage {
                msg: Some(out_message::Msg::SecureChannelHandshake(
                    create_secure_channel_handshake(node_id, peer_id),
                )),
            }]);

        let mut driver = DriverBuilder::new()
            .expect_on_init(|_| Ok(()))
            .expect_get_reference_values(ReferenceValues::default())
            .expect_on_save_snapshot(Ok(init_snapshot.clone()))
            .expect_on_load_snapshot(snapshot.data.into(), Ok(()))
            .expect_on_process_command(None, Ok(CommandOutcome::with_none()))
            .expect_on_apply_event(
                ActorEventContext {
                    index: committed_normal_entry.index,
                    owned: true,
                },
                ActorEvent {
                    correlation_id: entry_id.entry_id,
                    contents: entry.entry_contents.into(),
                },
                Ok(EventOutcome::with_command(ActorCommand {
                    correlation_id: entry_id.entry_id,
                    header: proposal_result.into(),
                    payload: Bytes::new(),
                })),
            )
            .take(raft_builder, snapshot_builder, communication_builder);

        assert_eq!(
            Ok(()),
            driver.receive_message(
                &mut mock_host,
                instant,
                Some(create_start_replica_request(
                    raft_config.clone(),
                    false,
                    node_id,
                    Bytes::new()
                )),
            )
        );

        assert_eq!(
            Ok(()),
            driver.receive_message(&mut mock_host, instant + 10, None)
        );
    }

    #[test]
    fn test_driver_raft_tick() {
        let (node_id, instant, raft_config) = create_default_parameters();
        let init_snapshot = Bytes::from(vec![2, 3, 4]);

        let raft_state = create_default_raft_state(node_id);

        let mut mock_host = MockHostBuilder::new()
            .expect_public_signing_key(vec![])
            .expect_send_messages(vec![create_start_replica_response(node_id)])
            .expect_send_messages(vec![])
            .take();

        let raft_builder = RaftBuilder::new()
            .expect_leader(false)
            .expect_init(|_, _, _, _, _, _| Ok(()))
            .expect_has_ready(false)
            .expect_has_ready(false)
            .expect_should_snapshot(false)
            .expect_state(&raft_state)
            .expect_make_tick();

        let snapshot_builder = SnapshotBuilder::new()
            .expect_init(node_id)
            .expect_receiver_set_instant()
            .expect_receiver_try_complete(None)
            .expect_receiver_try_complete(None);

        let communication_builder = CommunicationBuilder::new()
            .expect_init(node_id, get_default_comm_config(raft_config.clone()))
            .expect_make_tick()
            .expect_make_tick()
            .expect_take_out_messages(Vec::new())
            .expect_take_out_messages(Vec::new());

        let mut driver = DriverBuilder::new()
            .expect_on_init(|_| Ok(()))
            .expect_get_reference_values(ReferenceValues::default())
            .expect_on_save_snapshot(Ok(init_snapshot.clone()))
            .expect_on_process_command(None, Ok(CommandOutcome::with_none()))
            .take(raft_builder, snapshot_builder, communication_builder);

        assert_eq!(
            Ok(()),
            driver.receive_message(
                &mut mock_host,
                instant,
                Some(create_start_replica_request(
                    raft_config.clone(),
                    true,
                    node_id,
                    Bytes::new()
                )),
            )
        );

        assert_eq!(
            Ok(()),
            driver.receive_message(&mut mock_host, instant + raft_config.tick_period, None,)
        );
    }

    #[test]
    fn test_driver_raft_step() {
        let (node_id, instant, raft_config) = create_default_parameters();
        let init_snapshot = Bytes::from(vec![2, 3, 4]);
        let peer_id = 2;

        let raft_state = create_default_raft_state(node_id);

        let message_a = create_raft_message(peer_id, node_id, RaftMessageType::MsgBeat);

        let handshake_message = create_secure_channel_handshake(peer_id, node_id);

        let mut mock_host = MockHostBuilder::new()
            .expect_public_signing_key(vec![])
            .expect_send_messages(vec![create_start_replica_response(node_id)])
            .expect_send_messages(vec![])
            .expect_send_messages(vec![])
            .take();

        let raft_builder = RaftBuilder::new()
            .expect_leader(false)
            .expect_init(|_, _, _, _, _, _| Ok(()))
            .expect_has_ready(false)
            .expect_has_ready(false)
            .expect_has_ready(false)
            .expect_should_snapshot(false)
            .expect_state(&raft_state)
            .expect_make_step(&message_a, Ok(()));

        let snapshot_builder = SnapshotBuilder::new()
            .expect_init(node_id)
            .expect_receiver_set_instant()
            .expect_receiver_try_complete(None)
            .expect_receiver_try_complete(None)
            .expect_receiver_try_complete(None);

        let communication_builder = CommunicationBuilder::new()
            .expect_init(node_id, get_default_comm_config(raft_config.clone()))
            .expect_make_tick()
            .expect_take_out_messages(Vec::new())
            .expect_process_in_message(
                in_message::Msg::SecureChannelHandshake(handshake_message.clone()),
                Ok(None),
            )
            .expect_make_tick()
            .expect_take_out_messages(Vec::new())
            .expect_process_in_message(
                create_deliver_system_message_request(&message_a)
                    .msg
                    .unwrap(),
                Ok(Some(
                    create_deliver_system_message_request(&message_a)
                        .msg
                        .unwrap(),
                )),
            )
            .expect_make_tick()
            .expect_take_out_messages(Vec::new());

        let mut driver = DriverBuilder::new()
            .expect_on_init(|_| Ok(()))
            .expect_get_reference_values(ReferenceValues::default())
            .expect_on_save_snapshot(Ok(init_snapshot.clone()))
            .expect_on_process_command(None, Ok(CommandOutcome::with_none()))
            .take(raft_builder, snapshot_builder, communication_builder);

        assert_eq!(
            Ok(()),
            driver.receive_message(
                &mut mock_host,
                instant,
                Some(create_start_replica_request(
                    raft_config.clone(),
                    true,
                    node_id,
                    Bytes::new()
                )),
            )
        );

        assert_eq!(
            Ok(()),
            driver.receive_message(
                &mut mock_host,
                instant + 10,
                Some(InMessage {
                    msg: Some(in_message::Msg::SecureChannelHandshake(
                        handshake_message.clone()
                    ))
                }),
            )
        );

        assert_eq!(
            Ok(()),
            driver.receive_message(
                &mut mock_host,
                instant + 20,
                Some(create_deliver_system_message_request(&message_a)),
            )
        );
    }

    #[test]
    fn test_driver_trigger_snapshot() {
        let (node_id, instant, raft_config) = create_default_parameters();
        let init_snapshot = Bytes::from(vec![2, 3, 4]);

        let raft_state = create_default_raft_state(node_id);

        let proposal_result = vec![4, 5, 6];

        let entry_id = create_entry_id(node_id, 1);
        let entry = create_entry(entry_id.clone(), proposal_result.clone().into());

        let committed_normal_entry = create_raft_entry(
            2,
            2,
            RaftEntryType::EntryNormal,
            entry.encode_to_vec().into(),
        );

        let snapshot = Bytes::from(vec![4, 5, 6]);
        let latest_snapshot_size = snapshot.len() as u64;

        let mut mock_host = MockHostBuilder::new()
            .expect_public_signing_key(vec![])
            .expect_send_messages(vec![create_start_replica_response(node_id)])
            .expect_send_messages(vec![create_out_deliver_app_message(
                entry_id.entry_id,
                proposal_result.clone().into(),
            )])
            .expect_send_messages(vec![create_get_replica_state_response(
                committed_normal_entry.index,
                latest_snapshot_size,
            )])
            .take();

        let ready = RaftReady::new(
            vec![],
            vec![],
            vec![],
            vec![committed_normal_entry.clone()],
            None,
            RaftSnapshot::default(),
            1,
        );
        let light_ready = RaftLightReady::default();

        let raft_builder = RaftBuilder::new()
            .expect_leader(false)
            .expect_init(|_, _, _, _, _, _| Ok(()))
            .expect_has_ready(false)
            .expect_has_ready(true)
            .expect_has_ready(false)
            .expect_ready(&ready)
            .expect_should_snapshot(false)
            .expect_should_snapshot(true)
            .expect_create_snapshot(
                committed_normal_entry.index,
                create_raft_config_state(raft_state.committed_cluster_config.clone()),
                snapshot.clone(),
                Ok(()),
            )
            .expect_state(&raft_state)
            .expect_advance_ready(ready.number(), light_ready)
            .expect_advance_apply()
            .expect_latest_snapshot_size(latest_snapshot_size);

        let snapshot_builder = SnapshotBuilder::new()
            .expect_init(node_id)
            .expect_receiver_set_instant()
            .expect_receiver_try_complete(None)
            .expect_receiver_try_complete(None)
            .expect_receiver_try_complete(None);

        let communication_builder = CommunicationBuilder::new()
            .expect_init(node_id, get_default_comm_config(raft_config.clone()))
            .expect_make_tick()
            .expect_make_tick()
            .expect_make_tick()
            .expect_take_out_messages(Vec::new())
            .expect_take_out_messages(Vec::new())
            .expect_take_out_messages(Vec::new());

        let mut driver = DriverBuilder::new()
            .expect_on_init(|_| Ok(()))
            .expect_get_reference_values(ReferenceValues::default())
            .expect_on_save_snapshot(Ok(init_snapshot.clone()))
            .expect_on_process_command(None, Ok(CommandOutcome::with_none()))
            .expect_on_apply_event(
                ActorEventContext {
                    index: committed_normal_entry.index,
                    owned: true,
                },
                ActorEvent {
                    correlation_id: entry_id.entry_id,
                    contents: entry.entry_contents,
                },
                Ok(EventOutcome::with_command(ActorCommand {
                    correlation_id: entry_id.entry_id,
                    header: proposal_result.into(),
                    payload: Bytes::new(),
                })),
            )
            .expect_on_save_snapshot(Ok(snapshot.clone()))
            .take(raft_builder, snapshot_builder, communication_builder);

        assert_eq!(
            Ok(()),
            driver.receive_message(
                &mut mock_host,
                instant,
                Some(create_start_replica_request(
                    raft_config.clone(),
                    true,
                    node_id,
                    Bytes::new()
                )),
            )
        );

        assert_eq!(
            Ok(()),
            driver.receive_message(&mut mock_host, instant + 10, None)
        );

        assert_eq!(
            Ok(()),
            driver.receive_message(
                &mut mock_host,
                instant + 20,
                Some(create_get_replica_state_request())
            )
        );
    }

    #[test]
    fn test_driver_snapshot_processor_receiver() {
        let (node_id, instant, raft_config) = create_default_parameters();
        let init_snapshot = Bytes::from(vec![2, 3, 4]);
        let self_config = vec![1, 2, 3];

        let deliver_snapshot_request =
            create_deliver_snapshot_request(node_id, REPLICA_2, DELIVERY_1);
        let deliver_snapshot_response =
            create_deliver_snapshot_response(REPLICA_2, node_id, DELIVERY_1);

        let handshake_message_from_peer = create_secure_channel_handshake(REPLICA_2, node_id);
        let handshake_message_to_peer = create_secure_channel_handshake(node_id, REPLICA_2);

        let snapshot = create_raft_snapshot(
            create_raft_snapshot_metadata(1, 1, create_raft_config_state(vec![node_id, REPLICA_2])),
            vec![1, 2, 3].into(),
        );

        let mut snapshot_message =
            create_raft_message(REPLICA_2, node_id, RaftMessageType::MsgSnapshot);
        snapshot_message.snapshot = Some(snapshot.clone());

        let mut mock_host = MockHostBuilder::new()
            .expect_public_signing_key(vec![])
            .expect_send_messages(vec![create_start_replica_response(node_id)])
            .expect_send_messages(vec![out_message::Msg::SecureChannelHandshake(
                handshake_message_to_peer.clone(),
            )])
            .expect_send_messages(vec![wrap_deliver_snapshot_response_out(
                deliver_snapshot_response.clone(),
            )])
            .take();

        let raft_builder = RaftBuilder::new()
            .expect_leader(false)
            .expect_init(|_, _, _, _, _, _| Ok(()))
            .expect_has_ready(false)
            .expect_has_ready(false)
            .expect_has_ready(false)
            .expect_should_snapshot(false)
            .expect_state(&create_default_raft_state(node_id))
            .expect_make_step(&snapshot_message, Ok(()));

        let snapshot_builder = SnapshotBuilder::new()
            .expect_init(node_id)
            .expect_receiver_set_instant()
            .expect_receiver_try_complete(None)
            .expect_receiver_try_complete(None)
            .expect_receiver_try_complete(Some(Ok((REPLICA_2, snapshot.clone()))))
            .expect_receiver_process_request(
                deliver_snapshot_request.clone(),
                deliver_snapshot_response.clone(),
            );

        let communication_builder = CommunicationBuilder::new()
            .expect_init(node_id, get_default_comm_config(raft_config.clone()))
            .expect_make_tick()
            .expect_take_out_messages(Vec::new())
            .expect_process_in_message(
                in_message::Msg::SecureChannelHandshake(handshake_message_from_peer.clone()),
                Ok(None),
            )
            .expect_make_tick()
            .expect_take_out_messages(vec![OutMessage {
                msg: Some(out_message::Msg::SecureChannelHandshake(
                    handshake_message_to_peer.clone(),
                )),
            }])
            .expect_process_in_message(
                in_message::Msg::DeliverSnapshotRequest(deliver_snapshot_request.clone()),
                Ok(Some(in_message::Msg::DeliverSnapshotRequest(
                    deliver_snapshot_request.clone(),
                ))),
            )
            .expect_process_out_message(
                OutgoingMessage::DeliverSnapshotResponse(deliver_snapshot_response.clone()),
                Ok(()),
            )
            .expect_make_tick()
            .expect_take_out_messages(vec![OutMessage {
                msg: Some(wrap_deliver_snapshot_response_out(
                    deliver_snapshot_response.clone(),
                )),
            }]);

        let mut driver = DriverBuilder::new()
            .expect_on_init(|_| Ok(()))
            .expect_get_reference_values(ReferenceValues::default())
            .expect_on_save_snapshot(Ok(init_snapshot.clone()))
            .expect_on_process_command(None, Ok(CommandOutcome::with_none()))
            .take(raft_builder, snapshot_builder, communication_builder);

        assert_eq!(
            Ok(()),
            driver.receive_message(
                &mut mock_host,
                instant,
                Some(create_start_replica_request(
                    raft_config.clone(),
                    true,
                    node_id,
                    self_config.into()
                )),
            )
        );

        assert_eq!(
            Ok(()),
            driver.receive_message(
                &mut mock_host,
                instant + 10,
                Some(InMessage {
                    msg: Some(in_message::Msg::SecureChannelHandshake(
                        handshake_message_from_peer.clone()
                    ))
                }),
            )
        );

        assert_eq!(
            Ok(()),
            driver.receive_message(
                &mut mock_host,
                instant + 20,
                Some(wrap_deliver_snapshot_request_in(deliver_snapshot_request)),
            )
        );
    }

    #[test]
    fn test_driver_snapshot_processor_sender() {
        let (node_id, instant, raft_config) = create_default_parameters();
        let init_snapshot = Bytes::from(vec![2, 3, 4]);
        let self_config = vec![1, 2, 3];

        let follower_raft_state = create_raft_state(0, vec![node_id]);
        let leader_raft_state = create_raft_state(node_id, vec![node_id]);

        let snapshot = create_raft_snapshot(
            create_raft_snapshot_metadata(1, 1, create_raft_config_state(vec![node_id, REPLICA_2])),
            vec![1, 2, 3].into(),
        );

        let mut snapshot_message =
            create_raft_message(node_id, REPLICA_2, RaftMessageType::MsgSnapshot);
        snapshot_message.snapshot = Some(snapshot.clone());

        let ready = RaftReady::new(
            vec![snapshot_message.clone()],
            Vec::new(),
            Vec::new(),
            Vec::new(),
            None,
            RaftSnapshot {
                ..Default::default()
            },
            1,
        );

        let light_ready = RaftLightReady::default();

        let deliver_snapshot_request =
            create_deliver_snapshot_request(REPLICA_2, node_id, DELIVERY_1);

        let deliver_snapshot_response =
            create_deliver_snapshot_response(node_id, REPLICA_2, DELIVERY_1);

        let deliver_snapshot_failure = create_deliver_snapshot_failure(REPLICA_3, DELIVERY_2);

        let mut mock_host = MockHostBuilder::new()
            .expect_public_signing_key(vec![])
            .expect_send_messages(vec![
                create_start_replica_response(node_id),
                create_check_cluster_response(&leader_raft_state),
                wrap_deliver_snapshot_request_out(deliver_snapshot_request.clone()),
            ])
            .expect_send_messages(vec![])
            .take();

        let raft_builder = RaftBuilder::new()
            .expect_leader(true)
            .expect_init(|_, _, _, _, _, _| Ok(()))
            .expect_has_ready(true)
            .expect_has_ready(false)
            .expect_has_ready(false)
            .expect_ready(&ready)
            .expect_advance_ready(ready.number(), light_ready)
            .expect_advance_apply()
            .expect_should_snapshot(false)
            .expect_should_snapshot(false)
            .expect_state_once(&follower_raft_state)
            .expect_state_once(&leader_raft_state)
            .expect_state_once(&leader_raft_state)
            .expect_state_once(&leader_raft_state)
            .expect_report_snapshot(REPLICA_2, RaftSnapshotStatus::Finish);

        let snapshot_builder = SnapshotBuilder::new()
            .expect_init(node_id)
            .expect_receiver_set_instant()
            .expect_receiver_try_complete(None)
            .expect_receiver_reset()
            .expect_sender_set_instant()
            .expect_sender_next_request(Some(deliver_snapshot_request.clone()))
            .expect_sender_next_request(None)
            .expect_sender_next_request(None)
            .expect_sender_next_request(None)
            .expect_sender_start(REPLICA_2, snapshot)
            .expect_sender_process_response(
                REPLICA_2,
                DELIVERY_1,
                Ok(deliver_snapshot_response.clone()),
            )
            .expect_sender_try_complete(Some((REPLICA_2, RaftSnapshotStatus::Finish)))
            .expect_sender_process_response(
                REPLICA_3,
                DELIVERY_2,
                Err(SnapshotError::FailedDelivery),
            )
            .expect_sender_try_complete(None);

        let communication_builder = CommunicationBuilder::new()
            .expect_init(node_id, get_default_comm_config(raft_config.clone()))
            .expect_process_cluster_change(vec![node_id])
            .expect_process_out_message(
                OutgoingMessage::DeliverSnapshotRequest(deliver_snapshot_request.clone()),
                Ok(()),
            )
            .expect_make_tick()
            .expect_take_out_messages(vec![OutMessage {
                msg: Some(wrap_deliver_snapshot_request_out(
                    deliver_snapshot_request.clone(),
                )),
            }])
            .expect_process_in_message(
                in_message::Msg::DeliverSnapshotResponse(deliver_snapshot_response.clone()),
                Ok(Some(in_message::Msg::DeliverSnapshotResponse(
                    deliver_snapshot_response.clone(),
                ))),
            )
            .expect_make_tick()
            .expect_take_out_messages(Vec::new())
            .expect_make_tick()
            .expect_take_out_messages(Vec::new());

        let mut driver = DriverBuilder::new()
            .expect_on_init(|_| Ok(()))
            .expect_get_reference_values(ReferenceValues::default())
            .expect_on_save_snapshot(Ok(init_snapshot.clone()))
            .expect_on_process_command(None, Ok(CommandOutcome::with_none()))
            .take(raft_builder, snapshot_builder, communication_builder);

        assert_eq!(
            Ok(()),
            driver.receive_message(
                &mut mock_host,
                instant,
                Some(create_start_replica_request(
                    raft_config.clone(),
                    true,
                    node_id,
                    self_config.into()
                )),
            )
        );

        assert_eq!(
            Ok(()),
            driver.receive_message(
                &mut mock_host,
                instant,
                Some(wrap_deliver_snapshot_response_in(deliver_snapshot_response))
            )
        );

        assert_eq!(
            Ok(()),
            driver.receive_message(
                &mut mock_host,
                instant,
                Some(wrap_deliver_snapshot_failure_in(deliver_snapshot_failure))
            )
        );
    }
}
