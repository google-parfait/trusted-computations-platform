// Copyright 2023 The Trusted Computations Platform Authors.
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
use crate::consensus::{Raft, RaftState, Store};
use crate::logger::{log::create_remote_logger, DrainOutput};
use crate::model::{Actor, ActorContext, CommandOutcome, EventOutcome};
use crate::util::raft::{
    create_entry, create_entry_id, create_raft_config_change, deserialize_config_change,
    deserialize_raft_message, get_config_state, get_metadata, serialize_raft_message,
};
use alloc::boxed::Box;
use alloc::rc::Rc;
use alloc::vec::Vec;
use core::{
    cell::{RefCell, RefMut},
    cmp, mem,
};
use platform::{Application, Host, PalError};
use prost::Message;
use raft::{
    eraftpb::ConfChangeType as RaftConfigChangeType, eraftpb::ConfState as RaftConfigState,
    eraftpb::Entry as RaftEntry, eraftpb::EntryType as RaftEntryType,
    eraftpb::Message as RaftMessage, eraftpb::Snapshot as RaftSnapshot, Error as RaftError,
    Storage as RaftStorage,
};
use slog::{debug, error, info, o, warn, Logger};
use tcp_proto::runtime::endpoint::*;

struct DriverContextCore {
    id: u64,
    instant: u64,
    config: Vec<u8>,
    leader: bool,
    proposals: Vec<Vec<u8>>,
    messages: Vec<out_message::Msg>,
}

impl DriverContextCore {
    fn new() -> DriverContextCore {
        DriverContextCore {
            id: 0,
            instant: 0,
            config: Vec::new(),
            leader: false,
            proposals: Vec::new(),
            messages: Vec::new(),
        }
    }

    fn set_state(&mut self, instant: u64, leader: bool) {
        self.instant = instant;
        self.leader = leader;
    }

    fn set_immutable_state(&mut self, id: u64, config: Vec<u8>) {
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

    fn config(&self) -> Vec<u8> {
        self.config.clone()
    }

    fn append_proposal(&mut self, proposal: Vec<u8>) {
        self.proposals.push(proposal);
    }

    fn take_outputs(&mut self) -> (Vec<Vec<u8>>, Vec<out_message::Msg>) {
        (
            mem::take(&mut self.proposals),
            mem::take(&mut self.messages),
        )
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

    fn config(&self) -> Vec<u8> {
        self.core.borrow().config()
    }

    fn leader(&self) -> bool {
        self.core.borrow().leader()
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
    // Counter that is used to generate unique ids within this Raft instance.
    // The counter must never go back.
    next_entry_id: u64,
    // The lastest configuration of the cluster that has been committed.
    config_state: RaftConfigState,
}

impl RaftProgress {
    fn new() -> RaftProgress {
        RaftProgress {
            applied_index: 0,
            next_entry_id: 1,
            config_state: RaftConfigState::default(),
        }
    }
}

pub struct Driver<R: Raft, S: Store, A: Actor> {
    core: Rc<RefCell<DriverContextCore>>,
    driver_config: DriverConfig,
    driver_state: DriverState,
    messages: Vec<OutMessage>,
    id: u64,
    instant: u64,
    tick_instant: u64,
    logger: Logger,
    logger_output: Box<dyn DrainOutput>,
    raft: R,
    store: Box<dyn FnMut(Logger, u64) -> S>,
    actor: A,
    raft_state: RaftState,
    prev_raft_state: RaftState,
    raft_progress: RaftProgress,
}

impl<R: Raft<S = S>, S: Store + RaftStorage, A: Actor> Driver<R, S, A> {
    pub fn new(raft: R, store: Box<dyn FnMut(Logger, u64) -> S>, actor: A) -> Self {
        let (logger, logger_output) = create_remote_logger(0);
        Driver {
            core: Rc::new(RefCell::new(DriverContextCore::new())),
            driver_config: DriverConfig {
                tick_period: 100,
                snapshot_count: 1000,
            },
            driver_state: DriverState::Created,
            messages: Vec::new(),
            id: 0,
            instant: 0,
            tick_instant: 0,
            logger,
            logger_output,
            raft,
            store,
            actor,
            raft_state: RaftState::new(),
            prev_raft_state: RaftState::new(),
            raft_progress: RaftProgress::new(),
        }
    }

    fn mut_core(&mut self) -> RefMut<'_, DriverContextCore> {
        self.core.borrow_mut()
    }

    fn initilize_raft_node(
        &mut self,
        raft_config: &Option<RaftConfig>,
        leader: bool,
    ) -> Result<(), PalError> {
        let mut config = raft::Config {
            id: self.id,
            ..Default::default()
        };

        if let Some(raft_config) = raft_config {
            // Store driver relavant parts of the config.
            self.driver_config.tick_period = raft_config.tick_period;
            self.driver_config.snapshot_count = raft_config.snapshot_count;

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
                leader,
                (self.store)(self.logger.clone(), self.driver_config.snapshot_count),
                &self.logger,
            )
            .map_err(|e| {
                error!(self.logger, "Failed to create Raft node: {}", e);

                // Failure to create Raft node must lead to termination.
                PalError::Raft
            })?;

        self.tick_instant = self.instant;
        // No need to initially report the state of the cluster, only after the changes.
        self.prev_raft_state = self.raft.state();

        Ok(())
    }

    fn check_raft_leadership(&self) -> bool {
        self.raft.leader()
    }

    fn make_raft_step(
        &mut self,
        sender_replica_id: u64,
        recipient_replica_id: u64,
        message_contents: &Vec<u8>,
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

    fn make_raft_proposal(&mut self, proposal_contents: Vec<u8>) {
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
        committed_entries: Vec<RaftEntry>,
    ) -> Result<(), PalError> {
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
                debug!(self.logger, "Applying Raft entry");
                // Recover the entry id so that execute proposal response can be correlated
                let entry = Entry::decode(committed_entry.get_data()).map_err(|e| {
                    error!(self.logger, "Failed to deserialize Raft entry: {}", e);
                    // Failure to deserialize Raft config change must lead to termination.
                    return PalError::Raft;
                })?;

                // Pass committed entry to the actor to make effective.
                match self
                    .actor
                    .on_apply_event(committed_entry.index, &entry.entry_contents.as_ref())
                    .map_err(|e| {
                        error!(
                            self.logger,
                            "Failed to apply committed event to actor state: {}", e
                        );
                        // Failure to apply committed event to actor state must lead to termination.
                        PalError::Actor
                    })? {
                    EventOutcome::Response(response) => {
                        // Send follow up execute proposal response after the corresponding entry
                        // has been committed and applied.
                        self.stash_message(out_message::Msg::ExecuteProposal(
                            ExecuteProposalResponse {
                                entry_id: entry.entry_id,
                                result_contents: response,
                                status: ExecuteProposalStatus::ProposalStatusCompleted.into(),
                            },
                        ));
                    }
                    EventOutcome::None => {
                        // There is nothing to send
                    }
                }
            }
        }

        Ok(())
    }

    fn send_raft_messages(&mut self, raft_messages: Vec<RaftMessage>) -> Result<(), PalError> {
        for raft_message in raft_messages {
            // Buffer message to be sent out.
            self.stash_message(out_message::Msg::DeliverMessage(DeliverMessage {
                recipient_replica_id: raft_message.to,
                sender_replica_id: self.id,
                message_contents: serialize_raft_message(&raft_message).unwrap(),
            }));
        }

        Ok(())
    }

    fn restore_raft_snapshot(&mut self, raft_snapshot: &RaftSnapshot) -> Result<(), PalError> {
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
        self.actor
            .on_load_snapshot(raft_snapshot.get_data())
            .map_err(|e| {
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
        // Given that instant only set once trigger Raft tick once as well.
        self.trigger_raft_tick();

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
        self.restore_raft_snapshot(raft_ready.snapshot())?;

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
        self.raft_state = self.raft.state();

        if self.prev_raft_state == self.raft_state {
            return;
        }

        self.prev_raft_state = self.raft_state.clone();

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

    fn initialize_driver(&mut self, _app_signing_key: Vec<u8>, replica_id_hint: u64) {
        self.id = replica_id_hint;
        (self.logger, self.logger_output) = create_remote_logger(self.id);
    }

    fn process_start_node(
        &mut self,
        start_replica_request: &mut StartReplicaRequest,
        app_signing_key: Vec<u8>,
    ) -> Result<(), PalError> {
        self.check_driver_state(DriverState::Created)?;

        self.initialize_driver(app_signing_key, start_replica_request.replica_id_hint);

        self.initilize_raft_node(
            &start_replica_request.raft_config,
            start_replica_request.is_leader,
        )?;

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

        let change_status = match ChangeClusterType::from_i32(change_cluster_request.change_type) {
            Some(ChangeClusterType::ChangeTypeAddReplica) => self
                .make_raft_config_change_proposal(
                    change_cluster_request.replica_id,
                    RaftConfigChangeType::AddNode,
                )?,
            Some(ChangeClusterType::ChangeTypeRemoveReplica) => self
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

        self.reset_leader_state();

        Ok(())
    }

    fn process_deliver_message(
        &mut self,
        deliver_message: &DeliverMessage,
    ) -> Result<(), PalError> {
        self.check_driver_started()?;

        self.make_raft_step(
            deliver_message.sender_replica_id,
            deliver_message.recipient_replica_id,
            &deliver_message.message_contents,
        )
    }

    fn process_execute_proposal(
        &mut self,
        execute_proposal_request: &ExecuteProposalRequest,
    ) -> Result<(), PalError> {
        self.check_driver_started()?;
        // Generate unique entry id that will be used to correlate pending execute proposal
        // response and committed entry.
        let entry_id = create_entry_id(self.id, self.raft_progress.next_entry_id);
        self.raft_progress.next_entry_id += 1;

        match self
            .actor
            .on_process_command(execute_proposal_request.proposal_contents.as_ref())
            .map_err(|e| {
                error!(self.logger, "Failed to process actor command: {}", e);

                // Failure to process actor command must lead to termination.
                PalError::Actor
            })? {
            CommandOutcome::Response(response) => {
                // The proposal has been executed and there will be no follow up response.
                self.stash_message(out_message::Msg::ExecuteProposal(ExecuteProposalResponse {
                    entry_id: Some(entry_id),
                    result_contents: response,
                    status: ExecuteProposalStatus::ProposalStatusCompleted.into(),
                }));
            }
            CommandOutcome::Event(event) => {
                // The proposal has been accepted and there will be a follow up response.
                let entry = create_entry(entry_id, event);
                self.mut_core().append_proposal(entry.encode_to_vec())
            }
        }

        Ok(())
    }

    fn process_actor_output(&mut self) {
        let (proposals, messages) = self.mut_core().take_outputs();

        for proposal in proposals {
            self.make_raft_proposal(proposal);
        }

        for message in messages {
            self.stash_message(message);
        }
    }

    fn process_state_machine(&mut self) -> Result<Vec<OutMessage>, PalError> {
        if self.raft.initialized() {
            // Advance Raft internal state.
            self.advance_raft()?;

            // Maybe create a snashot of the actor to reduce the size of the log.
            self.maybe_create_raft_snapshot()?;

            // If the leader state has changed send it out for observability.
            self.stash_leader_state();
        }

        self.stash_log_entries();

        // Take messages to be sent out.
        Ok(mem::take(&mut self.messages))
    }

    fn stash_log_entries(&mut self) {
        for log_message in self.logger_output.take_entries() {
            self.stash_message(out_message::Msg::Log(log_message));
        }
    }

    fn stash_message(&mut self, message: out_message::Msg) {
        self.messages.push(OutMessage { msg: Some(message) });
    }
}

impl<R: Raft<S = S>, S: Store + RaftStorage, A: Actor> Application for Driver<R, S, A> {
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
                        in_message::Msg::StartReplica(ref mut start_node_request) => self
                            .process_start_node(
                                start_node_request,
                                host.get_self_attestation().public_signing_key(),
                            ),
                        in_message::Msg::StopReplica(ref stop_node_request) => {
                            self.process_stop_node(stop_node_request)
                        }
                        in_message::Msg::ChangeCluster(ref change_cluster_request) => {
                            self.process_change_cluster(change_cluster_request)
                        }
                        in_message::Msg::CheckCluster(ref check_cluster_request) => {
                            self.process_check_cluster(check_cluster_request)
                        }
                        in_message::Msg::DeliverMessage(ref deliver_message) => {
                            self.process_deliver_message(deliver_message)
                        }
                        in_message::Msg::ExecuteProposal(ref execute_proposal_request) => {
                            self.process_execute_proposal(execute_proposal_request)
                        }
                    }?;
                }
            };
        }

        // Collect outpus like messages, log entries and proposals from the actor.
        self.process_actor_output();

        // Advance the Raft and collect results messages.
        let out_messages = self.process_state_machine()?;

        // Send messages to Raft peers and consumers through the trusted host.
        host.send_messages(out_messages);

        Ok(())
    }
}

#[cfg(all(test, feature = "std"))]
mod test {
    extern crate mockall;
    extern crate spin;

    use crate::{
        consensus::{RaftLightReady, RaftReady},
        util::raft::{
            create_empty_raft_entry, create_raft_config_state, create_raft_entry,
            create_raft_message, create_raft_snapshot, create_raft_snapshot_metadata,
            serialize_config_change,
        },
    };

    use self::mockall::predicate::eq;
    use super::*;
    use mock::{MockActor, MockAttestation, MockHost, MockRaft, MockStore};
    use model::ActorError;
    use raft::eraftpb::{
        ConfChange as RaftConfigChange, EntryType as RaftEntryType, MessageType as RaftMessageType,
    };

    fn create_actor_config() -> Vec<u8> {
        Vec::new()
    }
    fn create_default_parameters() -> (u64, u64, RaftConfig) {
        let node_id = 1;
        let instant = 100;

        let raft_config = RaftConfig {
            tick_period: 100,
            election_tick: 20,
            heartbeat_tick: 2,
            max_size_per_msg: 0,
            snapshot_count: 10,
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

    fn create_start_replica_request(
        raft_config: RaftConfig,
        leader: bool,
        replica_id_hint: u64,
        app_config: Vec<u8>,
    ) -> InMessage {
        let envelope = InMessage {
            msg: Some(in_message::Msg::StartReplica(StartReplicaRequest {
                is_leader: leader,
                replica_id_hint,
                raft_config: Some(raft_config),
                app_config: app_config,
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

    fn create_execute_proposal_request(proposal_contents: Vec<u8>) -> InMessage {
        let envelope = InMessage {
            msg: Some(in_message::Msg::ExecuteProposal(ExecuteProposalRequest {
                proposal_contents,
            })),
        };
        envelope
    }

    fn create_execute_proposal_response(
        entry_id: Option<EntryId>,
        result_contents: Vec<u8>,
        status: ExecuteProposalStatus,
    ) -> out_message::Msg {
        out_message::Msg::ExecuteProposal(ExecuteProposalResponse {
            entry_id,
            result_contents: result_contents,
            status: status.into(),
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

    fn create_deliver_message_request(raft_message: &RaftMessage) -> InMessage {
        let envelope = InMessage {
            msg: Some(in_message::Msg::DeliverMessage(DeliverMessage {
                recipient_replica_id: raft_message.to,
                sender_replica_id: raft_message.from,
                message_contents: serialize_raft_message(raft_message).unwrap(),
            })),
        };
        envelope
    }

    fn create_deliver_message_response(raft_message: &RaftMessage) -> out_message::Msg {
        out_message::Msg::DeliverMessage(DeliverMessage {
            recipient_replica_id: raft_message.to,
            sender_replica_id: raft_message.from,
            message_contents: serialize_raft_message(raft_message).unwrap(),
        })
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

    struct MockHostBuilder {
        mock_attestation: MockAttestation,
        mock_host: MockHost,
    }

    impl MockHostBuilder {
        fn new() -> MockHostBuilder {
            MockHostBuilder {
                mock_attestation: MockAttestation::new(),
                mock_host: MockHost::new(),
            }
        }

        fn expect_public_signing_key(
            &mut self,
            public_signing_key: Vec<u8>,
        ) -> &mut MockHostBuilder {
            self.mock_attestation
                .expect_public_signing_key()
                .return_once(move || public_signing_key);
            self
        }

        fn expect_get_self_config(&mut self, self_config: Vec<u8>) -> &mut MockHostBuilder {
            self.mock_host
                .expect_get_self_config()
                .return_const(self_config);

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
            let mock_attestation = mem::take(&mut self.mock_attestation);
            let mut mock_host = mem::take(&mut self.mock_host);

            mock_host
                .expect_get_self_attestation()
                .return_once(move || Box::new(mock_attestation));

            mock_host
                .expect_get_self_config()
                .return_const(create_actor_config());

            mock_host
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
            handler: impl Fn(u64, &raft::Config, bool, MockStore, &Logger) -> Result<(), RaftError>
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
            snapshot_data: &[u8],
            result: Result<(), RaftError>,
        ) -> RaftBuilder {
            self.mock_store
                .expect_create_snapshot()
                .with(
                    eq(applied_index),
                    eq(config_state),
                    eq(snapshot_data.to_owned()),
                )
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

        fn take(&mut self) -> (MockStore, MockRaft<MockStore>) {
            (
                mem::take(&mut self.mock_store),
                mem::take(&mut self.mock_raft),
            )
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

        fn expect_on_shutdown(
            &mut self,
            shutdown_handler: impl Fn() + 'static,
        ) -> &mut DriverBuilder {
            self.mock_actor
                .expect_on_shutdown()
                .return_once_st(shutdown_handler);

            self
        }

        fn expect_on_process_command(
            &mut self,
            command: Vec<u8>,
            result: Result<CommandOutcome, ActorError>,
        ) -> &mut DriverBuilder {
            self.mock_actor
                .expect_on_process_command()
                .with(eq(command))
                .return_once(|_| result);

            self
        }

        fn expect_on_load_snapshot(
            &mut self,
            snapshot: Vec<u8>,
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
            result: Result<Vec<u8>, ActorError>,
        ) -> &mut DriverBuilder {
            self.mock_actor
                .expect_on_save_snapshot()
                .return_once(|| result);
            self
        }

        fn expect_on_apply_event(
            &mut self,
            index: u64,
            data: Vec<u8>,
            result: Result<EventOutcome, ActorError>,
        ) -> &mut DriverBuilder {
            self.mock_actor
                .expect_on_apply_event()
                .with(eq(index), eq(data))
                .return_once(|_, _| result);

            self
        }

        fn take(
            &mut self,
            mut raft_builder: RaftBuilder,
        ) -> Driver<MockRaft<MockStore>, MockStore, MockActor> {
            let (mock_store, mut mock_raft) = raft_builder.take();
            let mock_actor = mem::take(&mut self.mock_actor);

            mock_raft.expect_mut_store().return_var(mock_store);

            Driver::new(mock_raft, Box::new(|_, _| MockStore::new()), mock_actor)
        }
    }

    #[test]
    fn test_driver_start_node_request() {
        let (node_id, instant, raft_config) = create_default_parameters();

        let mut mock_host = MockHostBuilder::new()
            .expect_public_signing_key(vec![])
            .expect_send_messages(vec![create_start_replica_response(node_id)])
            .take();

        let exp_raft_config = raft_config.clone();
        let raft_builder = RaftBuilder::new()
            .expect_leader(false)
            .expect_init(move |id, config, leader, _, _| {
                assert_eq!(node_id, config.id);
                assert_eq!(exp_raft_config.election_tick as usize, config.election_tick);
                assert_eq!(
                    exp_raft_config.heartbeat_tick as usize,
                    config.heartbeat_tick
                );
                assert_eq!(exp_raft_config.max_size_per_msg, config.max_size_per_msg);
                assert_eq!(node_id, id);
                assert!(leader);
                Ok(())
            })
            .expect_has_ready(false)
            .expect_should_snapshot(false)
            .expect_state(&create_default_raft_state(node_id));

        let mut driver = DriverBuilder::new()
            .expect_on_init(|_| Ok(()))
            .take(raft_builder);

        assert_eq!(
            Ok(()),
            driver.receive_message(
                &mut mock_host,
                instant,
                Some(create_start_replica_request(
                    raft_config.clone(),
                    true,
                    node_id,
                    Vec::new()
                )),
            )
        );
    }

    #[test]
    fn test_driver_stop_node_request() {
        let (node_id, instant, raft_config) = create_default_parameters();

        let mut mock_host = MockHostBuilder::new()
            .expect_public_signing_key(vec![])
            .expect_send_messages(vec![create_start_replica_response(node_id)])
            .expect_send_messages(vec![create_stop_replica_response()])
            .take();

        let raft_builder = RaftBuilder::new()
            .expect_leader(false)
            .expect_init(|_, _, _, _, _| Ok(()))
            .expect_has_ready(false)
            .expect_has_ready(false)
            .expect_should_snapshot(false)
            .expect_state(&create_default_raft_state(node_id));

        let mut driver = DriverBuilder::new()
            .expect_on_init(|_| Ok(()))
            .expect_on_shutdown(|| ())
            .take(raft_builder);

        assert_eq!(
            Ok(()),
            driver.receive_message(
                &mut mock_host,
                instant,
                Some(create_start_replica_request(
                    raft_config.clone(),
                    true,
                    node_id,
                    Vec::new()
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
    fn test_driver_execute_proposal_request() {
        let (node_id, instant, raft_config) = create_default_parameters();
        let proposal_contents = vec![1, 2, 3];
        let proposal_result = vec![4, 4, 6];
        let entry_id = create_entry_id(node_id, 1);

        let mut mock_host = MockHostBuilder::new()
            .expect_public_signing_key(vec![])
            .expect_send_messages(vec![create_start_replica_response(node_id)])
            .expect_send_messages(vec![create_execute_proposal_response(
                Some(entry_id),
                proposal_result.clone(),
                ExecuteProposalStatus::ProposalStatusCompleted,
            )])
            .take();

        let raft_builder = RaftBuilder::new()
            .expect_leader(false)
            .expect_init(|_, _, _, _, _| Ok(()))
            .expect_has_ready(false)
            .expect_has_ready(false)
            .expect_should_snapshot(false)
            .expect_state(&create_default_raft_state(node_id));

        let mut driver = DriverBuilder::new()
            .expect_on_init(|_| Ok(()))
            .expect_on_process_command(
                proposal_contents.clone(),
                Ok(CommandOutcome::Response(proposal_result)),
            )
            .take(raft_builder);

        assert_eq!(
            Ok(()),
            driver.receive_message(
                &mut mock_host,
                instant,
                Some(create_start_replica_request(
                    raft_config.clone(),
                    true,
                    node_id,
                    Vec::new()
                )),
            )
        );

        assert_eq!(
            Ok(()),
            driver.receive_message(
                &mut mock_host,
                instant + 10,
                Some(create_execute_proposal_request(proposal_contents.clone())),
            )
        );
    }

    #[test]
    fn test_driver_actor_context() {
        let (node_id, instant, raft_config) = create_default_parameters();
        let self_config = vec![1, 2, 3];

        let proposal_response = vec![4, 5, 6];
        let mut mock_host = MockHostBuilder::new()
            .expect_public_signing_key(vec![])
            .expect_send_messages(vec![create_start_replica_response(node_id)])
            .take();

        let raft_builder = RaftBuilder::new()
            .expect_leader(false)
            .expect_init(|_, _, _, _, _| Ok(()))
            .expect_has_ready(false)
            .expect_should_snapshot(false)
            .expect_state(&create_default_raft_state(node_id));

        let exp_self_config = self_config.clone();
        let mut driver = DriverBuilder::new()
            .expect_on_init(move |mut actor_context| {
                assert_eq!(node_id, actor_context.id());
                assert_eq!(instant, actor_context.instant());
                assert_eq!(exp_self_config, actor_context.config());
                assert!(!actor_context.leader());

                Ok(())
            })
            .take(raft_builder);

        assert_eq!(
            Ok(()),
            driver.receive_message(
                &mut mock_host,
                instant,
                Some(create_start_replica_request(
                    raft_config.clone(),
                    true,
                    node_id,
                    self_config
                )),
            )
        );
    }

    #[test]
    fn test_driver_change_cluster_request() {
        let (node_id, instant, raft_config) = create_default_parameters();
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
            .expect_init(|_, _, _, _, _| Ok(()))
            .expect_has_ready(false)
            .expect_has_ready(false)
            .expect_should_snapshot(false)
            .expect_state(&create_default_raft_state(node_id))
            .expect_make_config_change_proposal(
                create_raft_config_change(peer_id, RaftConfigChangeType::AddNode),
                |_| Ok(()),
            );

        let mut driver = DriverBuilder::new()
            .expect_on_init(|_| Ok(()))
            .take(raft_builder);

        assert_eq!(
            Ok(()),
            driver.receive_message(
                &mut mock_host,
                instant,
                Some(create_start_replica_request(
                    raft_config.clone(),
                    true,
                    node_id,
                    Vec::new()
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
        let peer_id = 2;

        let raft_state = create_default_raft_state(node_id);

        let mut mock_host = MockHostBuilder::new()
            .expect_public_signing_key(vec![])
            .expect_send_messages(vec![create_start_replica_response(node_id)])
            .expect_send_messages(vec![create_check_cluster_response(&raft_state)])
            .take();

        let raft_builder = RaftBuilder::new()
            .expect_leader(false)
            .expect_init(|_, _, _, _, _| Ok(()))
            .expect_has_ready(false)
            .expect_has_ready(false)
            .expect_should_snapshot(false)
            .expect_state(&raft_state)
            .expect_make_config_change_proposal(
                create_raft_config_change(peer_id, RaftConfigChangeType::AddNode),
                |_| Ok(()),
            );

        let mut driver = DriverBuilder::new()
            .expect_on_init(|_| Ok(()))
            .take(raft_builder);

        assert_eq!(
            Ok(()),
            driver.receive_message(
                &mut mock_host,
                instant,
                Some(create_start_replica_request(
                    raft_config.clone(),
                    true,
                    node_id,
                    Vec::new()
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
        let peer_id = 2;

        let raft_state = create_default_raft_state(node_id);

        let message_a = create_raft_message(node_id, peer_id, RaftMessageType::MsgBeat);
        let messages = vec![message_a.clone()];

        let message_b = create_raft_message(node_id, peer_id, RaftMessageType::MsgAppend);
        let persisted_messages: Vec<RaftMessage> = vec![message_b.clone()];

        let entries = vec![create_empty_raft_entry(3, 2)];

        let proposal_result = vec![4, 5, 6];
        let entry_id = create_entry_id(node_id, 1);
        let entry = create_entry(entry_id.clone(), proposal_result.clone());
        let committed_normal_entry =
            create_raft_entry(2, 2, RaftEntryType::EntryNormal, entry.encode_to_vec());

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
            vec![1, 2, 3],
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
                create_deliver_message_response(&message_a),
                create_deliver_message_response(&message_b),
                create_execute_proposal_response(
                    Some(entry_id.clone()),
                    proposal_result.clone(),
                    ExecuteProposalStatus::ProposalStatusCompleted,
                ),
            ])
            .take();

        let raft_builder = RaftBuilder::new()
            .expect_leader(false)
            .expect_init(|_, _, _, _, _| Ok(()))
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

        let mut driver = DriverBuilder::new()
            .expect_on_init(|_| Ok(()))
            .expect_on_load_snapshot(snapshot.data.to_vec(), Ok(()))
            .expect_on_apply_event(
                committed_normal_entry.index,
                entry.entry_contents,
                Ok(EventOutcome::Response(proposal_result)),
            )
            .take(raft_builder);

        assert_eq!(
            Ok(()),
            driver.receive_message(
                &mut mock_host,
                instant,
                Some(create_start_replica_request(
                    raft_config.clone(),
                    true,
                    node_id,
                    Vec::new()
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

        let raft_state = create_default_raft_state(node_id);

        let mut mock_host = MockHostBuilder::new()
            .expect_public_signing_key(vec![])
            .expect_send_messages(vec![create_start_replica_response(node_id)])
            .expect_send_messages(vec![])
            .take();

        let raft_builder = RaftBuilder::new()
            .expect_leader(false)
            .expect_init(|_, _, _, _, _| Ok(()))
            .expect_has_ready(false)
            .expect_has_ready(false)
            .expect_should_snapshot(false)
            .expect_state(&raft_state)
            .expect_make_tick();

        let mut driver = DriverBuilder::new()
            .expect_on_init(|_| Ok(()))
            .take(raft_builder);

        assert_eq!(
            Ok(()),
            driver.receive_message(
                &mut mock_host,
                instant,
                Some(create_start_replica_request(
                    raft_config.clone(),
                    true,
                    node_id,
                    Vec::new()
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
        let peer_id = 2;

        let raft_state = create_default_raft_state(node_id);

        let message_a = create_raft_message(node_id, peer_id, RaftMessageType::MsgBeat);

        let mut mock_host = MockHostBuilder::new()
            .expect_public_signing_key(vec![])
            .expect_send_messages(vec![create_start_replica_response(node_id)])
            .expect_send_messages(vec![])
            .take();

        let raft_builder = RaftBuilder::new()
            .expect_leader(false)
            .expect_init(|_, _, _, _, _| Ok(()))
            .expect_has_ready(false)
            .expect_has_ready(false)
            .expect_should_snapshot(false)
            .expect_state(&raft_state)
            .expect_make_step(&message_a, Ok(()));

        let mut driver = DriverBuilder::new()
            .expect_on_init(|_| Ok(()))
            .take(raft_builder);

        assert_eq!(
            Ok(()),
            driver.receive_message(
                &mut mock_host,
                instant,
                Some(create_start_replica_request(
                    raft_config.clone(),
                    true,
                    node_id,
                    Vec::new()
                )),
            )
        );

        assert_eq!(
            Ok(()),
            driver.receive_message(
                &mut mock_host,
                instant + 10,
                Some(create_deliver_message_request(&message_a)),
            )
        );
    }

    #[test]
    fn test_driver_trigger_snapshot() {
        let (node_id, instant, raft_config) = create_default_parameters();

        let raft_state = create_default_raft_state(node_id);

        let proposal_result = vec![4, 5, 6];

        let entry_id = create_entry_id(node_id, 1);
        let entry = create_entry(entry_id.clone(), proposal_result.clone());

        let mut mock_host = MockHostBuilder::new()
            .expect_public_signing_key(vec![])
            .expect_send_messages(vec![create_start_replica_response(node_id)])
            .expect_send_messages(vec![create_execute_proposal_response(
                Some(entry_id.clone()),
                proposal_result.clone(),
                ExecuteProposalStatus::ProposalStatusCompleted,
            )])
            .take();

        let committed_normal_entry =
            create_raft_entry(2, 2, RaftEntryType::EntryNormal, entry.encode_to_vec());

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

        let snapshot = vec![4, 5, 6];

        let raft_builder = RaftBuilder::new()
            .expect_leader(false)
            .expect_init(|_, _, _, _, _| Ok(()))
            .expect_has_ready(false)
            .expect_has_ready(true)
            .expect_ready(&ready)
            .expect_should_snapshot(false)
            .expect_should_snapshot(true)
            .expect_create_snapshot(
                committed_normal_entry.index,
                create_raft_config_state(raft_state.committed_cluster_config.clone()),
                &snapshot,
                Ok(()),
            )
            .expect_state(&raft_state)
            .expect_advance_ready(ready.number(), light_ready)
            .expect_advance_apply();

        let mut driver = DriverBuilder::new()
            .expect_on_init(|_| Ok(()))
            .expect_on_apply_event(
                committed_normal_entry.index,
                entry.entry_contents,
                Ok(EventOutcome::Response(proposal_result)),
            )
            .expect_on_save_snapshot(Ok(snapshot.clone()))
            .take(raft_builder);

        assert_eq!(
            Ok(()),
            driver.receive_message(
                &mut mock_host,
                instant,
                Some(create_start_replica_request(
                    raft_config.clone(),
                    true,
                    node_id,
                    Vec::new()
                )),
            )
        );

        assert_eq!(
            Ok(()),
            driver.receive_message(&mut mock_host, instant + 10, None)
        );
    }
}
