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

use crate::logger::log::create_logger;
use crate::StdError;
use alloc::boxed::Box;
use alloc::vec::Vec;
use core::convert::TryInto;
use core::option::Option;
use core::{cmp, fmt};
use hashbrown::HashMap;
use prost::{
    bytes::{BufMut, Bytes, BytesMut},
    Message,
};
use tcp_proto::runtime::endpoint::{
    deliver_snapshot_request, deliver_snapshot_response, raft_config::SnapshotConfig,
    DeliverSnapshotRequest, DeliverSnapshotResponse, DeliverSnapshotStatus,
};

use raft::{
    eraftpb::Snapshot as RaftSnapshot, eraftpb::SnapshotMetadata as RaftSnapshotMetadata,
    SnapshotStatus as RaftSnapshotStatus,
};
use slog::{debug, info, warn, Logger};

/// Enumerates errors possible while sending or receiving a snapshot.
#[derive(Debug, PartialEq)]
pub enum SnapshotError {
    /// Failed to deliver part of the snapshot.
    FailedDelivery,
    Corrupted,
}

impl StdError for SnapshotError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        None
    }
}

impl fmt::Display for SnapshotError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            SnapshotError::FailedDelivery => write!(f, "Failed to deliver snapshot"),
            SnapshotError::Corrupted => write!(f, "Snapshot is corrupted"),
        }
    }
}

/// Represents snapshot processor that plays sender or receiver role depending
/// on the state of Raft.
pub trait SnapshotProcessor {
    /// Initializes the snapshot processor for the given replica id.
    ///
    /// # Note
    ///
    /// The processor must be initiailized once before the first use. The replica
    /// id is used to determine the role of the processor whenever the cluster
    /// state changes. For example, when replica is a follower it plays the receiver
    /// role, whereas then replica is a leader it plays the sender role.
    fn init(&mut self, logger: Logger, replica_id: u64, snapshot_config: &Option<SnapshotConfig>);

    /// Processes change in the cluster state.
    ///
    /// # Returns
    ///
    /// List of statuses for pending snapshot transfers to notify Raft when
    /// switching from sender to receiver role or cancelling pending transfers.
    ///
    /// # Note
    ///
    /// In response to the cluster state change the processor may switch the
    /// role. Role switch causes full internal state clean up and cancellation
    /// of in flight activity.
    ///
    /// If the processor is currently playing receiver role it will switch to
    /// sender role if it becomes the leader. Otherwise if the leader id or term
    /// changes, or current replica is no longer part of the cluster the processor
    /// will remain in receiver role, but all internal state will be cleaned up.
    ///
    /// If the processor is currently play sender role it will switch to receiver
    /// role if it becomes a follower or no longer part of the cluster. Otherwise
    /// if leader term changes all internal state will be cleaned up.
    fn process_cluster_change(
        &mut self,
        leader_id: u64,
        leader_term: u64,
        replicas: &[u64],
    ) -> Vec<(u64, RaftSnapshotStatus)>;

    /// Obtains processor in its current role.
    ///
    /// # Returns
    ///
    /// Snapshot processor in its current role. Must not be retained.
    fn mut_processor(&mut self, instant: u64) -> SnapshotProcessorRole<'_>;
}

/// Enumerates snapshot processor roles.
pub enum SnapshotProcessorRole<'a> {
    /// In sender role processor may be sending multiple snapshots to several
    /// replicas.
    Sender(&'a mut dyn SnapshotSender),

    /// In receiver role processor may only receive a single snapshot from the
    /// current leader.
    Receiver(&'a mut dyn SnapshotReceiver),
}

/// Represents snapshot sender.
///
/// May send multiple snapshots to different replicas concurrently.
pub trait SnapshotSender {
    /// Initiates transfer of given snapshot to replica with given id.
    ///
    /// # Note
    ///
    /// Sender will internally serialize and split snapshot into several chunks.
    fn start(&mut self, receiver_id: u64, snapshot: RaftSnapshot);

    /// Attempts to fetch next request to send.
    ///
    /// # Returns
    ///
    /// Nothing if there are no eligible requests to send. A request containing
    /// receiver replica id, delivery id and request payload otherwise.
    ///
    /// # Note
    ///
    /// Sender maintain multiple transfers at the same time. It controls that
    /// there is limited number of in-flight requests across all transfers
    /// to avoid overwhelming the channel. Processing responses or cancelling
    /// transfers frees up the in-flight request slots.
    fn next_request(&mut self) -> Option<DeliverSnapshotRequest>;

    /// Processes response identified by the deliver id from replica with given id.
    ///
    /// # Note
    ///
    /// The response may be a success or failure. In the failure case the sender will
    /// abort the transfer and mark it as completed. In the success case the sender
    /// will unblock next chunk to be sent or mark as whole snapshot being successfully
    /// sent.
    fn process_response(
        &mut self,
        sender_id: u64,
        delivery_id: u64,
        response: Result<DeliverSnapshotResponse, SnapshotError>,
    );

    /// Processes unexpected request while playing sender role.
    ///
    /// # Note
    ///
    /// The request is simply rejected.
    fn process_unexpected_request(
        &mut self,
        request: DeliverSnapshotRequest,
    ) -> DeliverSnapshotResponse;

    /// Attempts to complete any transfer.
    ///
    /// # Returns
    ///
    /// Nothing if there are no completed transfers after processing responses. Id of
    /// the replica and status of the snapshot otherwise. Tuple containing id and
    /// snapshot status that must be reported to Raft.
    fn try_complete(&mut self) -> Option<(u64, RaftSnapshotStatus)>;
}

/// Represents snapshot receiver.
///
/// May only receive a single snapshot from the current leader of the cluster.
pub trait SnapshotReceiver {
    /// Processes deliver snapshot request from given sender.
    ///
    /// # Note
    ///
    /// If the request comes from a sender that is not currently known to be
    /// the leader, the returned response will indicate to abort the transfer.
    ///
    /// If the request contains snapshot id that is not known, the returned
    /// response will indicate to abort the transfer.
    fn process_request(&mut self, request: DeliverSnapshotRequest) -> DeliverSnapshotResponse;

    /// Attempts to complete snapshot receiving.
    ///
    /// # Returns
    ///
    /// Nothing if not all chunks have been received. Error if fully assembled snapshot
    /// failed to pass checksum validation. Sender replica id and snapshot otherwise.
    fn try_complete(&mut self) -> Option<Result<(u64, RaftSnapshot), SnapshotError>>;
}

/// Enumerates the state the replica is currently in.
#[derive(Default, PartialEq, Debug)]
enum ReplicaState {
    #[default]
    Unknown,
    Follower,
    Leader,
}

pub trait SnapshotSenderImpl: SnapshotSender {
    fn init(&mut self, logger: Logger, replica_id: u64, snapshot_config: &Option<SnapshotConfig>);

    fn set_instant(&mut self, instant: u64);

    fn reset(&mut self) -> Vec<(u64, RaftSnapshotStatus)>;
}

pub trait SnapshotReceiverImpl: SnapshotReceiver {
    fn init(&mut self, logger: Logger, replica_id: u64);

    fn set_instant(&mut self, instant: u64);

    fn reset(&mut self);
}

pub struct DefaultSnapshotProcessor {
    replica_id: u64,
    leader_id: u64,
    leader_term: u64,
    state: ReplicaState,
    sender: Box<dyn SnapshotSenderImpl>,
    receiver: Box<dyn SnapshotReceiverImpl>,
}

impl DefaultSnapshotProcessor {
    pub fn new(
        sender: Box<dyn SnapshotSenderImpl>,
        receiver: Box<dyn SnapshotReceiverImpl>,
    ) -> Self {
        Self {
            replica_id: 0,
            leader_id: 0,
            leader_term: 0,
            state: ReplicaState::Unknown,
            sender,
            receiver,
        }
    }
}

impl SnapshotProcessor for DefaultSnapshotProcessor {
    fn init(&mut self, logger: Logger, replica_id: u64, snapshot_config: &Option<SnapshotConfig>) {
        assert_eq!(self.state, ReplicaState::Unknown);

        self.replica_id = replica_id;
        self.sender
            .init(logger.clone(), self.replica_id, snapshot_config);
        self.receiver.init(logger.clone(), self.replica_id);
        // Always start as a follower.
        self.state = ReplicaState::Follower;
    }

    fn process_cluster_change(
        &mut self,
        leader_id: u64,
        leader_term: u64,
        replicas: &[u64],
    ) -> Vec<(u64, RaftSnapshotStatus)> {
        // Sender or receiver state reset is needed if the leader or its term has
        // changed, or if the replica is no longer part of the cluster.
        let needs_reset = self.leader_id != leader_id
            || self.leader_term != leader_term
            || !replicas.contains(&self.replica_id);

        // Remember observed cluster state to compare during next cluster state
        // update.
        self.leader_id = leader_id;
        self.leader_term = leader_term;

        // Reset sender or receiver and collect snapshot sending cancellations.
        let mut cancelled_snapshots: Vec<(u64, RaftSnapshotStatus)> = Vec::new();
        if needs_reset {
            match self.state {
                ReplicaState::Follower => {
                    self.receiver.reset();
                }
                ReplicaState::Leader => {
                    cancelled_snapshots = self.sender.reset();
                }
                ReplicaState::Unknown => {
                    panic!("Snapshot processor is not initialized");
                }
            }
        }

        // Update replica state according to the cluster state.
        match self.state {
            ReplicaState::Follower => {
                if self.replica_id == self.leader_id {
                    self.state = ReplicaState::Leader;
                }
            }
            ReplicaState::Leader => {
                if self.replica_id != self.leader_id {
                    self.state = ReplicaState::Follower;
                }
            }
            ReplicaState::Unknown => {
                panic!("Snapshot processor is not initialized");
            }
        }

        cancelled_snapshots
    }

    fn mut_processor(&mut self, instant: u64) -> SnapshotProcessorRole<'_> {
        match self.state {
            ReplicaState::Follower => {
                self.receiver.set_instant(instant);
                SnapshotProcessorRole::Receiver(&mut *self.receiver)
            }
            ReplicaState::Leader => {
                self.sender.set_instant(instant);
                SnapshotProcessorRole::Sender(&mut *self.sender)
            }
            ReplicaState::Unknown => {
                panic!("Snapshot processor is not initialized");
            }
        }
    }
}

/// Calculates the number of chunks needed to transmit a snapshot.
fn chunk_count(snapshot_size: u64, chunk_size: u64) -> u64 {
    if snapshot_size > 0 {
        (snapshot_size - 1) / chunk_size + 1
    } else {
        1
    }
}

struct SnapshotSenderState {
    logger: Logger,
    snapshot_id: u32,
    snapshot_metadata: RaftSnapshotMetadata,
    snapshot_data: Bytes,
    chunk_size: u64,
    chunk_count: u64,
    next_chunk_index: u32,
    sent_chunk_count: u64,
    pending_chunks: HashMap<u64, u32>,
    status: Option<RaftSnapshotStatus>,
}

impl SnapshotSenderState {
    fn new(
        logger: Logger,
        snapshot_id: u32,
        snapshot: RaftSnapshot,
        chunk_size: u64,
    ) -> SnapshotSenderState {
        let snapshot_metadata = snapshot.metadata.unwrap();
        let snapshot_data: Bytes = snapshot.data.into();
        let snapshot_size = snapshot_data.len() as u64;

        SnapshotSenderState {
            logger,
            snapshot_id,
            snapshot_metadata,
            snapshot_data,
            chunk_size,
            chunk_count: chunk_count(snapshot_size, chunk_size),
            next_chunk_index: 0,
            sent_chunk_count: 0,
            pending_chunks: HashMap::new(),
            status: None,
        }
    }

    fn progress(&self) -> f64 {
        if self.status.is_some() {
            // The snapshot transfer has reached terminal state,
            // both success and failure are considered completion.
            return 1.0;
        }
        (self.sent_chunk_count as f64 + self.pending_chunks.len() as f64) / self.chunk_count as f64
    }

    fn pending_chunks(&self) -> u32 {
        self.pending_chunks.len() as u32
    }

    fn next_chunk(&mut self, delivery_id: u64) -> Option<Bytes> {
        if self.status.is_some() {
            // The snapshot transfer has reached terminal state,
            // no new chunks will be sent.
            return None;
        }

        // Register chunk as pending.
        self.pending_chunks
            .insert(delivery_id, self.next_chunk_index);

        // Compute the next chunk contents.
        let next_chunk_start = self.next_chunk_index as usize * self.chunk_size as usize;
        let next_chunk_end = cmp::min(
            self.snapshot_data.len(),
            next_chunk_start + self.chunk_size as usize,
        );
        let next_chunk = self.snapshot_data.slice(next_chunk_start..next_chunk_end);

        // Assemble request payload.
        let mut payload = deliver_snapshot_request::Payload {
            snapshot_id: self.snapshot_id,
            ..Default::default()
        };
        let chunk_size = next_chunk.len();
        if self.next_chunk_index == 0 {
            // Send header for the new snapshot transfer.
            payload.it = Some(deliver_snapshot_request::payload::It::Header(
                deliver_snapshot_request::payload::Header {
                    snapshot_size: self.snapshot_data.len() as u64,
                    snapshot_metadata: self.snapshot_metadata.encode_to_vec().into(),
                    chunk_contents: next_chunk,
                },
            ))
        } else {
            // Send next chunk of the existing snapshot transfer.
            payload.it = Some(deliver_snapshot_request::payload::It::Chunk(
                deliver_snapshot_request::payload::Chunk {
                    chunk_index: self.next_chunk_index,
                    chunk_contents: next_chunk,
                },
            ));
        }

        debug!(
            self.logger,
            "Sending next chunk: delivery id {}, index {}, size {}",
            delivery_id,
            self.next_chunk_index,
            chunk_size,
        );

        // Advance index of the next to be sent chunk.
        self.next_chunk_index += 1;

        Some(payload.encode_to_vec().into())
    }

    fn process_response(
        &mut self,
        delivery_id: u64,
        response: Result<DeliverSnapshotResponse, SnapshotError>,
    ) {
        let success = match response {
            Ok(response) => {
                let payload_result =
                    deliver_snapshot_response::Payload::decode(response.payload_contents);
                if payload_result.is_err() {
                    warn!(
                        self.logger,
                        "Rejecting delivery response: {}",
                        payload_result.err().unwrap()
                    );
                    false
                } else {
                    let payload = payload_result.ok().unwrap();
                    if self.snapshot_id != payload.snapshot_id {
                        warn!(self.logger, "Rejecting delivery response: wrong snapshot");
                        true
                    } else if self.chunk_count <= payload.chunk_index.into()
                        || self.pending_chunks.remove_entry(&delivery_id)
                            != Some((delivery_id, payload.chunk_index))
                    {
                        warn!(self.logger, "Rejecting delivery response: out of bounds");
                        false
                    } else {
                        if payload.status
                            == <DeliverSnapshotStatus as Into<i32>>::into(
                                DeliverSnapshotStatus::SnapshotStatusAccepted,
                            )
                        {
                            self.sent_chunk_count += 1;
                            true
                        } else {
                            warn!(self.logger, "Receiver rejected delivery request");
                            false
                        }
                    }
                }
            }
            Err(error) => {
                warn!(self.logger, "Rejecting delivery response: {}", error);
                false
            }
        };

        if !success {
            // The snapshot delivery has failed and we need to abort
            // snapshot transfer.
            self.status = Some(RaftSnapshotStatus::Failure);
        }
    }

    fn try_complete(&mut self) -> Option<RaftSnapshotStatus> {
        if self.status.is_none() && self.sent_chunk_count == self.chunk_count {
            self.complete_with(RaftSnapshotStatus::Finish);
        }

        self.status
    }

    fn complete_with(&mut self, status: RaftSnapshotStatus) {
        self.status = Some(status);
        // Free up the memory used by the snapshot.
        self.snapshot_data = Bytes::new();
    }
}

#[derive(Clone, Copy, Debug)]
pub struct SnapshotSenderConfig {
    pub chunk_size: u64,
    pub max_pending_chunks: u32,
}

pub struct DefaultSnapshotSender {
    logger: Logger,
    config: SnapshotSenderConfig,
    replica_id: u64,
    instant: u64,
    next_snapshot_id: u32,
    next_delivery_id: u64,
    receivers: HashMap<u64, SnapshotSenderState>,
}

impl DefaultSnapshotSender {
    pub fn new() -> DefaultSnapshotSender {
        DefaultSnapshotSender {
            logger: create_logger(),
            config: SnapshotSenderConfig {
                // System defaults.
                chunk_size: 1024 * 1024,
                max_pending_chunks: 2,
            },
            replica_id: 0,
            instant: 0,
            next_snapshot_id: 1,
            next_delivery_id: 1,
            receivers: HashMap::new(),
        }
    }
}

impl SnapshotSenderImpl for DefaultSnapshotSender {
    fn init(&mut self, logger: Logger, replica_id: u64, snapshot_config: &Option<SnapshotConfig>) {
        self.logger = logger;
        self.replica_id = replica_id;
        if let Some(snapshot_config) = snapshot_config {
            self.config.chunk_size = snapshot_config.chunk_size;
            self.config.max_pending_chunks = snapshot_config.max_pending_chunks
        }
    }

    fn set_instant(&mut self, instant: u64) {
        self.instant = instant;
    }

    fn reset(&mut self) -> Vec<(u64, RaftSnapshotStatus)> {
        // All uncompleted snapshot transfers are considered failed.
        let mut cancellations: Vec<(u64, RaftSnapshotStatus)> =
            Vec::with_capacity(self.receivers.len());
        for receiver_id in self.receivers.keys() {
            cancellations.push((*receiver_id, RaftSnapshotStatus::Failure));
        }
        self.receivers.clear();

        // Note that snapshot id or deliver id are not reset as
        // they are meant to be forward only counters.

        cancellations
    }
}

impl SnapshotSender for DefaultSnapshotSender {
    fn start(&mut self, receiver_id: u64, snapshot: RaftSnapshot) {
        info!(
            self.logger,
            "Starting snapshot sending to: receiver {}, snapshot size {}",
            receiver_id,
            snapshot.data.len()
        );

        // Note that we rely on Raft protocol to initiate transfers.
        // Hence we silently override any progress for the existing transfer.
        self.receivers.insert(
            receiver_id,
            SnapshotSenderState::new(
                self.logger.clone(),
                self.next_snapshot_id,
                snapshot,
                self.config.chunk_size,
            ),
        );
        self.next_snapshot_id += 1;
    }

    fn next_request(&mut self) -> Option<DeliverSnapshotRequest> {
        // Initiallly we will employ a very simple strategy of picking
        // which chunk to send next. Specifically we will pick viable
        // receiver that has made the least progress.
        let mut selected_receiver_id = 0;
        let mut min_progress = 1.0;
        let mut pending_chunks = 0;
        for (receiver_id, sender_state) in &self.receivers {
            pending_chunks += sender_state.pending_chunks();
            if min_progress > sender_state.progress() {
                min_progress = sender_state.progress();
                selected_receiver_id = *receiver_id;
            }
        }

        // Check if we can send another chunk.
        if pending_chunks >= self.config.max_pending_chunks || selected_receiver_id == 0 {
            debug!(
                self.logger,
                "No requests to send: pending chunks {}, selected receiver {}",
                pending_chunks,
                selected_receiver_id
            );
            return None;
        }

        let next_delivery_id = self.next_delivery_id;
        self.next_delivery_id += 1;

        let next_chunk = self
            .receivers
            .get_mut(&selected_receiver_id)
            .unwrap()
            .next_chunk(next_delivery_id);

        next_chunk.map(|payload_contents| DeliverSnapshotRequest {
            recipient_replica_id: selected_receiver_id,
            sender_replica_id: self.replica_id,
            delivery_id: next_delivery_id,
            payload_contents: payload_contents,
        })
    }

    fn process_response(
        &mut self,
        receiver_id: u64,
        delivery_id: u64,
        response: Result<DeliverSnapshotResponse, SnapshotError>,
    ) {
        // Ignore responses from receivers that we do not know about.
        // These responses may simply be delayed on the network while
        // the sender state has been reset due to cluster or role
        // changes.
        if let Some(sender_state) = self.receivers.get_mut(&receiver_id) {
            sender_state.process_response(delivery_id, response);
        }
    }

    fn process_unexpected_request(
        &mut self,
        request: DeliverSnapshotRequest,
    ) -> DeliverSnapshotResponse {
        // Unexpected request, simply indicate that it has been rejected.
        let mut response_payload = deliver_snapshot_response::Payload {
            status: DeliverSnapshotStatus::SnapshotStatusRejected.into(),
            ..Default::default()
        };

        match deliver_snapshot_request::Payload::decode(request.payload_contents) {
            Ok(payload) => match payload.it {
                None => {}
                Some(deliver_snapshot_request::payload::It::Header(_)) => {
                    response_payload.snapshot_id = payload.snapshot_id;
                    response_payload.chunk_index = 0;
                }
                Some(deliver_snapshot_request::payload::It::Chunk(chunk)) => {
                    response_payload.snapshot_id = payload.snapshot_id;
                    response_payload.chunk_index = chunk.chunk_index;
                }
            },
            Err(_) => {}
        }

        DeliverSnapshotResponse {
            recipient_replica_id: request.sender_replica_id,
            sender_replica_id: request.recipient_replica_id,
            delivery_id: request.delivery_id,
            payload_contents: response_payload.encode_to_vec().into(),
        }
    }

    fn try_complete(&mut self) -> Option<(u64, RaftSnapshotStatus)> {
        let mut result: Option<(u64, RaftSnapshotStatus)> = None;
        // Try to complete any snapshot transfer
        for (receiver_id, sender_state) in &mut self.receivers {
            if let Some(snapshot_status) = sender_state.try_complete() {
                result = Some((*receiver_id, snapshot_status));
                break;
            }
        }
        // Remove completed snapshot transfer
        if let Some((receiver_id, _)) = &result {
            info!(
                self.logger,
                "Completed snapshot sending: receiver {}", receiver_id
            );

            self.receivers.remove(receiver_id);
        }

        result
    }
}

struct ReceiverState {
    logger: Logger,
    sender_id: u64,
    snapshot_id: u32,
    snapshot_size: u64,
    snapshot_metadata: Bytes,
    chunk_size: u64,
    chunk_count: u64,
    chunks: HashMap<u64, Bytes>,
}

impl ReceiverState {
    fn new(
        logger: Logger,
        sender_id: u64,
        snapshot_id: u32,
        snapshot_size: u64,
        snapshot_metadata: Bytes,
        first_chunk: Bytes,
    ) -> ReceiverState {
        let chunk_size = first_chunk.len() as u64;
        let mut chunks = HashMap::new();
        chunks.insert(0, first_chunk);
        ReceiverState {
            logger,
            sender_id,
            snapshot_id,
            snapshot_size,
            snapshot_metadata,
            chunk_size,
            chunk_count: chunk_count(snapshot_size, chunk_size),
            chunks,
        }
    }

    fn accept_chunk(&mut self, sender_id: u64, index: u64, chunk_contents: Bytes) -> bool {
        if sender_id != self.sender_id {
            return false;
        }

        let chunk_size: u64 = chunk_contents.len() as u64;
        if index >= self.chunk_count
            || (index < self.chunk_count - 1 && chunk_size != self.chunk_size)
            || (index == self.chunk_count - 1
                && chunk_size != self.snapshot_size - (self.chunk_count - 1) * self.chunk_size)
        {
            return false;
        }
        self.chunks.insert(index, chunk_contents);
        true
    }

    fn try_complete(&mut self) -> Option<Result<(u64, RaftSnapshot), SnapshotError>> {
        if self.chunks.len() as u64 != self.chunk_count {
            return None;
        }
        // Decode snapshot metadata.
        let snapshot_metadata = RaftSnapshotMetadata::decode(self.snapshot_metadata.clone());
        if snapshot_metadata.is_err() {
            return Some(Err(SnapshotError::Corrupted));
        }
        // Copy snapshot data. Will try to remove the copy once Raft switch to use Bytes.
        let mut snapshot_data = BytesMut::with_capacity(self.snapshot_size.try_into().unwrap());
        for c in 0..self.chunk_count {
            snapshot_data.put(self.chunks.remove(&c).unwrap());
        }

        let snapshot = RaftSnapshot {
            data: snapshot_data.into(),
            metadata: Some(snapshot_metadata.unwrap()),
        };

        info!(
            self.logger,
            "Completed snapshot receiving: sender {}, snapshot id {}, snapshot size {}",
            self.sender_id,
            self.snapshot_id,
            self.snapshot_size
        );

        Some(Ok((self.sender_id, snapshot)))
    }
}

pub struct DefaultSnapshotReceiver {
    logger: Logger,
    replica_id: u64,
    instant: u64,
    state: Option<ReceiverState>,
}

impl DefaultSnapshotReceiver {
    pub fn new() -> DefaultSnapshotReceiver {
        DefaultSnapshotReceiver {
            logger: create_logger(),
            replica_id: 0,
            instant: 0,
            state: None,
        }
    }
}

impl SnapshotReceiverImpl for DefaultSnapshotReceiver {
    fn init(&mut self, logger: Logger, replica_id: u64) {
        self.logger = logger;
        self.replica_id = replica_id;
    }

    fn set_instant(&mut self, instant: u64) {
        self.instant = instant;
    }

    fn reset(&mut self) {
        self.state = None;
    }
}

impl SnapshotReceiver for DefaultSnapshotReceiver {
    fn process_request(&mut self, request: DeliverSnapshotRequest) -> DeliverSnapshotResponse {
        let mut response = DeliverSnapshotResponse {
            recipient_replica_id: request.sender_replica_id,
            sender_replica_id: request.recipient_replica_id,
            delivery_id: request.delivery_id,
            ..Default::default()
        };

        let mut response_payload = deliver_snapshot_response::Payload {
            snapshot_id: self.state.as_ref().map_or(0, |s| s.snapshot_id),
            ..Default::default()
        };

        match deliver_snapshot_request::Payload::decode(request.payload_contents) {
            Ok(payload) => {
                match payload.it {
                    None => {}
                    Some(deliver_snapshot_request::payload::It::Header(header)) => {
                        info!(self.logger,
                            "Starting snapshot receiving: sender {}, snapshot id {}, snapshot size {}",
                        request.sender_replica_id,
                        payload.snapshot_id,
                        header.snapshot_size);

                        // Received new header, must reset any progress as there can only
                        // be one snapshot at a time.
                        self.reset();
                        // Initiate new snapshot.
                        self.state = Some(ReceiverState::new(
                            self.logger.clone(),
                            request.sender_replica_id,
                            payload.snapshot_id,
                            header.snapshot_size,
                            header.snapshot_metadata.clone(),
                            header.chunk_contents,
                        ));
                        // Respond to the snapshot sender.
                        response_payload.snapshot_id = payload.snapshot_id;
                        response_payload.chunk_index = 0;
                        response_payload.status =
                            DeliverSnapshotStatus::SnapshotStatusAccepted.into();
                    }
                    Some(deliver_snapshot_request::payload::It::Chunk(chunk)) => {
                        response_payload.snapshot_id = payload.snapshot_id;
                        response_payload.chunk_index = chunk.chunk_index;

                        // Ensure the snapshot has been initiated.
                        match self.state {
                            Some(ref mut state) => {
                                // Ensure incoming chunk belongs to the current snapshot and
                                // within range.
                                if state.accept_chunk(
                                    request.sender_replica_id,
                                    chunk.chunk_index.into(),
                                    chunk.chunk_contents,
                                ) {
                                    // Respond with acceptance.
                                    response_payload.status =
                                        DeliverSnapshotStatus::SnapshotStatusAccepted.into();
                                } else {
                                    warn!(self.logger, "Rejecting payload: out of bounds");
                                    // Respond with rejection.
                                    response_payload.status =
                                        DeliverSnapshotStatus::SnapshotStatusRejected.into();
                                }
                            }
                            None => {
                                // Respond with rejection.
                                response_payload.status =
                                    DeliverSnapshotStatus::SnapshotStatusRejected.into();
                            }
                        }
                    }
                }
            }
            Err(e) => {
                warn!(self.logger, "Rejecting payload: {}", e);
                // Reject incoming request.
                response_payload.status = DeliverSnapshotStatus::SnapshotStatusRejected.into();
            }
        }

        response.payload_contents = response_payload.encode_to_vec().into();
        response
    }

    fn try_complete(&mut self) -> Option<Result<(u64, RaftSnapshot), SnapshotError>> {
        let result = self.state.as_mut().map(|s| s.try_complete()).flatten();
        // Reset state if snapshot has been succefully received.
        if result.is_some() {
            self.reset()
        }
        result
    }
}

#[cfg(all(test, feature = "std"))]
mod test {
    extern crate mockall;

    use self::mockall::predicate::{always, eq};
    use super::*;
    use alloc::vec;
    use core::matches;
    use mock::{MockSnapshotReceiver, MockSnapshotSender};

    use crate::logger::log::create_logger;
    use crate::util::raft::{create_raft_snapshot, create_raft_snapshot_metadata};

    use hashbrown::HashSet;

    use raft::eraftpb::ConfState as RaftConfigState;

    const REPLICA_0: u64 = 0;
    const REPLICA_1: u64 = 1;
    const REPLICA_2: u64 = 2;
    const TERM_0: u64 = 0;
    const TERM_1: u64 = 1;
    const TERM_2: u64 = 2;

    fn create_and_init_processor(
        replica_id: u64,
        sender: Box<dyn SnapshotSenderImpl>,
        receiver: Box<dyn SnapshotReceiverImpl>,
    ) -> DefaultSnapshotProcessor {
        let mut snapshot_processor = DefaultSnapshotProcessor::new(sender, receiver);
        let snapshot_config = default_snapshot_config();
        snapshot_processor.init(create_logger(), replica_id, &Some(snapshot_config));
        snapshot_processor
    }

    fn expect_sender_init(mock_sender: &mut MockSnapshotSender, replica_id: u64) {
        let snapshot_config = default_snapshot_config();
        mock_sender
            .expect_init()
            .with(always(), eq(replica_id), eq(Some(snapshot_config)))
            .return_const(());
    }

    fn expect_receiver_init(mock_receiver: &mut MockSnapshotReceiver, replica_id: u64) {
        mock_receiver
            .expect_init()
            .with(always(), eq(replica_id))
            .return_const(());
    }

    fn expect_sender_set_instant(mock_sender: &mut MockSnapshotSender, instant: u64) {
        mock_sender
            .expect_set_instant()
            .with(eq(instant))
            .return_const(());
    }

    fn expect_sender_reset(
        mock_sender: &mut MockSnapshotSender,
        cancellations: Vec<(u64, RaftSnapshotStatus)>,
    ) {
        mock_sender.expect_reset().return_const(cancellations);
    }

    fn expect_receiver_set_instant(mock_receiver: &mut MockSnapshotReceiver, instant: u64) {
        mock_receiver
            .expect_set_instant()
            .with(eq(instant))
            .return_const(());
    }

    fn expect_receiver_reset(mock_receiver: &mut MockSnapshotReceiver) {
        mock_receiver.expect_reset().return_const(());
    }

    #[test]
    fn test_snapshot_processor_starts_receiver() {
        let (instant, replica_id) = (10, REPLICA_1);

        let mut mock_sender = Box::new(MockSnapshotSender::new());
        expect_sender_init(&mut mock_sender, replica_id);

        let mut mock_receiver = Box::new(MockSnapshotReceiver::new());
        expect_receiver_init(&mut mock_receiver, replica_id);
        expect_receiver_set_instant(&mut mock_receiver, instant);

        let mut snapshot_processor =
            create_and_init_processor(replica_id, mock_sender, mock_receiver);

        assert!(matches!(
            snapshot_processor.mut_processor(instant),
            SnapshotProcessorRole::Receiver(_)
        ));
    }

    #[test]
    fn test_snapshot_processor_cluster_change_remains_follower_leader_changes() {
        let (instant, replica_id) = (10, REPLICA_1);

        let mut mock_sender = Box::new(MockSnapshotSender::new());
        expect_sender_init(&mut mock_sender, replica_id);

        let mut mock_receiver = Box::new(MockSnapshotReceiver::new());
        expect_receiver_init(&mut mock_receiver, replica_id);
        expect_receiver_reset(&mut mock_receiver);
        expect_receiver_set_instant(&mut mock_receiver, instant);

        let mut snapshot_processor =
            create_and_init_processor(replica_id, mock_sender, mock_receiver);

        assert_eq!(
            snapshot_processor.process_cluster_change(
                REPLICA_2,
                TERM_0,
                &vec![REPLICA_1, REPLICA_2]
            ),
            vec![]
        );

        assert!(matches!(
            snapshot_processor.mut_processor(instant),
            SnapshotProcessorRole::Receiver(_)
        ));
    }

    #[test]
    fn test_snapshot_processor_cluster_change_remains_follower_leader_term_changes() {
        let (instant, replica_id) = (10, REPLICA_1);

        let mut mock_sender = Box::new(MockSnapshotSender::new());
        expect_sender_init(&mut mock_sender, replica_id);

        let mut mock_receiver = Box::new(MockSnapshotReceiver::new());
        expect_receiver_init(&mut mock_receiver, replica_id);
        expect_receiver_reset(&mut mock_receiver);
        expect_receiver_set_instant(&mut mock_receiver, instant);

        let mut snapshot_processor =
            create_and_init_processor(replica_id, mock_sender, mock_receiver);

        assert_eq!(
            snapshot_processor.process_cluster_change(
                REPLICA_0,
                TERM_1,
                &vec![REPLICA_0, REPLICA_1]
            ),
            vec![]
        );

        assert!(matches!(
            snapshot_processor.mut_processor(instant),
            SnapshotProcessorRole::Receiver(_)
        ));
    }

    #[test]
    fn test_snapshot_processor_cluster_change_becomes_leader() {
        let (instant, replica_id) = (10, REPLICA_1);

        let mut mock_sender = Box::new(MockSnapshotSender::new());
        expect_sender_init(&mut mock_sender, replica_id);
        expect_sender_set_instant(&mut mock_sender, instant);

        let mut mock_receiver = Box::new(MockSnapshotReceiver::new());
        expect_receiver_init(&mut mock_receiver, replica_id);
        expect_receiver_reset(&mut mock_receiver);

        let mut snapshot_processor =
            create_and_init_processor(replica_id, mock_sender, mock_receiver);

        assert_eq!(
            snapshot_processor.process_cluster_change(REPLICA_1, TERM_1, &vec![REPLICA_1]),
            vec![]
        );

        assert!(matches!(
            snapshot_processor.mut_processor(instant),
            SnapshotProcessorRole::Sender(_)
        ));
    }

    #[test]
    fn test_snapshot_processor_cluster_change_becomes_follower() {
        let (instant, replica_id) = (10, REPLICA_1);

        let cancellations = vec![(1, RaftSnapshotStatus::Failure)];

        let mut mock_sender = Box::new(MockSnapshotSender::new());
        expect_sender_init(&mut mock_sender, replica_id);
        expect_sender_reset(&mut mock_sender, cancellations.clone());

        let mut mock_receiver = Box::new(MockSnapshotReceiver::new());
        expect_receiver_init(&mut mock_receiver, replica_id);
        expect_receiver_reset(&mut mock_receiver);
        expect_receiver_set_instant(&mut mock_receiver, instant);

        let mut snapshot_processor =
            create_and_init_processor(replica_id, mock_sender, mock_receiver);

        assert_eq!(
            snapshot_processor.process_cluster_change(
                REPLICA_1,
                TERM_1,
                &vec![REPLICA_1, REPLICA_2]
            ),
            vec![]
        );
        assert_eq!(
            snapshot_processor.process_cluster_change(
                REPLICA_2,
                TERM_2,
                &vec![REPLICA_1, REPLICA_2]
            ),
            cancellations
        );

        assert!(matches!(
            snapshot_processor.mut_processor(instant),
            SnapshotProcessorRole::Receiver(_)
        ));
    }

    #[test]
    fn test_snapshot_processor_cluster_change_remains_leader() {
        let (instant, replica_id) = (10, REPLICA_1);

        let cancellations = vec![(1, RaftSnapshotStatus::Failure)];

        let mut mock_sender = Box::new(MockSnapshotSender::new());
        expect_sender_init(&mut mock_sender, replica_id);
        expect_sender_reset(&mut mock_sender, cancellations.clone());
        expect_sender_set_instant(&mut mock_sender, instant);

        let mut mock_receiver = Box::new(MockSnapshotReceiver::new());
        expect_receiver_init(&mut mock_receiver, replica_id);
        expect_receiver_reset(&mut mock_receiver);

        let mut snapshot_processor =
            create_and_init_processor(replica_id, mock_sender, mock_receiver);

        assert_eq!(
            snapshot_processor.process_cluster_change(
                REPLICA_1,
                TERM_1,
                &vec![REPLICA_1, REPLICA_2]
            ),
            vec![]
        );
        assert_eq!(
            snapshot_processor.process_cluster_change(
                REPLICA_1,
                TERM_2,
                &vec![REPLICA_1, REPLICA_2]
            ),
            cancellations
        );

        assert!(matches!(
            snapshot_processor.mut_processor(instant),
            SnapshotProcessorRole::Sender(_)
        ));
    }

    fn default_snapshot_metadata() -> RaftSnapshotMetadata {
        create_raft_snapshot_metadata(
            1,
            2,
            RaftConfigState {
                ..Default::default()
            },
        )
    }

    fn create_deliver_snapshot_request_header(
        sender_id: u64,
        snapshot_id: u32,
        delivery_id: u64,
        snapshot_size: u64,
        snapshot_metadata: Bytes,
        chunk_contents: Bytes,
    ) -> DeliverSnapshotRequest {
        let header = deliver_snapshot_request::payload::Header {
            snapshot_size,
            snapshot_metadata,
            chunk_contents,
        };

        let payload = deliver_snapshot_request::Payload {
            snapshot_id,
            it: Some(deliver_snapshot_request::payload::It::Header(header)),
        };

        DeliverSnapshotRequest {
            recipient_replica_id: 1,
            sender_replica_id: sender_id,
            delivery_id,
            payload_contents: payload.encode_to_vec().into(),
        }
    }

    fn create_deliver_snapshot_request_chunk(
        sender_id: u64,
        snapshot_id: u32,
        delivery_id: u64,
        chunk_index: u32,
        chunk_contents: Bytes,
    ) -> DeliverSnapshotRequest {
        let chunk = deliver_snapshot_request::payload::Chunk {
            chunk_index,
            chunk_contents,
        };

        let payload = deliver_snapshot_request::Payload {
            snapshot_id,
            it: Some(deliver_snapshot_request::payload::It::Chunk(chunk)),
        };

        DeliverSnapshotRequest {
            recipient_replica_id: 1,
            sender_replica_id: sender_id,
            delivery_id,
            payload_contents: payload.encode_to_vec().into(),
        }
    }

    fn assert_snapshot_success(
        complete_result: Option<Result<(u64, RaftSnapshot), SnapshotError>>,
        snapshot_sender_id: u64,
        snapshot_data: Bytes,
        snapshot_metadata: RaftSnapshotMetadata,
    ) {
        assert!(complete_result.is_some());

        let snapshot_result = complete_result.unwrap();
        assert!(snapshot_result.is_ok());

        let (sender_id, snapshot) = snapshot_result.unwrap();
        assert_eq!(sender_id, snapshot_sender_id);
        assert_eq!(snapshot.data, snapshot_data);
        assert_eq!(snapshot.metadata, Some(snapshot_metadata));
    }

    fn assert_deliver_snapshot_accepted(
        response: DeliverSnapshotResponse,
        snapshot_id: u32,
        delivery_id: u64,
        chunk_index: u32,
    ) {
        assert_eq!(delivery_id, response.delivery_id);
        let payload =
            deliver_snapshot_response::Payload::decode(response.payload_contents).unwrap();
        assert_eq!(
            payload,
            deliver_snapshot_response::Payload {
                snapshot_id,
                chunk_index,
                status: DeliverSnapshotStatus::SnapshotStatusAccepted.into()
            }
        );
    }

    fn assert_deliver_snapshot_rejected(
        response: DeliverSnapshotResponse,
        snapshot_id: u32,
        delivery_id: u64,
        chunk_index: u32,
    ) {
        assert_eq!(delivery_id, response.delivery_id);
        let payload =
            deliver_snapshot_response::Payload::decode(response.payload_contents).unwrap();
        assert_eq!(
            payload,
            deliver_snapshot_response::Payload {
                snapshot_id,
                chunk_index,
                status: DeliverSnapshotStatus::SnapshotStatusRejected.into()
            }
        );
    }

    const DELIVERY_1: u64 = 1;
    const DELIVERY_2: u64 = 2;

    const SNAPSHOT_1: u32 = 1;
    const SNAPSHOT_2: u32 = 2;

    #[test]
    fn test_snapshot_receiver_single_chunk() {
        let mut receiver = DefaultSnapshotReceiver::new();

        let metadata = default_snapshot_metadata();

        let data = Bytes::from(vec![1, 2, 3, 4, 5]);

        assert_deliver_snapshot_accepted(
            receiver.process_request(create_deliver_snapshot_request_header(
                REPLICA_1,
                SNAPSHOT_1,
                DELIVERY_1,
                data.len() as u64,
                metadata.encode_to_vec().into(),
                data.clone(),
            )),
            SNAPSHOT_1,
            DELIVERY_1,
            0,
        );

        assert_snapshot_success(receiver.try_complete(), REPLICA_1, data, metadata);
    }

    #[test]
    fn test_snapshot_receiver_multiple_chunks() {
        let mut receiver = DefaultSnapshotReceiver::new();

        let metadata = default_snapshot_metadata();

        let data = Bytes::from(vec![1, 2, 3, 4, 5]);

        assert_deliver_snapshot_accepted(
            receiver.process_request(create_deliver_snapshot_request_header(
                REPLICA_1,
                SNAPSHOT_1,
                DELIVERY_1,
                data.len() as u64,
                metadata.encode_to_vec().into(),
                data.slice(0..3),
            )),
            SNAPSHOT_1,
            DELIVERY_1,
            0,
        );

        let complete_result = receiver.try_complete();

        assert!(complete_result.is_none());

        assert_deliver_snapshot_accepted(
            receiver.process_request(create_deliver_snapshot_request_chunk(
                REPLICA_1,
                SNAPSHOT_1,
                DELIVERY_1,
                1,
                data.slice(3..5),
            )),
            SNAPSHOT_1,
            DELIVERY_1,
            1,
        );

        assert_snapshot_success(receiver.try_complete(), REPLICA_1, data, metadata);
    }

    #[test]
    fn test_snapshot_receiver_reset_new_snapshot() {
        let mut receiver = DefaultSnapshotReceiver::new();

        let metadata = default_snapshot_metadata();

        let data_1 = Bytes::from(vec![1, 2, 3, 4, 5]);

        assert_deliver_snapshot_accepted(
            receiver.process_request(create_deliver_snapshot_request_header(
                REPLICA_1,
                SNAPSHOT_1,
                DELIVERY_1,
                data_1.len() as u64,
                metadata.encode_to_vec().into(),
                data_1.slice(0..3),
            )),
            SNAPSHOT_1,
            DELIVERY_1,
            0,
        );

        let complete_result = receiver.try_complete();

        assert!(complete_result.is_none());

        let data_2 = Bytes::from(vec![6, 7, 8, 9, 10]);

        assert_deliver_snapshot_accepted(
            receiver.process_request(create_deliver_snapshot_request_header(
                REPLICA_1,
                SNAPSHOT_2,
                DELIVERY_2,
                data_2.len() as u64,
                metadata.encode_to_vec().into(),
                data_2.slice(0..4),
            )),
            SNAPSHOT_2,
            DELIVERY_2,
            0,
        );

        assert_deliver_snapshot_accepted(
            receiver.process_request(create_deliver_snapshot_request_chunk(
                REPLICA_1,
                SNAPSHOT_2,
                DELIVERY_2,
                1,
                data_2.slice(4..5),
            )),
            SNAPSHOT_2,
            DELIVERY_2,
            1,
        );

        assert_snapshot_success(receiver.try_complete(), REPLICA_1, data_2, metadata);
    }

    #[test]
    fn test_snapshot_receiver_consequitive_snapshots() {
        let mut receiver = DefaultSnapshotReceiver::new();

        let metadata = default_snapshot_metadata();

        let data_1 = Bytes::from(vec![1, 2, 3, 4, 5]);

        assert_deliver_snapshot_accepted(
            receiver.process_request(create_deliver_snapshot_request_header(
                REPLICA_1,
                SNAPSHOT_1,
                DELIVERY_1,
                data_1.len() as u64,
                metadata.encode_to_vec().into(),
                data_1.clone(),
            )),
            SNAPSHOT_1,
            DELIVERY_1,
            0,
        );

        assert_snapshot_success(receiver.try_complete(), REPLICA_1, data_1, metadata.clone());

        let data_2 = Bytes::from(vec![6, 7, 8, 9, 10]);

        assert_deliver_snapshot_accepted(
            receiver.process_request(create_deliver_snapshot_request_header(
                REPLICA_1,
                SNAPSHOT_2,
                DELIVERY_2,
                data_2.len() as u64,
                metadata.encode_to_vec().into(),
                data_2.slice(0..4),
            )),
            SNAPSHOT_2,
            DELIVERY_2,
            0,
        );

        assert_deliver_snapshot_accepted(
            receiver.process_request(create_deliver_snapshot_request_chunk(
                REPLICA_1,
                SNAPSHOT_2,
                DELIVERY_2,
                1,
                data_2.slice(4..5),
            )),
            SNAPSHOT_2,
            DELIVERY_2,
            1,
        );

        assert_snapshot_success(receiver.try_complete(), REPLICA_1, data_2, metadata);
    }

    #[test]
    fn test_snapshot_receiver_rejected_wrong_snapshot() {
        let mut receiver = DefaultSnapshotReceiver::new();

        let metadata = default_snapshot_metadata();

        let data_1 = Bytes::from(vec![1, 2, 3, 4, 5]);

        assert_deliver_snapshot_accepted(
            receiver.process_request(create_deliver_snapshot_request_header(
                REPLICA_1,
                SNAPSHOT_1,
                DELIVERY_1,
                data_1.len() as u64,
                metadata.encode_to_vec().into(),
                data_1.slice(0..3),
            )),
            SNAPSHOT_1,
            DELIVERY_1,
            0,
        );

        assert_deliver_snapshot_rejected(
            receiver.process_request(create_deliver_snapshot_request_chunk(
                REPLICA_1,
                SNAPSHOT_2,
                DELIVERY_2,
                1,
                data_1.slice(4..5),
            )),
            SNAPSHOT_2,
            DELIVERY_2,
            1,
        );
    }

    #[test]
    fn test_snapshot_receiver_rejected_out_of_bounds() {
        let mut receiver = DefaultSnapshotReceiver::new();

        let metadata = default_snapshot_metadata();

        let data_1 = Bytes::from(vec![1, 2, 3, 4, 5]);

        assert_deliver_snapshot_accepted(
            receiver.process_request(create_deliver_snapshot_request_header(
                REPLICA_1,
                SNAPSHOT_1,
                DELIVERY_1,
                data_1.len() as u64,
                metadata.encode_to_vec().into(),
                data_1.slice(0..3),
            )),
            SNAPSHOT_1,
            DELIVERY_1,
            0,
        );

        assert_deliver_snapshot_rejected(
            receiver.process_request(create_deliver_snapshot_request_chunk(
                REPLICA_1,
                SNAPSHOT_1,
                DELIVERY_2,
                1,
                data_1.slice(2..5),
            )),
            SNAPSHOT_1,
            DELIVERY_2,
            1,
        );
    }

    #[test]
    fn test_snapshot_receiver_rejected_no_header() {
        let mut receiver = DefaultSnapshotReceiver::new();

        let data_1 = Bytes::from(vec![1, 2, 3, 4, 5]);

        assert_deliver_snapshot_rejected(
            receiver.process_request(create_deliver_snapshot_request_chunk(
                REPLICA_1,
                SNAPSHOT_1,
                DELIVERY_1,
                1,
                data_1.slice(2..5),
            )),
            SNAPSHOT_1,
            DELIVERY_1,
            1,
        );
    }

    const CHUNK_0: u32 = 0;
    const CHUNK_1: u32 = 1;
    const CHUNK_2: u32 = 2;

    fn configure_deliver_snapshot_request(
        mut request: DeliverSnapshotRequest,
        recipient_replica_id: u64,
    ) -> DeliverSnapshotRequest {
        request.recipient_replica_id = recipient_replica_id;

        request
    }

    fn create_deliver_snapshot_response(
        sender_replica_id: u64,
        recipient_replica_id: u64,
        snapshot_id: u32,
        chunk_index: u32,
        status: DeliverSnapshotStatus,
    ) -> DeliverSnapshotResponse {
        let payload = deliver_snapshot_response::Payload {
            snapshot_id,
            chunk_index,
            status: status.into(),
        };

        DeliverSnapshotResponse {
            recipient_replica_id,
            sender_replica_id,
            delivery_id: 0,
            payload_contents: payload.encode_to_vec().into(),
        }
    }

    fn default_snapshot_config() -> SnapshotConfig {
        SnapshotConfig {
            snapshot_count: 1000,
            chunk_size: 3,
            max_pending_chunks: 1,
        }
    }

    fn create_sender() -> DefaultSnapshotSender {
        let mut sender = DefaultSnapshotSender::new();
        let snapshot_config = default_snapshot_config();
        sender.init(create_logger(), REPLICA_0, &Some(snapshot_config));

        sender
    }

    #[test]
    fn test_snapshot_sender_reset_cancellations() {
        let mut sender = create_sender();

        let metadata = default_snapshot_metadata();

        let data_1 = Bytes::from(vec![1, 2, 3]);

        sender.start(
            REPLICA_1,
            create_raft_snapshot(metadata.clone(), data_1.clone()),
        );

        assert_eq!(
            sender.reset(),
            vec![(REPLICA_1, RaftSnapshotStatus::Failure)]
        );
    }

    #[test]
    fn test_snapshot_sender_complete_nothing() {
        let mut sender = create_sender();

        assert_eq!(sender.try_complete(), None);
    }

    #[test]
    fn test_snapshot_sender_next_request_nothing() {
        let mut sender = create_sender();

        assert_eq!(sender.next_request(), None);
    }

    #[test]
    fn test_snapshot_sender_single_chunk_success() {
        let mut sender = create_sender();

        let metadata = default_snapshot_metadata();

        let data_1 = Bytes::from(vec![1, 2, 3]);

        sender.start(
            REPLICA_1,
            create_raft_snapshot(metadata.clone(), data_1.clone()),
        );

        assert_eq!(sender.try_complete(), None);

        assert_eq!(
            sender.next_request(),
            Some(configure_deliver_snapshot_request(
                create_deliver_snapshot_request_header(
                    REPLICA_0,
                    SNAPSHOT_1,
                    DELIVERY_1,
                    data_1.len() as u64,
                    metadata.encode_to_vec().into(),
                    data_1.clone(),
                ),
                REPLICA_1,
            ))
        );

        sender.process_response(
            REPLICA_1,
            DELIVERY_1,
            Ok(create_deliver_snapshot_response(
                REPLICA_0,
                REPLICA_1,
                SNAPSHOT_1,
                CHUNK_0,
                DeliverSnapshotStatus::SnapshotStatusAccepted,
            )),
        );

        assert_eq!(
            sender.try_complete(),
            Some((REPLICA_1, RaftSnapshotStatus::Finish))
        );
    }

    #[test]
    fn test_snapshot_sender_multiple_chunks_success() {
        let mut sender = create_sender();

        let chunk_size = default_snapshot_config().chunk_size;
        let metadata = default_snapshot_metadata();

        let data_1 = Bytes::from(vec![1, 2, 3, 4, 5]);

        sender.start(
            REPLICA_1,
            create_raft_snapshot(metadata.clone(), data_1.clone()),
        );

        assert_eq!(sender.try_complete(), None);

        assert_eq!(
            sender.next_request(),
            Some(configure_deliver_snapshot_request(
                create_deliver_snapshot_request_header(
                    REPLICA_0,
                    SNAPSHOT_1,
                    DELIVERY_1,
                    data_1.len() as u64,
                    metadata.encode_to_vec().into(),
                    data_1.slice(0..chunk_size as usize),
                ),
                REPLICA_1,
            ))
        );

        assert_eq!(sender.next_request(), None);

        sender.process_response(
            REPLICA_1,
            DELIVERY_1,
            Ok(create_deliver_snapshot_response(
                REPLICA_0,
                REPLICA_1,
                SNAPSHOT_1,
                CHUNK_0,
                DeliverSnapshotStatus::SnapshotStatusAccepted,
            )),
        );

        assert_eq!(
            sender.next_request(),
            Some(configure_deliver_snapshot_request(
                create_deliver_snapshot_request_chunk(
                    REPLICA_0,
                    SNAPSHOT_1,
                    DELIVERY_2,
                    CHUNK_1,
                    data_1.slice(chunk_size as usize..),
                ),
                REPLICA_1,
            ))
        );

        sender.process_response(
            REPLICA_1,
            DELIVERY_2,
            Ok(create_deliver_snapshot_response(
                REPLICA_0,
                REPLICA_1,
                SNAPSHOT_1,
                CHUNK_1,
                DeliverSnapshotStatus::SnapshotStatusAccepted,
            )),
        );

        assert_eq!(
            sender.try_complete(),
            Some((REPLICA_1, RaftSnapshotStatus::Finish))
        );
    }

    #[test]
    fn test_snapshot_sender_response_rejection() {
        let mut sender = create_sender();

        let metadata = default_snapshot_metadata();

        let data_1 = Bytes::from(vec![1, 2, 3]);

        sender.start(
            REPLICA_1,
            create_raft_snapshot(metadata.clone(), data_1.clone()),
        );

        assert_eq!(sender.try_complete(), None);

        assert_eq!(
            sender.next_request(),
            Some(configure_deliver_snapshot_request(
                create_deliver_snapshot_request_header(
                    REPLICA_0,
                    SNAPSHOT_1,
                    DELIVERY_1,
                    data_1.len() as u64,
                    metadata.encode_to_vec().into(),
                    data_1.clone(),
                ),
                REPLICA_1,
            ))
        );

        sender.process_response(
            REPLICA_1,
            DELIVERY_1,
            Ok(create_deliver_snapshot_response(
                REPLICA_0,
                REPLICA_1,
                SNAPSHOT_1,
                CHUNK_0,
                DeliverSnapshotStatus::SnapshotStatusRejected,
            )),
        );

        assert_eq!(
            sender.try_complete(),
            Some((REPLICA_1, RaftSnapshotStatus::Failure))
        );
    }

    #[test]
    fn test_snapshot_sender_response_failure() {
        let mut sender = create_sender();

        let metadata = default_snapshot_metadata();

        let data_1 = Bytes::from(vec![1, 2, 3]);

        sender.start(
            REPLICA_1,
            create_raft_snapshot(metadata.clone(), data_1.clone()),
        );

        assert_eq!(sender.try_complete(), None);

        assert_eq!(
            sender.next_request(),
            Some(configure_deliver_snapshot_request(
                create_deliver_snapshot_request_header(
                    REPLICA_0,
                    SNAPSHOT_1,
                    DELIVERY_1,
                    data_1.len() as u64,
                    metadata.encode_to_vec().into(),
                    data_1.clone(),
                ),
                REPLICA_1,
            ))
        );

        sender.process_response(REPLICA_1, DELIVERY_1, Err(SnapshotError::FailedDelivery));

        assert_eq!(
            sender.try_complete(),
            Some((REPLICA_1, RaftSnapshotStatus::Failure))
        );
    }

    #[test]
    fn test_snapshot_sender_response_wrong_snapshot() {
        let mut sender = create_sender();

        let chunk_size = default_snapshot_config().chunk_size;
        let metadata = default_snapshot_metadata();

        let data_1 = Bytes::from(vec![1, 2, 3, 4, 5]);

        sender.start(
            REPLICA_1,
            create_raft_snapshot(metadata.clone(), data_1.clone()),
        );

        assert_eq!(
            sender.next_request(),
            Some(configure_deliver_snapshot_request(
                create_deliver_snapshot_request_header(
                    REPLICA_0,
                    SNAPSHOT_1,
                    DELIVERY_1,
                    data_1.len() as u64,
                    metadata.encode_to_vec().into(),
                    data_1.slice(0..chunk_size as usize),
                ),
                REPLICA_1,
            ))
        );

        sender.process_response(
            REPLICA_1,
            DELIVERY_1,
            Ok(create_deliver_snapshot_response(
                REPLICA_0,
                REPLICA_1,
                SNAPSHOT_2,
                CHUNK_0,
                DeliverSnapshotStatus::SnapshotStatusRejected,
            )),
        );

        assert_eq!(sender.try_complete(), None);
    }

    #[test]
    fn test_snapshot_sender_response_wrong_chunk_index() {
        let mut sender = create_sender();

        let chunk_size = default_snapshot_config().chunk_size;
        let metadata = default_snapshot_metadata();

        let data_1 = Bytes::from(vec![1, 2, 3, 4, 5]);

        sender.start(
            REPLICA_1,
            create_raft_snapshot(metadata.clone(), data_1.clone()),
        );

        assert_eq!(
            sender.next_request(),
            Some(configure_deliver_snapshot_request(
                create_deliver_snapshot_request_header(
                    REPLICA_0,
                    SNAPSHOT_1,
                    DELIVERY_1,
                    data_1.len() as u64,
                    metadata.encode_to_vec().into(),
                    data_1.slice(0..chunk_size as usize),
                ),
                REPLICA_1,
            ))
        );

        sender.process_response(
            REPLICA_1,
            DELIVERY_1,
            Ok(create_deliver_snapshot_response(
                REPLICA_0,
                REPLICA_1,
                SNAPSHOT_1,
                CHUNK_1,
                DeliverSnapshotStatus::SnapshotStatusRejected,
            )),
        );

        assert_eq!(
            sender.try_complete(),
            Some((REPLICA_1, RaftSnapshotStatus::Failure))
        );
    }

    #[test]
    fn test_snapshot_sender_response_out_of_bounds_chunk_index() {
        let mut sender = create_sender();

        let chunk_size = default_snapshot_config().chunk_size;
        let metadata = default_snapshot_metadata();

        let data_1 = Bytes::from(vec![1, 2, 3, 4, 5]);

        sender.start(
            REPLICA_1,
            create_raft_snapshot(metadata.clone(), data_1.clone()),
        );

        assert_eq!(
            sender.next_request(),
            Some(configure_deliver_snapshot_request(
                create_deliver_snapshot_request_header(
                    REPLICA_0,
                    SNAPSHOT_1,
                    DELIVERY_1,
                    data_1.len() as u64,
                    metadata.encode_to_vec().into(),
                    data_1.slice(0..chunk_size as usize),
                ),
                REPLICA_1,
            ))
        );

        sender.process_response(
            REPLICA_1,
            DELIVERY_1,
            Ok(create_deliver_snapshot_response(
                REPLICA_0,
                REPLICA_1,
                SNAPSHOT_1,
                CHUNK_2,
                DeliverSnapshotStatus::SnapshotStatusRejected,
            )),
        );

        assert_eq!(
            sender.try_complete(),
            Some((REPLICA_1, RaftSnapshotStatus::Failure))
        );
    }

    #[test]
    fn test_snapshot_sender_receiver_end_to_end() {
        let data = Bytes::from(vec![1, 2, 3, 4, 5, 6, 7, 8, 9]);
        let metadata = default_snapshot_metadata();

        for chunk_size in 1..data.len() {
            for max_pending_chunks in 1..data.len() {
                let config = Some(SnapshotConfig {
                    snapshot_count: 1000,
                    chunk_size: chunk_size as u64,
                    max_pending_chunks: max_pending_chunks as u32,
                });
                let mut sender = create_sender();
                sender.init(create_logger(), REPLICA_0, &config);

                let mut receivers: HashMap<u64, DefaultSnapshotReceiver> = HashMap::new();
                for replica_id in vec![REPLICA_1, REPLICA_2] {
                    receivers.insert(replica_id, DefaultSnapshotReceiver::new());
                    sender.start(
                        replica_id,
                        create_raft_snapshot(metadata.clone(), data.clone()),
                    );
                }

                let mut sender_completed: HashSet<u64> = HashSet::new();
                let mut receiver_completed: HashSet<u64> = HashSet::new();

                while sender_completed.len() < 2 && receiver_completed.len() < 2 {
                    let mut requests: Vec<DeliverSnapshotRequest> = Vec::new();
                    loop {
                        let request = sender.next_request();
                        if request.is_none() {
                            break;
                        }
                        requests.push(request.unwrap());
                    }

                    let mut responses: Vec<(u64, DeliverSnapshotResponse)> = Vec::new();
                    for request in requests {
                        if let Some(receiver) = receivers.get_mut(&request.recipient_replica_id) {
                            responses
                                .push((request.delivery_id, receiver.process_request(request)));
                        }
                    }

                    for (delivery_id, response) in responses {
                        let sender_replica_id = response.sender_replica_id;
                        sender.process_response(sender_replica_id, delivery_id, Ok(response));
                    }

                    loop {
                        let result = sender.try_complete();
                        if result.is_none() {
                            break;
                        }
                        let (replica_id, status) = result.unwrap();
                        sender_completed.insert(replica_id);
                        assert_eq!(status, RaftSnapshotStatus::Finish);
                    }

                    for (replica_id, receiver) in &mut receivers {
                        if let Some(Ok((sender_id, snapshot))) = receiver.try_complete() {
                            receiver_completed.insert(*replica_id);
                            assert_eq!(REPLICA_0, sender_id);
                            assert_eq!(data, snapshot.data);
                            assert_eq!(Some(metadata.clone()), snapshot.metadata);
                        }
                    }
                }

                assert!(sender_completed.contains(&REPLICA_1));
                assert!(sender_completed.contains(&REPLICA_2));
            }
        }
    }
}
