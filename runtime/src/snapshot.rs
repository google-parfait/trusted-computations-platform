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

use crate::StdError;
use alloc::boxed::Box;
use alloc::vec::Vec;
use core::convert::TryInto;
use core::fmt;
use core::option::Option;
use hashbrown::HashMap;
use prost::{
    bytes::{Buf, BufMut, Bytes, BytesMut},
    Message,
};
use tcp_proto::runtime::endpoint::{
    deliver_snapshot_request, deliver_snapshot_response, DeliverSnapshotRequest,
    DeliverSnapshotResponse, DeliverSnapshotStatus,
};

use raft::{
    eraftpb::Snapshot as RaftSnapshot, eraftpb::SnapshotMetadata as RaftSnapshotMetadata,
    SnapshotStatus as RaftSnapshotStatus,
};
use slog::{debug, warn, Logger};

/// Enumerates errors possible while sending or receiving a snapshot.
#[derive(Debug)]
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
    fn init(&mut self, replica_id: u64);

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
    /// failed to pass checksum validation. Snapshot otherwise.
    fn try_complete(&mut self) -> Option<Result<RaftSnapshot, SnapshotError>>;
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
    fn set_instant(&mut self, instant: u64);

    fn reset(&mut self) -> Vec<(u64, RaftSnapshotStatus)>;
}

pub trait SnapshotReceiverImpl: SnapshotReceiver {
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
    fn new(sender: Box<dyn SnapshotSenderImpl>, receiver: Box<dyn SnapshotReceiverImpl>) -> Self {
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
    fn init(&mut self, replica_id: u64) {
        assert_eq!(self.state, ReplicaState::Unknown);

        self.replica_id = replica_id;
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

#[derive(Default)]
pub struct DefaultSnapshotSender {
    instant: u64,
}

impl SnapshotSenderImpl for DefaultSnapshotSender {
    fn set_instant(&mut self, instant: u64) {
        self.instant = instant;
    }

    fn reset(&mut self) -> Vec<(u64, RaftSnapshotStatus)> {
        todo!()
    }
}

impl SnapshotSender for DefaultSnapshotSender {
    fn start(&mut self, receiver_id: u64, snapshot: RaftSnapshot) {
        todo!()
    }

    fn next_request(&mut self) -> Option<DeliverSnapshotRequest> {
        todo!()
    }

    fn process_response(
        &mut self,
        sender_id: u64,
        delivery_id: u64,
        response: Result<DeliverSnapshotResponse, SnapshotError>,
    ) {
        todo!()
    }

    fn try_complete(&mut self) -> Option<(u64, RaftSnapshotStatus)> {
        todo!()
    }
}

struct ReceiverState {
    snapshot_id: u32,
    snapshot_size: u64,
    snapshot_metadata: Bytes,
    chunk_size: u64,
    chunk_count: u64,
    chunks: HashMap<u64, Bytes>,
}

impl ReceiverState {
    fn new(
        snapshot_id: u32,
        snapshot_size: u64,
        snapshot_metadata: Bytes,
        first_chunk: Bytes,
    ) -> ReceiverState {
        let chunk_size = first_chunk.len() as u64;
        let mut chunks = HashMap::new();
        chunks.insert(0, first_chunk);
        ReceiverState {
            snapshot_id,
            snapshot_size,
            snapshot_metadata,
            chunk_size,
            chunk_count: (snapshot_size - 1) / chunk_size + 1,
            chunks,
        }
    }

    fn accept_chunk(&mut self, index: u64, contents: Bytes) -> bool {
        let chunk_size: u64 = contents.len() as u64;
        if index >= self.chunk_count
            || (index < self.chunk_count - 1 && chunk_size != self.chunk_size)
            || (index == self.chunk_count - 1
                && chunk_size != self.snapshot_size - (self.chunk_count - 1) * self.chunk_size)
        {
            return false;
        }
        self.chunks.insert(index, contents);
        true
    }

    fn try_complete(&mut self) -> Option<Result<RaftSnapshot, SnapshotError>> {
        if self.chunks.len() as u64 != self.chunk_count {
            return None;
        }
        // Decode snapshot metadata.
        let metadata = RaftSnapshotMetadata::decode(self.snapshot_metadata.clone());
        if metadata.is_err() {
            return Some(Err(SnapshotError::Corrupted));
        }
        // Copy snapshot data. Will try to remove the copy once Raft switch to use Bytes.
        let mut data = BytesMut::with_capacity(self.snapshot_size.try_into().unwrap());
        for c in 0..self.chunk_count {
            data.put(self.chunks.remove(&c).unwrap());
        }

        let snapshot = RaftSnapshot {
            data: data.into(),
            metadata: Some(metadata.unwrap()),
        };
        Some(Ok(snapshot))
    }
}

pub struct DefaultSnapshotReceiver {
    logger: Logger,
    instant: u64,
    state: Option<ReceiverState>,
}

impl DefaultSnapshotReceiver {
    pub fn new(logger: Logger) -> DefaultSnapshotReceiver {
        DefaultSnapshotReceiver {
            logger,
            instant: 0,
            state: None,
        }
    }
}

impl SnapshotReceiverImpl for DefaultSnapshotReceiver {
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
            ..Default::default()
        };

        let mut response_payload = deliver_snapshot_response::Payload {
            snapshot_id: self.state.as_ref().map_or(0, |s| s.snapshot_id),
            ..Default::default()
        };

        match deliver_snapshot_request::Payload::decode(request.payload_contents) {
            Ok(payload) => match payload.it {
                None => {}
                Some(deliver_snapshot_request::payload::It::Header(header)) => {
                    // Received new header, must reset any progress as there can only
                    // be one snapshot at a time.
                    self.reset();
                    // Initiate new snapshot.
                    self.state = Some(ReceiverState::new(
                        payload.snapshot_id,
                        header.size,
                        header.metadata.clone(),
                        header.contents,
                    ));
                    // Respond to the snapshot sender.
                    response_payload.snapshot_id = payload.snapshot_id;
                    response_payload.index = 0;
                    response_payload.status = DeliverSnapshotStatus::SnapshotStatusAccepted.into();
                }
                Some(deliver_snapshot_request::payload::It::Chunk(chunk)) => {
                    response_payload.snapshot_id = payload.snapshot_id;
                    response_payload.index = chunk.index;

                    // Ensure the snapshot has been initiated.
                    match self.state {
                        Some(ref mut state) => {
                            // Ensure incoming chunk belongs to the current snapshot and
                            // within range.
                            if state.accept_chunk(chunk.index.into(), chunk.contents) {
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
            },
            Err(e) => {
                warn!(self.logger, "Rejecting payload: {}", e);
                // Reject incoming request.
                response_payload.status = DeliverSnapshotStatus::SnapshotStatusRejected.into();
            }
        }

        response.payload_contents = response_payload.encode_to_vec().into();
        response
    }

    fn try_complete(&mut self) -> Option<Result<RaftSnapshot, SnapshotError>> {
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

    use self::mockall::predicate::eq;
    use super::*;
    use alloc::vec;
    use core::matches;
    use mock::{MockSnapshotReceiver, MockSnapshotSender};

    use crate::logger::log::create_logger;
    use crate::util::raft::create_raft_snapshot_metadata;

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
        snapshot_processor.init(replica_id);
        snapshot_processor
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

        let mut mock_receiver = Box::new(MockSnapshotReceiver::new());
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

        let mut mock_receiver = Box::new(MockSnapshotReceiver::new());
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

        let mut mock_receiver = Box::new(MockSnapshotReceiver::new());
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
        expect_sender_set_instant(&mut mock_sender, instant);

        let mut mock_receiver = Box::new(MockSnapshotReceiver::new());
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
        expect_sender_reset(&mut mock_sender, cancellations.clone());

        let mut mock_receiver = Box::new(MockSnapshotReceiver::new());
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
        expect_sender_reset(&mut mock_sender, cancellations.clone());
        expect_sender_set_instant(&mut mock_sender, instant);

        let mut mock_receiver = Box::new(MockSnapshotReceiver::new());
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

    fn create_deliver_snapshot_request_header(
        snapshot_id: u32,
        size: u64,
        metadata: Bytes,
        contents: Bytes,
    ) -> DeliverSnapshotRequest {
        let header = deliver_snapshot_request::payload::Header {
            size,
            metadata,
            contents,
        };

        let payload = deliver_snapshot_request::Payload {
            snapshot_id,
            it: Some(deliver_snapshot_request::payload::It::Header(header)),
        };

        DeliverSnapshotRequest {
            recipient_replica_id: 1,
            sender_replica_id: 2,
            delivery_id: 3,
            payload_contents: payload.encode_to_vec().into(),
        }
    }

    fn create_deliver_snapshot_request_chunk(
        snapshot_id: u32,
        index: u32,
        contents: Bytes,
    ) -> DeliverSnapshotRequest {
        let chunk = deliver_snapshot_request::payload::Chunk { index, contents };

        let payload = deliver_snapshot_request::Payload {
            snapshot_id,
            it: Some(deliver_snapshot_request::payload::It::Chunk(chunk)),
        };

        DeliverSnapshotRequest {
            recipient_replica_id: 1,
            sender_replica_id: 2,
            delivery_id: 3,
            payload_contents: payload.encode_to_vec().into(),
        }
    }

    fn assert_snapshot_success(
        complete_result: Option<Result<RaftSnapshot, SnapshotError>>,
        data: Bytes,
        metadata: RaftSnapshotMetadata,
    ) {
        assert!(complete_result.is_some());

        let snapshot_result = complete_result.unwrap();
        assert!(snapshot_result.is_ok());

        let snapshot = snapshot_result.unwrap();
        assert_eq!(snapshot.data, data);
        assert_eq!(snapshot.metadata, Some(metadata));
    }

    fn assert_deliver_snapshot_accepted(
        response: DeliverSnapshotResponse,
        snapshot_id: u32,
        index: u32,
    ) {
        let payload =
            deliver_snapshot_response::Payload::decode(response.payload_contents).unwrap();
        assert_eq!(
            payload,
            deliver_snapshot_response::Payload {
                snapshot_id,
                index,
                status: DeliverSnapshotStatus::SnapshotStatusAccepted.into()
            }
        );
    }

    fn assert_deliver_snapshot_rejected(
        response: DeliverSnapshotResponse,
        snapshot_id: u32,
        index: u32,
    ) {
        let payload =
            deliver_snapshot_response::Payload::decode(response.payload_contents).unwrap();
        assert_eq!(
            payload,
            deliver_snapshot_response::Payload {
                snapshot_id,
                index,
                status: DeliverSnapshotStatus::SnapshotStatusRejected.into()
            }
        );
    }

    const SNAPSHOT_0: u32 = 0;
    const SNAPSHOT_1: u32 = 1;

    #[test]
    fn test_snapshot_receiver_single_chunk() {
        let mut receiver = DefaultSnapshotReceiver::new(create_logger(1));

        let metadata = create_raft_snapshot_metadata(
            1,
            2,
            RaftConfigState {
                ..Default::default()
            },
        );

        let data = Bytes::from(vec![1, 2, 3, 4, 5]);

        assert_deliver_snapshot_accepted(
            receiver.process_request(create_deliver_snapshot_request_header(
                SNAPSHOT_0,
                data.len() as u64,
                metadata.encode_to_vec().into(),
                data.clone(),
            )),
            SNAPSHOT_0,
            0,
        );

        assert_snapshot_success(receiver.try_complete(), data, metadata);
    }

    #[test]
    fn test_snapshot_receiver_multiple_chunks() {
        let mut receiver = DefaultSnapshotReceiver::new(create_logger(1));

        let metadata = create_raft_snapshot_metadata(
            1,
            2,
            RaftConfigState {
                ..Default::default()
            },
        );

        let data = Bytes::from(vec![1, 2, 3, 4, 5]);

        assert_deliver_snapshot_accepted(
            receiver.process_request(create_deliver_snapshot_request_header(
                SNAPSHOT_0,
                data.len() as u64,
                metadata.encode_to_vec().into(),
                data.slice(0..3),
            )),
            SNAPSHOT_0,
            0,
        );

        let mut complete_result = receiver.try_complete();

        assert!(complete_result.is_none());

        assert_deliver_snapshot_accepted(
            receiver.process_request(create_deliver_snapshot_request_chunk(
                SNAPSHOT_0,
                1,
                data.slice(3..5),
            )),
            SNAPSHOT_0,
            1,
        );

        assert_snapshot_success(receiver.try_complete(), data, metadata);
    }

    #[test]
    fn test_snapshot_receiver_reset_new_snapshot() {
        let mut receiver = DefaultSnapshotReceiver::new(create_logger(1));

        let metadata = create_raft_snapshot_metadata(
            1,
            2,
            RaftConfigState {
                ..Default::default()
            },
        );

        let data_0 = Bytes::from(vec![1, 2, 3, 4, 5]);

        assert_deliver_snapshot_accepted(
            receiver.process_request(create_deliver_snapshot_request_header(
                SNAPSHOT_0,
                data_0.len() as u64,
                metadata.encode_to_vec().into(),
                data_0.slice(0..3),
            )),
            SNAPSHOT_0,
            0,
        );

        let mut complete_result = receiver.try_complete();

        assert!(complete_result.is_none());

        let data_1 = Bytes::from(vec![6, 7, 8, 9, 10]);

        assert_deliver_snapshot_accepted(
            receiver.process_request(create_deliver_snapshot_request_header(
                SNAPSHOT_1,
                data_1.len() as u64,
                metadata.encode_to_vec().into(),
                data_1.slice(0..4),
            )),
            SNAPSHOT_1,
            0,
        );

        assert_deliver_snapshot_accepted(
            receiver.process_request(create_deliver_snapshot_request_chunk(
                SNAPSHOT_1,
                1,
                data_1.slice(4..5),
            )),
            SNAPSHOT_1,
            1,
        );

        assert_snapshot_success(receiver.try_complete(), data_1, metadata);
    }

    #[test]
    fn test_snapshot_receiver_consequitive_snapshots() {
        let mut receiver = DefaultSnapshotReceiver::new(create_logger(1));

        let metadata = create_raft_snapshot_metadata(
            1,
            2,
            RaftConfigState {
                ..Default::default()
            },
        );

        let data_0 = Bytes::from(vec![1, 2, 3, 4, 5]);

        assert_deliver_snapshot_accepted(
            receiver.process_request(create_deliver_snapshot_request_header(
                SNAPSHOT_0,
                data_0.len() as u64,
                metadata.encode_to_vec().into(),
                data_0.clone(),
            )),
            SNAPSHOT_0,
            0,
        );

        assert_snapshot_success(receiver.try_complete(), data_0, metadata.clone());

        let data_1 = Bytes::from(vec![6, 7, 8, 9, 10]);

        assert_deliver_snapshot_accepted(
            receiver.process_request(create_deliver_snapshot_request_header(
                SNAPSHOT_1,
                data_1.len() as u64,
                metadata.encode_to_vec().into(),
                data_1.slice(0..4),
            )),
            SNAPSHOT_1,
            0,
        );

        assert_deliver_snapshot_accepted(
            receiver.process_request(create_deliver_snapshot_request_chunk(
                SNAPSHOT_1,
                1,
                data_1.slice(4..5),
            )),
            SNAPSHOT_1,
            1,
        );

        assert_snapshot_success(receiver.try_complete(), data_1, metadata);
    }

    #[test]
    fn test_snapshot_receiver_rejected_wrong_snapshot() {
        let mut receiver = DefaultSnapshotReceiver::new(create_logger(1));

        let metadata = create_raft_snapshot_metadata(
            1,
            2,
            RaftConfigState {
                ..Default::default()
            },
        );

        let data_0 = Bytes::from(vec![1, 2, 3, 4, 5]);

        assert_deliver_snapshot_accepted(
            receiver.process_request(create_deliver_snapshot_request_header(
                SNAPSHOT_0,
                data_0.len() as u64,
                metadata.encode_to_vec().into(),
                data_0.slice(0..3),
            )),
            SNAPSHOT_0,
            0,
        );

        assert_deliver_snapshot_rejected(
            receiver.process_request(create_deliver_snapshot_request_chunk(
                SNAPSHOT_1,
                1,
                data_0.slice(4..5),
            )),
            SNAPSHOT_1,
            1,
        );
    }

    #[test]
    fn test_snapshot_receiver_rejected_out_of_bounds() {
        let mut receiver = DefaultSnapshotReceiver::new(create_logger(1));

        let metadata = create_raft_snapshot_metadata(
            1,
            2,
            RaftConfigState {
                ..Default::default()
            },
        );

        let data_0 = Bytes::from(vec![1, 2, 3, 4, 5]);

        assert_deliver_snapshot_accepted(
            receiver.process_request(create_deliver_snapshot_request_header(
                SNAPSHOT_0,
                data_0.len() as u64,
                metadata.encode_to_vec().into(),
                data_0.slice(0..3),
            )),
            SNAPSHOT_0,
            0,
        );

        assert_deliver_snapshot_rejected(
            receiver.process_request(create_deliver_snapshot_request_chunk(
                SNAPSHOT_0,
                1,
                data_0.slice(2..5),
            )),
            SNAPSHOT_0,
            1,
        );
    }

    #[test]
    fn test_snapshot_receiver_rejected_no_header() {
        let mut receiver = DefaultSnapshotReceiver::new(create_logger(1));

        let metadata = create_raft_snapshot_metadata(
            1,
            2,
            RaftConfigState {
                ..Default::default()
            },
        );

        let data_0 = Bytes::from(vec![1, 2, 3, 4, 5]);

        assert_deliver_snapshot_rejected(
            receiver.process_request(create_deliver_snapshot_request_chunk(
                SNAPSHOT_0,
                1,
                data_0.slice(2..5),
            )),
            SNAPSHOT_0,
            1,
        );
    }
}
