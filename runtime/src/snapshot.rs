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

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::option::Option;
use tcp_proto::runtime::endpoint::{DeliverSnapshotRequest, DeliverSnapshotResponse};

use raft::{eraftpb::Snapshot as RaftSnapshot, SnapshotStatus as RaftSnapshotStatus};

/// Enumerates errors possible while sending or receiving a snapshot.
pub enum SnapshotError {
    /// Failed to deliver part of the snapshot.
    FailedDelivery,
    Corrupted,
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
    fn mut_processor(&mut self, instant: u64) -> &mut SnapshotProcessorRole;
}

/// Enumerates snapshot processor roles.
pub enum SnapshotProcessorRole {
    /// In sender role processor may be sending multiple snapshots to several
    /// replicas.
    Sender(Box<dyn SnapshotSender>),

    /// In receiver role processor may only receive a single snapshot from the
    /// current leader.
    Receiver(Box<dyn SnapshotReceiver>),
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
    /// Nothing if there are no eligible requests to send. A tuple containing
    /// receiver replica id, delivery id and request otherwise.
    ///
    /// # Note
    ///
    /// Sender maintain multiple transfers at the same time. It controls that
    /// there is limited number of in-flight requests across all transfers
    /// to avoid overwhelming the channel. Processing responses or cancelling
    /// transfers frees up the in-flight request slots.
    fn next_request(&mut self) -> Option<(u64, u64, DeliverSnapshotRequest)>;

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
    fn process_request(
        &mut self,
        sender_id: u64,
        request: DeliverSnapshotRequest,
    ) -> DeliverSnapshotResponse;

    /// Attempts to complete snapshot receiving.
    ///
    /// # Returns
    ///
    /// Nothing if not all chunks have been received. Error if fully assembled snapshot
    /// failed to pass checksum validation. Snapshot otherwise.
    fn try_complete(&mut self) -> Option<Result<RaftSnapshot, SnapshotError>>;
}
