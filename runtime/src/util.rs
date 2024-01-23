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

use crate::StdError;
use alloc::vec::Vec;
use core::fmt;
use core::result::Result;
use raft::eraftpb::{
    ConfChange as RaftConfigChange, ConfChangeType as RaftConfigChangeType,
    ConfState as RaftConfigState, Entry as RaftEntry, EntryType as RaftEntryType,
    Message as RaftMessage, MessageType as RaftMessageType, Snapshot as RaftSnapshot,
    SnapshotMetadata as RaftSnapshotMetadata,
};
use tcp_proto::runtime::endpoint::{Entry, EntryId};

#[derive(Debug)]
pub enum UtilError {
    Decoding,
    Encoding,
}

impl StdError for UtilError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        None
    }
}

impl fmt::Display for UtilError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            UtilError::Decoding => write!(f, "Failed to decode"),
            UtilError::Encoding => write!(f, "Failed to encode"),
        }
    }
}

pub mod raft {
    use super::*;
    use prost::{bytes::Bytes, Message};

    pub fn message_size<M: Message>(message: &M) -> u32 {
        message.encoded_len() as u32
    }

    pub fn deserialize_raft_message(message_contents: Bytes) -> Result<RaftMessage, UtilError> {
        RaftMessage::decode(message_contents).map_err(|_e| UtilError::Decoding)
    }

    pub fn serialize_raft_message(message: &RaftMessage) -> Result<Bytes, UtilError> {
        Ok(message.encode_to_vec().into())
    }

    pub fn serialize_config_change(config_change: &RaftConfigChange) -> Result<Bytes, UtilError> {
        Ok(config_change.encode_to_vec().into())
    }

    pub fn deserialize_config_change(
        change_contents: &Vec<u8>,
    ) -> Result<RaftConfigChange, UtilError> {
        RaftConfigChange::decode(change_contents.as_ref()).map_err(|_e| UtilError::Decoding)
    }

    pub fn create_raft_config_change(
        node_id: u64,
        change_type: RaftConfigChangeType,
    ) -> RaftConfigChange {
        RaftConfigChange {
            change_type: change_type.into(),
            node_id,
            ..Default::default()
        }
    }

    pub fn get_metadata(snapshot: &RaftSnapshot) -> &RaftSnapshotMetadata {
        snapshot.metadata.as_ref().unwrap()
    }

    pub fn get_config_state(snapshot: &RaftSnapshot) -> &RaftConfigState {
        get_metadata(&snapshot).conf_state.as_ref().unwrap()
    }

    pub fn create_raft_snapshot(metadata: RaftSnapshotMetadata, data: Bytes) -> RaftSnapshot {
        RaftSnapshot {
            metadata: Some(metadata),
            data: data.into(),
        }
    }

    pub fn create_raft_snapshot_metadata(
        index: u64,
        term: u64,
        config_state: RaftConfigState,
    ) -> RaftSnapshotMetadata {
        RaftSnapshotMetadata {
            index,
            term,
            conf_state: Some(config_state),
        }
    }

    pub fn create_raft_config_state(voters: Vec<u64>) -> RaftConfigState {
        RaftConfigState {
            voters: voters,
            ..Default::default()
        }
    }

    pub fn create_empty_raft_entry(index: u64, term: u64) -> RaftEntry {
        RaftEntry {
            index,
            term,
            ..Default::default()
        }
    }

    pub fn create_raft_entry(
        index: u64,
        term: u64,
        entry_type: RaftEntryType,
        data: Bytes,
    ) -> RaftEntry {
        RaftEntry {
            index,
            term,
            entry_type: entry_type.into(),
            data: data.into(),
            ..Default::default()
        }
    }

    pub fn create_raft_message(
        node_from: u64,
        node_to: u64,
        message_type: RaftMessageType,
    ) -> RaftMessage {
        RaftMessage {
            msg_type: message_type.into(),
            to: node_to,
            from: node_from,
            ..Default::default()
        }
    }

    pub fn create_entry_id(node_id: u64, entry_id: u64) -> EntryId {
        EntryId {
            replica_id: node_id,
            entry_id,
        }
    }

    pub fn create_entry(entry_id: EntryId, entry_contents: Bytes) -> Entry {
        Entry {
            entry_id: Some(entry_id),
            entry_contents,
        }
    }

    pub fn config_state_contains_node(config_state: &RaftConfigState, node_id: u64) -> bool {
        config_state
            .voters
            .iter()
            .chain(&config_state.learners)
            .chain(&config_state.voters_outgoing)
            .any(|id| *id == node_id)
    }
}
