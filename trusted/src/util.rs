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

#[cfg(feature = "protobuf-codec")]
pub mod raft {
    extern crate protobuf;

    use super::*;
    use prost::bytes::Bytes;
    use util::raft::protobuf::Message;

    pub fn message_size<M: Message>(message: &M) -> u32 {
        message.compute_size()
    }

    pub fn deserialize_raft_message(message_contents: &Vec<u8>) -> Result<RaftMessage, UtilError> {
        let mut message = RaftMessage::new();
        message
            .merge_from_bytes(message_contents.as_ref())
            .map_err(|_e| UtilError::Decoding)?;
        Ok(message)
    }

    pub fn serialize_raft_message(message: &RaftMessage) -> Result<Vec<u8>, UtilError> {
        message.write_to_bytes().map_err(|_e| UtilError::Encoding)
    }

    pub fn serialize_config_change(config_change: &RaftConfigChange) -> Result<Vec<u8>, UtilError> {
        config_change
            .write_to_bytes()
            .map_err(|_e| UtilError::Encoding)
    }

    pub fn deserialize_config_change(
        change_contents: &Bytes,
    ) -> Result<RaftConfigChange, UtilError> {
        let mut config_change = RaftConfigChange::default();
        config_change
            .merge_from_bytes(change_contents.as_ref())
            .map_err(|_e| UtilError::Decoding)?;
        Ok(config_change)
    }

    pub fn create_raft_config_change(
        node_id: u64,
        change_type: RaftConfigChangeType,
    ) -> RaftConfigChange {
        RaftConfigChange {
            change_type,
            node_id,
            ..Default::default()
        }
    }

    pub fn get_metadata(snapshot: &RaftSnapshot) -> &RaftSnapshotMetadata {
        snapshot.get_metadata()
    }

    pub fn get_config_state(snapshot: &RaftSnapshot) -> &RaftConfigState {
        snapshot.get_metadata().get_conf_state()
    }

    pub fn create_raft_snapshot(metadata: RaftSnapshotMetadata, data: Vec<u8>) -> RaftSnapshot {
        let mut snapshot = RaftSnapshot::default();
        *snapshot.mut_metadata() = metadata;
        *snapshot.mut_data() = data.into();
        snapshot
    }

    pub fn create_raft_snapshot_metadata(
        index: u64,
        term: u64,
        config_state: RaftConfigState,
    ) -> RaftSnapshotMetadata {
        let mut metadata = RaftSnapshotMetadata {
            index,
            term,
            ..Default::default()
        };
        *metadata.mut_conf_state() = config_state;
        metadata
    }

    pub fn create_raft_config_state(voters: Vec<u64>) -> RaftConfigState {
        RaftConfigState {
            voters,
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
        data: Vec<u8>,
    ) -> RaftEntry {
        RaftEntry {
            index,
            term,
            entry_type,
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
            msg_type: message_type,
            to: node_to,
            from: node_from,
            ..Default::default()
        }
    }

    pub fn config_state_contains_node(config_state: &RaftConfigState, node_id: u64) -> bool {
        config_state
            .get_voters()
            .iter()
            .chain(config_state.get_learners())
            .chain(config_state.get_voters_outgoing())
            .any(|id| *id == node_id)
    }
}

#[cfg(feature = "prost-codec")]
pub mod raft {
    use super::*;
    use prost::Message;

    pub fn message_size<M: Message>(message: &M) -> u32 {
        message.encoded_len() as u32
    }

    pub fn deserialize_raft_message(message_contents: &Vec<u8>) -> Result<RaftMessage, UtilError> {
        RaftMessage::decode(message_contents.as_ref()).map_err(|_e| UtilError::Decoding)
    }

    pub fn serialize_raft_message(message: &RaftMessage) -> Result<Vec<u8>, UtilError> {
        Ok(message.encode_to_vec())
    }

    pub fn serialize_config_change(config_change: &RaftConfigChange) -> Result<Vec<u8>, UtilError> {
        Ok(config_change.encode_to_vec())
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

    pub fn create_raft_snapshot(metadata: RaftSnapshotMetadata, data: Vec<u8>) -> RaftSnapshot {
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
        data: Vec<u8>,
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

    pub fn config_state_contains_node(config_state: &RaftConfigState, node_id: u64) -> bool {
        config_state
            .voters
            .iter()
            .chain(&config_state.learners)
            .chain(&config_state.voters_outgoing)
            .any(|id| *id == node_id)
    }
}
