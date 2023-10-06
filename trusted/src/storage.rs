#![allow(dead_code)]

use crate::{
    consensus::Store,
    util::raft::{
        config_state_contains_node, create_raft_config_state, create_raft_snapshot,
        create_raft_snapshot_metadata, get_config_state, get_metadata,
    },
};
use alloc::vec;
use alloc::vec::Vec;
use core::{cell::RefCell, cmp, result::Result};
use hashbrown::HashMap;
use raft::{
    eraftpb::ConfState as RaftConfigState, eraftpb::Entry as RaftEntry,
    eraftpb::HardState as RaftHardState, eraftpb::Snapshot as RaftSnapshot, util::limit_size,
    Error as RaftError, RaftState, Storage, StorageError as RaftStorageError,
};
use slog::{debug, Logger};

fn statisfies_snapshot_request(
    snapshot_index: u64,
    snapshot_config_state: &RaftConfigState,
    peer_id: u64,
    request_index: u64,
) -> bool {
    snapshot_index >= request_index && config_state_contains_node(snapshot_config_state, peer_id)
}

struct MemoryStorageCore {
    logger: Logger,
    state: RaftHardState,
    entries: Vec<RaftEntry>,
    max_snapshot_diff: u64,
    snapshot: RaftSnapshot,
    snapshot_peer_requests: HashMap<u64, u64>,
}

impl MemoryStorageCore {
    fn new(logger: Logger, max_snapshot_diff: u64) -> MemoryStorageCore {
        MemoryStorageCore {
            logger,
            max_snapshot_diff,
            state: RaftHardState::default(),
            entries: Vec::new(),
            snapshot: create_raft_snapshot(
                create_raft_snapshot_metadata(0, 0, create_raft_config_state(vec![])),
                Vec::new(),
            ),
            snapshot_peer_requests: HashMap::new(),
        }
    }

    fn snapshot_index(&self) -> u64 {
        get_metadata(&self.snapshot).index
    }

    fn snapshot_term(&self) -> u64 {
        get_metadata(&self.snapshot).term
    }

    fn config_state(&self) -> &RaftConfigState {
        get_config_state(&self.snapshot)
    }

    fn first_entry_index(&self) -> u64 {
        match self.entries.first() {
            Some(entry) => entry.index,
            None => self.snapshot_index() + 1,
        }
    }

    fn last_entry_index(&self) -> u64 {
        match self.entries.last() {
            Some(entry) => entry.index,
            None => self.snapshot_index(),
        }
    }

    fn set_hard_state(&mut self, state: RaftHardState) {
        self.state = state;
    }

    fn append_entries(&mut self, entries: &[RaftEntry]) -> Result<(), RaftError> {
        debug!(self.logger, "Append, entries: {:?}", entries);

        if entries.is_empty() {
            return Ok(());
        }

        let first_append_index = entries[0].index;

        // Check that new entries do not overwrite previsouly compacted entries.
        if self.first_entry_index() > first_append_index {
            panic!(
                "Overwriting compacted Raft logs, compacted index: {}, append idnex: {}",
                self.first_entry_index() - 1,
                first_append_index,
            );
        }

        // Check that log will remain continuous.
        if self.last_entry_index() + 1 < first_append_index {
            panic!(
                "Creating gap in Raft log, must be continuous, last index: {}, append index: {}",
                self.last_entry_index(),
                first_append_index,
            );
        }

        // Remove all overwritten entries.
        let overwritten_entries = first_append_index - self.first_entry_index();
        self.entries.drain(overwritten_entries as usize..);
        // Append new entries.
        self.entries.extend_from_slice(entries);

        Ok(())
    }

    fn compact_entries(&mut self, compact_index: u64) -> Result<(), RaftError> {
        debug!(self.logger, "Compact, index {}", compact_index);

        if compact_index <= self.first_entry_index() {
            // The log has already been compated, there is nothing to do.
            return Ok(());
        }

        // Check that entries to compact exist.
        if compact_index > self.last_entry_index() + 1 {
            panic!(
                "Compacting beyond available Raft log entries, compact index: {}, last index: {}",
                compact_index,
                self.last_entry_index()
            );
        }

        if let Some(entry) = self.entries.first() {
            let offset = compact_index - entry.index;
            self.entries.drain(..offset as usize);
        }
        Ok(())
    }

    fn apply_snapshot(&mut self, snapshot: RaftSnapshot) -> Result<(), RaftError> {
        debug!(self.logger, "Applying snapshot, snapshot {:?}", snapshot);

        let snapshot_metadata = get_metadata(&snapshot);

        // Handle check for old snapshot being applied.
        if self.first_entry_index() > snapshot_metadata.index {
            return Err(RaftError::Store(RaftStorageError::SnapshotOutOfDate));
        }

        self.state.commit = snapshot_metadata.index;
        self.state.term = cmp::max(self.state.term, snapshot_metadata.term);

        self.entries.clear();
        self.set_snapshot(snapshot);

        Ok(())
    }

    fn create_snapshot(
        &mut self,
        applied_index: u64,
        config_state: RaftConfigState,
        snapshot_data: Vec<u8>,
    ) -> Result<(), RaftError> {
        debug!(
            self.logger,
            "Creating snapshot, applied index: {}, config state {:?}", applied_index, config_state
        );

        if applied_index > self.last_entry_index() {
            panic!(
                "Raft log index is out of bounds, last index: {}, applied index: {}",
                self.last_entry_index(),
                applied_index
            );
        }

        // Handle check for old snapshot being applied.
        if self.first_entry_index() > applied_index {
            return Err(RaftError::Store(RaftStorageError::SnapshotOutOfDate));
        }

        let snapshot = create_raft_snapshot(
            create_raft_snapshot_metadata(
                applied_index,
                self.entry_term(applied_index)?,
                config_state,
            ),
            snapshot_data,
        );

        self.set_snapshot(snapshot);
        self.compact_entries(applied_index)
    }

    fn try_satisfy_request(&mut self, peer_id: u64, request_index: u64) -> Option<RaftSnapshot> {
        // Return snapshot only if it has all requested entries and configuration
        // contains the node requesting snapshot.
        if statisfies_snapshot_request(
            self.snapshot_index(),
            self.config_state(),
            peer_id,
            request_index,
        ) {
            return Some(self.snapshot.clone());
        }
        // Remember that snapshot has been requested and needs to be produced
        // on the next opportunity.
        self.snapshot_peer_requests.insert(peer_id, request_index);
        None
    }

    fn set_snapshot(&mut self, snapshot: RaftSnapshot) {
        self.snapshot = snapshot;
        let snapshot_index = self.snapshot_index();
        let config_state = self.config_state().clone();
        // Remove pending peer requests that are satisfied by given snapshot.
        self.snapshot_peer_requests
            .extract_if(|peer_id, request_index| {
                statisfies_snapshot_request(snapshot_index, &config_state, *peer_id, *request_index)
            })
            .count();
    }

    fn should_snapshot(&self, applied_index: u64, config_state: &RaftConfigState) -> bool {
        // Check if existing snapshot is too old.
        if self.snapshot_index() + self.max_snapshot_diff < applied_index {
            return true;
        }
        // Check if snapshotting at applied index and config state will satisfy any of the
        // pending peer requests.
        self.snapshot_peer_requests
            .iter()
            .any(|(peer_id, request_index)| {
                statisfies_snapshot_request(applied_index, config_state, *peer_id, *request_index)
            })
    }

    fn initial_state(&self) -> Result<RaftState, RaftError> {
        Ok(RaftState {
            hard_state: self.state.clone(),
            conf_state: self.config_state().clone(),
        })
    }

    fn entries(
        &self,
        low_index: u64,
        high_index: u64,
        entries_max_size: impl Into<Option<u64>>,
        _context: raft::GetEntriesContext,
    ) -> Result<Vec<RaftEntry>, RaftError> {
        debug!(
            self.logger,
            "Getting entries, low: {}, high: {}", low_index, high_index
        );

        let entries_max_size = entries_max_size.into();

        if self.entries.is_empty() {
            return Err(RaftError::Store(RaftStorageError::Unavailable));
        }

        if low_index < self.first_entry_index() {
            return Err(RaftError::Store(RaftStorageError::Compacted));
        }

        if high_index > self.last_entry_index() + 1 {
            panic!(
                "Raft log index is out of bounds, last index: {}, high index: {}",
                self.last_entry_index(),
                high_index
            );
        }

        let offset = self.first_entry_index();
        let lo = (low_index - offset) as usize;
        let hi = (high_index - offset) as usize;
        let mut entries_slice = self.entries[lo..hi].to_vec();
        limit_size(&mut entries_slice, entries_max_size);

        Ok(entries_slice)
    }

    fn entry_term(&self, index: u64) -> Result<u64, RaftError> {
        debug!(self.logger, "Getting term, index: {}", index);

        if index == self.snapshot_index() {
            return Ok(self.snapshot_term());
        }

        let offset = self.first_entry_index();
        if index < offset {
            return Err(RaftError::Store(RaftStorageError::Compacted));
        }

        if index > self.last_entry_index() {
            return Err(RaftError::Store(RaftStorageError::Unavailable));
        }

        Ok(self.entries[(index - offset) as usize].term)
    }

    fn snapshot(&mut self, request_index: u64, peer_id: u64) -> Result<RaftSnapshot, RaftError> {
        debug!(
            self.logger,
            "Getting snapshot, request index: {}, peer id {}", request_index, peer_id
        );

        match self.try_satisfy_request(peer_id, request_index) {
            Some(snapshot) => Ok(snapshot),
            None => Err(RaftError::Store(
                RaftStorageError::SnapshotTemporarilyUnavailable,
            )),
        }
    }
}

pub struct MemoryStorage {
    core: RefCell<MemoryStorageCore>,
}

impl MemoryStorage {
    pub fn new(logger: Logger, max_snapshot_diff: u64) -> MemoryStorage {
        MemoryStorage {
            core: RefCell::new(MemoryStorageCore::new(logger, max_snapshot_diff)),
        }
    }

    /// Discards all log entries prior to compact_index.
    /// It is the application's responsibility to not attempt to compact an index
    /// greater than RaftLog.applied.
    ///
    /// # Panics
    ///
    /// Panics if `compact_index` is higher than `Storage::last_index(&self) + 1`.
    fn compact_entries(&mut self, compact_index: u64) -> Result<(), RaftError> {
        self.core.borrow_mut().compact_entries(compact_index)
    }
}

impl Store for MemoryStorage {
    fn set_hard_state(&mut self, state: RaftHardState) {
        self.core.borrow_mut().set_hard_state(state);
    }

    fn append_entries(&mut self, entries: &[RaftEntry]) -> Result<(), RaftError> {
        self.core.borrow_mut().append_entries(entries)
    }

    fn apply_snapshot(&mut self, snapshot: RaftSnapshot) -> Result<(), RaftError> {
        self.core.borrow_mut().apply_snapshot(snapshot)
    }

    fn create_snapshot(
        &mut self,
        applied_index: u64,
        config_state: RaftConfigState,
        snapshot_data: Vec<u8>,
    ) -> Result<(), RaftError> {
        self.core
            .borrow_mut()
            .create_snapshot(applied_index, config_state, snapshot_data)
    }

    fn should_snapshot(&self, applied_index: u64, config_state: &RaftConfigState) -> bool {
        self.core
            .borrow()
            .should_snapshot(applied_index, config_state)
    }
}

impl Storage for MemoryStorage {
    fn initial_state(&self) -> Result<RaftState, RaftError> {
        self.core.borrow().initial_state()
    }

    fn entries(
        &self,
        low_index: u64,
        high_index: u64,
        entries_max_size: impl Into<Option<u64>>,
        context: raft::GetEntriesContext,
    ) -> Result<Vec<RaftEntry>, RaftError> {
        self.core
            .borrow()
            .entries(low_index, high_index, entries_max_size, context)
    }

    fn term(&self, index: u64) -> Result<u64, RaftError> {
        self.core.borrow().entry_term(index)
    }

    fn first_index(&self) -> Result<u64, RaftError> {
        Ok(self.core.borrow().first_entry_index())
    }

    fn last_index(&self) -> Result<u64, RaftError> {
        Ok(self.core.borrow().last_entry_index())
    }

    fn snapshot(&self, request_index: u64, peer_id: u64) -> Result<RaftSnapshot, RaftError> {
        self.core.borrow_mut().snapshot(request_index, peer_id)
    }
}

#[cfg(test)]
mod test {
    use crate::{
        logger::log::create_logger,
        util::raft::{
            create_empty_raft_entry, create_raft_config_state, create_raft_snapshot,
            create_raft_snapshot_metadata, message_size,
        },
    };

    use super::*;
    use raft::{eraftpb::Entry as RaftEntry, GetEntriesContext};

    fn create_snapshot(snapshot_index: u64, snapshot_term: u64, voters: &[u64]) -> RaftSnapshot {
        create_raft_snapshot(
            create_raft_snapshot_metadata(
                snapshot_index,
                snapshot_term,
                create_raft_config_state(Vec::from(voters)),
            ),
            Vec::new(),
        )
    }

    fn create_storage(
        snapshot_index: u64,
        snapshot_term: u64,
        max_snapshot_diff: u64,
        entries: &Vec<RaftEntry>,
        voters: &[u64],
    ) -> MemoryStorage {
        let mut storage = MemoryStorage::new(create_logger(1), max_snapshot_diff);

        let snapshot = create_snapshot(snapshot_index, snapshot_term, voters);

        storage.apply_snapshot(snapshot).unwrap();
        storage.append_entries(entries.as_ref()).unwrap();

        storage
    }

    #[test]
    fn test_storage_term() {
        let entries = vec![
            create_empty_raft_entry(3, 3),
            create_empty_raft_entry(4, 4),
            create_empty_raft_entry(5, 5),
        ];

        let voters = vec![1];

        let storage = create_storage(2, 2, 1, &entries, &voters);

        let tests = vec![
            (1, Err(RaftError::Store(RaftStorageError::Compacted))),
            (3, Ok(3)),
            (4, Ok(4)),
            (5, Ok(5)),
            (6, Err(RaftError::Store(RaftStorageError::Unavailable))),
        ];

        for (index, term) in tests {
            assert_eq!(term, storage.term(index));
        }
    }

    #[test]
    fn test_storage_entries() {
        let entries = vec![
            create_empty_raft_entry(3, 3),
            create_empty_raft_entry(4, 4),
            create_empty_raft_entry(5, 5),
            create_empty_raft_entry(6, 6),
        ];

        let voters = vec![1];

        let storage = create_storage(2, 2, 1, &entries, &voters);

        let tests = vec![
            (
                2,
                6,
                u64::max_value(),
                Err(RaftError::Store(RaftStorageError::Compacted)),
            ),
            (
                3,
                4,
                u64::max_value(),
                Ok(vec![create_empty_raft_entry(3, 3)]),
            ),
            (
                4,
                5,
                u64::max_value(),
                Ok(vec![create_empty_raft_entry(4, 4)]),
            ),
            (
                4,
                6,
                u64::max_value(),
                Ok(vec![
                    create_empty_raft_entry(4, 4),
                    create_empty_raft_entry(5, 5),
                ]),
            ),
            (
                4,
                7,
                u64::max_value(),
                Ok(vec![
                    create_empty_raft_entry(4, 4),
                    create_empty_raft_entry(5, 5),
                    create_empty_raft_entry(6, 6),
                ]),
            ),
            // even if maxsize is zero, the first entry should be returned
            (4, 7, 0, Ok(vec![create_empty_raft_entry(4, 4)])),
            // limit to 2
            (
                4,
                7,
                u64::from(message_size(&entries[1]) + message_size(&entries[2])),
                Ok(vec![
                    create_empty_raft_entry(4, 4),
                    create_empty_raft_entry(5, 5),
                ]),
            ),
            (
                4,
                7,
                u64::from(
                    message_size(&entries[1])
                        + message_size(&entries[2])
                        + message_size(&entries[3]) / 2,
                ),
                Ok(vec![
                    create_empty_raft_entry(4, 4),
                    create_empty_raft_entry(5, 5),
                ]),
            ),
            (
                4,
                7,
                u64::from(
                    message_size(&entries[1])
                        + message_size(&entries[2])
                        + message_size(&entries[3])
                        - 1,
                ),
                Ok(vec![
                    create_empty_raft_entry(4, 4),
                    create_empty_raft_entry(5, 5),
                ]),
            ),
            // all
            (
                4,
                7,
                u64::from(
                    message_size(&entries[1])
                        + message_size(&entries[2])
                        + message_size(&entries[3]),
                ),
                Ok(vec![
                    create_empty_raft_entry(4, 4),
                    create_empty_raft_entry(5, 5),
                    create_empty_raft_entry(6, 6),
                ]),
            ),
        ];

        for (low, high, max_size, entries) in tests {
            assert_eq!(
                entries,
                storage.entries(low, high, max_size, GetEntriesContext::empty(false))
            );
        }
    }

    #[test]
    fn test_storage_last_index() {
        let entries = vec![
            create_empty_raft_entry(3, 3),
            create_empty_raft_entry(4, 4),
            create_empty_raft_entry(5, 5),
        ];

        let voters = vec![1];

        let mut storage = create_storage(2, 2, 1, &entries, &voters);

        assert_eq!(Ok(5), storage.last_index());

        storage
            .append_entries(&[create_empty_raft_entry(6, 5)])
            .unwrap();

        assert_eq!(Ok(6), storage.last_index());
    }

    #[test]
    fn test_storage_first_index() {
        let entries = vec![
            create_empty_raft_entry(3, 3),
            create_empty_raft_entry(4, 4),
            create_empty_raft_entry(5, 5),
        ];

        let voters = vec![1];

        let mut storage = create_storage(2, 2, 1, &entries, &voters);

        assert_eq!(Ok(3), storage.first_index());

        storage.compact_entries(4).unwrap();

        assert_eq!(Ok(4), storage.first_index());
    }

    #[test]
    fn test_storage_compact_entries() {
        let entries = vec![
            create_empty_raft_entry(3, 3),
            create_empty_raft_entry(4, 4),
            create_empty_raft_entry(5, 5),
        ];

        let voters = vec![1];

        let tests = vec![(2, 3, 3, 3), (3, 3, 3, 3), (4, 4, 4, 2), (5, 5, 5, 1)];

        for (compact_index, first_index, first_term, remaining_entries) in tests {
            let mut storage = create_storage(2, 2, 1, &entries, &voters);

            storage.compact_entries(compact_index).unwrap();

            assert_eq!(Ok(first_index), storage.first_index());

            assert_eq!(Ok(first_term), storage.term(first_index));

            assert_eq!(
                remaining_entries,
                storage
                    .entries(
                        first_index,
                        storage.last_index().unwrap() + 1,
                        100,
                        GetEntriesContext::empty(false)
                    )
                    .unwrap()
                    .len()
            )
        }
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_storage_append_entries() {
        use std::panic::{self, AssertUnwindSafe};

        let entries = vec![
            create_empty_raft_entry(3, 3),
            create_empty_raft_entry(4, 4),
            create_empty_raft_entry(5, 5),
        ];

        let voters = vec![1];

        let tests = vec![
            (
                vec![
                    create_empty_raft_entry(3, 3),
                    create_empty_raft_entry(4, 4),
                    create_empty_raft_entry(5, 5),
                ],
                Some(vec![
                    create_empty_raft_entry(3, 3),
                    create_empty_raft_entry(4, 4),
                    create_empty_raft_entry(5, 5),
                ]),
            ),
            (
                vec![
                    create_empty_raft_entry(3, 3),
                    create_empty_raft_entry(4, 6),
                    create_empty_raft_entry(5, 6),
                ],
                Some(vec![
                    create_empty_raft_entry(3, 3),
                    create_empty_raft_entry(4, 6),
                    create_empty_raft_entry(5, 6),
                ]),
            ),
            (
                vec![
                    create_empty_raft_entry(3, 3),
                    create_empty_raft_entry(4, 4),
                    create_empty_raft_entry(5, 5),
                    create_empty_raft_entry(6, 5),
                ],
                Some(vec![
                    create_empty_raft_entry(3, 3),
                    create_empty_raft_entry(4, 4),
                    create_empty_raft_entry(5, 5),
                    create_empty_raft_entry(6, 5),
                ]),
            ),
            // overwrite compacted raft logs is not allowed
            (
                vec![
                    create_empty_raft_entry(2, 3),
                    create_empty_raft_entry(3, 3),
                    create_empty_raft_entry(4, 5),
                ],
                None,
            ),
            // truncate the existing entries and append
            (
                vec![create_empty_raft_entry(4, 5)],
                Some(vec![
                    create_empty_raft_entry(3, 3),
                    create_empty_raft_entry(4, 5),
                ]),
            ),
            // direct append
            (
                vec![create_empty_raft_entry(6, 6)],
                Some(vec![
                    create_empty_raft_entry(3, 3),
                    create_empty_raft_entry(4, 4),
                    create_empty_raft_entry(5, 5),
                    create_empty_raft_entry(6, 6),
                ]),
            ),
        ];

        for (append_entries, result_entries) in tests {
            let mut storage = create_storage(2, 2, 1, &entries, &voters);

            let result =
                panic::catch_unwind(AssertUnwindSafe(|| storage.append_entries(&append_entries)));

            if let Some(result_entries) = result_entries {
                assert_eq!(
                    result_entries,
                    storage
                        .entries(
                            storage.first_index().unwrap(),
                            storage.last_index().unwrap() + 1,
                            100,
                            GetEntriesContext::empty(false)
                        )
                        .unwrap()
                );
            } else {
                result.unwrap_err();
            }
        }
    }

    #[test]
    fn test_storage_get_snapshot() {
        let entries = vec![
            create_empty_raft_entry(3, 3),
            create_empty_raft_entry(4, 4),
            create_empty_raft_entry(5, 5),
        ];

        let mut voters = vec![1];

        let mut storage = create_storage(2, 2, 1, &entries, &voters);

        let tests = vec![
            (2, 1, Ok(create_snapshot(2, 2, &voters))),
            (
                3,
                1,
                Err(RaftError::Store(
                    RaftStorageError::SnapshotTemporarilyUnavailable,
                )),
            ),
            (
                2,
                2,
                Err(RaftError::Store(
                    RaftStorageError::SnapshotTemporarilyUnavailable,
                )),
            ),
        ];

        for (snapshot_index, peer_id, snapshot_result) in tests {
            assert_eq!(snapshot_result, storage.snapshot(snapshot_index, peer_id));
        }

        voters = vec![1, 2];
        let config_state = create_raft_config_state(voters.clone());

        assert!(storage.should_snapshot(3, &config_state));

        storage
            .create_snapshot(3, config_state, Vec::new())
            .unwrap();

        assert_eq!(Ok(create_snapshot(3, 3, &voters)), storage.snapshot(3, 1));
        assert_eq!(Ok(create_snapshot(3, 3, &voters)), storage.snapshot(2, 2));
    }

    #[test]
    fn test_storage_apply_snapshot() {
        let entries = vec![];

        let voters = vec![1, 2, 3];

        let mut storage = create_storage(1, 1, 1, &entries, &voters);

        let snapshot = create_snapshot(4, 4, &voters);

        assert_eq!(Ok(()), storage.apply_snapshot(snapshot.clone()));

        assert_eq!(Ok(snapshot), storage.snapshot(4, 1));

        let snapshot = create_snapshot(3, 3, &voters);

        assert_eq!(
            Err(RaftError::Store(RaftStorageError::SnapshotOutOfDate)),
            storage.apply_snapshot(snapshot)
        );
    }
}
