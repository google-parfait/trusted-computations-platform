#![cfg(all(test, feature = "std"))]
extern crate mockall;

use self::mockall::mock;
use consensus;
use consensus::{Raft, RaftLightReady, RaftReady, Store};
use model::{Actor, ActorContext, ActorError};
use platform::{Attestation, Host, MessageEnvelope, PalError};
use raft::{
    eraftpb::ConfChange as RaftConfigChange, eraftpb::ConfState as RaftConfigState,
    eraftpb::Entry as RaftEntry, eraftpb::HardState as RaftHardState,
    eraftpb::Message as RaftMessage, eraftpb::Snapshot as RaftSnapshot, Error as RaftError,
    GetEntriesContext as RaftGetEntriesContext, Storage as RaftStorage,
};
use slog::Logger;

mock! {
    pub Actor {
    }

    impl Actor for Actor {
        fn on_init(&mut self, context: Box<dyn ActorContext>) -> Result<(), ActorError>;

        fn on_shutdown(&mut self);

        fn on_save_snapshot(&mut self) -> Result<Vec<u8>, ActorError>;

        fn on_load_snapshot(&mut self, snapshot: &[u8]) -> Result<(), ActorError>;

        fn on_process_command(&mut self, command: &[u8]) -> Result<(), ActorError>;

        fn on_apply_event(&mut self, index: u64, event: &[u8]) -> Result<(), ActorError>;
    }
}

mock! {
    pub Host {
    }

    impl Host for Host {
        fn get_self_attestation(&self) -> Box<dyn Attestation>;

        fn get_self_config(&self) -> Vec<u8>;

        fn send_messages(&mut self, messages: &[MessageEnvelope]);

        fn verify_peer_attestation(
            &self,
            peer_attestation: &[u8],
        ) -> Result<Box<dyn Attestation>, PalError>;
    }
}

mock! {
    pub Attestation {
    }

    impl Attestation for Attestation {
        fn serialize(&self) -> Result<Vec<u8>, PalError>;

        fn sign(&self, data: &[u8]) -> Result<Vec<u8>, PalError>;

        fn verify(&self, data: &[u8], signature: &[u8]) -> Result<(), PalError>;

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
            snapshot_data: Vec<u8>,
        ) -> Result<(), RaftError>;
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

        fn init(&mut self, node_id: u64, leader: bool, store: S, logger: &Logger) -> Result<(), RaftError>;

        fn make_step(&mut self, message: RaftMessage) -> Result<(), RaftError>;

        fn make_proposal(&mut self, proposal: Vec<u8>) -> Result<(), RaftError>;

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
    }
}
