#![allow(dead_code)]

extern crate alloc;
extern crate core;
extern crate hashbrown;
extern crate prost;
extern crate slog;
extern crate trusted;

pub mod counter {
    #![allow(non_snake_case)]
    include!(concat!(env!("OUT_DIR"), "/counter.rs"));
}

use crate::counter::{
    counter_request, counter_response, CounterCompareAndSwapRequest, CounterCompareAndSwapResponse,
    CounterConfig, CounterRequest, CounterResponse, CounterSnapshot, CounterStatus,
};
use alloc::collections::BTreeMap;
use alloc::string::String;
use core::cell::RefCell;
use hashbrown::HashMap;
use prost::Message;
use slog::{debug, warn};
use trusted::{
    consensus::RaftSimple,
    driver::{Driver, DriverConfig},
    endpoint::*,
    model::{Actor, ActorContext, ActorError},
    platform::{Application, Attestation, Host, MessageEnvelope, PalError},
    storage::MemoryStorage,
};

struct CounterActor {
    context: Option<Box<dyn ActorContext>>,
    values: HashMap<String, i64>,
}

impl CounterActor {
    pub fn new() -> Self {
        CounterActor {
            context: None,
            values: HashMap::new(),
        }
    }

    fn get_context(&mut self) -> &mut dyn ActorContext {
        self.context
            .as_mut()
            .expect("Context is initialized")
            .as_mut()
    }

    fn send_message<M: Message>(&mut self, message: &M) {
        self.get_context().send_message(message.encode_to_vec())
    }

    fn apply_compare_and_swap(
        &mut self,
        id: u64,
        counter_name: &String,
        compare_and_swap_request: &CounterCompareAndSwapRequest,
    ) -> CounterResponse {
        debug!(
            self.get_context().logger(),
            "Applying #{} compare and swap command {:?}", id, compare_and_swap_request
        );

        let mut response = CounterResponse {
            id,
            status: CounterStatus::Unspecified.into(),
            op: None,
        };
        let mut compare_and_swap_response = CounterCompareAndSwapResponse {
            ..Default::default()
        };

        let existing_value_ref = self.values.entry_ref(counter_name);
        let existing_value = existing_value_ref.or_insert(0);
        compare_and_swap_response.old_value = *existing_value;
        if *existing_value == compare_and_swap_request.expected_value {
            *existing_value = compare_and_swap_request.new_value;

            response.status = CounterStatus::Success.into();
            compare_and_swap_response.new_value = compare_and_swap_request.new_value;
        } else {
            response.status = CounterStatus::InvalidArgumentError.into();
        }
        response.op = Some(counter_response::Op::CompareAndSwap(
            compare_and_swap_response,
        ));

        response
    }
}

impl Actor for CounterActor {
    fn on_init(&mut self, context: Box<dyn ActorContext>) -> Result<(), ActorError> {
        self.context = Some(context);
        self.values = HashMap::new();

        let config = CounterConfig::decode(self.get_context().config().as_ref())
            .map_err(|_| ActorError::ConfigLoading)?;

        for (counter_name, counter_value) in config.initial_values {
            self.values.insert(counter_name, counter_value);
        }

        Ok(())
    }

    fn on_shutdown(&mut self) {}

    fn on_save_snapshot(&mut self) -> Result<Vec<u8>, ActorError> {
        let mut snapshot = CounterSnapshot {
            values: BTreeMap::new(),
        };

        for (counter_name, counter_value) in &self.values {
            snapshot
                .values
                .insert(counter_name.to_string(), *counter_value);
        }

        Ok(snapshot.encode_to_vec())
    }

    fn on_load_snapshot(&mut self, snapshot: &[u8]) -> Result<(), ActorError> {
        let snapshot =
            CounterSnapshot::decode(snapshot).map_err(|_| ActorError::SnapshotLoading)?;

        for (counter_name, counter_value) in snapshot.values {
            self.values.insert(counter_name, counter_value);
        }

        Ok(())
    }

    fn on_process_command(&mut self, command: &[u8]) -> Result<(), ActorError> {
        match CounterRequest::decode(command) {
            Ok(request) => {
                debug!(
                    self.get_context().logger(),
                    "Processing #{} command", request.id
                );

                let mut response = CounterResponse {
                    id: request.id,
                    ..Default::default()
                };
                let mut status = CounterStatus::Success;
                if request.op.is_none() {
                    status = CounterStatus::InvalidArgumentError;

                    warn!(
                        self.get_context().logger(),
                        "Rejecting #{} command: unknown op", request.id
                    );
                }
                if !self.get_context().leader() {
                    status = CounterStatus::NotLeaderError;

                    warn!(
                        self.get_context().logger(),
                        "Rejecting #{} command: not a leader", request.id
                    );
                }

                if let CounterStatus::Success = status {
                    self.get_context().propose_event(command.to_vec())?;
                } else {
                    response.status = status.into();
                    self.send_message(&response);
                }
            }
            Err(e) => {
                warn!(self.get_context().logger(), "Rejecting command: {}", e);
            }
        }

        Ok(())
    }

    fn on_apply_event(&mut self, _index: u64, event: &[u8]) -> Result<(), ActorError> {
        let request = CounterRequest::decode(event).map_err(|_| ActorError::Internal)?;

        let op = request.op.unwrap();

        let response = match op {
            counter_request::Op::CompareAndSwap(ref compare_and_swap_request) => {
                self.apply_compare_and_swap(request.id, &request.name, compare_and_swap_request)
            }
        };

        if self.get_context().leader() {
            self.send_message(&response);
        }

        Ok(())
    }
}

struct FakeCluster {
    advance_step: u64,
    platforms: HashMap<u64, FakePlatform>,
    leader_id: u64,
    pull_messages: Vec<EnvelopeOut>,
}

impl FakeCluster {
    fn new() -> FakeCluster {
        FakeCluster {
            advance_step: 100,
            platforms: HashMap::new(),
            leader_id: 0,
            pull_messages: Vec::new(),
        }
    }

    fn leader_id(&self) -> u64 {
        self.leader_id
    }

    fn non_leader_id(&self) -> u64 {
        *self
            .platforms
            .keys()
            .find(|id| **id != self.leader_id)
            .unwrap()
    }

    fn start_node(&mut self, node_id: u64, leader: bool) {
        self.platforms.insert(node_id, FakePlatform::new(node_id));

        self.platforms
            .get_mut(&node_id)
            .unwrap()
            .send_start_node(leader);
    }

    fn stop_node(&mut self, node_id: u64) {
        self.platforms.remove(&node_id);

        if self.leader_id == node_id {
            self.leader_id = 0;
        }
    }

    fn add_node_to_cluster(&mut self, node_id: u64) {
        self.platforms
            .get_mut(&self.leader_id)
            .unwrap()
            .send_change_cluster(0, node_id, ChangeClusterType::ChangeTypeAddNode);

        self.advance_until_added_to_cluster(node_id);
    }

    fn advance_until_added_to_cluster(&mut self, node_id: u64) {
        self.advance_until(&mut |envelope_out| match &envelope_out.msg {
            Some(envelope_out::Msg::CheckCluster(response)) => {
                !response.has_pending_changes && response.cluster_node_ids.contains(&node_id)
            }
            _ => false,
        });
    }

    fn advance_until_elected_leader(&mut self, excluding_node_id: Option<u64>) {
        let mut leader_id = 0;

        self.advance_until(&mut |envelope_out| match &envelope_out.msg {
            Some(envelope_out::Msg::CheckCluster(response)) => {
                if response.leader_node_id == 0 {
                    return false;
                }
                match excluding_node_id {
                    Some(exclucding_leader_id)
                        if exclucding_leader_id == response.leader_node_id =>
                    {
                        false
                    }
                    _ => {
                        leader_id = response.leader_node_id;
                        true
                    }
                }
            }
            _ => false,
        });

        self.leader_id = leader_id;
    }

    fn advance_until(
        &mut self,
        condition: &mut impl FnMut(&EnvelopeOut) -> bool,
    ) -> Vec<EnvelopeOut> {
        loop {
            self.advance();

            let pull_messages = self.extract_pull_messages(condition);

            if !pull_messages.is_empty() {
                return pull_messages;
            }
        }
    }

    fn advance(&mut self) {
        let mut messages_in: Vec<DeliverMessage> = Vec::new();
        for (_, platform) in &mut self.platforms {
            let messages_out = platform.take_messages_out();
            for message_out in messages_out {
                if let Some(envelope_out::Msg::DeliverMessage(deliver_message)) = message_out.msg {
                    messages_in.push(deliver_message);
                } else {
                    self.pull_messages.push(message_out);
                }
            }
        }

        for message_in in messages_in {
            if let Some(platform) = self.platforms.get_mut(&message_in.recipient_node_id) {
                platform.append_meessage_in(EnvelopeIn {
                    msg: Some(envelope_in::Msg::DeliverMessage(message_in)),
                });
            }
        }

        for (_, platform) in &mut self.platforms {
            platform.advance_time(self.advance_step);
            platform.send_messages_in();
        }

        self.print_log_messages();
    }

    fn extract_pull_messages(
        &mut self,
        filter: &mut impl FnMut(&EnvelopeOut) -> bool,
    ) -> Vec<EnvelopeOut> {
        let mut result: Vec<EnvelopeOut> = Vec::new();

        let mut i = 0;
        while i < self.pull_messages.len() {
            if filter(&self.pull_messages[i]) {
                result.push(self.pull_messages.remove(i));
            } else {
                i += 1;
            }
        }

        result
    }

    fn print_log_messages(&mut self) {
        let _ = self.extract_pull_messages(&mut |envelope_out| match &envelope_out.msg {
            Some(envelope_out::Msg::Log(log_message)) => {
                println!("{}", log_message.message);
                true
            }
            _ => false,
        });
    }

    fn stop(&mut self) {}

    fn send_cas_counter_request(
        &mut self,
        node_id: u64,
        request_id: u64,
        counter_name: &str,
        expected_value: i64,
        new_value: i64,
    ) {
        self.send_counter_request(
            node_id,
            CounterRequest {
                id: request_id,
                name: counter_name.to_string(),
                op: Some(counter_request::Op::CompareAndSwap(
                    CounterCompareAndSwapRequest {
                        expected_value,
                        new_value,
                    },
                )),
            },
        )
    }

    fn send_counter_request(&mut self, node_id: u64, counter_request: CounterRequest) {
        self.platforms
            .get_mut(&node_id)
            .unwrap()
            .send_counter_request(&counter_request);
    }

    fn advance_until_counter_response(&mut self, response_id: u64) -> CounterResponse {
        let mut counter_response_opt: Option<CounterResponse> = None;
        let response_messages = self.advance_until(&mut |envelope_out| match &envelope_out.msg {
            Some(envelope_out::Msg::ExecuteProposal(response)) => {
                let counter_response =
                    CounterResponse::decode(response.result_contents.as_ref()).unwrap();
                if counter_response.id == response_id {
                    counter_response_opt = Some(counter_response);
                    return true;
                }
                false
            }
            _ => false,
        });

        assert!(!response_messages.is_empty());

        counter_response_opt.unwrap()
    }

    fn advance_until_cas_counter_response(
        &mut self,
        counter_request_id: u64,
        counter_response_status: CounterStatus,
        old_value: i64,
        new_value: i64,
    ) -> bool {
        let counter_response = self.advance_until_counter_response(counter_request_id);

        let counter_op = if counter_response_status == CounterStatus::Success {
            Some(counter_response::Op::CompareAndSwap(
                CounterCompareAndSwapResponse {
                    old_value,
                    new_value,
                },
            ))
        } else {
            None
        };

        counter_response
            == CounterResponse {
                id: counter_request_id,
                status: counter_response_status.into(),
                op: counter_op,
            }
    }
}

struct FakePlatform {
    id: u64,
    messages_in: Vec<EnvelopeIn>,
    instant: u64,
    driver: RefCell<Driver<RaftSimple<MemoryStorage>, MemoryStorage, CounterActor>>,
    host: RefCell<FakeHost>,
}

impl FakePlatform {
    fn new(id: u64) -> FakePlatform {
        FakePlatform {
            id,
            messages_in: Vec::new(),
            instant: 0,
            driver: RefCell::new(Driver::new(
                DriverConfig {
                    tick_period: 10,
                    snapshot_count: 1000,
                },
                RaftSimple::new(),
                Box::new(MemoryStorage::new),
                CounterActor::new(),
            )),
            host: RefCell::new(FakeHost::new()),
        }
    }

    fn send_start_node(&mut self, is_leader: bool) {
        self.append_meessage_in(EnvelopeIn {
            msg: Some(envelope_in::Msg::StartNode(StartNodeRequest {
                is_leader,
                node_id_hint: self.id,
            })),
        });
    }

    fn send_stop_node(&mut self) {
        self.append_meessage_in(EnvelopeIn {
            msg: Some(envelope_in::Msg::StopNode(StopNodeRequest {})),
        });
    }

    fn send_change_cluster(
        &mut self,
        change_id: u64,
        node_id: u64,
        change_type: ChangeClusterType,
    ) {
        self.append_meessage_in(EnvelopeIn {
            msg: Some(envelope_in::Msg::ChangeCluster(ChangeClusterRequest {
                change_id,
                node_id,
                change_type: change_type.into(),
            })),
        });
    }

    fn send_check_cluster(&mut self) {
        self.append_meessage_in(EnvelopeIn {
            msg: Some(envelope_in::Msg::CheckCluster(CheckClusterRequest {})),
        });
    }

    fn advance_time(&mut self, duration: u64) {
        self.instant += duration;
    }

    fn append_meessage_in(&mut self, message_in: EnvelopeIn) {
        self.messages_in.push(message_in)
    }

    fn send_messages_in(&mut self) {
        let mut messages: Vec<MessageEnvelope> = Vec::with_capacity(self.messages_in.len());
        for message_in in &self.messages_in {
            messages.push(message_in.encode_to_vec());
        }
        self.messages_in.clear();

        let mut driver = self.driver.borrow_mut();
        let mut host = self.host.borrow_mut();

        if messages.is_empty() {
            driver
                .receive_message(&mut *host, self.instant, None)
                .unwrap();
        } else {
            for message in messages {
                driver
                    .receive_message(&mut *host, self.instant, Some(message))
                    .unwrap()
            }
        }
    }

    fn take_messages_out(&mut self) -> Vec<EnvelopeOut> {
        self.host.borrow_mut().take_messages_out()
    }

    fn send_counter_request(&mut self, counter_request: &CounterRequest) {
        self.append_meessage_in(EnvelopeIn {
            msg: Some(envelope_in::Msg::ExecuteProposal(ExecuteProposalRequest {
                proposal_contents: counter_request.encode_to_vec(),
            })),
        });
    }
}

struct FakeHost {
    config: Vec<u8>,
    messages_out: Vec<EnvelopeOut>,
}

impl FakeHost {
    fn new() -> FakeHost {
        FakeHost {
            config: CounterConfig {
                initial_values: BTreeMap::new(),
            }
            .encode_to_vec(),
            messages_out: Vec::new(),
        }
    }

    fn take_messages_out(&mut self) -> Vec<EnvelopeOut> {
        core::mem::take(&mut self.messages_out)
    }
}

impl Host for FakeHost {
    fn get_self_attestation(&self) -> Box<dyn Attestation> {
        Box::new(FakeAttestation {})
    }

    fn get_self_config(&self) -> Vec<u8> {
        self.config.clone()
    }

    fn send_messages(&mut self, messages: &[MessageEnvelope]) {
        for message_envelope in messages {
            self.messages_out
                .push(EnvelopeOut::decode(message_envelope.as_ref()).unwrap());
        }
    }

    fn verify_peer_attestation(
        &self,
        _peer_attestation: &[u8],
    ) -> Result<Box<dyn Attestation>, PalError> {
        todo!()
    }
}

struct FakeAttestation {}

impl Attestation for FakeAttestation {
    fn serialize(&self) -> Result<Vec<u8>, PalError> {
        todo!()
    }

    fn sign(&self, _data: &[u8]) -> Result<Vec<u8>, PalError> {
        todo!()
    }

    fn verify(&self, _data: &[u8], _signature: &[u8]) -> Result<(), PalError> {
        todo!()
    }

    fn public_signing_key(&self) -> Vec<u8> {
        Vec::new()
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn integration() {
        let mut cluster = FakeCluster::new();

        cluster.start_node(1, true);
        cluster.advance_until_elected_leader(None);
        assert!(cluster.leader_id() == 1);

        cluster.start_node(2, false);
        cluster.start_node(3, false);

        cluster.add_node_to_cluster(2);

        cluster.send_cas_counter_request(cluster.leader_id(), 1, "counter 1", 0, 1);
        cluster.send_cas_counter_request(cluster.leader_id(), 2, "counter 2", 0, 1);

        assert!(cluster.advance_until_cas_counter_response(1, CounterStatus::Success, 0, 1));
        assert!(cluster.advance_until_cas_counter_response(2, CounterStatus::Success, 0, 1));

        cluster.add_node_to_cluster(3);

        cluster.send_cas_counter_request(cluster.non_leader_id(), 3, "counter 1", 1, 2);
        assert!(cluster.advance_until_cas_counter_response(3, CounterStatus::NotLeaderError, 0, 0));

        let leader_id = cluster.leader_id();
        cluster.stop_node(leader_id);
        cluster.advance_until_elected_leader(Some(leader_id));

        cluster.send_cas_counter_request(cluster.leader_id(), 4, "counter 2", 1, 2);
        assert!(cluster.advance_until_cas_counter_response(4, CounterStatus::Success, 1, 2));
    }
}
