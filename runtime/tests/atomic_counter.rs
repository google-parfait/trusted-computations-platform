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

#![allow(dead_code)]

extern crate alloc;
extern crate core;
extern crate hashbrown;
extern crate prost;
extern crate slog;
extern crate tcp_proto;
extern crate tcp_runtime;

use alloc::collections::BTreeMap;
use core::cell::RefCell;
use core::mem;
use hashbrown::HashMap;
use prost::{bytes::Bytes, Message};
use slog::{info, Logger};
use tcp_proto::examples::atomic_counter::{
    counter_request, counter_response, CounterCompareAndSwapRequest, CounterCompareAndSwapResponse,
    CounterConfig, CounterRequest, CounterResponse, CounterStatus,
};
use tcp_proto::runtime::endpoint::raft_config::SnapshotConfig;
use tcp_proto::runtime::endpoint::*;
use tcp_runtime::driver::Driver;
use tcp_runtime::examples::CounterActor;
use tcp_runtime::logger::log::create_logger;
use tcp_runtime::platform::{Application, Attestation, Host, PalError};
use tcp_runtime::snapshot::{
    DefaultSnapshotProcessor, DefaultSnapshotReceiver, DefaultSnapshotSender,
};
use tcp_runtime::{consensus::RaftSimple, storage::MemoryStorage};

struct FakeCluster {
    app_config: Bytes,
    advance_step: u64,
    platforms: HashMap<u64, FakePlatform>,
    leader_id: u64,
    pull_messages: Vec<OutMessage>,
    logger: Logger,
}

impl FakeCluster {
    fn new(app_config: Bytes) -> FakeCluster {
        FakeCluster {
            app_config,
            advance_step: 100,
            platforms: HashMap::new(),
            leader_id: 0,
            pull_messages: Vec::new(),
            logger: create_logger(),
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
            .send_start_node(self.app_config.clone(), leader);
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
            .send_change_cluster(0, node_id, ChangeClusterType::ChangeTypeAddReplica);

        self.advance_until_added_to_cluster(node_id);
    }

    fn advance_until_added_to_cluster(&mut self, node_id: u64) {
        self.advance_until(&mut |envelope_out| match &envelope_out.msg {
            Some(out_message::Msg::CheckCluster(response)) => {
                !response.has_pending_changes && response.cluster_replica_ids.contains(&node_id)
            }
            _ => false,
        });
    }

    fn advance_until_elected_leader(&mut self, excluding_node_id: Option<u64>) {
        let mut leader_id = 0;

        self.advance_until(&mut |envelope_out| match &envelope_out.msg {
            Some(out_message::Msg::CheckCluster(response)) => {
                if response.leader_replica_id == 0 {
                    return false;
                }
                match excluding_node_id {
                    Some(exclucding_leader_id)
                        if exclucding_leader_id == response.leader_replica_id =>
                    {
                        false
                    }
                    _ => {
                        leader_id = response.leader_replica_id;
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
        condition: &mut impl FnMut(&OutMessage) -> bool,
    ) -> Vec<OutMessage> {
        loop {
            self.advance();

            let pull_messages = self.extract_pull_messages(condition);

            if !pull_messages.is_empty() {
                return pull_messages;
            }
        }
    }

    fn advance(&mut self) {
        let mut messages_in: Vec<(u64, in_message::Msg)> = Vec::new();
        for (_, platform) in &mut self.platforms {
            let messages_out = platform.take_messages_out();
            for message_out in messages_out {
                match message_out.msg {
                    Some(out_message::Msg::DeliverMessage(deliver_message)) => {
                        messages_in.push((
                            deliver_message.recipient_replica_id,
                            in_message::Msg::DeliverMessage(deliver_message),
                        ));
                    }
                    Some(out_message::Msg::DeliverSnapshotRequest(deliver_snapshot_request)) => {
                        messages_in.push((
                            deliver_snapshot_request.recipient_replica_id,
                            in_message::Msg::DeliverSnapshotRequest(deliver_snapshot_request),
                        ));
                    }
                    Some(out_message::Msg::DeliverSnapshotResponse(deliver_snapshot_response)) => {
                        messages_in.push((
                            deliver_snapshot_response.recipient_replica_id,
                            in_message::Msg::DeliverSnapshotResponse(deliver_snapshot_response),
                        ));
                    }
                    _ => {
                        self.pull_messages.push(message_out);
                    }
                }
            }
        }

        for (recipient_replica_id, message_in) in messages_in {
            if let Some(platform) = self.platforms.get_mut(&recipient_replica_id) {
                platform.append_meessage_in(InMessage {
                    msg: Some(message_in),
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
        filter: &mut impl FnMut(&OutMessage) -> bool,
    ) -> Vec<OutMessage> {
        let mut result: Vec<OutMessage> = Vec::new();

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
        let messages = self.extract_pull_messages(&mut |envelope_out| match &envelope_out.msg {
            Some(out_message::Msg::Log(_)) => true,
            _ => false,
        });
        for message in &messages {
            if let OutMessage {
                msg: Some(out_message::Msg::Log(log_message)),
            } = message
            {
                info!(self.logger, "{}", log_message.message);
            }
        }
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
                ..Default::default()
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
            Some(out_message::Msg::ExecuteProposal(response)) => {
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
    messages_in: Vec<InMessage>,
    instant: u64,
    driver: RefCell<
        Driver<RaftSimple<MemoryStorage>, MemoryStorage, DefaultSnapshotProcessor, CounterActor>,
    >,
    host: RefCell<FakeHost>,
}

impl FakePlatform {
    fn new(id: u64) -> FakePlatform {
        FakePlatform {
            id,
            messages_in: Vec::new(),
            instant: 0,
            driver: RefCell::new(Driver::new(
                RaftSimple::new(),
                Box::new(MemoryStorage::new),
                DefaultSnapshotProcessor::new(
                    Box::new(DefaultSnapshotSender::new()),
                    Box::new(DefaultSnapshotReceiver::new()),
                ),
                CounterActor::new(),
            )),
            host: RefCell::new(FakeHost::new()),
        }
    }

    fn send_start_node(&mut self, app_config: Bytes, is_leader: bool) {
        self.append_meessage_in(InMessage {
            msg: Some(in_message::Msg::StartReplica(StartReplicaRequest {
                is_leader,
                replica_id_hint: self.id,
                raft_config: Some(RaftConfig {
                    tick_period: 10,
                    election_tick: 20,
                    heartbeat_tick: 2,
                    max_size_per_msg: 0,
                    snapshot_config: Some(SnapshotConfig {
                        snapshot_count: 1000,
                        chunk_size: 20,
                        max_pending_chunks: 2,
                    }),
                }),
                app_config: app_config,
            })),
        });
    }

    fn send_stop_node(&mut self) {
        self.append_meessage_in(InMessage {
            msg: Some(in_message::Msg::StopReplica(StopReplicaRequest {})),
        });
    }

    fn send_change_cluster(
        &mut self,
        change_id: u64,
        replica_id: u64,
        change_type: ChangeClusterType,
    ) {
        self.append_meessage_in(InMessage {
            msg: Some(in_message::Msg::ChangeCluster(ChangeClusterRequest {
                change_id,
                replica_id,
                change_type: change_type.into(),
            })),
        });
    }

    fn send_check_cluster(&mut self) {
        self.append_meessage_in(InMessage {
            msg: Some(in_message::Msg::CheckCluster(CheckClusterRequest {})),
        });
    }

    fn advance_time(&mut self, duration: u64) {
        self.instant += duration;
    }

    fn append_meessage_in(&mut self, message_in: InMessage) {
        self.messages_in.push(message_in)
    }

    fn send_messages_in(&mut self) {
        let messages = mem::take(&mut self.messages_in);

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

    fn take_messages_out(&mut self) -> Vec<OutMessage> {
        self.host.borrow_mut().take_messages_out()
    }

    fn send_counter_request(&mut self, counter_request: &CounterRequest) {
        self.append_meessage_in(InMessage {
            msg: Some(in_message::Msg::ExecuteProposal(ExecuteProposalRequest {
                proposal_contents: counter_request.encode_to_vec().into(),
            })),
        });
    }
}

struct FakeHost {
    config: Vec<u8>,
    messages_out: Vec<OutMessage>,
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

    fn take_messages_out(&mut self) -> Vec<OutMessage> {
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

    fn send_messages(&mut self, mut messages: Vec<OutMessage>) {
        self.messages_out.append(&mut messages);
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
        let counter_name_1 = "counter 1";
        let counter_value_1: i64 = 10;
        let counter_name_2 = "counter 2";
        let counter_value_2: i64 = 15;
        let config = CounterConfig {
            initial_values: BTreeMap::from([
                (counter_name_1.to_string(), counter_value_1),
                (counter_name_2.to_string(), counter_value_2),
            ]),
        };

        let mut cluster = FakeCluster::new(config.encode_to_vec().into());

        cluster.start_node(1, true);
        cluster.advance_until_elected_leader(None);
        assert!(cluster.leader_id() == 1);

        cluster.start_node(2, false);
        cluster.start_node(3, false);

        cluster.add_node_to_cluster(2);

        cluster.send_cas_counter_request(
            cluster.leader_id(),
            1,
            counter_name_1,
            counter_value_1,
            counter_value_1 + 1,
        );
        cluster.send_cas_counter_request(
            cluster.leader_id(),
            2,
            counter_name_2,
            counter_value_2,
            counter_value_2 + 1,
        );

        assert!(cluster.advance_until_cas_counter_response(
            1,
            CounterStatus::Success,
            counter_value_1,
            counter_value_1 + 1
        ));
        assert!(cluster.advance_until_cas_counter_response(
            2,
            CounterStatus::Success,
            counter_value_2,
            counter_value_2 + 1
        ));

        cluster.add_node_to_cluster(3);

        cluster.send_cas_counter_request(
            cluster.non_leader_id(),
            3,
            counter_name_1,
            counter_value_1 + 1,
            counter_value_1 + 2,
        );
        assert!(cluster.advance_until_cas_counter_response(3, CounterStatus::Rejected, 0, 0));

        let leader_id = cluster.leader_id();
        cluster.stop_node(leader_id);
        cluster.advance_until_elected_leader(Some(leader_id));

        cluster.send_cas_counter_request(
            cluster.leader_id(),
            4,
            counter_name_2,
            counter_value_2 + 1,
            counter_value_2 + 2,
        );
        assert!(cluster.advance_until_cas_counter_response(
            4,
            CounterStatus::Success,
            counter_value_2 + 1,
            counter_value_2 + 2
        ));
    }
}
