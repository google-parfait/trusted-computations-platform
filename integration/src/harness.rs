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

#![allow(dead_code)]

use core::cell::RefCell;
use core::mem;
use hashbrown::HashMap;
use prost::bytes::Bytes;
use slog::{info, Logger};
use tcp_proto::runtime::endpoint::raft_config::SnapshotConfig;
use tcp_proto::runtime::endpoint::*;
use tcp_runtime::attestation::DefaultAttestationProvider;
use tcp_runtime::communication::DefaultCommunicationModule;
use tcp_runtime::driver::Driver;
use tcp_runtime::handshake::DefaultHandshakeSessionProvider;
use tcp_runtime::logger::log::create_logger;
use tcp_runtime::model::Actor;
use tcp_runtime::oak_handshaker::DefaultOakHandshakerFactory;
use tcp_runtime::platform::{Application, Host};
use tcp_runtime::snapshot::{
    DefaultSnapshotProcessor, DefaultSnapshotReceiver, DefaultSnapshotSender,
};
use tcp_runtime::{consensus::RaftSimple, storage::MemoryStorage};

pub struct FakeCluster<A: Actor> {
    app_config: Bytes,
    advance_step: u64,
    platforms: HashMap<u64, FakePlatform<A>>,
    leader_id: u64,
    pull_messages: Vec<OutMessage>,
    logger: Logger,
}

impl<A: Actor> FakeCluster<A> {
    pub fn new(app_config: Bytes) -> FakeCluster<A> {
        FakeCluster {
            app_config,
            advance_step: 100,
            platforms: HashMap::new(),
            leader_id: 0,
            pull_messages: Vec::new(),
            logger: create_logger(),
        }
    }

    pub fn leader_id(&self) -> u64 {
        self.leader_id
    }

    pub fn non_leader_id(&self) -> u64 {
        *self
            .platforms
            .keys()
            .find(|id| **id != self.leader_id)
            .unwrap()
    }

    pub fn send_app_message(
        &mut self,
        node_id: u64,
        correlation_id: u64,
        header: Bytes,
        payload: Bytes,
    ) {
        self.platforms
            .get_mut(&node_id)
            .unwrap()
            .send_app_message(correlation_id, header, payload);
    }

    pub fn start_node(&mut self, node_id: u64, leader: bool, actor: A) {
        self.platforms.insert(
            node_id,
            FakePlatform::new(node_id, self.app_config.clone(), actor),
        );

        self.platforms
            .get_mut(&node_id)
            .unwrap()
            .send_start_node(self.app_config.clone(), leader);
    }

    pub fn stop_node(&mut self, node_id: u64) {
        self.platforms.remove(&node_id);

        if self.leader_id == node_id {
            self.leader_id = 0;
        }
    }

    pub fn add_node_to_cluster(&mut self, node_id: u64) {
        self.platforms
            .get_mut(&self.leader_id)
            .unwrap()
            .send_change_cluster(0, node_id, ChangeClusterType::ChangeTypeAddReplica);

        self.advance_until_added_to_cluster(node_id);
    }

    pub fn advance_until_added_to_cluster(&mut self, node_id: u64) {
        self.advance_until(&mut |envelope_out| match &envelope_out.msg {
            Some(out_message::Msg::CheckCluster(response)) => {
                !response.has_pending_changes && response.cluster_replica_ids.contains(&node_id)
            }
            _ => false,
        });
    }

    pub fn advance_until_elected_leader(&mut self, excluding_node_id: Option<u64>) {
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

    pub fn advance_until(
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

    pub fn advance(&mut self) {
        let mut messages_in: Vec<(u64, in_message::Msg)> = Vec::new();
        for (_, platform) in &mut self.platforms {
            let messages_out = platform.take_messages_out();
            for message_out in messages_out {
                match message_out.msg {
                    Some(out_message::Msg::DeliverSystemMessage(deliver_system_message)) => {
                        messages_in.push((
                            deliver_system_message.recipient_replica_id,
                            in_message::Msg::DeliverSystemMessage(deliver_system_message),
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
                    Some(out_message::Msg::SecureChannelHandshake(secure_channel_handshake)) => {
                        messages_in.push((
                            secure_channel_handshake.recipient_replica_id,
                            in_message::Msg::SecureChannelHandshake(secure_channel_handshake),
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
                platform.append_message_in(InMessage {
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

    pub fn extract_pull_messages(
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

    pub fn print_log_messages(&mut self) {
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

    pub fn stop(&mut self) {}
}

pub struct FakePlatform<A: Actor> {
    id: u64,
    messages_in: Vec<InMessage>,
    instant: u64,
    driver: RefCell<
        Driver<
            RaftSimple<MemoryStorage>,
            MemoryStorage,
            DefaultSnapshotProcessor,
            A,
            DefaultCommunicationModule,
        >,
    >,
    host: RefCell<FakeHost>,
}

impl<A: Actor> FakePlatform<A> {
    pub fn new(id: u64, app_config: Bytes, actor: A) -> FakePlatform<A> {
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
                actor,
                DefaultCommunicationModule::new(Box::new(DefaultHandshakeSessionProvider::new(
                    Box::new(DefaultAttestationProvider {}),
                    Box::new(DefaultOakHandshakerFactory {}),
                ))),
            )),
            host: RefCell::new(FakeHost::new(app_config)),
        }
    }

    pub fn send_start_node(&mut self, app_config: Bytes, is_leader: bool) {
        self.append_message_in(InMessage {
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
                attestation_config: None,
                is_ephemeral: false,
            })),
        });
    }

    pub fn send_stop_node(&mut self) {
        self.append_message_in(InMessage {
            msg: Some(in_message::Msg::StopReplica(StopReplicaRequest {})),
        });
    }

    pub fn send_change_cluster(
        &mut self,
        change_id: u64,
        replica_id: u64,
        change_type: ChangeClusterType,
    ) {
        self.append_message_in(InMessage {
            msg: Some(in_message::Msg::ChangeCluster(ChangeClusterRequest {
                change_id,
                replica_id,
                change_type: change_type.into(),
            })),
        });
    }

    pub fn send_check_cluster(&mut self) {
        self.append_message_in(InMessage {
            msg: Some(in_message::Msg::CheckCluster(CheckClusterRequest {})),
        });
    }

    pub fn send_app_message(&mut self, correlation_id: u64, header: Bytes, payload: Bytes) {
        self.append_message_in(InMessage {
            msg: Some(in_message::Msg::DeliverAppMessage(DeliverAppMessage {
                correlation_id,
                message_header: header,
                message_payload: payload,
            })),
        });
    }

    pub fn advance_time(&mut self, duration: u64) {
        self.instant += duration;
    }

    pub fn append_message_in(&mut self, message_in: InMessage) {
        self.messages_in.push(message_in)
    }

    pub fn send_messages_in(&mut self) {
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

    pub fn take_messages_out(&mut self) -> Vec<OutMessage> {
        self.host.borrow_mut().take_messages_out()
    }
}

pub struct FakeHost {
    config: Bytes,
    messages_out: Vec<OutMessage>,
}

impl FakeHost {
    fn new(app_config: Bytes) -> FakeHost {
        FakeHost {
            config: app_config,
            messages_out: Vec::new(),
        }
    }

    fn take_messages_out(&mut self) -> Vec<OutMessage> {
        core::mem::take(&mut self.messages_out)
    }
}

impl Host for FakeHost {
    fn send_messages(&mut self, mut messages: Vec<OutMessage>) {
        self.messages_out.append(&mut messages);
    }

    fn public_signing_key(&self) -> Vec<u8> {
        Vec::new()
    }
}
