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

extern crate alloc;
extern crate micro_rpc;
extern crate prost;
extern crate tcp_proto;

use self::micro_rpc::Status;
use crate::communication::DefaultCommunicationModule;
use crate::handshake::DefaultHandshakeSessionProvider;
use crate::model::Actor;
use crate::platform::{Application, Host};
use crate::session::{
    DefaultOakAttesterFactory, DefaultOakSessionBinderFactory, DefaultOakSessionFactory,
};
use crate::snapshot::{DefaultSnapshotReceiver, DefaultSnapshotSender};
use crate::{
    consensus::RaftSimple, driver::Driver, snapshot::DefaultSnapshotProcessor,
    storage::MemoryStorage,
};
use alloc::boxed::Box;
use alloc::vec::Vec;
use core::mem;
use tcp_proto::runtime::endpoint::{
    EndpointService, OutMessage, ReceiveMessageRequest, ReceiveMessageResponse,
};

struct ApplicationHost {
    messages: Vec<OutMessage>,
}

impl ApplicationHost {
    fn new() -> ApplicationHost {
        ApplicationHost {
            messages: Vec::new(),
        }
    }

    fn take_messages(&mut self) -> Vec<OutMessage> {
        mem::take(&mut self.messages)
    }
}

impl Host for ApplicationHost {
    fn send_messages(&mut self, mut messages: Vec<OutMessage>) {
        self.messages.append(&mut messages)
    }

    fn public_signing_key(&self) -> Vec<u8> {
        Vec::new()
    }
}

pub struct ApplicationService<A: Actor> {
    driver: Driver<
        RaftSimple<MemoryStorage>,
        MemoryStorage,
        DefaultSnapshotProcessor,
        A,
        DefaultCommunicationModule,
    >,
}

impl<A: Actor> ApplicationService<A> {
    pub fn new(actor: A) -> ApplicationService<A> {
        ApplicationService {
            driver: Driver::new(
                RaftSimple::new(),
                Box::new(MemoryStorage::new),
                DefaultSnapshotProcessor::new(
                    Box::new(DefaultSnapshotSender::new()),
                    Box::new(DefaultSnapshotReceiver::new()),
                ),
                actor,
                DefaultCommunicationModule::new(Box::new(DefaultHandshakeSessionProvider::new(
                    Box::new(DefaultOakSessionFactory::new(
                        Box::new(DefaultOakSessionBinderFactory {}),
                        Box::new(DefaultOakAttesterFactory {}),
                    )),
                ))),
            ),
        }
    }
}

impl<A: Actor> EndpointService for ApplicationService<A> {
    fn receive_message(
        &mut self,
        request: ReceiveMessageRequest,
    ) -> Result<ReceiveMessageResponse, Status> {
        let mut host = ApplicationHost::new();

        let Ok(()) = self
            .driver
            .receive_message(&mut host, request.instant, request.message)
        else {
            // The application has encoutered an unrecoverable error.
            panic!();
        };

        let response = ReceiveMessageResponse {
            messages: host.take_messages(),
        };

        Ok(response)
    }
}
