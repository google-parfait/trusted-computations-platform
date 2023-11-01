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

extern crate alloc;
extern crate micro_rpc;
extern crate prost;
extern crate tcp_proto;

use crate::model::Actor;
use crate::platform::{Application, Attestation, Host, PalError};
use crate::{consensus::RaftSimple, driver::Driver, storage::MemoryStorage};
use alloc::boxed::Box;
use alloc::vec::Vec;
use core::mem;
use service::micro_rpc::Status;
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
    fn get_self_attestation(&self) -> Box<dyn Attestation> {
        Box::new(ApplicationAttestation {})
    }

    fn get_self_config(&self) -> Vec<u8> {
        Vec::new()
    }

    fn send_messages(&mut self, mut messages: Vec<OutMessage>) {
        self.messages.append(&mut messages)
    }

    fn verify_peer_attestation(&self, _: &[u8]) -> Result<Box<dyn Attestation>, PalError> {
        todo!()
    }
}

struct ApplicationAttestation {}

impl Attestation for ApplicationAttestation {
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

pub struct ApplicationService<A: Actor> {
    driver: Driver<RaftSimple<MemoryStorage>, MemoryStorage, A>,
}

impl<A: Actor> ApplicationService<A> {
    pub fn new(actor: A) -> ApplicationService<A> {
        ApplicationService {
            driver: Driver::new(RaftSimple::new(), Box::new(MemoryStorage::new), actor),
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
