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
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::mem;
#[cfg(feature = "tonic")]
use tcp_proto::runtime::endpoint::endpoint_service_server;
use tcp_proto::runtime::endpoint::{
    EndpointService, OutMessage, ReceiveMessageRequest, ReceiveMessageResponse,
};
#[cfg(feature = "tonic")]
use tokio::sync::{mpsc, oneshot};
#[cfg(feature = "tonic")]
use tonic::{Request, Response};

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

// A micro_rpc EndpointService implementation that delivers messages to an
// Actor. This class should be used with the Restricted Kernel.
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
                        Arc::new(oak_session::key_extractor::DefaultSigningKeyExtractor {}),
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

// A gRPC (Tonic) EndpointService implementation that delivers messages to an
// Actor. This class should be used with Oak Containers.
#[cfg(feature = "tonic")]
pub struct TonicApplicationService {
    // A channel for sending requests to the Driver. Each request is paired with a sender to receive
    // the response.
    sender: Option<
        mpsc::Sender<(
            ReceiveMessageRequest,
            oneshot::Sender<Result<ReceiveMessageResponse, Status>>,
        )>,
    >,

    /// The handle to a thread that handles all interactions with the Driver.
    join_handle: Option<tokio::task::JoinHandle<()>>,
}

#[cfg(feature = "tonic")]
impl TonicApplicationService {
    /// Creates a new `TonicApplicationService` with the `Actor` created by the factory. The factory
    /// ensures that the Actor can be placed on another thread even if it is not `Send`.
    pub fn new<A, F>(
        channel: tonic::transport::channel::Channel,
        evidence: oak_proto_rust::oak::attestation::v1::Evidence,
        factory: F,
    ) -> Self
    where
        A: Actor,
        F: FnOnce() -> A + Send + 'static,
    {
        // Create a new thread to serialize all interactions with the Driver, which isn't
        // thread-safe.
        let (tx, rx) = mpsc::channel::<(
            ReceiveMessageRequest,
            oneshot::Sender<Result<ReceiveMessageResponse, Status>>,
        )>(1);
        let join_handle = tokio::task::spawn_blocking(move || {
            Self::run_driver_loop(factory(), &channel, evidence, rx)
        });
        Self {
            sender: Some(tx),
            join_handle: Some(join_handle),
        }
    }

    fn run_driver_loop<A: Actor>(
        actor: A,
        channel: &tonic::transport::channel::Channel,
        evidence: oak_proto_rust::oak::attestation::v1::Evidence,
        mut rx: mpsc::Receiver<(
            ReceiveMessageRequest,
            oneshot::Sender<Result<ReceiveMessageResponse, Status>>,
        )>,
    ) {
        let mut driver = Self::new_driver(actor, channel, evidence);
        while let Some((request, tx)) = rx.blocking_recv() {
            let mut host = ApplicationHost::new();
            driver
                .receive_message(&mut host, request.instant, request.message)
                .expect("application has encountered an unrecoverable error");
            tx.send(Ok(ReceiveMessageResponse {
                messages: host.take_messages(),
            }))
            .expect("failed to send receive_message response");
        }
    }

    fn new_driver<A: Actor>(
        actor: A,
        channel: &tonic::transport::channel::Channel,
        evidence: oak_proto_rust::oak::attestation::v1::Evidence,
    ) -> Driver<
        RaftSimple<MemoryStorage>,
        MemoryStorage,
        DefaultSnapshotProcessor,
        A,
        DefaultCommunicationModule,
    > {
        Driver::new(
            RaftSimple::new(),
            Box::new(MemoryStorage::new),
            DefaultSnapshotProcessor::new(
                Box::new(DefaultSnapshotSender::new()),
                Box::new(DefaultSnapshotReceiver::new()),
            ),
            actor,
            DefaultCommunicationModule::new(Box::new(DefaultHandshakeSessionProvider::new(
                Box::new(DefaultOakSessionFactory::new(
                    Box::new(crate::session::OakContainersSessionBinderFactory::new(
                        channel,
                    )),
                    Box::new(crate::session::OakContainersAttesterFactory::new(evidence)),
                    Arc::new(oak_session::key_extractor::DefaultBindingKeyExtractor {}),
                )),
            ))),
        )
    }
}

#[cfg(feature = "tonic")]
impl Drop for TonicApplicationService {
    fn drop(&mut self) {
        // Close the channel to signal the thread to exit.
        drop(self.sender.take());
        if let Err(err) =
            tokio::runtime::Handle::current().block_on(self.join_handle.take().unwrap())
        {
            std::panic::resume_unwind(Box::new(err));
        }
    }
}

#[cfg(feature = "tonic")]
#[tonic::async_trait]
impl endpoint_service_server::EndpointService for TonicApplicationService {
    async fn receive_message(
        &self,
        request: Request<ReceiveMessageRequest>,
    ) -> Result<Response<ReceiveMessageResponse>, tonic::Status> {
        let (tx, rx) = oneshot::channel();
        self.sender
            .as_ref()
            .unwrap()
            .send((request.into_inner(), tx))
            .await
            .map_err(|err| tonic::Status::internal(format!("failed to send: {}", err)))?;
        let response = rx
            .await
            .map_err(|err| tonic::Status::internal(format!("failed to receive response: {}", err)))?
            .map_err(|err| tonic::Status::new((err.code as i32).into(), err.message))?;
        Ok(Response::new(response))
    }
}
