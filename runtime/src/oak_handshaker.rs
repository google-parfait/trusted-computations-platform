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

use alloc::boxed::Box;
use alloc::{vec, vec::Vec};
use oak_proto_rust::oak::{
    crypto::v1::SessionKeys,
    session::v1::{HandshakeRequest, HandshakeResponse},
};
use oak_session::config::HandshakerConfig;
use oak_session::handshake::{ClientHandshaker, HandshakeType, ServerHandshaker};

pub trait OakClientHandshaker = OakHandshaker<HandshakeResponse, HandshakeRequest>;
pub trait OakServerHandshaker = OakHandshaker<HandshakeRequest, HandshakeResponse>;

// Factory class for creating instances of `OakClientHandshaker` and `OakServerHandshaker`
// traits which are used for initiating crypto key exchange using Noise protocol implementation
// provided by the Oak restricted kernel SDK.
pub trait OakHandshakerFactory {
    // Returns OakClientHandshaker, responsible for initiating crypto key exchange
    // between 2 raft replicas using Noise protocol.
    fn get_client_oak_handshaker(&self) -> Box<dyn OakClientHandshaker>;
    // Returns OakServerHandshaker, recipient of the initial crypto key exchange
    // message from the client.
    fn get_server_oak_handshaker(&self) -> Box<dyn OakServerHandshaker>;
}

// Responsible for performing key exchange between 2 raft replicas using Noise protocol.
// Receives incoming Noise handshake messages and prepares outgoing messages in
// response. `SessionKeys` can be retrieved once key exchange has successfully
// completed after an initial exchange of messages.
pub trait OakHandshaker<I, O> {
    fn init(&mut self, peer_static_public_key: Vec<u8>);
    fn put_incoming_message(&mut self, incoming_message: &I) -> anyhow::Result<Option<()>>;
    fn get_outgoing_message(&mut self) -> anyhow::Result<Option<O>>;
    fn derive_session_keys(self: Box<Self>) -> Option<SessionKeys>;
}

// Default implementation of `OakHandshakerFactory`.
pub struct DefaultOakHandshakerFactory {}

impl OakHandshakerFactory for DefaultOakHandshakerFactory {
    fn get_client_oak_handshaker(&self) -> Box<dyn OakClientHandshaker> {
        Box::new(DefaultOakClientHandshaker::new())
    }

    fn get_server_oak_handshaker(&self) -> Box<dyn OakServerHandshaker> {
        Box::new(DefaultOakServerHandshaker::new())
    }
}

// Default implementation of `OakClientHandshaker`.
pub struct DefaultOakClientHandshaker {
    inner: Option<ClientHandshaker>,
}

impl DefaultOakClientHandshaker {
    pub fn new() -> Self {
        Self { inner: None }
    }
}

impl OakHandshaker<HandshakeResponse, HandshakeRequest> for DefaultOakClientHandshaker {
    // TODO: Delegate to `inner` once the implementation is complete on Oak side.
    fn init(&mut self, peer_static_public_key: Vec<u8>) {
        let config = HandshakerConfig {
            // TODO: review the parameters below.
            handshake_type: HandshakeType::NoiseNN,
            self_static_private_key: None,
            peer_static_public_key: Some(peer_static_public_key),
            peer_attestation_binding_public_key: None,
        };
        // TODO: handle error to create ClientHandshaker instead of unwrap().
        self.inner = Some(ClientHandshaker::create(&config).unwrap());
    }

    fn get_outgoing_message(&mut self) -> anyhow::Result<Option<HandshakeRequest>> {
        Ok(Some(HandshakeRequest {
            attestation_binding: None,
            handshake_type: None,
        }))
    }

    fn put_incoming_message(
        &mut self,
        _incoming_message: &HandshakeResponse,
    ) -> anyhow::Result<Option<()>> {
        Ok(Some(()))
    }

    fn derive_session_keys(self: Box<Self>) -> Option<SessionKeys> {
        Some(SessionKeys {
            request_key: vec![],
            response_key: vec![],
        })
    }
}

// Default implementation of `OakServerHandshaker`.
pub struct DefaultOakServerHandshaker<'a> {
    inner: Option<ServerHandshaker<'a>>,
}

impl<'a> DefaultOakServerHandshaker<'a> {
    pub fn new() -> Self {
        Self { inner: None }
    }
}

impl<'a> OakHandshaker<HandshakeRequest, HandshakeResponse> for DefaultOakServerHandshaker<'a> {
    // TODO: Delegate to `inner` once the implementation is complete on Oak side.
    fn init(&mut self, peer_static_public_key: Vec<u8>) {
        let config = HandshakerConfig {
            handshake_type: HandshakeType::NoiseNN,
            self_static_private_key: None,
            peer_static_public_key: Some(peer_static_public_key),
            peer_attestation_binding_public_key: None,
        };
        self.inner = Some(ServerHandshaker::new(&config));
    }

    fn get_outgoing_message(&mut self) -> anyhow::Result<Option<HandshakeResponse>> {
        Ok(Some(HandshakeResponse {
            attestation_binding: None,
            handshake_type: None,
        }))
    }

    fn put_incoming_message(
        &mut self,
        _incoming_message: &HandshakeRequest,
    ) -> anyhow::Result<Option<()>> {
        Ok(Some(()))
    }

    fn derive_session_keys(self: Box<Self>) -> Option<SessionKeys> {
        Some(SessionKeys {
            request_key: vec![],
            response_key: vec![],
        })
    }
}
