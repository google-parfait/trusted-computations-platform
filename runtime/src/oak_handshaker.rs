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
use platform::PalError;

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
    fn put_incoming_message(&mut self, incoming_message: &I) -> Result<Option<()>, PalError>;
    fn get_outgoing_message(&mut self) -> Result<Option<O>, PalError>;
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
pub struct DefaultOakClientHandshaker<'a> {
    inner: Option<ClientHandshaker<'a>>,
}

impl<'a> DefaultOakClientHandshaker<'a> {
    pub fn new() -> Self {
        Self { inner: None }
    }
}

impl<'a> OakHandshaker<HandshakeResponse, HandshakeRequest> for DefaultOakClientHandshaker<'a> {
    // TODO: Delegate to `inner` once the implementation is complete on Oak side.
    fn init(&mut self, peer_static_public_key: Vec<u8>) {
        let config = HandshakerConfig {
            // TODO: Switch to using NoiseNN when implemented in oak. Use `session_binding_key` for
            // NoiseNN as `peer_session_binding_key`.
            handshake_type: HandshakeType::NoiseKK,
            self_static_private_key: None,
            peer_static_public_key: Some(peer_static_public_key),
        };
        self.inner = Some(ClientHandshaker::new(config));
    }

    fn get_outgoing_message(&mut self) -> Result<Option<HandshakeRequest>, PalError> {
        Ok(Some(HandshakeRequest {
            ephemeral_public_key: vec![],
            ciphertext: vec![],
        }))
    }

    fn put_incoming_message(
        &mut self,
        _incoming_message: &HandshakeResponse,
    ) -> Result<Option<()>, PalError> {
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
            handshake_type: HandshakeType::NoiseKK,
            self_static_private_key: None,
            peer_static_public_key: Some(peer_static_public_key),
        };
        self.inner = Some(ServerHandshaker::new(config));
    }

    fn get_outgoing_message(&mut self) -> Result<Option<HandshakeResponse>, PalError> {
        Ok(Some(HandshakeResponse {
            ephemeral_public_key: vec![],
            ciphertext: vec![],
        }))
    }

    fn put_incoming_message(
        &mut self,
        _incoming_message: &HandshakeRequest,
    ) -> Result<Option<()>, PalError> {
        Ok(Some(()))
    }

    fn derive_session_keys(self: Box<Self>) -> Option<SessionKeys> {
        Some(SessionKeys {
            request_key: vec![],
            response_key: vec![],
        })
    }
}
