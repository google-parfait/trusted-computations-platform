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
use alloc::string::String;
use alloc::vec;
use oak_proto_rust::oak::{
    attestation::v1::AttestationResults,
    session::v1::{AttestRequest, AttestResponse},
};
use oak_session::attestation::{
    AttestationType, ClientAttestationProvider, ServerAttestationProvider,
};
use oak_session::config::AttestationProviderConfig;
use platform::PalError;

pub trait ClientAttestation = Attestation<AttestResponse, AttestRequest>;
pub trait ServerAttestation = Attestation<AttestRequest, AttestResponse>;

// Provider for `ClientAttestation` and `ServerAttestation` traits which
// are used for performing remote bidirectional attestation between 2 raft replicas
// before an encrypted secure channel is established between them.
pub trait AttestationProvider {
    // Returns ClientAttestation, responsible for initiating attestation between 2
    // raft replicas.
    fn get_client_attestation(&self) -> Box<dyn ClientAttestation>;
    // Returns ServerAttestation, recipient of the initial attestation message from
    // the client.
    fn get_server_attestation(&self) -> Box<dyn ServerAttestation>;
}

// Responsible for performing remote bidirectional attestation between 2 raft replicas.
// Receives incoming attestation specific messages and prepares outgoing messages in
// response. `AttestationResults` can be retrieved once remote attestation has successfully
// completed after an initial exchange of messages.
pub trait Attestation<I, O> {
    fn get_attestation_results(self) -> Option<AttestationResults>;
    fn put_incoming_message(&mut self, incoming_message: &I) -> Result<Option<()>, PalError>;
    fn get_outgoing_message(&mut self) -> Result<Option<O>, PalError>;
}

// Default implementation of `AttestationProvider`.
pub struct DefaultAttestationProvider {}

impl AttestationProvider for DefaultAttestationProvider {
    fn get_client_attestation(&self) -> Box<dyn ClientAttestation> {
        Box::new(DefaultClientAttestation::new())
    }

    fn get_server_attestation(&self) -> Box<dyn ServerAttestation> {
        Box::new(DefaultServerAttestation::new())
    }
}

// Default implementation of `ClientAttestation`.
pub struct DefaultClientAttestation<'a> {
    _inner: ClientAttestationProvider<'a>,
}

impl<'a> DefaultClientAttestation<'a> {
    pub fn new() -> Self {
        let config = AttestationProviderConfig {
            attestation_type: AttestationType::Bidirectional,
            self_attesters: vec![],
            peer_verifiers: vec![],
        };
        Self {
            _inner: ClientAttestationProvider::new(config),
        }
    }
}

impl<'a> Attestation<AttestResponse, AttestRequest> for DefaultClientAttestation<'a> {
    // TODO: Delegate to `inner` once the implementation is complete on Oak side.
    fn get_attestation_results(self) -> Option<AttestationResults> {
        Some(AttestationResults {
            status: 0,
            reason: String::new(),
            encryption_public_key: vec![],
            signing_public_key: vec![],
            extracted_evidence: None,
        })
    }

    fn get_outgoing_message(&mut self) -> Result<Option<AttestRequest>, PalError> {
        Ok(Some(AttestRequest {
            endorsed_evidence: vec![],
        }))
    }

    fn put_incoming_message(
        &mut self,
        _incoming_message: &AttestResponse,
    ) -> Result<Option<()>, PalError> {
        Ok(Some(()))
    }
}

// Default implementation of `ServerAttestation`.
pub struct DefaultServerAttestation<'a> {
    _inner: ServerAttestationProvider<'a>,
}

impl<'a> DefaultServerAttestation<'a> {
    pub fn new() -> Self {
        let config = AttestationProviderConfig {
            attestation_type: AttestationType::Bidirectional,
            self_attesters: vec![],
            peer_verifiers: vec![],
        };
        Self {
            _inner: ServerAttestationProvider::new(config),
        }
    }
}

impl<'a> Attestation<AttestRequest, AttestResponse> for DefaultServerAttestation<'a> {
    // TODO: Delegate to `inner` once the implementation is complete on Oak side.
    fn get_attestation_results(self) -> Option<AttestationResults> {
        Some(AttestationResults {
            status: 0,
            reason: String::new(),
            encryption_public_key: vec![],
            signing_public_key: vec![],
            extracted_evidence: None,
        })
    }

    fn get_outgoing_message(&mut self) -> Result<Option<AttestResponse>, PalError> {
        Ok(Some(AttestResponse {
            endorsed_evidence: vec![],
        }))
    }

    fn put_incoming_message(
        &mut self,
        _incoming_message: &AttestRequest,
    ) -> Result<Option<()>, PalError> {
        Ok(Some(()))
    }
}
