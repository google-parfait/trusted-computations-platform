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

use crate::{
    attestation::{AttestationProvider, ClientAttestation, ServerAttestation},
    logger::log::create_logger,
    oak_handshaker::{OakClientHandshaker, OakHandshakerFactory, OakServerHandshaker},
    platform::PalError,
};
use alloc::{boxed::Box, format};
use oak_proto_rust::oak::session::v1::{
    AttestRequest as OakAttestRequest, AttestResponse as OakAttestResponse,
    HandshakeRequest as OakHandshakeRequest, HandshakeResponse as OakHandshakeResponse,
};
use slog::{debug, warn, Logger};
use tcp_proto::runtime::endpoint::{
    secure_channel_handshake::{
        noise_protocol, noise_protocol::initiator_request::Message::AttestRequest,
        noise_protocol::initiator_request::Message::HandshakeRequest,
        noise_protocol::recipient_response::Message::AttestResponse,
        noise_protocol::recipient_response::Message::HandshakeResponse,
        noise_protocol::Message::InitiatorRequest, noise_protocol::Message::RecipientResponse,
        Encryption, NoiseProtocol,
    },
    *,
};

// Role associated with a HandshakeSession.
#[derive(Debug, PartialEq)]
pub enum Role {
    // Initiator of the handshake.
    Initiator,
    // Recipient of the handshake.
    Recipient,
}

/// Returns a HandshakeSession for a given role.
pub trait HandshakeSessionProvider {
    /// Get a HandshakeSession object for a given role.
    fn get(
        &self,
        self_replica_id: u64,
        peer_replica_id: u64,
        role: Role,
    ) -> Box<dyn HandshakeSession>;
}

/// Responsible for establishing a handshake between two raft replicas.
/// This includes performing mutual attestation and using noise protocol
/// to exchange symmetric keys which can be later used for encrypting/decrypting
/// payloads.
pub trait HandshakeSession {
    // Process an incoming SecureChanneHandshake message.
    fn process_message(&mut self, message: &SecureChannelHandshake) -> Result<(), PalError>;

    // Take out any pending handshake messages that need to be sent out for this session.
    // Returns None if no such message exists.
    fn take_out_message(&mut self) -> Result<Option<SecureChannelHandshake>, PalError>;

    // Returns true if this handshake session is now complete.
    fn is_completed(&self) -> bool;
}

pub struct DefaultHandshakeSessionProvider {
    attestation_provider: Box<dyn AttestationProvider>,
    oak_handshaker_factory: Box<dyn OakHandshakerFactory>,
}

impl DefaultHandshakeSessionProvider {
    pub fn new(
        attestation_provider: Box<dyn AttestationProvider>,
        oak_handshaker_factory: Box<dyn OakHandshakerFactory>,
    ) -> Self {
        Self {
            attestation_provider,
            oak_handshaker_factory,
        }
    }
}
impl HandshakeSessionProvider for DefaultHandshakeSessionProvider {
    fn get(
        &self,
        self_replica_id: u64,
        peer_replica_id: u64,
        role: Role,
    ) -> Box<dyn HandshakeSession> {
        match role {
            Role::Initiator => Box::new(ClientHandshakeSession::new(
                create_logger(),
                self_replica_id,
                peer_replica_id,
                self.attestation_provider.get_client_attestation(),
                self.oak_handshaker_factory.get_client_oak_handshaker(),
            )),
            Role::Recipient => Box::new(ServerHandshakeSession::new(
                create_logger(),
                self_replica_id,
                peer_replica_id,
                self.attestation_provider.get_server_attestation(),
                self.oak_handshaker_factory.get_server_oak_handshaker(),
            )),
        }
    }
}

#[derive(PartialEq)]
enum State {
    // State is unknown.
    Unknown,
    // Bidirectional remote attestation initiated. Waiting for completion.
    Attesting,
    // Crypto key exchange based on Noise Protocol initiated. This occurs after
    // attestation has been verified.
    KeyExchange,
    // Handshake completed successfully.
    Completed,
    // Handshake failed due to internal errors or failed attestation.
    Failed,
}

pub struct ClientHandshakeSession {
    logger: Logger,
    self_replica_id: u64,
    peer_replica_id: u64,
    attestation: Option<Box<dyn ClientAttestation>>,
    oak_handshaker: Option<Box<dyn OakClientHandshaker>>,
    state: State,
}

impl ClientHandshakeSession {
    fn new(
        logger: Logger,
        self_replica_id: u64,
        peer_replica_id: u64,
        attestation: Box<dyn ClientAttestation>,
        oak_handshaker: Box<dyn OakClientHandshaker>,
    ) -> Self {
        Self {
            logger,
            self_replica_id,
            peer_replica_id,
            attestation: Some(attestation),
            oak_handshaker: Some(oak_handshaker),
            state: State::Unknown,
        }
    }

    fn create_secure_channel_handshake(
        &self,
        initiator_request: noise_protocol::InitiatorRequest,
    ) -> SecureChannelHandshake {
        SecureChannelHandshake {
            recipient_replica_id: self.peer_replica_id,
            sender_replica_id: self.self_replica_id,
            encryption: Some(Encryption::NoiseProtocol(NoiseProtocol {
                message: Some(InitiatorRequest(initiator_request)),
            })),
        }
    }

    fn transition_to_failed(&mut self, msg: &str) {
        warn!(self.logger, "{}", msg);
        self.state = State::Failed;
    }

    fn get_attest_request(&mut self) -> Result<SecureChannelHandshake, PalError> {
        if let Ok(Some(attest_request)) = self.attestation.as_mut().unwrap().get_outgoing_message()
        {
            Ok(
                self.create_secure_channel_handshake(noise_protocol::InitiatorRequest {
                    message: Some(AttestRequest(attest_request)),
                }),
            )
        } else {
            self.transition_to_failed("No outgoing `AttestRequest` message retrieved.");
            Err(PalError::Internal)
        }
    }

    fn handle_attest_response(
        &mut self,
        attest_response: &OakAttestResponse,
    ) -> Result<(), PalError> {
        self.attestation
            .as_mut()
            .unwrap()
            .put_incoming_message(attest_response)
            .or_else(|err| {
                self.transition_to_failed(&format!("Failed to put incoming message {}.", err));
                Err(PalError::Internal)
            })?;

        // Take out `self.attestation` out of `self` so that it can be consumed.
        let attestation = self.attestation.take();
        let attestation_results =
            attestation
                .unwrap()
                .get_attestation_results()
                .ok_or_else(|| {
                    self.transition_to_failed("Failed to get AttestationResults.");
                    PalError::Internal
                })?;

        // Initialize `self.oak_handshaker` with the peer's public key.
        self.oak_handshaker.as_mut().unwrap().init(
            attestation_results
                .extracted_evidence
                .unwrap()
                .encryption_public_key,
        );

        Ok(())
    }

    fn get_handshake_request(&mut self) -> Result<SecureChannelHandshake, PalError> {
        if let Ok(Some(handshake_request)) =
            self.oak_handshaker.as_mut().unwrap().get_outgoing_message()
        {
            Ok(
                self.create_secure_channel_handshake(noise_protocol::InitiatorRequest {
                    message: Some(HandshakeRequest(handshake_request)),
                }),
            )
        } else {
            self.transition_to_failed("No outgoing `HandshakeRequest` message retrieved.");
            Err(PalError::Internal)
        }
    }

    fn handle_handshake_response(
        &mut self,
        handshake_response: &OakHandshakeResponse,
    ) -> Result<(), PalError> {
        self.oak_handshaker
            .as_mut()
            .unwrap()
            .put_incoming_message(handshake_response)
            .or_else(|err| {
                self.transition_to_failed(&format!("Failed to put incoming message {}.", err));
                Err(PalError::Internal)
            })?;

        // Take out `self.oak_handshaker` out of `self` so that it can be consumed.
        let oak_handshaker = self.oak_handshaker.take();
        // TODO: Use `session_keys` to initialize Encryptor.
        let _session_keys = oak_handshaker
            .unwrap()
            .derive_session_keys()
            .ok_or_else(|| {
                self.transition_to_failed("Failed to derive SessionKeys.");
                PalError::Internal
            })?;

        Ok(())
    }
}

impl HandshakeSession for ClientHandshakeSession {
    fn process_message(&mut self, message: &SecureChannelHandshake) -> Result<(), PalError> {
        return match self.state {
            State::Unknown => {
                self.transition_to_failed(&format!(
                    "Unexpected handshake message {:?} received in state Unknown.",
                    message
                ));
                Err(PalError::Internal)
            }
            State::Attesting => {
                if let Some(Encryption::NoiseProtocol(ref noise_protocol)) = message.encryption
                    && let Some(RecipientResponse(ref recipient_response)) = noise_protocol.message
                    && let Some(AttestResponse(ref attest_response)) = recipient_response.message
                {
                    self.handle_attest_response(attest_response)?;
                    self.state = State::KeyExchange;
                    Ok(())
                } else {
                    self.transition_to_failed(&format!(
                        "Unexpected handshake message {:?} received in state Attesting.",
                        message
                    ));
                    Err(PalError::Internal)
                }
            }
            State::KeyExchange => {
                if let Some(Encryption::NoiseProtocol(ref noise_protocol)) = message.encryption
                    && let Some(RecipientResponse(ref recipient_response)) = noise_protocol.message
                    && let Some(HandshakeResponse(ref handshake_response)) =
                        recipient_response.message
                {
                    self.handle_handshake_response(handshake_response)?;
                    self.state = State::Completed;
                    Ok(())
                } else {
                    self.transition_to_failed(&format!(
                        "Unexpected handshake message {:?} received in state KeyExchange.",
                        message
                    ));
                    Err(PalError::Internal)
                }
            }
            State::Completed => {
                debug!(
                    self.logger,
                    "Ignoring message since handshake already completed."
                );
                Ok(())
            }
            State::Failed => {
                warn!(self.logger, "Cannot process messages in state Failed.");
                Err(PalError::Internal)
            }
        };
    }

    fn take_out_message(&mut self) -> Result<Option<SecureChannelHandshake>, PalError> {
        return match self.state {
            State::Unknown => {
                let attest_request = self.get_attest_request()?;
                self.state = State::Attesting;
                Ok(Some(attest_request))
            }
            State::Attesting => {
                debug!(
                    self.logger,
                    "No messages to take out while state is still Attesting."
                );
                Ok(None)
            }
            State::KeyExchange => {
                let handshake_request = self.get_handshake_request()?;
                Ok(Some(handshake_request))
            }
            State::Completed => {
                debug!(
                    self.logger,
                    "No messages to take out since handshake already completed."
                );
                Ok(None)
            }
            State::Failed => {
                warn!(self.logger, "Cannot take out messages in state Failed.");
                Err(PalError::Internal)
            }
        };
    }

    fn is_completed(&self) -> bool {
        self.state == State::Completed
    }
}

pub struct ServerHandshakeSession {
    logger: Logger,
    self_replica_id: u64,
    peer_replica_id: u64,
    attestation: Option<Box<dyn ServerAttestation>>,
    oak_handshaker: Option<Box<dyn OakServerHandshaker>>,
    state: State,
}

impl ServerHandshakeSession {
    fn new(
        logger: Logger,
        self_replica_id: u64,
        peer_replica_id: u64,
        attestation: Box<dyn ServerAttestation>,
        oak_handshaker: Box<dyn OakServerHandshaker>,
    ) -> Self {
        Self {
            logger,
            self_replica_id,
            peer_replica_id,
            attestation: Some(attestation),
            oak_handshaker: Some(oak_handshaker),
            state: State::Unknown,
        }
    }

    fn create_secure_channel_handshake(
        &self,
        recipient_response: noise_protocol::RecipientResponse,
    ) -> SecureChannelHandshake {
        SecureChannelHandshake {
            recipient_replica_id: self.peer_replica_id,
            sender_replica_id: self.self_replica_id,
            encryption: Some(Encryption::NoiseProtocol(NoiseProtocol {
                message: Some(RecipientResponse(recipient_response)),
            })),
        }
    }

    fn transition_to_failed(&mut self, msg: &str) {
        warn!(self.logger, "{}", msg);
        self.state = State::Failed;
    }

    fn handle_attest_request(&mut self, attest_request: &OakAttestRequest) -> Result<(), PalError> {
        self.attestation
            .as_mut()
            .unwrap()
            .put_incoming_message(attest_request)
            .or_else(|err| {
                self.transition_to_failed(&format!("Failed to put incoming message {}.", err));
                Err(PalError::Internal)
            })?;
        Ok(())
    }

    fn get_attest_response(&mut self) -> Result<SecureChannelHandshake, PalError> {
        if let Ok(Some(attest_response)) = self.attestation.as_mut().unwrap().get_outgoing_message()
        {
            Ok(
                self.create_secure_channel_handshake(noise_protocol::RecipientResponse {
                    message: Some(AttestResponse(attest_response)),
                }),
            )
        } else {
            self.transition_to_failed("No outgoing `AttestResponse` message retrieved.");
            Err(PalError::Internal)
        }
    }

    fn init_oak_handshaker(&mut self) -> Result<(), PalError> {
        // Take out `self.attestation` out of `self` so that it can be consumed.
        let attestation = self.attestation.take();
        let attestation_results =
            attestation
                .unwrap()
                .get_attestation_results()
                .ok_or_else(|| {
                    self.transition_to_failed("Failed to get AttestationResults.");
                    PalError::Internal
                })?;

        // Initialize `self.oak_handshaker` with the peer's public key.
        self.oak_handshaker.as_mut().unwrap().init(
            attestation_results
                .extracted_evidence
                .unwrap()
                .encryption_public_key,
        );

        Ok(())
    }

    fn handle_handshake_request(
        &mut self,
        handshake_request: &OakHandshakeRequest,
    ) -> Result<(), PalError> {
        self.oak_handshaker
            .as_mut()
            .unwrap()
            .put_incoming_message(handshake_request)
            .or_else(|err| {
                self.transition_to_failed(&format!("Failed to put incoming message {}.", err));
                Err(PalError::Internal)
            })?;
        Ok(())
    }

    fn get_handshake_response(&mut self) -> Result<SecureChannelHandshake, PalError> {
        if let Ok(Some(handshake_response)) =
            self.oak_handshaker.as_mut().unwrap().get_outgoing_message()
        {
            Ok(
                self.create_secure_channel_handshake(noise_protocol::RecipientResponse {
                    message: Some(HandshakeResponse(handshake_response)),
                }),
            )
        } else {
            self.transition_to_failed("No outgoing `HandshakeResponse` message retrieved.");
            Err(PalError::Internal)
        }
    }

    fn init_encryptor(&mut self) -> Result<(), PalError> {
        // Take out `self.oak_handshaker` out of `self` so that it can be consumed.
        let oak_handshaker = self.oak_handshaker.take();
        //TODO: Use session keys to create Encryptor.
        let _session_keys = oak_handshaker
            .unwrap()
            .derive_session_keys()
            .ok_or_else(|| {
                self.transition_to_failed("Failed to derive SessionKeys.");
                PalError::Internal
            })?;

        Ok(())
    }
}

impl HandshakeSession for ServerHandshakeSession {
    fn process_message(&mut self, message: &SecureChannelHandshake) -> Result<(), PalError> {
        return match self.state {
            State::Unknown => {
                if let Some(Encryption::NoiseProtocol(ref noise_protocol)) = message.encryption
                    && let Some(InitiatorRequest(ref initiator_request)) = noise_protocol.message
                    && let Some(AttestRequest(ref attest_request)) = initiator_request.message
                {
                    self.handle_attest_request(attest_request)?;
                    self.state = State::Attesting;
                    Ok(())
                } else {
                    self.transition_to_failed(&format!(
                        "Unexpected handshake message {:?} received in state Unknown.",
                        message
                    ));
                    Err(PalError::Internal)
                }
            }
            State::Attesting => {
                self.transition_to_failed(&format!(
                    "Unexpected handshake message {:?} received in state Attesting.",
                    message
                ));
                Err(PalError::Internal)
            }
            State::KeyExchange => {
                if let Some(Encryption::NoiseProtocol(ref noise_protocol)) = message.encryption
                    && let Some(InitiatorRequest(ref initiator_request)) = noise_protocol.message
                    && let Some(HandshakeRequest(ref handshake_request)) = initiator_request.message
                {
                    self.handle_handshake_request(handshake_request)
                } else {
                    self.transition_to_failed(&format!(
                        "Unexpected handshake message {:?} received in state KeyExchange.",
                        message
                    ));
                    Err(PalError::Internal)
                }
            }
            State::Completed => {
                debug!(
                    self.logger,
                    "Ignoring message since handshake already completed."
                );
                Ok(())
            }
            State::Failed => {
                warn!(self.logger, "Cannot process messages in state Failed.");
                Err(PalError::Internal)
            }
        };
    }

    fn take_out_message(&mut self) -> Result<Option<SecureChannelHandshake>, PalError> {
        return match self.state {
            State::Unknown => {
                debug!(self.logger, "No messages to take out in state Unknown");
                Ok(None)
            }
            State::Attesting => {
                let attest_response = self.get_attest_response()?;
                self.init_oak_handshaker()?;
                self.state = State::KeyExchange;
                Ok(Some(attest_response))
            }
            State::KeyExchange => {
                let handshake_response = self.get_handshake_response()?;
                self.init_encryptor()?;
                self.state = State::Completed;
                Ok(Some(handshake_response))
            }
            State::Completed => {
                debug!(
                    self.logger,
                    "No messages to take out since handshake already completed."
                );
                Ok(None)
            }
            State::Failed => {
                warn!(self.logger, "Cannot take out messages in state Failed.");
                Err(PalError::Internal)
            }
        };
    }

    fn is_completed(&self) -> bool {
        self.state == State::Completed
    }
}

#[cfg(all(test, feature = "std"))]
mod test {
    extern crate mockall;

    use self::mockall::predicate::eq;
    use crate::handshake::{
        ClientHandshakeSession, DefaultHandshakeSessionProvider, HandshakeSession,
        HandshakeSessionProvider, Role, ServerHandshakeSession,
    };
    use crate::logger::log::create_logger;
    use alloc::vec;
    use core::mem;
    use mock::{
        MockAttestationProvider, MockClientAttestation, MockOakClientHandshaker,
        MockOakHandshakerFactory, MockOakServerHandshaker, MockServerAttestation,
    };
    use oak_proto_rust::oak::attestation::v1::{AttestationResults, ExtractedEvidence};
    use oak_proto_rust::oak::crypto::v1::SessionKeys;
    use oak_proto_rust::oak::session::v1::{
        AttestRequest as OakAttestRequest, AttestResponse as OakAttestResponse,
        HandshakeRequest as OakHandshakeRequest, HandshakeResponse as OakHandshakeResponse,
    };
    use platform::PalError;
    use tcp_proto::runtime::endpoint::{
        secure_channel_handshake::{
            noise_protocol, noise_protocol::initiator_request::Message::AttestRequest,
            noise_protocol::initiator_request::Message::HandshakeRequest,
            noise_protocol::recipient_response::Message::AttestResponse,
            noise_protocol::recipient_response::Message::HandshakeResponse,
            noise_protocol::Message::InitiatorRequest, noise_protocol::Message::RecipientResponse,
            Encryption, NoiseProtocol,
        },
        *,
    };

    fn create_attest_request(
        sender_replica_id: u64,
        recipient_replica_id: u64,
    ) -> SecureChannelHandshake {
        SecureChannelHandshake {
            recipient_replica_id,
            sender_replica_id,
            encryption: Some(Encryption::NoiseProtocol(NoiseProtocol {
                message: Some(InitiatorRequest(noise_protocol::InitiatorRequest {
                    message: Some(AttestRequest(OakAttestRequest::default())),
                })),
            })),
        }
    }

    fn create_attest_response(
        sender_replica_id: u64,
        recipient_replica_id: u64,
    ) -> SecureChannelHandshake {
        SecureChannelHandshake {
            recipient_replica_id,
            sender_replica_id,
            encryption: Some(Encryption::NoiseProtocol(NoiseProtocol {
                message: Some(RecipientResponse(noise_protocol::RecipientResponse {
                    message: Some(AttestResponse(OakAttestResponse::default())),
                })),
            })),
        }
    }

    fn create_handshake_request(
        sender_replica_id: u64,
        recipient_replica_id: u64,
    ) -> SecureChannelHandshake {
        SecureChannelHandshake {
            recipient_replica_id,
            sender_replica_id,
            encryption: Some(Encryption::NoiseProtocol(NoiseProtocol {
                message: Some(InitiatorRequest(noise_protocol::InitiatorRequest {
                    message: Some(HandshakeRequest(OakHandshakeRequest::default())),
                })),
            })),
        }
    }

    fn create_handshake_response(
        sender_replica_id: u64,
        recipient_replica_id: u64,
    ) -> SecureChannelHandshake {
        SecureChannelHandshake {
            recipient_replica_id,
            sender_replica_id,
            encryption: Some(Encryption::NoiseProtocol(NoiseProtocol {
                message: Some(RecipientResponse(noise_protocol::RecipientResponse {
                    message: Some(HandshakeResponse(OakHandshakeResponse::default())),
                })),
            })),
        }
    }

    struct AttestationProviderBuilder {
        mock_attestation_provider: MockAttestationProvider,
    }

    impl AttestationProviderBuilder {
        fn new() -> AttestationProviderBuilder {
            AttestationProviderBuilder {
                mock_attestation_provider: MockAttestationProvider::new(),
            }
        }

        fn expect_get_client_attestation(
            mut self,
            mock_attestation: MockClientAttestation,
        ) -> AttestationProviderBuilder {
            self.mock_attestation_provider
                .expect_get_client_attestation()
                .return_once(move || Box::new(mock_attestation));
            self
        }

        fn expect_get_server_attestation(
            mut self,
            mock_attestation: MockServerAttestation,
        ) -> AttestationProviderBuilder {
            self.mock_attestation_provider
                .expect_get_server_attestation()
                .return_once(move || Box::new(mock_attestation));
            self
        }

        fn take(mut self) -> MockAttestationProvider {
            mem::take(&mut self.mock_attestation_provider)
        }
    }

    struct ClientAttestationBuilder {
        mock_client_attestation: MockClientAttestation,
    }

    impl ClientAttestationBuilder {
        fn new() -> ClientAttestationBuilder {
            ClientAttestationBuilder {
                mock_client_attestation: MockClientAttestation::new(),
            }
        }

        fn expect_get_outgoing_message(
            mut self,
            message: Result<Option<OakAttestRequest>, PalError>,
        ) -> ClientAttestationBuilder {
            self.mock_client_attestation
                .expect_get_outgoing_message()
                .once()
                .return_once(move || message);
            self
        }

        fn expect_put_incoming_message(
            mut self,
            message: OakAttestResponse,
            result: Result<Option<()>, PalError>,
        ) -> ClientAttestationBuilder {
            self.mock_client_attestation
                .expect_put_incoming_message()
                .with(eq(message))
                .once()
                .return_once(move |_| result);
            self
        }

        fn expect_get_attestation_results(mut self) -> ClientAttestationBuilder {
            self.mock_client_attestation
                .expect_get_attestation_results()
                .once()
                .return_const(Some(AttestationResults {
                    status: 0,
                    reason: String::new(),
                    encryption_public_key: vec![],
                    signing_public_key: vec![],
                    extracted_evidence: Some(ExtractedEvidence {
                        encryption_public_key: vec![],
                        signing_public_key: vec![],
                        evidence_values: None,
                    }),
                }));
            self
        }

        fn take(mut self) -> MockClientAttestation {
            mem::take(&mut self.mock_client_attestation)
        }
    }

    struct ServerAttestationBuilder {
        mock_server_attestation: MockServerAttestation,
    }

    impl ServerAttestationBuilder {
        fn new() -> ServerAttestationBuilder {
            ServerAttestationBuilder {
                mock_server_attestation: MockServerAttestation::new(),
            }
        }

        fn expect_get_outgoing_message(
            mut self,
            message: Result<Option<OakAttestResponse>, PalError>,
        ) -> ServerAttestationBuilder {
            self.mock_server_attestation
                .expect_get_outgoing_message()
                .once()
                .return_once(move || message);
            self
        }

        fn expect_put_incoming_message(
            mut self,
            message: OakAttestRequest,
            result: Result<Option<()>, PalError>,
        ) -> ServerAttestationBuilder {
            self.mock_server_attestation
                .expect_put_incoming_message()
                .with(eq(message))
                .once()
                .return_once(move |_| result);
            self
        }

        fn expect_get_attestation_results(mut self) -> ServerAttestationBuilder {
            self.mock_server_attestation
                .expect_get_attestation_results()
                .once()
                .return_const(Some(AttestationResults {
                    status: 0,
                    reason: String::new(),
                    encryption_public_key: vec![],
                    signing_public_key: vec![],
                    extracted_evidence: Some(ExtractedEvidence {
                        encryption_public_key: vec![],
                        signing_public_key: vec![],
                        evidence_values: None,
                    }),
                }));
            self
        }

        fn take(mut self) -> MockServerAttestation {
            mem::take(&mut self.mock_server_attestation)
        }
    }

    struct OakHandshakerFactoryBuilder {
        mock_oak_handshaker_factory: MockOakHandshakerFactory,
    }

    impl OakHandshakerFactoryBuilder {
        fn new() -> OakHandshakerFactoryBuilder {
            OakHandshakerFactoryBuilder {
                mock_oak_handshaker_factory: MockOakHandshakerFactory::new(),
            }
        }

        fn expect_get_client_oak_handshaker(
            mut self,
            mock_oak_handshaker: MockOakClientHandshaker,
        ) -> OakHandshakerFactoryBuilder {
            self.mock_oak_handshaker_factory
                .expect_get_client_oak_handshaker()
                .return_once(move || Box::new(mock_oak_handshaker));
            self
        }

        fn expect_get_server_oak_handshaker(
            mut self,
            mock_oak_handshaker: MockOakServerHandshaker,
        ) -> OakHandshakerFactoryBuilder {
            self.mock_oak_handshaker_factory
                .expect_get_server_oak_handshaker()
                .return_once(move || Box::new(mock_oak_handshaker));
            self
        }

        fn take(mut self) -> MockOakHandshakerFactory {
            mem::take(&mut self.mock_oak_handshaker_factory)
        }
    }

    struct OakClientHandshakerBuilder {
        mock_oak_client_handshaker: MockOakClientHandshaker,
    }

    impl OakClientHandshakerBuilder {
        fn new() -> OakClientHandshakerBuilder {
            OakClientHandshakerBuilder {
                mock_oak_client_handshaker: MockOakClientHandshaker::new(),
            }
        }

        fn expect_init(mut self) -> OakClientHandshakerBuilder {
            self.mock_oak_client_handshaker
                .expect_init()
                .once()
                .return_const(());
            self
        }

        fn expect_get_outgoing_message(
            mut self,
            message: Result<Option<OakHandshakeRequest>, PalError>,
        ) -> OakClientHandshakerBuilder {
            self.mock_oak_client_handshaker
                .expect_get_outgoing_message()
                .once()
                .return_once(move || message);
            self
        }

        fn expect_put_incoming_message(
            mut self,
            message: OakHandshakeResponse,
            result: Result<Option<()>, PalError>,
        ) -> OakClientHandshakerBuilder {
            self.mock_oak_client_handshaker
                .expect_put_incoming_message()
                .with(eq(message))
                .once()
                .return_once(move |_| result);
            self
        }

        fn expect_derive_session_keys(mut self) -> OakClientHandshakerBuilder {
            self.mock_oak_client_handshaker
                .expect_derive_session_keys()
                .once()
                .return_const(Some(SessionKeys {
                    request_key: vec![],
                    response_key: vec![],
                }));
            self
        }

        fn take(mut self) -> MockOakClientHandshaker {
            mem::take(&mut self.mock_oak_client_handshaker)
        }
    }

    struct OakServerHandshakerBuilder {
        mock_oak_server_handshaker: MockOakServerHandshaker,
    }

    impl OakServerHandshakerBuilder {
        fn new() -> OakServerHandshakerBuilder {
            OakServerHandshakerBuilder {
                mock_oak_server_handshaker: MockOakServerHandshaker::new(),
            }
        }

        fn expect_init(mut self) -> OakServerHandshakerBuilder {
            self.mock_oak_server_handshaker
                .expect_init()
                .once()
                .return_const(());
            self
        }

        fn expect_get_outgoing_message(
            mut self,
            message: Result<Option<OakHandshakeResponse>, PalError>,
        ) -> OakServerHandshakerBuilder {
            self.mock_oak_server_handshaker
                .expect_get_outgoing_message()
                .once()
                .return_once(move || message);
            self
        }

        fn expect_put_incoming_message(
            mut self,
            message: OakHandshakeRequest,
            result: Result<Option<()>, PalError>,
        ) -> OakServerHandshakerBuilder {
            self.mock_oak_server_handshaker
                .expect_put_incoming_message()
                .with(eq(message))
                .once()
                .return_once(move |_| result);
            self
        }

        fn expect_derive_session_keys(mut self) -> OakServerHandshakerBuilder {
            self.mock_oak_server_handshaker
                .expect_derive_session_keys()
                .once()
                .return_const(Some(SessionKeys {
                    request_key: vec![],
                    response_key: vec![],
                }));
            self
        }

        fn take(mut self) -> MockOakServerHandshaker {
            mem::take(&mut self.mock_oak_server_handshaker)
        }
    }

    #[test]
    fn test_client_session_success() {
        let self_replica_id = 11111;
        let peer_replica_id = 22222;
        let attest_request = create_attest_request(self_replica_id, peer_replica_id);
        let attest_response = create_attest_response(self_replica_id, peer_replica_id);
        let handshake_request = create_handshake_request(self_replica_id, peer_replica_id);
        let handshake_response = create_handshake_response(self_replica_id, peer_replica_id);
        let mock_client_attestation = ClientAttestationBuilder::new()
            .expect_get_outgoing_message(Ok(Some(OakAttestRequest::default())))
            .expect_put_incoming_message(OakAttestResponse::default(), Ok(Some(())))
            .expect_get_attestation_results()
            .take();
        let mock_attestation_provider = AttestationProviderBuilder::new()
            .expect_get_client_attestation(mock_client_attestation)
            .take();
        let mock_oak_client_handshaker = OakClientHandshakerBuilder::new()
            .expect_init()
            .expect_get_outgoing_message(Ok(Some(OakHandshakeRequest::default())))
            .expect_put_incoming_message(OakHandshakeResponse::default(), Ok(Some(())))
            .expect_derive_session_keys()
            .take();
        let mock_oak_handshaker_factory = OakHandshakerFactoryBuilder::new()
            .expect_get_client_oak_handshaker(mock_oak_client_handshaker)
            .take();
        let handshake_session_provider = DefaultHandshakeSessionProvider::new(
            Box::new(mock_attestation_provider),
            Box::new(mock_oak_handshaker_factory),
        );
        let mut client_handshake_session =
            handshake_session_provider.get(self_replica_id, peer_replica_id, Role::Initiator);

        assert_eq!(
            Ok(Some(attest_request)),
            client_handshake_session.take_out_message()
        );
        assert_eq!(Ok(None), client_handshake_session.take_out_message());
        assert_eq!(
            Ok(()),
            client_handshake_session.process_message(&attest_response)
        );
        assert_eq!(false, client_handshake_session.is_completed());
        assert_eq!(
            Ok(Some(handshake_request)),
            client_handshake_session.take_out_message()
        );
        assert_eq!(
            Ok(()),
            client_handshake_session.process_message(&handshake_response)
        );
        assert_eq!(true, client_handshake_session.is_completed());

        // Processing messages in COMPLETED state is ignored.
        assert_eq!(
            Ok(()),
            client_handshake_session.process_message(&attest_response)
        );
        assert_eq!(Ok(None), client_handshake_session.take_out_message());
    }

    #[test]
    fn test_client_session_get_attest_request_error() {
        let self_replica_id = 11111;
        let peer_replica_id = 22222;
        let attest_response = create_attest_response(self_replica_id, peer_replica_id);
        let mock_client_attestation = ClientAttestationBuilder::new()
            .expect_get_outgoing_message(Err(PalError::InvalidOperation))
            .take();
        let mut client_handshake_session = ClientHandshakeSession::new(
            create_logger(),
            self_replica_id,
            peer_replica_id,
            Box::new(mock_client_attestation),
            Box::new(MockOakClientHandshaker::new()),
        );

        assert_eq!(
            Err(PalError::Internal),
            client_handshake_session.take_out_message()
        );

        // Processing any messages in FAILED state should fail.
        assert_eq!(
            Err(PalError::Internal),
            client_handshake_session.process_message(&attest_response)
        );
        assert_eq!(
            Err(PalError::Internal),
            client_handshake_session.take_out_message()
        );
        assert_eq!(false, client_handshake_session.is_completed());
    }

    #[test]
    fn test_client_session_put_attest_response_error() {
        let self_replica_id = 11111;
        let peer_replica_id = 22222;
        let attest_request = create_attest_request(self_replica_id, peer_replica_id);
        let attest_response = create_attest_response(self_replica_id, peer_replica_id);
        let mock_client_attestation = ClientAttestationBuilder::new()
            .expect_get_outgoing_message(Ok(Some(OakAttestRequest::default())))
            .expect_put_incoming_message(
                OakAttestResponse::default(),
                Err(PalError::InvalidOperation),
            )
            .take();
        let mut client_handshake_session = ClientHandshakeSession::new(
            create_logger(),
            self_replica_id,
            peer_replica_id,
            Box::new(mock_client_attestation),
            Box::new(MockOakClientHandshaker::new()),
        );

        assert_eq!(
            Ok(Some(attest_request)),
            client_handshake_session.take_out_message()
        );
        assert_eq!(
            Err(PalError::Internal),
            client_handshake_session.process_message(&attest_response)
        );
    }

    #[test]
    fn test_client_session_get_handshake_request_error() {
        let self_replica_id = 11111;
        let peer_replica_id = 22222;
        let attest_request = create_attest_request(self_replica_id, peer_replica_id);
        let attest_response = create_attest_response(self_replica_id, peer_replica_id);
        let mock_client_attestation = ClientAttestationBuilder::new()
            .expect_get_outgoing_message(Ok(Some(OakAttestRequest::default())))
            .expect_put_incoming_message(OakAttestResponse::default(), Ok(Some(())))
            .expect_get_attestation_results()
            .take();
        let mock_oak_client_handshaker = OakClientHandshakerBuilder::new()
            .expect_init()
            .expect_get_outgoing_message(Err(PalError::InvalidOperation))
            .take();
        let mut client_handshake_session = ClientHandshakeSession::new(
            create_logger(),
            self_replica_id,
            peer_replica_id,
            Box::new(mock_client_attestation),
            Box::new(mock_oak_client_handshaker),
        );

        assert_eq!(
            Ok(Some(attest_request)),
            client_handshake_session.take_out_message()
        );
        assert_eq!(
            Ok(()),
            client_handshake_session.process_message(&attest_response)
        );
        assert_eq!(
            Err(PalError::Internal),
            client_handshake_session.take_out_message()
        );
    }

    #[test]
    fn test_client_session_put_handshake_response_error() {
        let self_replica_id = 11111;
        let peer_replica_id = 22222;
        let attest_request = create_attest_request(self_replica_id, peer_replica_id);
        let attest_response = create_attest_response(self_replica_id, peer_replica_id);
        let handshake_request = create_handshake_request(self_replica_id, peer_replica_id);
        let handshake_response = create_handshake_response(self_replica_id, peer_replica_id);
        let mock_client_attestation = ClientAttestationBuilder::new()
            .expect_get_outgoing_message(Ok(Some(OakAttestRequest::default())))
            .expect_put_incoming_message(OakAttestResponse::default(), Ok(Some(())))
            .expect_get_attestation_results()
            .take();
        let mock_oak_client_handshaker = OakClientHandshakerBuilder::new()
            .expect_init()
            .expect_get_outgoing_message(Ok(Some(OakHandshakeRequest::default())))
            .expect_put_incoming_message(
                OakHandshakeResponse::default(),
                Err(PalError::InvalidOperation),
            )
            .take();
        let mut client_handshake_session = ClientHandshakeSession::new(
            create_logger(),
            self_replica_id,
            peer_replica_id,
            Box::new(mock_client_attestation),
            Box::new(mock_oak_client_handshaker),
        );

        assert_eq!(
            Ok(Some(attest_request)),
            client_handshake_session.take_out_message()
        );
        assert_eq!(
            Ok(()),
            client_handshake_session.process_message(&attest_response)
        );
        assert_eq!(
            Ok(Some(handshake_request)),
            client_handshake_session.take_out_message()
        );
        assert_eq!(
            Err(PalError::Internal),
            client_handshake_session.process_message(&handshake_response)
        );
    }

    #[test]
    fn test_client_session_unknown_state_process_message() {
        let self_replica_id = 11111;
        let peer_replica_id = 22222;
        let attest_response = create_attest_response(self_replica_id, peer_replica_id);
        let mut client_handshake_session = ClientHandshakeSession::new(
            create_logger(),
            self_replica_id,
            peer_replica_id,
            Box::new(MockClientAttestation::new()),
            Box::new(MockOakClientHandshaker::new()),
        );

        assert_eq!(
            Err(PalError::Internal),
            client_handshake_session.process_message(&attest_response)
        );
    }

    #[test]
    fn test_client_session_attesting_state_invalid_message() {
        let self_replica_id = 11111;
        let peer_replica_id = 22222;
        let attest_request = create_attest_request(self_replica_id, peer_replica_id);
        let mock_client_attestation = ClientAttestationBuilder::new()
            .expect_get_outgoing_message(Ok(Some(OakAttestRequest::default())))
            .take();
        let mut client_handshake_session = ClientHandshakeSession::new(
            create_logger(),
            self_replica_id,
            peer_replica_id,
            Box::new(mock_client_attestation),
            Box::new(MockOakClientHandshaker::new()),
        );

        assert_eq!(
            Ok(Some(attest_request.clone())),
            client_handshake_session.take_out_message()
        );
        assert_eq!(
            Err(PalError::Internal),
            client_handshake_session.process_message(&attest_request)
        );
    }

    #[test]
    fn test_client_session_key_exchange_state_invalid_message() {
        let self_replica_id = 11111;
        let peer_replica_id = 22222;
        let attest_request = create_attest_request(self_replica_id, peer_replica_id);
        let attest_response = create_attest_response(self_replica_id, peer_replica_id);
        let mock_client_attestation = ClientAttestationBuilder::new()
            .expect_get_outgoing_message(Ok(Some(OakAttestRequest::default())))
            .expect_put_incoming_message(OakAttestResponse::default(), Ok(Some(())))
            .expect_get_attestation_results()
            .take();
        let mock_oak_client_handshaker = OakClientHandshakerBuilder::new().expect_init().take();
        let mut client_handshake_session = ClientHandshakeSession::new(
            create_logger(),
            self_replica_id,
            peer_replica_id,
            Box::new(mock_client_attestation),
            Box::new(mock_oak_client_handshaker),
        );

        assert_eq!(
            Ok(Some(attest_request)),
            client_handshake_session.take_out_message()
        );
        assert_eq!(
            Ok(()),
            client_handshake_session.process_message(&attest_response)
        );
        assert_eq!(
            Err(PalError::Internal),
            client_handshake_session.process_message(&attest_response)
        );
    }

    #[test]
    fn test_server_session_success() {
        let self_replica_id = 11111;
        let peer_replica_id = 22222;
        let attest_request = create_attest_request(self_replica_id, peer_replica_id);
        let attest_response = create_attest_response(self_replica_id, peer_replica_id);
        let handshake_request = create_handshake_request(self_replica_id, peer_replica_id);
        let handshake_response = create_handshake_response(self_replica_id, peer_replica_id);
        let mock_server_attestation = ServerAttestationBuilder::new()
            .expect_get_outgoing_message(Ok(Some(OakAttestResponse::default())))
            .expect_put_incoming_message(OakAttestRequest::default(), Ok(Some(())))
            .expect_get_attestation_results()
            .take();
        let mock_attestation_provider = AttestationProviderBuilder::new()
            .expect_get_server_attestation(mock_server_attestation)
            .take();
        let mock_oak_server_handshaker = OakServerHandshakerBuilder::new()
            .expect_init()
            .expect_get_outgoing_message(Ok(Some(OakHandshakeResponse::default())))
            .expect_put_incoming_message(OakHandshakeRequest::default(), Ok(Some(())))
            .expect_derive_session_keys()
            .take();
        let mock_oak_handshaker_factory = OakHandshakerFactoryBuilder::new()
            .expect_get_server_oak_handshaker(mock_oak_server_handshaker)
            .take();
        let handshake_session_provider = DefaultHandshakeSessionProvider::new(
            Box::new(mock_attestation_provider),
            Box::new(mock_oak_handshaker_factory),
        );
        let mut server_handshake_session =
            handshake_session_provider.get(self_replica_id, peer_replica_id, Role::Recipient);

        assert_eq!(Ok(None), server_handshake_session.take_out_message());
        assert_eq!(
            Ok(()),
            server_handshake_session.process_message(&attest_request)
        );
        assert_eq!(
            Ok(Some(attest_response)),
            server_handshake_session.take_out_message()
        );
        assert_eq!(false, server_handshake_session.is_completed());
        assert_eq!(
            Ok(()),
            server_handshake_session.process_message(&handshake_request)
        );
        assert_eq!(
            Ok(Some(handshake_response)),
            server_handshake_session.take_out_message()
        );
        assert_eq!(true, server_handshake_session.is_completed());

        // Processing messages in COMPLETED state is ignored.
        assert_eq!(
            Ok(()),
            server_handshake_session.process_message(&attest_request)
        );
        assert_eq!(Ok(None), server_handshake_session.take_out_message());
    }

    #[test]
    fn test_server_session_put_attest_request_error() {
        let self_replica_id = 11111;
        let peer_replica_id = 22222;
        let attest_request = create_attest_request(self_replica_id, peer_replica_id);
        let mock_server_attestation = ServerAttestationBuilder::new()
            .expect_put_incoming_message(
                OakAttestRequest::default(),
                Err(PalError::InvalidOperation),
            )
            .take();
        let mut server_handshake_session = ServerHandshakeSession::new(
            create_logger(),
            self_replica_id,
            peer_replica_id,
            Box::new(mock_server_attestation),
            Box::new(MockOakServerHandshaker::new()),
        );

        assert_eq!(
            Err(PalError::Internal),
            server_handshake_session.process_message(&attest_request)
        );

        // Processing any messages in FAILED state should fail.
        assert_eq!(
            Err(PalError::Internal),
            server_handshake_session.process_message(&attest_request)
        );
        assert_eq!(
            Err(PalError::Internal),
            server_handshake_session.take_out_message()
        );
        assert_eq!(false, server_handshake_session.is_completed());
    }

    #[test]
    fn test_server_session_get_attest_response_error() {
        let self_replica_id = 11111;
        let peer_replica_id = 22222;
        let attest_request = create_attest_request(self_replica_id, peer_replica_id);
        let mock_server_attestation = ServerAttestationBuilder::new()
            .expect_put_incoming_message(OakAttestRequest::default(), Ok(Some(())))
            .expect_get_outgoing_message(Err(PalError::InvalidOperation))
            .take();
        let mut server_handshake_session = ServerHandshakeSession::new(
            create_logger(),
            self_replica_id,
            peer_replica_id,
            Box::new(mock_server_attestation),
            Box::new(MockOakServerHandshaker::new()),
        );

        assert_eq!(
            Ok(()),
            server_handshake_session.process_message(&attest_request)
        );
        assert_eq!(
            Err(PalError::Internal),
            server_handshake_session.take_out_message()
        );
    }

    #[test]
    fn test_server_session_put_handshake_request_error() {
        let self_replica_id = 11111;
        let peer_replica_id = 22222;
        let attest_request = create_attest_request(self_replica_id, peer_replica_id);
        let attest_response = create_attest_response(self_replica_id, peer_replica_id);
        let handshake_request = create_handshake_request(self_replica_id, peer_replica_id);
        let mock_server_attestation = ServerAttestationBuilder::new()
            .expect_get_outgoing_message(Ok(Some(OakAttestResponse::default())))
            .expect_put_incoming_message(OakAttestRequest::default(), Ok(Some(())))
            .expect_get_attestation_results()
            .take();
        let mock_oak_server_handshaker = OakServerHandshakerBuilder::new()
            .expect_init()
            .expect_put_incoming_message(
                OakHandshakeRequest::default(),
                Err(PalError::InvalidOperation),
            )
            .take();
        let mut server_handshake_session = ServerHandshakeSession::new(
            create_logger(),
            self_replica_id,
            peer_replica_id,
            Box::new(mock_server_attestation),
            Box::new(mock_oak_server_handshaker),
        );

        assert_eq!(
            Ok(()),
            server_handshake_session.process_message(&attest_request)
        );
        assert_eq!(
            Ok(Some(attest_response)),
            server_handshake_session.take_out_message()
        );
        assert_eq!(
            Err(PalError::Internal),
            server_handshake_session.process_message(&handshake_request)
        );
    }

    #[test]
    fn test_server_session_get_handshake_response_error() {
        let self_replica_id = 11111;
        let peer_replica_id = 22222;
        let attest_request = create_attest_request(self_replica_id, peer_replica_id);
        let attest_response = create_attest_response(self_replica_id, peer_replica_id);
        let handshake_request = create_handshake_request(self_replica_id, peer_replica_id);
        let mock_server_attestation = ServerAttestationBuilder::new()
            .expect_get_outgoing_message(Ok(Some(OakAttestResponse::default())))
            .expect_put_incoming_message(OakAttestRequest::default(), Ok(Some(())))
            .expect_get_attestation_results()
            .take();
        let mock_oak_server_handshaker = OakServerHandshakerBuilder::new()
            .expect_init()
            .expect_put_incoming_message(OakHandshakeRequest::default(), Ok(Some(())))
            .expect_get_outgoing_message(Err(PalError::InvalidOperation))
            .take();
        let mut server_handshake_session = ServerHandshakeSession::new(
            create_logger(),
            self_replica_id,
            peer_replica_id,
            Box::new(mock_server_attestation),
            Box::new(mock_oak_server_handshaker),
        );

        assert_eq!(
            Ok(()),
            server_handshake_session.process_message(&attest_request)
        );
        assert_eq!(
            Ok(Some(attest_response)),
            server_handshake_session.take_out_message()
        );
        assert_eq!(
            Ok(()),
            server_handshake_session.process_message(&handshake_request)
        );
        assert_eq!(
            Err(PalError::Internal),
            server_handshake_session.take_out_message()
        );
    }

    #[test]
    fn test_server_session_unknown_state_invalid_message() {
        let self_replica_id = 11111;
        let peer_replica_id = 22222;
        let attest_response = create_attest_response(self_replica_id, peer_replica_id);
        let mut server_handshake_session = ServerHandshakeSession::new(
            create_logger(),
            self_replica_id,
            peer_replica_id,
            Box::new(MockServerAttestation::new()),
            Box::new(MockOakServerHandshaker::new()),
        );

        assert_eq!(
            Err(PalError::Internal),
            server_handshake_session.process_message(&attest_response)
        );
    }

    #[test]
    fn test_server_session_attesting_state_process_message() {
        let self_replica_id = 11111;
        let peer_replica_id = 22222;
        let attest_request = create_attest_request(self_replica_id, peer_replica_id);
        let mock_server_attestation = ServerAttestationBuilder::new()
            .expect_put_incoming_message(OakAttestRequest::default(), Ok(Some(())))
            .take();
        let mut server_handshake_session = ServerHandshakeSession::new(
            create_logger(),
            self_replica_id,
            peer_replica_id,
            Box::new(mock_server_attestation),
            Box::new(MockOakServerHandshaker::new()),
        );

        assert_eq!(
            Ok(()),
            server_handshake_session.process_message(&attest_request)
        );
        assert_eq!(
            Err(PalError::Internal),
            server_handshake_session.process_message(&attest_request)
        );
    }

    #[test]
    fn test_server_session_key_exchange_state_invalid_message() {
        let self_replica_id = 11111;
        let peer_replica_id = 22222;
        let attest_request = create_attest_request(self_replica_id, peer_replica_id);
        let attest_response = create_attest_response(self_replica_id, peer_replica_id);
        let mock_server_attestation = ServerAttestationBuilder::new()
            .expect_get_outgoing_message(Ok(Some(OakAttestResponse::default())))
            .expect_put_incoming_message(OakAttestRequest::default(), Ok(Some(())))
            .expect_get_attestation_results()
            .take();
        let mock_oak_server_handshaker = OakServerHandshakerBuilder::new().expect_init().take();
        let mut server_handshake_session = ServerHandshakeSession::new(
            create_logger(),
            self_replica_id,
            peer_replica_id,
            Box::new(mock_server_attestation),
            Box::new(mock_oak_server_handshaker),
        );

        assert_eq!(
            Ok(()),
            server_handshake_session.process_message(&attest_request)
        );
        assert_eq!(
            Ok(Some(attest_response)),
            server_handshake_session.take_out_message()
        );
        assert_eq!(
            Err(PalError::Internal),
            server_handshake_session.process_message(&attest_request)
        );
    }
}
