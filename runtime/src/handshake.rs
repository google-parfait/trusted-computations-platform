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

use alloc::boxed::Box;
use slog::{debug, warn, Logger};
use tcp_proto::runtime::endpoint::{
    secure_channel_handshake::{
        noise_protocol, noise_protocol::initiator_request::Message::AttestRequest,
        noise_protocol::recipient_response::Message::AttestResponse,
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
    attestation: Box<dyn ClientAttestation>,
    _oak_handshaker: Box<dyn OakClientHandshaker>,
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
            attestation,
            _oak_handshaker: oak_handshaker,
            state: State::Unknown,
        }
    }
}

impl HandshakeSession for ClientHandshakeSession {
    fn process_message(&mut self, message: &SecureChannelHandshake) -> Result<(), PalError> {
        return match self.state {
            State::Unknown => {
                warn!(
                    self.logger,
                    "Unexpected handshake message {:?} received in state Unknown.", message
                );
                self.state = State::Failed;
                Err(PalError::Internal)
            }
            State::Attesting => {
                if let Some(Encryption::NoiseProtocol(ref noise_protocol)) = message.encryption
                    && let Some(RecipientResponse(ref recipient_response)) = noise_protocol.message
                    && let Some(AttestResponse(ref attest_response)) = recipient_response.message
                {
                    self.attestation
                        .put_incoming_message(attest_response)
                        .or_else(|err| {
                            warn!(
                                self.logger,
                                "Failed to put incoming message in state Attesting {}.", err
                            );
                            self.state = State::Failed;
                            Err(PalError::Internal)
                        })?;
                    // TODO: Integrate with KeyExchange state instead of Completing.
                    self.state = State::Completed;
                    Ok(())
                } else {
                    warn!(
                        self.logger,
                        "Unexpected handshake message {:?} received in state Attesting.", message
                    );
                    self.state = State::Failed;
                    Err(PalError::Internal)
                }
            }
            State::KeyExchange => todo!(),
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
                if let Ok(Some(attest_request)) = self.attestation.get_outgoing_message() {
                    self.state = State::Attesting;
                    Ok(Some(SecureChannelHandshake {
                        recipient_replica_id: self.peer_replica_id,
                        sender_replica_id: self.self_replica_id,
                        encryption: Some(Encryption::NoiseProtocol(NoiseProtocol {
                            message: Some(InitiatorRequest(noise_protocol::InitiatorRequest {
                                message: Some(AttestRequest(attest_request)),
                            })),
                        })),
                    }))
                } else {
                    warn!(
                        self.logger,
                        "No outgoing `AttestRequest` message retrieved in state Unknown."
                    );
                    self.state = State::Failed;
                    Err(PalError::Internal)
                }
            }
            State::Attesting => {
                debug!(
                    self.logger,
                    "No messages to take out while state is still Attesting."
                );
                Ok(None)
            }
            State::KeyExchange => todo!(),
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
    attestation: Box<dyn ServerAttestation>,
    _oak_handshaker: Box<dyn OakServerHandshaker>,
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
            attestation,
            _oak_handshaker: oak_handshaker,
            state: State::Unknown,
        }
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
                    self.attestation
                        .put_incoming_message(attest_request)
                        .or_else(|err| {
                            warn!(
                                self.logger,
                                "Failed to put incoming message in state Unknown {}.", err
                            );
                            self.state = State::Failed;
                            Err(PalError::Internal)
                        })?;
                    self.state = State::Attesting;
                    Ok(())
                } else {
                    warn!(
                        self.logger,
                        "Unexpected handshake message {:?} received in state Unknown.", message
                    );
                    self.state = State::Failed;
                    Err(PalError::Internal)
                }
            }
            State::Attesting => {
                warn!(
                    self.logger,
                    "Unexpected handshake message {:?} received in state Attesting.", message
                );
                self.state = State::Failed;
                Err(PalError::Internal)
            }
            State::KeyExchange => todo!(),
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
                if let Ok(Some(attest_response)) = self.attestation.get_outgoing_message() {
                    // TODO: Integrate with state KeyExchange instead of Completing.
                    self.state = State::Completed;
                    Ok(Some(SecureChannelHandshake {
                        recipient_replica_id: self.peer_replica_id,
                        sender_replica_id: self.self_replica_id,
                        encryption: Some(Encryption::NoiseProtocol(NoiseProtocol {
                            message: Some(RecipientResponse(noise_protocol::RecipientResponse {
                                message: Some(AttestResponse(attest_response)),
                            })),
                        })),
                    }))
                } else {
                    warn!(
                        self.logger,
                        "No outgoing `AttestResponse` message retrieved in state Attesting."
                    );
                    self.state = State::Failed;
                    Err(PalError::Internal)
                }
            }
            State::KeyExchange => todo!(),
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
    use core::mem;
    use mock::{
        MockAttestationProvider, MockClientAttestation, MockOakClientHandshaker,
        MockOakHandshakerFactory, MockOakServerHandshaker, MockServerAttestation,
    };
    use oak_proto_rust::oak::session::v1::{
        AttestRequest as OakAttestRequest, AttestResponse as OakAttestResponse,
    };
    use platform::PalError;
    use tcp_proto::runtime::endpoint::{
        secure_channel_handshake::{
            noise_protocol, noise_protocol::initiator_request::Message::AttestRequest,
            noise_protocol::recipient_response::Message::AttestResponse,
            noise_protocol::Message::InitiatorRequest, noise_protocol::Message::RecipientResponse,
            Encryption, NoiseProtocol,
        },
        *,
    };

    fn create_handshake_attest_request(
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

    fn create_handshake_attest_response(
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

    #[test]
    fn test_client_session_success() {
        let self_replica_id = 11111;
        let peer_replica_id = 22222;
        let handshake_attest_request =
            create_handshake_attest_request(self_replica_id, peer_replica_id);
        let handshake_attest_response =
            create_handshake_attest_response(self_replica_id, peer_replica_id);
        let mock_client_attestation = ClientAttestationBuilder::new()
            .expect_get_outgoing_message(Ok(Some(OakAttestRequest::default())))
            .expect_put_incoming_message(OakAttestResponse::default(), Ok(Some(())))
            .take();
        let mock_attestation_provider = AttestationProviderBuilder::new()
            .expect_get_client_attestation(mock_client_attestation)
            .take();
        let mock_oak_handshaker_factory = OakHandshakerFactoryBuilder::new()
            .expect_get_client_oak_handshaker(MockOakClientHandshaker::new())
            .take();
        let handshake_session_provider = DefaultHandshakeSessionProvider::new(
            Box::new(mock_attestation_provider),
            Box::new(mock_oak_handshaker_factory),
        );
        let mut client_handshake_session =
            handshake_session_provider.get(self_replica_id, peer_replica_id, Role::Initiator);

        assert_eq!(
            Ok(Some(handshake_attest_request.clone())),
            client_handshake_session.take_out_message()
        );
        assert_eq!(Ok(None), client_handshake_session.take_out_message());
        assert_eq!(
            Ok(()),
            client_handshake_session.process_message(&handshake_attest_response)
        );
        assert_eq!(true, client_handshake_session.is_completed());

        // Processing messages in COMPLETED state is ignored.
        assert_eq!(
            Ok(()),
            client_handshake_session.process_message(&handshake_attest_response)
        );
        assert_eq!(Ok(None), client_handshake_session.take_out_message());
    }

    #[test]
    fn test_client_session_get_attest_request_error() {
        let self_replica_id = 11111;
        let peer_replica_id = 22222;
        let handshake_attest_response =
            create_handshake_attest_response(self_replica_id, peer_replica_id);
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
            client_handshake_session.process_message(&handshake_attest_response)
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
        let handshake_attest_request =
            create_handshake_attest_request(self_replica_id, peer_replica_id);
        let handshake_attest_response =
            create_handshake_attest_response(self_replica_id, peer_replica_id);
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
            Ok(Some(handshake_attest_request.clone())),
            client_handshake_session.take_out_message()
        );
        assert_eq!(
            Err(PalError::Internal),
            client_handshake_session.process_message(&handshake_attest_response)
        );
    }

    #[test]
    fn test_client_session_unknown_state_process_message() {
        let self_replica_id = 11111;
        let peer_replica_id = 22222;
        let handshake_attest_request =
            create_handshake_attest_request(self_replica_id, peer_replica_id);
        let handshake_attest_response =
            create_handshake_attest_response(self_replica_id, peer_replica_id);
        let mut client_handshake_session = ClientHandshakeSession::new(
            create_logger(),
            self_replica_id,
            peer_replica_id,
            Box::new(MockClientAttestation::new()),
            Box::new(MockOakClientHandshaker::new()),
        );

        assert_eq!(
            Err(PalError::Internal),
            client_handshake_session.process_message(&handshake_attest_response)
        );
    }

    #[test]
    fn test_client_session_attesting_state_invalid_message() {
        let self_replica_id = 11111;
        let peer_replica_id = 22222;
        let handshake_attest_request =
            create_handshake_attest_request(self_replica_id, peer_replica_id);
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
            Ok(Some(handshake_attest_request.clone())),
            client_handshake_session.take_out_message()
        );
        assert_eq!(
            Err(PalError::Internal),
            client_handshake_session.process_message(&handshake_attest_request)
        );
    }

    #[test]
    fn test_server_session_success() {
        let self_replica_id = 11111;
        let peer_replica_id = 22222;
        let handshake_attest_request =
            create_handshake_attest_request(self_replica_id, peer_replica_id);
        let handshake_attest_response =
            create_handshake_attest_response(self_replica_id, peer_replica_id);
        let mock_server_attestation = ServerAttestationBuilder::new()
            .expect_get_outgoing_message(Ok(Some(OakAttestResponse::default())))
            .expect_put_incoming_message(OakAttestRequest::default(), Ok(Some(())))
            .take();
        let mock_attestation_provider = AttestationProviderBuilder::new()
            .expect_get_server_attestation(mock_server_attestation)
            .take();
        let mock_oak_handshaker_factory = OakHandshakerFactoryBuilder::new()
            .expect_get_server_oak_handshaker(MockOakServerHandshaker::new())
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
            server_handshake_session.process_message(&handshake_attest_request)
        );
        assert_eq!(
            Ok(Some(handshake_attest_response.clone())),
            server_handshake_session.take_out_message()
        );
        assert_eq!(true, server_handshake_session.is_completed());

        // Processing messages in COMPLETED state is ignored.
        assert_eq!(
            Ok(()),
            server_handshake_session.process_message(&handshake_attest_response)
        );
        assert_eq!(Ok(None), server_handshake_session.take_out_message());
    }

    #[test]
    fn test_server_session_put_attest_request_error() {
        let self_replica_id = 11111;
        let peer_replica_id = 22222;
        let handshake_attest_request =
            create_handshake_attest_request(self_replica_id, peer_replica_id);
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
            server_handshake_session.process_message(&handshake_attest_request)
        );

        // Processing any messages in FAILED state should fail.
        assert_eq!(
            Err(PalError::Internal),
            server_handshake_session.process_message(&handshake_attest_request)
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
        let handshake_attest_request =
            create_handshake_attest_request(self_replica_id, peer_replica_id);
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
            server_handshake_session.process_message(&handshake_attest_request)
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
        let handshake_attest_response =
            create_handshake_attest_response(self_replica_id, peer_replica_id);
        let mut server_handshake_session = ServerHandshakeSession::new(
            create_logger(),
            self_replica_id,
            peer_replica_id,
            Box::new(MockServerAttestation::new()),
            Box::new(MockOakServerHandshaker::new()),
        );

        assert_eq!(
            Err(PalError::Internal),
            server_handshake_session.process_message(&handshake_attest_response)
        );
    }

    #[test]
    fn test_server_session_attesting_state_process_message() {
        let self_replica_id = 11111;
        let peer_replica_id = 22222;
        let handshake_attest_request =
            create_handshake_attest_request(self_replica_id, peer_replica_id);
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
            server_handshake_session.process_message(&handshake_attest_request)
        );
        assert_eq!(
            Err(PalError::Internal),
            server_handshake_session.process_message(&handshake_attest_request)
        );
    }
}
