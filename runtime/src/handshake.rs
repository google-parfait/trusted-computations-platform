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

use crate::encryptor::{DefaultClientEncryptor, DefaultServerEncryptor, Encryptor};
use crate::logger::log::create_logger;
use crate::session::{OakClientSession, OakServerSession, OakSessionFactory};
use alloc::sync::Arc;
use alloc::{boxed::Box, format};
use anyhow::{anyhow, Error, Result};
use oak_attestation_verification_types::util::Clock;
use oak_proto_rust::oak::attestation::v1::{Endorsements, ReferenceValues};
use slog::{info, o, warn, Logger};
use tcp_proto::runtime::endpoint::{
    secure_channel_handshake::{
        noise_protocol, noise_protocol::initiator_request::Message::SessionRequest,
        noise_protocol::recipient_response::Message::SessionResponse,
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
    // Initialize the HandshakeSessionProvider.
    fn init(
        &mut self,
        logger: Logger,
        clock: Arc<dyn Clock>,
        reference_values: ReferenceValues,
        endorsements: Endorsements,
    );

    /// Get a HandshakeSession object for a given role.
    fn get(
        &self,
        self_replica_id: u64,
        peer_replica_id: u64,
        role: Role,
    ) -> Result<Box<dyn HandshakeSession>>;
}

/// Responsible for establishing a handshake between two raft replicas.
/// This includes performing mutual attestation and using noise protocol
/// to exchange symmetric keys which can be later used for encrypting/decrypting
/// payloads.
pub trait HandshakeSession {
    // Process an incoming SecureChanneHandshake message.
    fn process_message(&mut self, message: SecureChannelHandshake) -> Result<()>;

    // Take out any pending handshake messages that need to be sent out for this session.
    // Returns None if no such message exists.
    fn take_out_message(&mut self) -> Result<Option<SecureChannelHandshake>>;

    // Returns true if this handshake session is now complete.
    fn is_completed(&self) -> bool;

    // This method `consumes` the HandshakeSession and returns the Encryptor which can be
    // used for encrypting/decrypting any subsequent messages between the 2 replicas once
    // handshake has successfully completed.
    // Returns `None` if `is_completed` is false. This should ideally be invoked when
    // `is_completed` returns true.
    fn get_encryptor(self: Box<Self>) -> Option<Box<dyn Encryptor>>;
}

pub struct DefaultHandshakeSessionProvider {
    logger: Logger,
    session_factory: Box<dyn OakSessionFactory>,
}

impl DefaultHandshakeSessionProvider {
    pub fn new(session_factory: Box<dyn OakSessionFactory>) -> Self {
        Self {
            logger: create_logger(),
            session_factory,
        }
    }
}
impl HandshakeSessionProvider for DefaultHandshakeSessionProvider {
    fn init(
        &mut self,
        logger: Logger,
        clock: Arc<dyn Clock>,
        reference_values: ReferenceValues,
        endorsements: Endorsements,
    ) {
        self.logger = logger;
        self.session_factory
            .init(clock, reference_values, endorsements);
    }

    fn get(
        &self,
        self_replica_id: u64,
        peer_replica_id: u64,
        role: Role,
    ) -> Result<Box<dyn HandshakeSession>> {
        match role {
            Role::Initiator => Ok(Box::new(ClientHandshakeSession::new(
                self.logger.new(o!("type" => "ClientHandshakeSession")),
                self_replica_id,
                peer_replica_id,
                self.session_factory.get_oak_client_session()?,
            ))),
            Role::Recipient => Ok(Box::new(ServerHandshakeSession::new(
                self.logger.new(o!("type" => "ServerHandshakeSession")),
                self_replica_id,
                peer_replica_id,
                self.session_factory.get_oak_server_session()?,
            ))),
        }
    }
}

#[derive(PartialEq)]
enum State {
    // State is unknown.
    Unknown,
    // Handshake has been initiated. This stage may include multiple steps such as
    // verifying remote attestation and performing crypto key exchange using Noise
    // protocol.
    Initiated,
    // Handshake completed successfully.
    Completed,
    // Handshake failed due to internal errors or failed attestation.
    Failed,
}

pub struct ClientHandshakeSession {
    logger: Logger,
    self_replica_id: u64,
    peer_replica_id: u64,
    session: Box<dyn OakClientSession>,
    state: State,
}

impl ClientHandshakeSession {
    fn new(
        logger: Logger,
        self_replica_id: u64,
        peer_replica_id: u64,
        session: Box<dyn OakClientSession>,
    ) -> Self {
        Self {
            logger,
            self_replica_id,
            peer_replica_id,
            session,
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

    fn transition_to_failed(&mut self, err: &Error) {
        warn!(self.logger, "{:?}", err);
        self.state = State::Failed;
    }

    fn get_session_request(&mut self) -> Result<Option<SecureChannelHandshake>> {
        if let Some(session_request) = self.session.get_outgoing_message()? {
            Ok(Some(self.create_secure_channel_handshake(
                noise_protocol::InitiatorRequest {
                    message: Some(SessionRequest(session_request)),
                },
            )))
        } else {
            info!(
                self.logger,
                "No outgoing `SessionRequest` message retrieved.",
            );
            Ok(None)
        }
    }
}

impl HandshakeSession for ClientHandshakeSession {
    fn process_message(&mut self, message: SecureChannelHandshake) -> Result<()> {
        return match self.state {
            State::Unknown => {
                let err = anyhow!(format!(
                    "Unexpected handshake message {:?} received in state Unknown.",
                    message
                ));
                self.transition_to_failed(&err);
                Err(err)
            }
            State::Initiated => {
                if let SecureChannelHandshake {
                    encryption:
                        Some(Encryption::NoiseProtocol(NoiseProtocol {
                            message:
                                Some(RecipientResponse(noise_protocol::RecipientResponse {
                                    message: Some(SessionResponse(session_response)),
                                    ..
                                })),
                            ..
                        })),
                    ..
                } = message
                {
                    info!(
                        self.logger,
                        "ClientHandshakeSession: Replica {} received SessionResponse from replica {}",
                        self.self_replica_id,
                        self.peer_replica_id
                    );
                    self.session
                        .put_incoming_message(session_response)
                        .inspect_err(|err| self.transition_to_failed(err))?;
                    Ok(())
                } else {
                    let err = anyhow!(format!(
                        "Unexpected handshake message {:?} received in state Initiated.",
                        message
                    ));
                    self.transition_to_failed(&err);
                    Err(err)
                }
            }
            State::Completed => {
                info!(
                    self.logger,
                    "Ignoring message since handshake already completed."
                );
                Ok(())
            }
            State::Failed => {
                warn!(self.logger, "Cannot process messages in state Failed.");
                Ok(())
            }
        };
    }

    fn take_out_message(&mut self) -> Result<Option<SecureChannelHandshake>> {
        return match self.state {
            State::Unknown => {
                info!(
                    self.logger,
                    "ClientHandshakeSession: Replica {} initiating SessionRequest with peer {}",
                    self.self_replica_id,
                    self.peer_replica_id
                );
                let session_request = self
                    .get_session_request()
                    .inspect_err(|err| self.transition_to_failed(err))?;
                self.state = State::Initiated;
                Ok(session_request)
            }
            State::Initiated => {
                let mut result = None;
                let session_request = self
                    .get_session_request()
                    .inspect_err(|err| self.transition_to_failed(err))?;
                if session_request.is_some() {
                    info!(
                            self.logger,
                            "ClientHandshakeSession: Replica {} retrieving next SessionRequest for peer {}",
                            self.self_replica_id,
                            self.peer_replica_id
                        );
                    result = session_request;
                }

                if self.session.is_open() {
                    info!(
                        self.logger,
                        "ClientHandshakeSession: {} completed handshake with peer {}",
                        self.self_replica_id,
                        self.peer_replica_id
                    );
                    self.state = State::Completed;
                }
                Ok(result)
            }
            State::Completed => {
                info!(
                    self.logger,
                    "No messages to take out since handshake already completed."
                );
                Ok(None)
            }
            State::Failed => {
                warn!(self.logger, "Cannot take out messages in state Failed.");
                Ok(None)
            }
        };
    }

    fn is_completed(&self) -> bool {
        self.state == State::Completed
    }

    fn get_encryptor(self: Box<Self>) -> Option<Box<dyn Encryptor>> {
        if self.state != State::Completed {
            return None;
        }

        Some(Box::new(DefaultClientEncryptor::new(self.session)))
    }
}

pub struct ServerHandshakeSession {
    logger: Logger,
    self_replica_id: u64,
    peer_replica_id: u64,
    session: Box<dyn OakServerSession>,
    state: State,
}

impl ServerHandshakeSession {
    fn new(
        logger: Logger,
        self_replica_id: u64,
        peer_replica_id: u64,
        session: Box<dyn OakServerSession>,
    ) -> Self {
        Self {
            logger,
            self_replica_id,
            peer_replica_id,
            session,
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

    fn transition_to_failed(&mut self, err: &Error) {
        warn!(self.logger, "{}", err);
        self.state = State::Failed;
    }

    fn get_session_response(&mut self) -> Result<Option<SecureChannelHandshake>> {
        if let Some(session_response) = self.session.get_outgoing_message()? {
            Ok(Some(self.create_secure_channel_handshake(
                noise_protocol::RecipientResponse {
                    message: Some(SessionResponse(session_response)),
                },
            )))
        } else {
            info!(
                self.logger,
                "No outgoing `SessionResponse` message retrieved.",
            );
            Ok(None)
        }
    }
}

impl HandshakeSession for ServerHandshakeSession {
    fn process_message(&mut self, message: SecureChannelHandshake) -> Result<()> {
        return match self.state {
            State::Unknown | State::Initiated => {
                if let SecureChannelHandshake {
                    encryption:
                        Some(Encryption::NoiseProtocol(NoiseProtocol {
                            message:
                                Some(InitiatorRequest(noise_protocol::InitiatorRequest {
                                    message: Some(SessionRequest(session_request)),
                                    ..
                                })),
                            ..
                        })),
                    ..
                } = message
                {
                    info!(
                        self.logger,
                        "ServerHandshakeSession: Replica {} received SessionRequest from peer {}",
                        self.self_replica_id,
                        self.peer_replica_id
                    );
                    self.session
                        .put_incoming_message(session_request)
                        .inspect_err(|err| self.transition_to_failed(err))?;
                    if self.state != State::Initiated {
                        self.state = State::Initiated;
                    }
                    Ok(())
                } else {
                    let err = anyhow!(format!(
                        "Unexpected handshake message {:?} received in state Unknown.",
                        message
                    ));
                    self.transition_to_failed(&err);
                    Err(err)
                }
            }
            State::Completed => {
                info!(
                    self.logger,
                    "Ignoring message since handshake already completed."
                );
                Ok(())
            }
            State::Failed => {
                warn!(self.logger, "Cannot process messages in state Failed.");
                Ok(())
            }
        };
    }

    fn take_out_message(&mut self) -> Result<Option<SecureChannelHandshake>> {
        return match self.state {
            State::Unknown => {
                info!(self.logger, "No messages to take out in state Unknown");
                Ok(None)
            }
            State::Initiated => {
                info!(
                    self.logger,
                    "ServerHandshakeSession: Replica {} responding with SessionResponse to peer {}",
                    self.self_replica_id,
                    self.peer_replica_id
                );
                let session_response = self
                    .get_session_response()
                    .inspect_err(|err| self.transition_to_failed(err))?;
                if self.session.is_open() {
                    info!(
                        self.logger,
                        "ServerHandshakeSession: {} completed handshake with peer {}",
                        self.self_replica_id,
                        self.peer_replica_id,
                    );
                    self.state = State::Completed;
                }
                Ok(session_response)
            }
            State::Completed => {
                info!(
                    self.logger,
                    "No messages to take out since handshake already completed."
                );
                Ok(None)
            }
            State::Failed => {
                warn!(self.logger, "Cannot take out messages in state Failed.");
                Ok(None)
            }
        };
    }

    fn is_completed(&self) -> bool {
        self.state == State::Completed
    }

    fn get_encryptor(self: Box<Self>) -> Option<Box<dyn Encryptor>> {
        if self.state != State::Completed {
            return None;
        }

        Some(Box::new(DefaultServerEncryptor::new(self.session)))
    }
}

#[cfg(all(test, feature = "std"))]
mod test {
    extern crate mockall;

    use self::mockall::predicate::{always, eq};
    use crate::handshake::{
        ClientHandshakeSession, DefaultHandshakeSessionProvider, HandshakeSession,
        HandshakeSessionProvider, Role, ServerHandshakeSession,
    };
    use crate::logger::log::create_logger;
    use crate::mock::{
        MockClock, MockOakClientSession, MockOakServerSession, MockOakSessionFactory,
    };
    use alloc::sync::Arc;
    use anyhow::{anyhow, Result};
    use core::mem;
    use oak_proto_rust::oak::attestation::v1::{Endorsements, ReferenceValues};
    use oak_proto_rust::oak::session::v1::{
        SessionRequest as OakSessionRequest, SessionResponse as OakSessionResponse,
    };
    use tcp_proto::runtime::endpoint::{
        secure_channel_handshake::{
            noise_protocol, noise_protocol::initiator_request::Message::SessionRequest,
            noise_protocol::recipient_response::Message::SessionResponse,
            noise_protocol::Message::InitiatorRequest, noise_protocol::Message::RecipientResponse,
            Encryption, NoiseProtocol,
        },
        *,
    };

    fn create_session_request(
        sender_replica_id: u64,
        recipient_replica_id: u64,
    ) -> SecureChannelHandshake {
        SecureChannelHandshake {
            recipient_replica_id,
            sender_replica_id,
            encryption: Some(Encryption::NoiseProtocol(NoiseProtocol {
                message: Some(InitiatorRequest(noise_protocol::InitiatorRequest {
                    message: Some(SessionRequest(OakSessionRequest::default())),
                })),
            })),
        }
    }

    fn create_session_response(
        sender_replica_id: u64,
        recipient_replica_id: u64,
    ) -> SecureChannelHandshake {
        SecureChannelHandshake {
            recipient_replica_id,
            sender_replica_id,
            encryption: Some(Encryption::NoiseProtocol(NoiseProtocol {
                message: Some(RecipientResponse(noise_protocol::RecipientResponse {
                    message: Some(SessionResponse(OakSessionResponse::default())),
                })),
            })),
        }
    }

    struct OakSessionFactoryBuilder {
        mock_oak_session_factory: MockOakSessionFactory,
    }

    impl OakSessionFactoryBuilder {
        fn new() -> OakSessionFactoryBuilder {
            OakSessionFactoryBuilder {
                mock_oak_session_factory: MockOakSessionFactory::new(),
            }
        }

        fn expect_init(
            mut self,
            reference_values: ReferenceValues,
            endorsements: Endorsements,
        ) -> OakSessionFactoryBuilder {
            self.mock_oak_session_factory
                .expect_init()
                .with(always(), eq(reference_values), eq(endorsements))
                .once()
                .return_const(());
            self
        }

        fn expect_get_oak_client_session(
            mut self,
            mock_oak_session: MockOakClientSession,
        ) -> OakSessionFactoryBuilder {
            self.mock_oak_session_factory
                .expect_get_oak_client_session()
                .return_once(move || Ok(Box::new(mock_oak_session)));
            self
        }

        fn expect_get_oak_server_session(
            mut self,
            mock_oak_session: MockOakServerSession,
        ) -> OakSessionFactoryBuilder {
            self.mock_oak_session_factory
                .expect_get_oak_server_session()
                .return_once(move || Ok(Box::new(mock_oak_session)));
            self
        }

        fn take(mut self) -> MockOakSessionFactory {
            mem::take(&mut self.mock_oak_session_factory)
        }
    }

    struct OakClientSessionBuilder {
        mock_oak_client_session: MockOakClientSession,
    }

    impl OakClientSessionBuilder {
        fn new() -> OakClientSessionBuilder {
            OakClientSessionBuilder {
                mock_oak_client_session: MockOakClientSession::new(),
            }
        }

        fn expect_get_outgoing_message(
            mut self,
            message: Result<Option<OakSessionRequest>>,
        ) -> OakClientSessionBuilder {
            self.mock_oak_client_session
                .expect_get_outgoing_message()
                .once()
                .return_once(move || message);
            self
        }

        fn expect_put_incoming_message(
            mut self,
            message: OakSessionResponse,
            result: Result<Option<()>>,
        ) -> OakClientSessionBuilder {
            self.mock_oak_client_session
                .expect_put_incoming_message()
                .with(eq(message))
                .once()
                .return_once(move |_| result);
            self
        }

        fn expect_is_open(mut self, is_open: bool) -> OakClientSessionBuilder {
            self.mock_oak_client_session
                .expect_is_open()
                .once()
                .return_const(is_open);
            self
        }

        fn take(mut self) -> MockOakClientSession {
            mem::take(&mut self.mock_oak_client_session)
        }
    }

    struct OakServerSessionBuilder {
        mock_oak_server_session: MockOakServerSession,
    }

    impl OakServerSessionBuilder {
        fn new() -> OakServerSessionBuilder {
            OakServerSessionBuilder {
                mock_oak_server_session: MockOakServerSession::new(),
            }
        }

        fn expect_get_outgoing_message(
            mut self,
            message: Result<Option<OakSessionResponse>>,
        ) -> OakServerSessionBuilder {
            self.mock_oak_server_session
                .expect_get_outgoing_message()
                .once()
                .return_once(move || message);
            self
        }

        fn expect_put_incoming_message(
            mut self,
            message: OakSessionRequest,
            result: Result<Option<()>>,
        ) -> OakServerSessionBuilder {
            self.mock_oak_server_session
                .expect_put_incoming_message()
                .with(eq(message))
                .once()
                .return_once(move |_| result);
            self
        }

        fn expect_is_open(mut self, is_open: bool) -> OakServerSessionBuilder {
            self.mock_oak_server_session
                .expect_is_open()
                .once()
                .return_const(is_open);
            self
        }

        fn take(mut self) -> MockOakServerSession {
            mem::take(&mut self.mock_oak_server_session)
        }
    }

    #[test]
    fn test_client_session_success() {
        let self_replica_id = 11111;
        let peer_replica_id = 22222;
        let session_request = create_session_request(self_replica_id, peer_replica_id);
        let session_response = create_session_response(self_replica_id, peer_replica_id);
        let mock_oak_client_session = OakClientSessionBuilder::new()
            .expect_get_outgoing_message(Ok(Some(OakSessionRequest::default())))
            .expect_is_open(false)
            .expect_get_outgoing_message(Ok(None))
            .expect_put_incoming_message(OakSessionResponse::default(), Ok(Some(())))
            .expect_is_open(true)
            .expect_get_outgoing_message(Ok(None))
            .take();
        let mock_oak_session_factory = OakSessionFactoryBuilder::new()
            .expect_init(ReferenceValues::default(), Endorsements::default())
            .expect_get_oak_client_session(mock_oak_client_session)
            .take();
        let mut handshake_session_provider =
            DefaultHandshakeSessionProvider::new(Box::new(mock_oak_session_factory));
        handshake_session_provider.init(
            create_logger(),
            Arc::new(MockClock::new()),
            ReferenceValues::default(),
            Endorsements::default(),
        );
        let mut client_handshake_session = handshake_session_provider
            .get(self_replica_id, peer_replica_id, Role::Initiator)
            .unwrap();

        assert_eq!(
            Some(session_request),
            client_handshake_session.take_out_message().unwrap()
        );
        assert_eq!(None, client_handshake_session.take_out_message().unwrap());
        assert_eq!(
            true,
            client_handshake_session
                .process_message(session_response.clone())
                .is_ok()
        );
        assert_eq!(None, client_handshake_session.take_out_message().unwrap());
        assert_eq!(true, client_handshake_session.is_completed());

        // Processing messages in COMPLETED state is ignored.
        assert_eq!(
            true,
            client_handshake_session
                .process_message(session_response)
                .is_ok()
        );
        assert_eq!(None, client_handshake_session.take_out_message().unwrap());

        assert!(Box::new(client_handshake_session).get_encryptor().is_some());
    }

    #[test]
    fn test_client_session_get_session_request_error() {
        let self_replica_id = 11111;
        let peer_replica_id = 22222;
        let mock_oak_client_session = OakClientSessionBuilder::new()
            .expect_get_outgoing_message(Err(anyhow!("Error")))
            .take();
        let mut client_handshake_session = ClientHandshakeSession::new(
            create_logger(),
            self_replica_id,
            peer_replica_id,
            Box::new(mock_oak_client_session),
        );

        assert_eq!(true, client_handshake_session.take_out_message().is_err());
    }

    #[test]
    fn test_client_session_put_session_response_error() {
        let self_replica_id = 11111;
        let peer_replica_id = 22222;
        let session_request = create_session_request(self_replica_id, peer_replica_id);
        let session_response = create_session_response(self_replica_id, peer_replica_id);
        let mock_oak_client_session = OakClientSessionBuilder::new()
            .expect_get_outgoing_message(Ok(Some(OakSessionRequest::default())))
            .expect_put_incoming_message(OakSessionResponse::default(), Err(anyhow!("Error")))
            .take();
        let mut client_handshake_session = ClientHandshakeSession::new(
            create_logger(),
            self_replica_id,
            peer_replica_id,
            Box::new(mock_oak_client_session),
        );

        assert_eq!(
            Some(session_request),
            client_handshake_session.take_out_message().unwrap()
        );
        assert_eq!(
            true,
            client_handshake_session
                .process_message(session_response)
                .is_err()
        );
    }

    #[test]
    fn test_client_session_unknown_state_process_message() {
        let self_replica_id = 11111;
        let peer_replica_id = 22222;
        let session_response = create_session_response(self_replica_id, peer_replica_id);
        let mut client_handshake_session = ClientHandshakeSession::new(
            create_logger(),
            self_replica_id,
            peer_replica_id,
            Box::new(MockOakClientSession::new()),
        );

        assert_eq!(
            true,
            client_handshake_session
                .process_message(session_response)
                .is_err()
        );
    }

    #[test]
    fn test_client_session_initiating_state_invalid_message() {
        let self_replica_id = 11111;
        let peer_replica_id = 22222;
        let session_request = create_session_request(self_replica_id, peer_replica_id);
        let mock_oak_client_session = OakClientSessionBuilder::new()
            .expect_get_outgoing_message(Ok(Some(OakSessionRequest::default())))
            .take();
        let mut client_handshake_session = ClientHandshakeSession::new(
            create_logger(),
            self_replica_id,
            peer_replica_id,
            Box::new(mock_oak_client_session),
        );

        assert_eq!(
            Some(session_request.clone()),
            client_handshake_session.take_out_message().unwrap()
        );
        assert_eq!(
            true,
            client_handshake_session
                .process_message(session_request)
                .is_err()
        );
    }

    #[test]
    fn test_server_session_success() {
        let self_replica_id = 11111;
        let peer_replica_id = 22222;
        let session_request = create_session_request(self_replica_id, peer_replica_id);
        let session_response = create_session_response(self_replica_id, peer_replica_id);
        let mock_oak_server_session = OakServerSessionBuilder::new()
            .expect_get_outgoing_message(Ok(Some(OakSessionResponse::default())))
            .expect_put_incoming_message(OakSessionRequest::default(), Ok(Some(())))
            .expect_is_open(true)
            .take();
        let mock_oak_session_factory = OakSessionFactoryBuilder::new()
            .expect_init(ReferenceValues::default(), Endorsements::default())
            .expect_get_oak_server_session(mock_oak_server_session)
            .take();
        let mut handshake_session_provider =
            DefaultHandshakeSessionProvider::new(Box::new(mock_oak_session_factory));
        handshake_session_provider.init(
            create_logger(),
            Arc::new(MockClock::new()),
            ReferenceValues::default(),
            Endorsements::default(),
        );
        let clock = MockClock::new();
        let mut server_handshake_session = handshake_session_provider
            .get(self_replica_id, peer_replica_id, Role::Recipient)
            .unwrap();

        assert_eq!(None, server_handshake_session.take_out_message().unwrap());
        assert_eq!(
            true,
            server_handshake_session
                .process_message(session_request.clone())
                .is_ok()
        );
        assert_eq!(
            Some(session_response),
            server_handshake_session.take_out_message().unwrap()
        );
        assert_eq!(true, server_handshake_session.is_completed());

        // Processing messages in COMPLETED state is ignored.
        assert_eq!(
            true,
            server_handshake_session
                .process_message(session_request)
                .is_ok()
        );
        assert_eq!(None, server_handshake_session.take_out_message().unwrap());

        assert!(Box::new(server_handshake_session).get_encryptor().is_some());
    }

    #[test]
    fn test_server_session_put_session_request_error() {
        let self_replica_id = 11111;
        let peer_replica_id = 22222;
        let session_request = create_session_request(self_replica_id, peer_replica_id);
        let mock_oak_server_session = OakServerSessionBuilder::new()
            .expect_put_incoming_message(OakSessionRequest::default(), Err(anyhow!("Error")))
            .take();
        let mut server_handshake_session = ServerHandshakeSession::new(
            create_logger(),
            self_replica_id,
            peer_replica_id,
            Box::new(mock_oak_server_session),
        );

        assert_eq!(
            true,
            server_handshake_session
                .process_message(session_request)
                .is_err()
        );
    }

    #[test]
    fn test_server_session_get_session_response_error() {
        let self_replica_id = 11111;
        let peer_replica_id = 22222;
        let session_request = create_session_request(self_replica_id, peer_replica_id);
        let mock_oak_server_session = OakServerSessionBuilder::new()
            .expect_put_incoming_message(OakSessionRequest::default(), Ok(Some(())))
            .expect_get_outgoing_message(Err(anyhow!("Error")))
            .take();
        let mut server_handshake_session = ServerHandshakeSession::new(
            create_logger(),
            self_replica_id,
            peer_replica_id,
            Box::new(mock_oak_server_session),
        );

        assert_eq!(
            true,
            server_handshake_session
                .process_message(session_request)
                .is_ok()
        );
        assert_eq!(true, server_handshake_session.take_out_message().is_err());
    }

    #[test]
    fn test_server_session_unknown_state_invalid_message() {
        let self_replica_id = 11111;
        let peer_replica_id = 22222;
        let session_response = create_session_response(self_replica_id, peer_replica_id);
        let mut server_handshake_session = ServerHandshakeSession::new(
            create_logger(),
            self_replica_id,
            peer_replica_id,
            Box::new(MockOakServerSession::new()),
        );

        assert_eq!(
            true,
            server_handshake_session
                .process_message(session_response)
                .is_err()
        );
    }

    #[test]
    fn test_server_session_initiating_state_invalid_message() {
        let self_replica_id = 11111;
        let peer_replica_id = 22222;
        let session_request = create_session_request(self_replica_id, peer_replica_id);
        let session_response = create_session_response(self_replica_id, peer_replica_id);
        let mock_oak_server_session = OakServerSessionBuilder::new()
            .expect_put_incoming_message(OakSessionRequest::default(), Ok(Some(())))
            .expect_get_outgoing_message(Ok(Some(OakSessionResponse::default())))
            .expect_is_open(false)
            .take();
        let mut server_handshake_session = ServerHandshakeSession::new(
            create_logger(),
            self_replica_id,
            peer_replica_id,
            Box::new(mock_oak_server_session),
        );

        assert_eq!(
            true,
            server_handshake_session
                .process_message(session_request)
                .is_ok()
        );
        assert_eq!(
            Some(session_response.clone()),
            server_handshake_session.take_out_message().unwrap()
        );
        assert_eq!(
            true,
            server_handshake_session
                .process_message(session_response)
                .is_err()
        );
    }
}
