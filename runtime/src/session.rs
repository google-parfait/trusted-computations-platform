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
use alloc::vec::Vec;
use anyhow::Result;
use oak_crypto::encryptor::Encryptor;
use oak_proto_rust::oak::crypto::v1::SessionKeys;
use oak_proto_rust::oak::session::v1::{PlaintextMessage, SessionRequest, SessionResponse};
use oak_session::attestation::AttestationType;
use oak_session::config::{EncryptorProvider, SessionConfig};
use oak_session::encryptors::UnorderedChannelEncryptor;
use oak_session::handshake::HandshakeType;
use oak_session::session::{ClientSession, ServerSession, Session};
use oak_session::ProtocolEngine;

const UNORDERED_CHANNEL_ENCRYPTOR_WINDOW_SIZE: u32 = 3;

// Factory class for creating instances of `OakClientSession` and `OakServerSession`
// traits.
pub trait OakSessionFactory {
    // Returns OakClientSession, responsible for initiating handshake between 2 raft
    // replicas using Noise protocol.
    fn get_oak_client_session(&self) -> Result<Box<dyn OakClientSession>>;
    // Returns OakServerSession, recipient of the handshake message from the client.
    fn get_oak_server_session(&self) -> Result<Box<dyn OakServerSession>>;
}

/// Session representing an end-to-end encrypted bidirectional streaming session
/// between two raft peers.
pub trait OakSession<I, O> {
    /// Puts a message received from the peer into the state-machine changing
    /// its state.
    fn put_incoming_message(&mut self, incoming_message: &I) -> Result<Option<()>>;

    /// Gets the next message that needs to be sent to the peer.
    fn get_outgoing_message(&mut self) -> Result<Option<O>>;

    /// Checks whether session is ready to send and receive encrypted messages.
    fn is_open(&self) -> bool;

    /// Encrypts `plaintext` and stashes it to be sent to the peer later.
    fn write(&mut self, plaintext: &[u8]) -> Result<()>;

    /// Reads an encrypted message from the peer and decrypts it.
    fn read(&mut self) -> Result<Option<Vec<u8>>>;
}

pub trait OakClientSession = OakSession<SessionResponse, SessionRequest>;
pub trait OakServerSession = OakSession<SessionRequest, SessionResponse>;

// Default implementation of `OakSessionFactory`.
pub struct DefaultOakSessionFactory {}

impl OakSessionFactory for DefaultOakSessionFactory {
    fn get_oak_client_session(&self) -> Result<Box<dyn OakClientSession>> {
        let client_session = DefaultOakClientSession::create()?;
        Ok(Box::new(client_session))
    }

    fn get_oak_server_session(&self) -> Result<Box<dyn OakServerSession>> {
        let server_session = DefaultOakServerSession::create()?;
        Ok(Box::new(server_session))
    }
}

struct DefaultEncryptorProvider;

impl EncryptorProvider for DefaultEncryptorProvider {
    fn provide_encryptor(
        &self,
        session_keys: SessionKeys,
    ) -> Result<Box<dyn Encryptor>, anyhow::Error> {
        TryInto::<UnorderedChannelEncryptor>::try_into((
            session_keys,
            UNORDERED_CHANNEL_ENCRYPTOR_WINDOW_SIZE,
        ))
        .map(|v| Box::new(v) as Box<dyn Encryptor>)
    }
}

// Default implementation of `OakClientSession`.
pub struct DefaultOakClientSession {
    inner: ClientSession,
}

impl DefaultOakClientSession {
    pub fn create() -> Result<Self> {
        Ok(Self {
            inner: ClientSession::create(
                SessionConfig::builder(AttestationType::Unattested, HandshakeType::NoiseNN)
                    .set_encryption_provider(Box::new(DefaultEncryptorProvider))
                    .build(),
            )?,
        })
    }
}

impl OakSession<SessionResponse, SessionRequest> for DefaultOakClientSession {
    fn get_outgoing_message(&mut self) -> Result<Option<SessionRequest>> {
        self.inner.get_outgoing_message()
    }

    fn put_incoming_message(&mut self, incoming_message: &SessionResponse) -> Result<Option<()>> {
        self.inner.put_incoming_message(incoming_message)
    }

    fn is_open(&self) -> bool {
        self.inner.is_open()
    }

    fn write(&mut self, plaintext: &[u8]) -> Result<()> {
        self.inner.write(&PlaintextMessage {
            plaintext: plaintext.to_vec(),
        })
    }

    fn read(&mut self) -> Result<Option<Vec<u8>>> {
        let plaintext_message = self.inner.read()?;
        Ok(plaintext_message.map(|m| m.plaintext))
    }
}

// Default implementation of `OakServerSession`.
pub struct DefaultOakServerSession {
    inner: ServerSession,
}

impl DefaultOakServerSession {
    pub fn create() -> Result<Self> {
        Ok(Self {
            inner: ServerSession::new(
                SessionConfig::builder(AttestationType::Unattested, HandshakeType::NoiseNN)
                    .set_encryption_provider(Box::new(DefaultEncryptorProvider))
                    .build(),
            ),
        })
    }
}

impl OakSession<SessionRequest, SessionResponse> for DefaultOakServerSession {
    fn get_outgoing_message(&mut self) -> Result<Option<SessionResponse>> {
        self.inner.get_outgoing_message()
    }

    fn put_incoming_message(&mut self, incoming_message: &SessionRequest) -> Result<Option<()>> {
        self.inner.put_incoming_message(incoming_message)
    }

    fn is_open(&self) -> bool {
        self.inner.is_open()
    }

    fn write(&mut self, plaintext: &[u8]) -> Result<()> {
        self.inner.write(&PlaintextMessage {
            plaintext: plaintext.to_vec(),
        })
    }

    fn read(&mut self) -> Result<Option<Vec<u8>>> {
        let plaintext_message = self.inner.read()?;
        Ok(plaintext_message.map(|m| m.plaintext))
    }
}

#[cfg(all(test, feature = "std"))]
mod test {
    use oak_crypto::encryptor::Encryptor;
    use oak_crypto::{encryptor::Payload, noise_handshake::SYMMETRIC_KEY_LEN};
    use oak_proto_rust::oak::crypto::v1::SessionKeys;
    use oak_session::config::EncryptorProvider;

    use crate::session::UnorderedChannelEncryptor;

    use super::DefaultEncryptorProvider;

    fn clone_payload(payload: &Payload) -> Payload {
        Payload {
            message: payload.message.clone(),
            nonce: payload.nonce.clone(),
            aad: payload.aad.clone(),
        }
    }

    #[test]
    fn test_encryption_decryption_ordered() {
        let key_1 = &[42u8; SYMMETRIC_KEY_LEN];
        let key_2 = &[52u8; SYMMETRIC_KEY_LEN];
        let test_messages = vec![vec![1u8, 2u8, 3u8, 4u8], vec![4u8, 3u8, 2u8, 1u8], vec![]];
        let default_encryption_provider = DefaultEncryptorProvider {};
        let mut replica_1 = default_encryption_provider
            .provide_encryptor(SessionKeys {
                request_key: key_1.to_vec(),
                response_key: key_2.to_vec(),
            })
            .unwrap();
        let mut replica_2 = default_encryption_provider
            .provide_encryptor(SessionKeys {
                request_key: key_2.to_vec(),
                response_key: key_1.to_vec(),
            })
            .unwrap();

        for message in &test_messages {
            let payload = Payload {
                message: message.to_vec(),
                nonce: None,
                aad: None,
            };
            let encrypted_payload = replica_1.encrypt(&payload).unwrap();
            let plaintext = replica_2.decrypt(&encrypted_payload).unwrap().message;
            assert_eq!(message, &plaintext);
        }
    }

    #[test]
    fn test_encryption_decryption_unordered() {
        let key_1 = &[42u8; SYMMETRIC_KEY_LEN];
        let key_2 = &[52u8; SYMMETRIC_KEY_LEN];
        let test_messages = vec![
            vec![1u8, 2u8, 3u8, 4u8],
            vec![4u8, 3u8, 2u8, 1u8],
            vec![1u8, 1u8, 1u8, 1u8],
            vec![2u8, 2u8, 2u8, 2u8],
            vec![3u8, 3u8, 3u8, 3u8],
            vec![4u8, 4u8, 4u8, 4u8],
        ];
        let default_encryption_provider = DefaultEncryptorProvider {};
        let mut replica_1 = default_encryption_provider
            .provide_encryptor(SessionKeys {
                request_key: key_1.to_vec(),
                response_key: key_2.to_vec(),
            })
            .unwrap();
        let mut replica_2 = default_encryption_provider
            .provide_encryptor(SessionKeys {
                request_key: key_2.to_vec(),
                response_key: key_1.to_vec(),
            })
            .unwrap();
        let mut encrypted_payloads = vec![];
        for i in 0..test_messages.len() {
            encrypted_payloads.push(
                replica_1
                    .encrypt(&Payload {
                        message: test_messages[i].to_vec(),
                        nonce: None,
                        aad: None,
                    })
                    .unwrap(),
            );
        }

        // Out-of-order decryption
        assert_eq!(
            test_messages[3],
            replica_2
                .decrypt(&clone_payload(&encrypted_payloads[3]))
                .unwrap()
                .message
        );
        // Decrypting messages within the window should be ok.
        assert_eq!(
            test_messages[1],
            replica_2
                .decrypt(&clone_payload(&encrypted_payloads[1]))
                .unwrap()
                .message
        );
        assert_eq!(
            test_messages[2],
            replica_2
                .decrypt(&clone_payload(&encrypted_payloads[2]))
                .unwrap()
                .message
        );
        // Replaying message should fail.
        assert_eq!(
            true,
            replica_2
                .decrypt(&clone_payload(&encrypted_payloads[3]))
                .is_err()
        );
        assert_eq!(
            true,
            replica_2
                .decrypt(&clone_payload(&encrypted_payloads[2]))
                .is_err()
        );
        assert_eq!(
            true,
            replica_2
                .decrypt(&clone_payload(&encrypted_payloads[1]))
                .is_err()
        );
        // Decrypting messages outside the window should fail.
        assert_eq!(
            true,
            replica_2
                .decrypt(&clone_payload(&encrypted_payloads[0]))
                .is_err()
        );

        // Decrypt more messages in order.
        assert_eq!(
            test_messages[4],
            replica_2
                .decrypt(&clone_payload(&encrypted_payloads[4]))
                .unwrap()
                .message
        );
        assert_eq!(
            test_messages[5],
            replica_2
                .decrypt(&clone_payload(&encrypted_payloads[5]))
                .unwrap()
                .message
        );
    }
}
