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
use anyhow::{anyhow, Result};
use oak_crypto::encryptor::{Encryptor, Payload};
use oak_crypto::noise_handshake::{
    aes_256_gcm_open_in_place, aes_256_gcm_seal_in_place, Nonce, NONCE_LEN, SYMMETRIC_KEY_LEN,
};
use oak_proto_rust::oak::crypto::v1::SessionKeys;
use oak_proto_rust::oak::session::v1::{
    session_request::Request, session_response::Response, SessionRequest, SessionResponse,
};
use oak_session::attestation::AttestationType;
use oak_session::config::SessionConfig;
use oak_session::handshake::HandshakeType;
use oak_session::session::{ClientSession, ServerSession};

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

// Default implementation of `OakClientSession`.
pub struct DefaultOakClientSession {
    _inner: ClientSession,
    incoming_ciphertext: Option<Vec<u8>>,
    outgoing_ciphertext: Option<Vec<u8>>,
}

impl DefaultOakClientSession {
    pub fn create() -> Result<Self> {
        // TODO: Revisit config parameters.
        Ok(Self {
            _inner: ClientSession::create(
                SessionConfig::builder(AttestationType::Bidirectional, HandshakeType::NoiseNN)
                    .build(),
            )?,
            incoming_ciphertext: None,
            outgoing_ciphertext: None,
        })
    }
}

impl OakSession<SessionResponse, SessionRequest> for DefaultOakClientSession {
    // TODO: Delegate to `inner` once the implementation is complete on Oak side.
    fn get_outgoing_message(&mut self) -> Result<Option<SessionRequest>> {
        if self.outgoing_ciphertext.is_some() {
            return Ok(Some(SessionRequest {
                request: Some(Request::Ciphertext(
                    self.outgoing_ciphertext.take().unwrap(),
                )),
            }));
        }
        Ok(Some(SessionRequest { request: None }))
    }

    fn put_incoming_message(&mut self, incoming_message: &SessionResponse) -> Result<Option<()>> {
        match &incoming_message.response {
            Some(Response::Ciphertext(ciphertext)) => {
                self.incoming_ciphertext = Some(ciphertext.to_vec());
            }
            _ => {}
        }
        Ok(Some(()))
    }

    fn is_open(&self) -> bool {
        true
    }

    fn write(&mut self, plaintext: &[u8]) -> Result<()> {
        self.outgoing_ciphertext = Some(plaintext.to_vec());
        Ok(())
    }

    fn read(&mut self) -> Result<Option<Vec<u8>>> {
        Ok(self.incoming_ciphertext.take())
    }
}

// Default implementation of `OakServerSession`.
pub struct DefaultOakServerSession {
    _inner: ServerSession,
    incoming_ciphertext: Option<Vec<u8>>,
    outgoing_ciphertext: Option<Vec<u8>>,
}

impl DefaultOakServerSession {
    pub fn create() -> Result<Self> {
        Ok(Self {
            _inner: ServerSession::new(
                SessionConfig::builder(AttestationType::Bidirectional, HandshakeType::NoiseNN)
                    .set_encryption_provider(Box::new(|sk| {
                        <SessionKeys as TryInto<UnorderedChannelEncryptor>>::try_into(sk)
                            .map(|v| Box::new(v) as Box<dyn Encryptor>)
                    }))
                    .build(),
            ),
            incoming_ciphertext: None,
            outgoing_ciphertext: None,
        })
    }
}

impl OakSession<SessionRequest, SessionResponse> for DefaultOakServerSession {
    // TODO: Delegate to `inner` once the implementation is complete on Oak side.
    fn get_outgoing_message(&mut self) -> Result<Option<SessionResponse>> {
        if self.outgoing_ciphertext.is_some() {
            return Ok(Some(SessionResponse {
                response: Some(Response::Ciphertext(
                    self.outgoing_ciphertext.take().unwrap(),
                )),
            }));
        }
        Ok(Some(SessionResponse { response: None }))
    }

    fn put_incoming_message(&mut self, incoming_message: &SessionRequest) -> Result<Option<()>> {
        match &incoming_message.request {
            Some(Request::Ciphertext(ciphertext)) => {
                self.incoming_ciphertext = Some(ciphertext.to_vec());
            }
            _ => {}
        }
        Ok(Some(()))
    }

    fn is_open(&self) -> bool {
        true
    }

    fn write(&mut self, plaintext: &[u8]) -> Result<()> {
        self.outgoing_ciphertext = Some(plaintext.to_vec());
        Ok(())
    }

    fn read(&mut self) -> Result<Option<Vec<u8>>> {
        Ok(self.incoming_ciphertext.take())
    }
}

// Custom encryptor to use with the Noise protocol capable of handling
// unordered and dropped messages.
// TODO: Move to oak repo once the implementation is stable and
// verified.
pub struct UnorderedChannelEncryptor {
    read_key: [u8; SYMMETRIC_KEY_LEN],
    write_key: [u8; SYMMETRIC_KEY_LEN],
    write_nonce: Nonce,
}

impl UnorderedChannelEncryptor {
    fn new(read_key: &[u8; SYMMETRIC_KEY_LEN], write_key: &[u8; SYMMETRIC_KEY_LEN]) -> Self {
        Self {
            read_key: *read_key,
            write_key: *write_key,
            write_nonce: Nonce { nonce: 0 },
        }
    }
}
impl Encryptor for UnorderedChannelEncryptor {
    fn encrypt(&mut self, payload: Payload) -> Result<Payload> {
        const PADDING_GRANULARITY: usize = 32;
        let plaintext = payload.message.as_slice();

        let mut padded_size: usize = plaintext.len();
        // AES GCM is limited to encrypting 64GiB of data in a single AEAD invocation.
        // 256MiB is just a sane upper limit on message size, which greatly exceeds
        // the noise specified 64KiB, which will be too restrictive for our use cases.
        if padded_size > (1usize << 28) {
            return Err(anyhow!(
                "Data exceeds max allowed size 256MiB, Actual Size: {:?},",
                padded_size
            ));
        }
        padded_size += 1; // padding-length byte

        // This is standard low-level bit manipulation to round up to the nearest
        // multiple of PADDING_GRANULARITY.  We know PADDING_GRANULARRITY is a
        // power of 2, so we compute the mask with !(PADDING_GRANULARITY - 1).
        // If padded_size is not already a multiple of PADDING_GRANULARITY, then
        // padded_size will not change.  Otherwise, it is rounded up to the next
        // multiple of PADDED_GRANULARITY.
        padded_size = (padded_size + PADDING_GRANULARITY - 1) & !(PADDING_GRANULARITY - 1);

        let mut padded_encrypt_data = Vec::with_capacity(padded_size);
        padded_encrypt_data.extend_from_slice(plaintext);
        padded_encrypt_data.resize(padded_size, 0u8);
        let num_zeros = padded_size - plaintext.len() - 1;
        padded_encrypt_data[padded_size - 1] = num_zeros as u8;

        let next_nonce = &self
            .write_nonce
            .next()
            .map_err(|e| anyhow!("Failed to get nonce error: {e:#?}"))?;
        aes_256_gcm_seal_in_place(&self.write_key, next_nonce, &[], &mut padded_encrypt_data);

        Ok(Payload {
            message: padded_encrypt_data,
            nonce: Some(next_nonce.to_vec()),
            aad: None,
        })
    }

    fn decrypt(&mut self, payload: Payload) -> Result<Payload> {
        let ciphertext = payload.message.as_slice();
        let nonce: [u8; NONCE_LEN] = payload
            .nonce
            .unwrap()
            .try_into()
            .map_err(|e| anyhow!("Failed to extract nonce error: {e:#?}"))?;
        let plaintext =
            aes_256_gcm_open_in_place(&self.read_key, &nonce, &[], Vec::from(ciphertext))
                .map_err(|()| anyhow!("Failed to decrypt message."))?;

        // Plaintext must have a padding byte, and the unpadded length must be
        // at least one.
        if plaintext.is_empty() || (plaintext[plaintext.len() - 1] as usize) >= plaintext.len() {
            return Err(anyhow!("Decryption padding failed."));
        }
        let unpadded_length = plaintext.len() - (plaintext[plaintext.len() - 1] as usize);
        Ok(Payload {
            message: Vec::from(&plaintext[0..unpadded_length - 1]),
            nonce: None,
            aad: None,
        })
    }
}

impl TryFrom<SessionKeys> for UnorderedChannelEncryptor {
    type Error = anyhow::Error;

    fn try_from(sk: SessionKeys) -> Result<Self, Self::Error> {
        Ok(UnorderedChannelEncryptor::new(
            sk.response_key
                .as_slice()
                .try_into()
                .map_err(|e| anyhow!("Unexpected format of the read key: {e:#?}"))?,
            sk.request_key
                .as_slice()
                .try_into()
                .map_err(|e| anyhow!("Unexpected format of the read key: {e:#?}"))?,
        ))
    }
}

#[cfg(all(test, feature = "std"))]
mod test {
    use oak_crypto::encryptor::Encryptor;
    use oak_crypto::{encryptor::Payload, noise_handshake::SYMMETRIC_KEY_LEN};

    use crate::session::UnorderedChannelEncryptor;

    #[test]
    fn test_encryption_decryption_ordered() {
        let key_1 = &[42u8; SYMMETRIC_KEY_LEN];
        let key_2 = &[52u8; SYMMETRIC_KEY_LEN];
        let test_messages = vec![vec![1u8, 2u8, 3u8, 4u8], vec![4u8, 3u8, 2u8, 1u8], vec![]];
        let mut replica_1 = UnorderedChannelEncryptor::new(key_1, key_2);
        let mut replica_2 = UnorderedChannelEncryptor::new(key_2, key_1);

        for message in &test_messages {
            let payload = Payload {
                message: message.to_vec(),
                nonce: None,
                aad: None,
            };
            let encrypted_payload = replica_1.encrypt(payload).unwrap();
            let plaintext = replica_2.decrypt(encrypted_payload).unwrap().message;
            assert_eq!(message, &plaintext);
        }
    }

    #[test]
    fn test_encryption_decryption_unordered() {
        let key_1 = &[42u8; SYMMETRIC_KEY_LEN];
        let key_2 = &[52u8; SYMMETRIC_KEY_LEN];
        let test_messages = vec![vec![1u8, 2u8, 3u8, 4u8], vec![4u8, 3u8, 2u8, 1u8]];
        let mut replica_1 = UnorderedChannelEncryptor::new(key_1, key_2);
        let mut replica_2 = UnorderedChannelEncryptor::new(key_2, key_1);

        let encrypted_payload_1 = replica_1
            .encrypt(Payload {
                message: test_messages[0].to_vec(),
                nonce: None,
                aad: None,
            })
            .unwrap();
        let encrypted_payload_2 = replica_1
            .encrypt(Payload {
                message: test_messages[1].to_vec(),
                nonce: None,
                aad: None,
            })
            .unwrap();

        // Decrypt in reverse order
        let plaintext_2 = replica_2.decrypt(encrypted_payload_2).unwrap().message;
        let plaintext_1 = replica_2.decrypt(encrypted_payload_1).unwrap().message;
        assert_eq!(test_messages[0], plaintext_1);
        assert_eq!(test_messages[1], plaintext_2);
    }
}
