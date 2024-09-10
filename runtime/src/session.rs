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
use hashbrown::HashSet;
use oak_crypto::encryptor::{Encryptor, Payload};
use oak_crypto::noise_handshake::{
    aes_256_gcm_open_in_place, aes_256_gcm_seal_in_place, Nonce, NONCE_LEN, SYMMETRIC_KEY_LEN,
};
use oak_proto_rust::oak::crypto::v1::SessionKeys;
use oak_proto_rust::oak::session::v1::{PlaintextMessage, SessionRequest, SessionResponse};
use oak_session::attestation::AttestationType;
use oak_session::config::SessionConfig;
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

// Default implementation of `OakClientSession`.
pub struct DefaultOakClientSession {
    inner: ClientSession,
}

impl DefaultOakClientSession {
    pub fn create() -> Result<Self> {
        // TODO: Revisit config parameters.
        Ok(Self {
            inner: ClientSession::create(
                SessionConfig::builder(AttestationType::Bidirectional, HandshakeType::NoiseNN)
                    .set_encryption_provider(Box::new(|sk| {
                        <SessionKeys as TryInto<UnorderedChannelEncryptor>>::try_into(sk)
                            .map(|v| Box::new(v) as Box<dyn Encryptor>)
                    }))
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
                SessionConfig::builder(AttestationType::Bidirectional, HandshakeType::NoiseNN)
                    .set_encryption_provider(Box::new(|sk| {
                        <SessionKeys as TryInto<UnorderedChannelEncryptor>>::try_into(sk)
                            .map(|v| Box::new(v) as Box<dyn Encryptor>)
                    }))
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

// Custom encryptor to use with the Noise protocol capable of handling
// unordered and dropped messages.
// TODO: Move to oak repo once the implementation is stable and
// verified.
pub struct UnorderedChannelEncryptor {
    read_key: [u8; SYMMETRIC_KEY_LEN],
    write_key: [u8; SYMMETRIC_KEY_LEN],
    write_nonce: Nonce,
    // The current furthest read nonce seen so far.
    furthest_read_nonce: u32,
    // Window size to ratchet receiving nonces in order to avoid receiving
    // nonces way too far in the past.
    window_size: u32,
    // Buffered read nonces with max capacity equivalent to `window_size` i.e.
    // nonces lower than (`furthest_read_nonce-window_size`) will not be decrypted.
    buffered_read_nonces: HashSet<u32>,
}

impl UnorderedChannelEncryptor {
    fn new(
        read_key: &[u8; SYMMETRIC_KEY_LEN],
        write_key: &[u8; SYMMETRIC_KEY_LEN],
        window_size: u32,
    ) -> Self {
        Self {
            read_key: *read_key,
            write_key: *write_key,
            write_nonce: Nonce { nonce: 1 },
            furthest_read_nonce: 0,
            window_size,
            buffered_read_nonces: HashSet::with_capacity(window_size.try_into().unwrap()),
        }
    }

    fn get_nonce_value(nonce: &[u8; NONCE_LEN]) -> Result<u32> {
        // Nonce must be 12 bytes with the first 8 bytes padded with 0.
        if !nonce.starts_with(&[0u8; NONCE_LEN - 4]) {
            return Err(anyhow!("Invalid nonce received."));
        }
        let mut nonce_be_bytes = [0u8; 4];
        nonce_be_bytes.copy_from_slice(&nonce[NONCE_LEN - 4..]);
        Ok(u32::from_be_bytes(nonce_be_bytes))
    }

    fn get_lowest_acceptable_read_nonce(&self) -> u32 {
        let mut lowest_allowed_nonce = 1;
        if self.furthest_read_nonce > self.window_size {
            lowest_allowed_nonce = self.furthest_read_nonce - self.window_size + 1;
        }
        lowest_allowed_nonce
    }
}
impl Encryptor for UnorderedChannelEncryptor {
    fn encrypt(&mut self, payload: &Payload) -> Result<Payload> {
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

    fn decrypt(&mut self, payload: &Payload) -> Result<Payload> {
        let nonce: [u8; NONCE_LEN] = payload
            .nonce
            .as_ref()
            .unwrap()
            .clone()
            .try_into()
            .map_err(|e| anyhow!("Failed to extract nonce error: {e:#?}"))?;
        let nonce_value = UnorderedChannelEncryptor::get_nonce_value(&nonce)?;

        let lowest_acceptable_nonce = self.get_lowest_acceptable_read_nonce();
        // Nonce is way too far in the past, reject it.
        if nonce_value < lowest_acceptable_nonce {
            return Err(anyhow!(
                "Current nonce {} must be strictly greater than `furthest_read_nonce-window_size`. 
            furthest_read_nonce {}, window_size {}",
                nonce_value,
                self.furthest_read_nonce,
                self.window_size
            ));
        }
        // Nonce is within the window, check for replayed nonces.
        else if nonce_value >= lowest_acceptable_nonce && nonce_value <= self.furthest_read_nonce
        {
            if self.buffered_read_nonces.contains(&nonce_value) {
                return Err(anyhow!(
                    "Current nonce {} was replayed, rejecting message.",
                    nonce_value,
                ));
            }
            self.buffered_read_nonces.insert(nonce_value);
        }
        // Nonce is greater than the furthest seen so far.
        else {
            self.furthest_read_nonce = nonce_value;
            // Retain only buffered nonces in the new window span.
            let new_lowest_acceptable_nonce = self.get_lowest_acceptable_read_nonce();
            self.buffered_read_nonces
                .retain(|&n| n >= new_lowest_acceptable_nonce);
            self.buffered_read_nonces.insert(nonce_value);
        }

        let ciphertext = payload.message.as_slice();
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
            UNORDERED_CHANNEL_ENCRYPTOR_WINDOW_SIZE,
        ))
    }
}

#[cfg(all(test, feature = "std"))]
mod test {
    use oak_crypto::encryptor::Encryptor;
    use oak_crypto::{encryptor::Payload, noise_handshake::SYMMETRIC_KEY_LEN};

    use crate::session::UnorderedChannelEncryptor;

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
        let mut replica_1 = UnorderedChannelEncryptor::new(key_1, key_2, 0);
        let mut replica_2 = UnorderedChannelEncryptor::new(key_2, key_1, 0);

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
    fn test_encryption_decryption_unordered_window_size_0() {
        let key_1 = &[42u8; SYMMETRIC_KEY_LEN];
        let key_2 = &[52u8; SYMMETRIC_KEY_LEN];
        let test_messages = vec![vec![1u8, 2u8, 3u8, 4u8], vec![4u8, 3u8, 2u8, 1u8]];
        let mut replica_1 = UnorderedChannelEncryptor::new(key_1, key_2, 0);
        let mut replica_2 = UnorderedChannelEncryptor::new(key_2, key_1, 0);

        let encrypted_payload_1 = replica_1
            .encrypt(&Payload {
                message: test_messages[0].to_vec(),
                nonce: None,
                aad: None,
            })
            .unwrap();
        let encrypted_payload_2 = replica_1
            .encrypt(&Payload {
                message: test_messages[1].to_vec(),
                nonce: None,
                aad: None,
            })
            .unwrap();

        // Decrypt in reverse order
        let plaintext_2 = replica_2.decrypt(&encrypted_payload_2).unwrap().message;
        assert_eq!(test_messages[1], plaintext_2);
        // Decrypting first message fails since it is from a lower nonce.
        assert_eq!(true, replica_2.decrypt(&encrypted_payload_1).is_err());
    }

    #[test]
    fn test_encryption_decryption_unordered_window_size_3() {
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
        let mut replica_1 = UnorderedChannelEncryptor::new(key_1, key_2, 3);
        let mut replica_2 = UnorderedChannelEncryptor::new(key_2, key_1, 3);
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
