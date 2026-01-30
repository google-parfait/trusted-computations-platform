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
use alloc::sync::Arc;
use alloc::{vec, vec::Vec};
use anyhow::Result;
use oak_attestation_types::{attester::Attester, endorser::Endorser};
use oak_attestation_verification::{
    AmdSevSnpDiceAttestationVerifier, AmdSevSnpPolicy, ContainerPolicy, FirmwarePolicy,
    InsecureAttestationVerifier, KernelPolicy, SystemPolicy,
};
use oak_attestation_verification_types::verifier::AttestationVerifier;
use oak_crypto::{encryptor::Encryptor, noise_handshake::OrderedCrypter};
use oak_dice_attestation_verifier::DiceAttestationVerifier;
use oak_proto_rust::oak::attestation::v1::{
    reference_values, AmdSevReferenceValues, Endorsements, Evidence, OakContainersReferenceValues,
    ReferenceValues, RootLayerReferenceValues,
};
use oak_proto_rust::oak::session::v1::{PlaintextMessage, SessionRequest, SessionResponse};
use oak_restricted_kernel_sdk::{attestation::InstanceAttester, crypto::InstanceSessionBinder};
use oak_session::aggregators::PassThrough;
use oak_session::attestation::AttestationType;
use oak_session::config::{EncryptorProvider, SessionConfig};
use oak_session::encryptors::UnorderedChannelEncryptor;
use oak_session::generator::BindableAssertionGenerator;
use oak_session::handshake::HandshakeType;
use oak_session::key_extractor::KeyExtractor;
use oak_session::session::{ClientSession, ServerSession, Session};
use oak_session::session_binding::SessionBinder;
use oak_session::session_binding::SignatureBindingVerifierProvider;
use oak_session::verifier::BoundAssertionVerifier;
use oak_session::ProtocolEngine;
use oak_session_endorsed_evidence::EndorsedEvidenceBindableAssertionGenerator;
use oak_session_endorsed_evidence::EndorsedEvidenceBoundAssertionVerifier;
use oak_time::Clock;

const UNORDERED_CHANNEL_ENCRYPTOR_WINDOW_SIZE: u32 = 3;
const TCP_ASSERTION_ID: &str = "tcp_assertion_id";

// Factory class for creating instances of `OakClientSession` and `OakServerSession`
// traits.
pub trait OakSessionFactory {
    // Initialize the OakSessionFactory.
    fn init(
        &mut self,
        clock: Arc<dyn Clock>,
        reference_values: ReferenceValues,
        endorsements: Endorsements,
    );

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
    fn put_incoming_message(&mut self, incoming_message: I) -> Result<Option<()>>;

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

// Factory class for creating instances of `SessionBinder` allows binding
// session to arbitrary data.
pub trait OakSessionBinderFactory {
    fn get(&self) -> Result<Box<dyn SessionBinder>>;
}

// Factory class for creating instances of oak `Attester`.
pub trait OakAttesterFactory {
    fn get(&self) -> Result<Box<dyn Attester>>;
}

// Default implementation of `OakSessionBinderFactory` for the Restricted Kernel.
pub struct DefaultOakSessionBinderFactory {}

impl OakSessionBinderFactory for DefaultOakSessionBinderFactory {
    fn get(&self) -> Result<Box<dyn SessionBinder>> {
        Ok(Box::new(InstanceSessionBinder::create()?))
    }
}

// Default implementation of `OakSessionBinderFactory` for Oak Containers.
#[cfg(feature = "std")]
pub struct OakContainersSessionBinderFactory {
    channel: tonic::transport::channel::Channel,
}

#[cfg(feature = "std")]
impl OakContainersSessionBinderFactory {
    pub fn new(channel: tonic::transport::channel::Channel) -> Self {
        Self { channel }
    }
}

#[cfg(feature = "std")]
impl OakSessionBinderFactory for OakContainersSessionBinderFactory {
    fn get(&self) -> Result<Box<dyn SessionBinder>> {
        Ok(Box::new(oak_sdk_containers::InstanceSessionBinder::create(
            &self.channel,
        )))
    }
}

// Default implementation of `OakAttesterFactory` for the Restricted Kernel.
pub struct DefaultOakAttesterFactory {}

impl OakAttesterFactory for DefaultOakAttesterFactory {
    fn get(&self) -> Result<Box<dyn Attester>> {
        Ok(Box::new(InstanceAttester::create()?))
    }
}

// Default implementation of `OakAttesterFactory` for Oak Containers.
#[cfg(feature = "std")]
pub struct OakContainersAttesterFactory {
    evidence: Evidence,
}

#[cfg(feature = "std")]
impl OakContainersAttesterFactory {
    pub fn new(evidence: Evidence) -> Self {
        Self { evidence }
    }
}

#[cfg(feature = "std")]
impl OakAttesterFactory for OakContainersAttesterFactory {
    fn get(&self) -> Result<Box<dyn Attester>> {
        Ok(Box::new(oak_sdk_common::StaticAttester::new(
            self.evidence.clone(),
        )))
    }
}

struct DefaultEndorser {
    endorsements: Endorsements,
}

impl Endorser for DefaultEndorser {
    fn endorse(&self, _evidence: Option<&Evidence>) -> anyhow::Result<Endorsements> {
        Ok(self.endorsements.clone())
    }
}

// Default implementation of `OakSessionFactory`.
pub struct DefaultOakSessionFactory {
    session_binder_factory: Box<dyn OakSessionBinderFactory>,
    attester_factory: Box<dyn OakAttesterFactory>,
    peer_verifier: Option<Arc<dyn AttestationVerifier>>,
    key_extractor: Option<Arc<dyn KeyExtractor>>,
    endorsements: Endorsements,
}

impl DefaultOakSessionFactory {
    pub fn new(
        session_binder_factory: Box<dyn OakSessionBinderFactory>,
        attester_factory: Box<dyn OakAttesterFactory>,
    ) -> Self {
        Self {
            session_binder_factory,
            attester_factory,
            peer_verifier: None,
            key_extractor: None,
            endorsements: Endorsements::default(),
        }
    }
}
impl OakSessionFactory for DefaultOakSessionFactory {
    fn init(
        &mut self,
        clock: Arc<dyn Clock>,
        reference_values: ReferenceValues,
        endorsements: Endorsements,
    ) {
        let (peer_verifier, key_extractor): (Arc<dyn AttestationVerifier>, Arc<dyn KeyExtractor>) =
            match &reference_values.r#type {
                // Oak Containers (insecure)
                Some(reference_values::Type::OakContainers(OakContainersReferenceValues {
                    root_layer:
                        Some(RootLayerReferenceValues {
                            insecure: Some(_), ..
                        }),
                    kernel_layer: Some(kernel_ref_vals),
                    system_layer: Some(system_ref_vals),
                    container_layer: Some(container_ref_vals),
                })) => (
                    Arc::new(InsecureAttestationVerifier::new(
                        clock,
                        vec![
                            Box::new(KernelPolicy::new(kernel_ref_vals)),
                            Box::new(SystemPolicy::new(system_ref_vals)),
                            Box::new(ContainerPolicy::new(container_ref_vals)),
                        ],
                    )),
                    Arc::new(oak_session::key_extractor::DefaultBindingKeyExtractor {}),
                ),

                // Oak Containers (SEV-SNP)
                Some(reference_values::Type::OakContainers(OakContainersReferenceValues {
                    root_layer:
                        Some(RootLayerReferenceValues {
                            amd_sev:
                                Some(
                                    amd_sev_ref_vals @ AmdSevReferenceValues {
                                        stage0: Some(stage0_ref_vals),
                                        ..
                                    },
                                ),
                            insecure: None,
                            ..
                        }),
                    kernel_layer: Some(kernel_ref_vals),
                    system_layer: Some(system_ref_vals),
                    container_layer: Some(container_ref_vals),
                })) => (
                    Arc::new(AmdSevSnpDiceAttestationVerifier::new(
                        AmdSevSnpPolicy::new(amd_sev_ref_vals),
                        Box::new(FirmwarePolicy::new(stage0_ref_vals)),
                        vec![
                            Box::new(KernelPolicy::new(kernel_ref_vals)),
                            Box::new(SystemPolicy::new(system_ref_vals)),
                            Box::new(ContainerPolicy::new(container_ref_vals)),
                        ],
                        clock,
                    )),
                    Arc::new(oak_session::key_extractor::DefaultBindingKeyExtractor {}),
                ),

                // Restricted Kernel
                _ => (
                    Arc::new(DiceAttestationVerifier::create(reference_values, clock)),
                    Arc::new(oak_session::key_extractor::DefaultSigningKeyExtractor {}),
                ),
            };

        self.peer_verifier = Some(peer_verifier);
        self.key_extractor = Some(key_extractor);
        self.endorsements = endorsements;
    }

    fn get_oak_client_session(&self) -> Result<Box<dyn OakClientSession>> {
        let assertion_generator = Box::new(EndorsedEvidenceBindableAssertionGenerator::new(
            self.attester_factory.get()?.into(),
            Arc::new(DefaultEndorser {
                endorsements: self.endorsements.clone(),
            }),
            self.session_binder_factory.get()?.into(),
        ));
        let assertion_verifier = Box::new(EndorsedEvidenceBoundAssertionVerifier::new(
            self.peer_verifier.as_ref().unwrap().clone(),
            Arc::new(SignatureBindingVerifierProvider::new(
                self.key_extractor.as_ref().unwrap().clone(),
            )),
        ));
        let client_session =
            DefaultOakClientSession::create(assertion_generator, assertion_verifier)?;
        Ok(Box::new(client_session))
    }

    fn get_oak_server_session(&self) -> Result<Box<dyn OakServerSession>> {
        let assertion_generator = Box::new(EndorsedEvidenceBindableAssertionGenerator::new(
            self.attester_factory.get()?.into(),
            Arc::new(DefaultEndorser {
                endorsements: self.endorsements.clone(),
            }),
            self.session_binder_factory.get()?.into(),
        ));
        let assertion_verifier = Box::new(EndorsedEvidenceBoundAssertionVerifier::new(
            self.peer_verifier.as_ref().unwrap().clone(),
            Arc::new(SignatureBindingVerifierProvider::new(
                self.key_extractor.as_ref().unwrap().clone(),
            )),
        ));
        let server_session =
            DefaultOakServerSession::create(assertion_generator, assertion_verifier)?;
        Ok(Box::new(server_session))
    }
}

struct DefaultEncryptorProvider;

impl EncryptorProvider for DefaultEncryptorProvider {
    fn provide_encryptor(
        &self,
        crypter: OrderedCrypter,
    ) -> Result<Box<dyn Encryptor>, anyhow::Error> {
        TryInto::<UnorderedChannelEncryptor>::try_into((
            crypter,
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
    pub fn create(
        assertion_generator: Box<dyn BindableAssertionGenerator>,
        assertion_verifier: Box<dyn BoundAssertionVerifier>,
    ) -> Result<Self> {
        Ok(Self {
            inner: ClientSession::create(
                SessionConfig::builder(AttestationType::Bidirectional, HandshakeType::NoiseNN)
                    .add_self_assertion_generator(
                        String::from(TCP_ASSERTION_ID),
                        assertion_generator,
                    )
                    .add_peer_assertion_verifier(String::from(TCP_ASSERTION_ID), assertion_verifier)
                    // Since TCP only uses one assertion type for the attestation verification we
                    // can use the trivial PassThrough aggregator. If more assertion types are added
                    // in the future Any/All or custom aggregator needs to be specified.
                    .set_assertion_attestation_aggregator(Box::new(PassThrough {}))
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

    fn put_incoming_message(&mut self, incoming_message: SessionResponse) -> Result<Option<()>> {
        self.inner.put_incoming_message(incoming_message)
    }

    fn is_open(&self) -> bool {
        self.inner.is_open()
    }

    fn write(&mut self, plaintext: &[u8]) -> Result<()> {
        self.inner.write(PlaintextMessage {
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
    pub fn create(
        assertion_generator: Box<dyn BindableAssertionGenerator>,
        assertion_verifier: Box<dyn BoundAssertionVerifier>,
    ) -> Result<Self> {
        Ok(Self {
            inner: ServerSession::create(
                SessionConfig::builder(AttestationType::Bidirectional, HandshakeType::NoiseNN)
                    .add_self_assertion_generator(
                        String::from(TCP_ASSERTION_ID),
                        assertion_generator,
                    )
                    .add_peer_assertion_verifier(String::from(TCP_ASSERTION_ID), assertion_verifier)
                    // Since TCP only uses one assertion type for the attestation verification we
                    // can use the trivial PassThrough aggregator. If more assertion types are added
                    // in the future Any/All or custom aggregator needs to be specified.
                    .set_assertion_attestation_aggregator(Box::new(PassThrough {}))
                    .set_encryption_provider(Box::new(DefaultEncryptorProvider))
                    .build(),
            )?,
        })
    }
}

impl OakSession<SessionRequest, SessionResponse> for DefaultOakServerSession {
    fn get_outgoing_message(&mut self) -> Result<Option<SessionResponse>> {
        self.inner.get_outgoing_message()
    }

    fn put_incoming_message(&mut self, incoming_message: SessionRequest) -> Result<Option<()>> {
        self.inner.put_incoming_message(incoming_message)
    }

    fn is_open(&self) -> bool {
        self.inner.is_open()
    }

    fn write(&mut self, plaintext: &[u8]) -> Result<()> {
        self.inner.write(PlaintextMessage {
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
    use oak_crypto::{
        encryptor::Payload,
        noise_handshake::{OrderedCrypter, SYMMETRIC_KEY_LEN},
    };
    use oak_session::config::EncryptorProvider;

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
            .provide_encryptor(OrderedCrypter::new(key_1, key_2))
            .unwrap();
        let mut replica_2 = default_encryption_provider
            .provide_encryptor(OrderedCrypter::new(key_2, key_1))
            .unwrap();

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
            .provide_encryptor(OrderedCrypter::new(key_1, key_2))
            .unwrap();
        let mut replica_2 = default_encryption_provider
            .provide_encryptor(OrderedCrypter::new(key_2, key_1))
            .unwrap();
        let mut encrypted_payloads = vec![];
        for i in 0..test_messages.len() {
            encrypted_payloads.push(
                replica_1
                    .encrypt(Payload {
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
                .decrypt(clone_payload(&encrypted_payloads[3]))
                .unwrap()
                .message
        );
        // Decrypting messages within the window should be ok.
        assert_eq!(
            test_messages[1],
            replica_2
                .decrypt(clone_payload(&encrypted_payloads[1]))
                .unwrap()
                .message
        );
        assert_eq!(
            test_messages[2],
            replica_2
                .decrypt(clone_payload(&encrypted_payloads[2]))
                .unwrap()
                .message
        );
        // Replaying message should fail.
        assert_eq!(
            true,
            replica_2
                .decrypt(clone_payload(&encrypted_payloads[3]))
                .is_err()
        );
        assert_eq!(
            true,
            replica_2
                .decrypt(clone_payload(&encrypted_payloads[2]))
                .is_err()
        );
        assert_eq!(
            true,
            replica_2
                .decrypt(clone_payload(&encrypted_payloads[1]))
                .is_err()
        );
        // Decrypting messages outside the window should fail.
        assert_eq!(
            true,
            replica_2
                .decrypt(clone_payload(&encrypted_payloads[0]))
                .is_err()
        );

        // Decrypt more messages in order.
        assert_eq!(
            test_messages[4],
            replica_2
                .decrypt(clone_payload(&encrypted_payloads[4]))
                .unwrap()
                .message
        );
        assert_eq!(
            test_messages[5],
            replica_2
                .decrypt(clone_payload(&encrypted_payloads[5]))
                .unwrap()
                .message
        );
    }
}
