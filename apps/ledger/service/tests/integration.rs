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

#[cfg(test)]

mod test {
    use prost::bytes::Bytes;
    use prost::Message;
    use std::{collections::LinkedList, format};

    use cfc_crypto::{extract_key_from_cwt, PUBLIC_KEY_CLAIM};
    use coset::{
        cbor::Value,
        cwt,
        cwt::{ClaimsSet, ClaimsSetBuilder},
        iana, Algorithm, CborSerializable, CoseKey, CoseSign1, CoseSign1Builder,
    };
    use federated_compute::proto::{
        access_budget::Kind as AccessBudgetKind, data_access_policy::*, *,
    };
    use googletest::{
        assert_that,
        prelude::{contains_substring, displays_as, err},
    };
    use oak_crypto::signer::Signer;
    use oak_proto_rust::oak::attestation::v1::Evidence;
    use oak_restricted_kernel_sdk::testing::{MockAttester, MockSigner};
    use sha2::{Digest, Sha256};

    use tcp_integration::harness::*;
    use tcp_ledger_service::attestation::{
        get_test_endorsements, get_test_evidence, get_test_reference_values,
    };
    use tcp_ledger_service::{
        actor::LedgerActor,
        assert_err,
        ledger::{service::*, *},
    };
    use tcp_proto::runtime::endpoint::*;

    // The proxy implementation of the Ledger
    // that makes requests via LedgerActor
    struct LedgerService {
        cluster: FakeCluster<LedgerActor>,
        create_actor_fn: fn() -> LedgerActor,
        correlation_id: u64,
        responses: LinkedList<LedgerResponse>,
    }

    impl LedgerService {
        fn create(create_actor_fn: fn() -> LedgerActor) -> Self {
            let config = LedgerConfig {};
            let mut service = LedgerService {
                cluster: FakeCluster::new(config.encode_to_vec().into()),
                create_actor_fn,
                correlation_id: 0,
                responses: LinkedList::new(),
            };
            service.start(3u64);
            service
        }

        fn default() -> Self {
            Self::create(|| Self::create_actor_with_signer(Box::new(MockSigner::create().unwrap())))
        }

        fn create_actor_with_signer(signer: Box<dyn Signer>) -> LedgerActor {
            LedgerActor::create(Box::new(MockAttester::create().unwrap()), signer).unwrap()
        }

        fn start(&mut self, num_replicas: u64) {
            assert!(num_replicas > 0u64);
            self.cluster.start_node(1, true, (self.create_actor_fn)());
            self.cluster.advance_until_elected_leader(None);
            assert!(self.leader_id() == 1);

            for i in 2u64..num_replicas {
                self.cluster.start_node(i, false, (self.create_actor_fn)());
                self.cluster.add_node_to_cluster(i);
            }
        }

        fn leader_id(&self) -> u64 {
            self.cluster.leader_id()
        }

        fn send_request(&mut self, ledger_request: LedgerRequest) {
            self.correlation_id += 1;
            self.cluster.send_app_message(
                self.leader_id(),
                self.correlation_id,
                ledger_request.encode_to_vec().into(),
                Bytes::new(),
            );
        }

        fn advance_until_response(&mut self) -> LedgerResponse {
            if self.responses.is_empty() {
                let response_messages =
                    self.cluster
                        .advance_until(&mut |envelope_out| match &envelope_out.msg {
                            Some(out_message::Msg::DeliverAppMessage(message)) => {
                                let response =
                                    LedgerResponse::decode(message.message_header.as_ref())
                                        .unwrap();
                                self.responses.push_back(response);
                                return true;
                            }
                            _ => false,
                        });

                assert!(!response_messages.is_empty());
            }
            self.responses.pop_front().unwrap()
        }

        fn parse_error(ledger_response: LedgerResponse) -> micro_rpc::Status {
            if let Some(ledger_response::Response::Error(err)) = ledger_response.response {
                micro_rpc::Status::new_with_message(
                    micro_rpc::StatusCode::from(err.code as u32),
                    err.message,
                )
            } else {
                micro_rpc::Status::new_with_message(
                    micro_rpc::StatusCode::Internal,
                    format!("Unexpected response: {:?}", ledger_response),
                )
            }
        }

        fn wrap_create_key_request(request: CreateKeyRequest) -> LedgerRequest {
            LedgerRequest {
                request: Some(ledger_request::Request::CreateKey(request)),
            }
        }

        fn unwrap_create_key_response(
            response: LedgerResponse,
        ) -> Result<CreateKeyResponse, micro_rpc::Status> {
            if let Some(ledger_response::Response::CreateKey(response)) = response.response {
                Ok(response)
            } else {
                Err(Self::parse_error(response))
            }
        }

        fn wrap_delete_key_request(request: DeleteKeyRequest) -> LedgerRequest {
            LedgerRequest {
                request: Some(ledger_request::Request::DeleteKey(request)),
            }
        }

        fn unwrap_delete_key_response(
            response: LedgerResponse,
        ) -> Result<DeleteKeyResponse, micro_rpc::Status> {
            if let Some(ledger_response::Response::DeleteKey(response)) = response.response {
                Ok(response)
            } else {
                Err(Self::parse_error(response))
            }
        }

        fn wrap_authorize_access_request(request: AuthorizeAccessRequest) -> LedgerRequest {
            LedgerRequest {
                request: Some(ledger_request::Request::AuthorizeAccess(request)),
            }
        }

        fn unwrap_authorize_access_response(
            response: LedgerResponse,
        ) -> Result<AuthorizeAccessResponse, micro_rpc::Status> {
            if let Some(ledger_response::Response::AuthorizeAccess(response)) = response.response {
                Ok(response)
            } else {
                Err(Self::parse_error(response))
            }
        }

        fn wrap_revoke_access_request(request: RevokeAccessRequest) -> LedgerRequest {
            LedgerRequest {
                request: Some(ledger_request::Request::RevokeAccess(request)),
            }
        }

        fn unwrap_revoke_access_response(
            response: LedgerResponse,
        ) -> Result<RevokeAccessResponse, micro_rpc::Status> {
            if let Some(ledger_response::Response::RevokeAccess(response)) = response.response {
                Ok(response)
            } else {
                Err(Self::parse_error(response))
            }
        }
    }

    impl Ledger for LedgerService {
        fn create_key(
            &mut self,
            request: CreateKeyRequest,
        ) -> Result<CreateKeyResponse, micro_rpc::Status> {
            self.send_request(Self::wrap_create_key_request(request));
            let ledger_response = self.advance_until_response();
            Self::unwrap_create_key_response(ledger_response)
        }

        fn delete_key(
            &mut self,
            request: DeleteKeyRequest,
        ) -> Result<DeleteKeyResponse, micro_rpc::Status> {
            self.send_request(Self::wrap_delete_key_request(request));
            let ledger_response = self.advance_until_response();
            Self::unwrap_delete_key_response(ledger_response)
        }

        fn authorize_access(
            &mut self,
            request: AuthorizeAccessRequest,
        ) -> Result<AuthorizeAccessResponse, micro_rpc::Status> {
            self.send_request(Self::wrap_authorize_access_request(request));
            let ledger_response = self.advance_until_response();
            Self::unwrap_authorize_access_response(ledger_response)
        }

        fn revoke_access(
            &mut self,
            request: RevokeAccessRequest,
        ) -> Result<RevokeAccessResponse, micro_rpc::Status> {
            self.send_request(Self::wrap_revoke_access_request(request));
            let ledger_response = self.advance_until_response();
            Self::unwrap_revoke_access_response(ledger_response)
        }
    }

    /// Helper function to create a LedgerService with one key.
    fn create_ledger_service() -> (LedgerService, Vec<u8>) {
        let mut ledger = LedgerService::default();
        let response = ledger
            .create_key(CreateKeyRequest {
                ttl: Some(prost_types::Duration {
                    seconds: 3600,
                    ..Default::default()
                }),
                ..Default::default()
            })
            .unwrap();
        (ledger, response.public_key)
    }

    /// Helper function to wrap a CoseKey in a CWT as would be generated by app requesting access.
    fn create_recipient_cwt(cose_key: CoseKey) -> Vec<u8> {
        let claims = ClaimsSetBuilder::new()
            .private_claim(PUBLIC_KEY_CLAIM, Value::from(cose_key.to_vec().unwrap()))
            .build();
        CoseSign1Builder::new()
            .payload(claims.to_vec().unwrap())
            .build()
            .to_vec()
            .unwrap()
    }

    #[test]
    fn test_create_key() {
        struct FakeSigner;
        impl Signer for FakeSigner {
            fn sign(&self, message: &[u8]) -> Vec<u8> {
                return Sha256::digest(message).to_vec();
            }
        }
        let mut ledger =
            LedgerService::create(|| LedgerService::create_actor_with_signer(Box::new(FakeSigner)));

        let response1 = ledger
            .create_key(CreateKeyRequest {
                now: Some(prost_types::Timestamp {
                    seconds: 1000,
                    ..Default::default()
                }),
                ttl: Some(prost_types::Duration {
                    seconds: 100,
                    ..Default::default()
                }),
            })
            .unwrap();
        assert!(response1.attestation_evidence.is_some());

        let cwt = CoseSign1::from_slice(&response1.public_key).unwrap();
        cwt.verify_signature(b"", |signature, message| {
            anyhow::ensure!(signature == Sha256::digest(message).as_slice());
            Ok(())
        })
        .expect("signature mismatch");
        assert_eq!(
            cwt.protected.header.alg,
            Some(Algorithm::Assigned(iana::Algorithm::ES256))
        );
        let claims = ClaimsSet::from_slice(&cwt.payload.unwrap()).unwrap();
        assert_eq!(claims.issued_at, Some(cwt::Timestamp::WholeSeconds(1000)));
        assert_eq!(
            claims.expiration_time,
            Some(cwt::Timestamp::WholeSeconds(1100))
        );
        let key1 = extract_key_from_cwt(&response1.public_key).unwrap();

        // Since the key contains random fields, we can't check them directly. Instead, we create a
        // second key and verify that those fields are different.
        let response2 = ledger
            .create_key(CreateKeyRequest {
                now: Some(prost_types::Timestamp {
                    seconds: 1000,
                    ..Default::default()
                }),
                ttl: Some(prost_types::Duration {
                    seconds: 100,
                    ..Default::default()
                }),
            })
            .unwrap();
        let key2 = extract_key_from_cwt(&response2.public_key).unwrap();
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_delete_key() {
        let (mut ledger, public_key) = create_ledger_service();
        assert_eq!(
            ledger.delete_key(DeleteKeyRequest {
                public_key: public_key.clone(),
                ..Default::default()
            }),
            Ok(DeleteKeyResponse::default())
        );

        // To verify that the key was actually deleted, we check that attempting to delete it again
        // produces an error.
        assert_err!(
            ledger.delete_key(DeleteKeyRequest {
                public_key,
                ..Default::default()
            }),
            micro_rpc::StatusCode::NotFound,
            "public key not found"
        );
    }

    #[test]
    fn test_delete_key_invalid() {
        let (mut ledger, _) = create_ledger_service();
        assert_err!(
            ledger.delete_key(DeleteKeyRequest {
                public_key: b"invalid".into(),
                ..Default::default()
            }),
            micro_rpc::StatusCode::InvalidArgument,
            "public_key is invalid"
        );
    }

    #[test]
    fn test_delete_key_not_found() {
        let (_, public_key) = create_ledger_service();
        let (mut ledger, _) = create_ledger_service();
        assert_err!(
            ledger.delete_key(DeleteKeyRequest {
                public_key,
                ..Default::default()
            }),
            micro_rpc::StatusCode::NotFound,
            "public key not found"
        );
    }

    #[test]
    fn test_authorize_access() {
        let (mut ledger, public_key) = create_ledger_service();
        let cose_key = extract_key_from_cwt(&public_key).unwrap();

        // Define an access policy that grants access.
        let recipient_tag = "tag";
        let access_policy = DataAccessPolicy {
            transforms: vec![Transform {
                application: Some(ApplicationMatcher {
                    tag: Some(recipient_tag.to_owned()),
                    ..Default::default()
                }),
                ..Default::default()
            }],
            ..Default::default()
        }
        .encode_to_vec();

        // Construct a client message.
        let plaintext = b"plaintext";
        let blob_header = BlobHeader {
            blob_id: "blob-id".into(),
            key_id: cose_key.key_id.clone(),
            access_policy_sha256: Sha256::digest(&access_policy).to_vec(),
            ..Default::default()
        }
        .encode_to_vec();
        let (ciphertext, encapsulated_key, encrypted_symmetric_key) =
            cfc_crypto::encrypt_message(plaintext, &cose_key, &blob_header).unwrap();

        // Request access.
        let (recipient_private_key, recipient_public_key) = cfc_crypto::gen_keypair(b"key-id");
        let recipient_nonce: &[u8] = b"nonce";
        let response = ledger
            .authorize_access(AuthorizeAccessRequest {
                access_policy,
                blob_header: blob_header.clone(),
                encapsulated_key,
                encrypted_symmetric_key,
                recipient_public_key: create_recipient_cwt(recipient_public_key),
                recipient_tag: recipient_tag.to_owned(),
                recipient_nonce: recipient_nonce.to_owned(),
                ..Default::default()
            })
            .unwrap();

        // Verify that the response contains the right public key and allows the message to be read.
        assert_eq!(response.reencryption_public_key, public_key);
        assert_eq!(
            cfc_crypto::decrypt_message(
                &ciphertext,
                &blob_header,
                &response.encrypted_symmetric_key,
                &[&response.reencryption_public_key, recipient_nonce].concat(),
                &response.encapsulated_key,
                &recipient_private_key
            )
            .unwrap(),
            plaintext
        );
    }

    #[test]
    fn test_concurrent_authorize_access() {
        let (mut ledger, public_key) = create_ledger_service();
        let cose_key = extract_key_from_cwt(&public_key).unwrap();

        // Define an access policy that grants access.
        let recipient_tag = "tag";
        let access_policy = DataAccessPolicy {
            transforms: vec![Transform {
                application: Some(ApplicationMatcher {
                    tag: Some(recipient_tag.to_owned()),
                    ..Default::default()
                }),
                ..Default::default()
            }],
            ..Default::default()
        }
        .encode_to_vec();

        let (recipient_private_key, recipient_public_key) = cfc_crypto::gen_keypair(b"key-id");
        let recipient_public_key = create_recipient_cwt(recipient_public_key);
        let recipient_nonce: &[u8] = b"nonce";

        // Construct client two ledger requests.
        let plaintext1 = b"plaintext1";
        let blob_header1 = BlobHeader {
            blob_id: "blob1".into(),
            key_id: cose_key.key_id.clone(),
            access_policy_sha256: Sha256::digest(&access_policy).to_vec(),
            ..Default::default()
        }
        .encode_to_vec();
        let (ciphertext1, encapsulated_key1, encrypted_symmetric_key1) =
            cfc_crypto::encrypt_message(plaintext1, &cose_key, &blob_header1).unwrap();
        let ledger_request1 =
            LedgerService::wrap_authorize_access_request(AuthorizeAccessRequest {
                access_policy: access_policy.clone(),
                blob_header: blob_header1.clone(),
                encapsulated_key: encapsulated_key1,
                encrypted_symmetric_key: encrypted_symmetric_key1,
                recipient_public_key: recipient_public_key.clone(),
                recipient_tag: recipient_tag.to_owned(),
                recipient_nonce: recipient_nonce.to_owned(),
                ..Default::default()
            });

        let plaintext2 = b"plaintext2";
        let blob_header2 = BlobHeader {
            blob_id: "blob2".into(),
            key_id: cose_key.key_id.clone(),
            access_policy_sha256: Sha256::digest(&access_policy).to_vec(),
            ..Default::default()
        }
        .encode_to_vec();
        let (ciphertext2, encapsulated_key2, encrypted_symmetric_key2) =
            cfc_crypto::encrypt_message(plaintext2, &cose_key, &blob_header2).unwrap();
        let ledger_request2 =
            LedgerService::wrap_authorize_access_request(AuthorizeAccessRequest {
                access_policy: access_policy.clone(),
                blob_header: blob_header2.clone(),
                encapsulated_key: encapsulated_key2,
                encrypted_symmetric_key: encrypted_symmetric_key2,
                recipient_public_key: recipient_public_key.clone(),
                recipient_tag: recipient_tag.to_owned(),
                recipient_nonce: recipient_nonce.to_owned(),
                ..Default::default()
            });

        // Send both requests simultaneously
        ledger.send_request(ledger_request1);
        ledger.send_request(ledger_request2);

        // Retrieve both responses
        let response1 =
            LedgerService::unwrap_authorize_access_response(ledger.advance_until_response())
                .unwrap();

        let response2 =
            LedgerService::unwrap_authorize_access_response(ledger.advance_until_response())
                .unwrap();

        // Verify both responses
        assert_eq!(
            cfc_crypto::decrypt_message(
                &ciphertext1,
                &blob_header1,
                &response1.encrypted_symmetric_key,
                &[&response1.reencryption_public_key, recipient_nonce].concat(),
                &response1.encapsulated_key,
                &recipient_private_key
            )
            .unwrap(),
            plaintext1
        );
        assert_eq!(
            cfc_crypto::decrypt_message(
                &ciphertext2,
                &blob_header2,
                &response2.encrypted_symmetric_key,
                &[&response2.reencryption_public_key, recipient_nonce].concat(),
                &response2.encapsulated_key,
                &recipient_private_key
            )
            .unwrap(),
            plaintext2
        );
    }

    #[test]
    fn test_authorize_access_with_attestation() {
        let (mut ledger, public_key) = create_ledger_service();
        let cose_key = extract_key_from_cwt(&public_key).unwrap();

        // Define an access policy that grants access.
        let access_policy = DataAccessPolicy {
            transforms: vec![Transform {
                application: Some(ApplicationMatcher {
                    reference_values: Some(get_test_reference_values()),
                    ..Default::default()
                }),
                ..Default::default()
            }],
            ..Default::default()
        }
        .encode_to_vec();

        // Construct a client message.
        let plaintext = b"plaintext";
        let blob_header = BlobHeader {
            blob_id: "blob-id".into(),
            key_id: cose_key.key_id.clone(),
            access_policy_sha256: Sha256::digest(&access_policy).to_vec(),
            ..Default::default()
        }
        .encode_to_vec();
        let (ciphertext, encapsulated_key, encrypted_symmetric_key) =
            cfc_crypto::encrypt_message(plaintext, &cose_key, &blob_header).unwrap();

        // Request access.
        let (recipient_private_key, recipient_public_key) = cfc_crypto::gen_keypair(b"key-id");
        let recipient_cwt = CoseSign1Builder::new()
            .payload(
                ClaimsSetBuilder::new()
                    .private_claim(
                        PUBLIC_KEY_CLAIM,
                        Value::from(recipient_public_key.to_vec().unwrap()),
                    )
                    .build()
                    .to_vec()
                    .unwrap(),
            )
            .create_signature(b"", |message| {
                // The MockSigner signs the key with application signing key provided by the
                // MockAttester.
                MockSigner::create().unwrap().sign(message)
            })
            .build()
            .to_vec()
            .unwrap();
        let recipient_nonce: &[u8] = b"nonce";
        let response = ledger
            .authorize_access(AuthorizeAccessRequest {
                access_policy,
                blob_header: blob_header.clone(),
                encapsulated_key,
                encrypted_symmetric_key,
                recipient_public_key: recipient_cwt,
                recipient_attestation_evidence: Some(get_test_evidence()),
                recipient_attestation_endorsements: Some(get_test_endorsements()),
                recipient_nonce: recipient_nonce.to_owned(),
                ..Default::default()
            })
            .unwrap();

        // Verify that the response contains the right public key and allows the message to be read.
        assert_eq!(response.reencryption_public_key, public_key);
        assert_eq!(
            cfc_crypto::decrypt_message(
                &ciphertext,
                &blob_header,
                &response.encrypted_symmetric_key,
                &[&response.reencryption_public_key, recipient_nonce].concat(),
                &response.encapsulated_key,
                &recipient_private_key
            )
            .unwrap(),
            plaintext
        );
    }

    #[test]
    fn test_authorize_access_invalid_evidence() {
        let (mut ledger, public_key) = create_ledger_service();
        let cose_key = extract_key_from_cwt(&public_key).unwrap();

        // Define an access policy that grants access.
        let access_policy = DataAccessPolicy {
            transforms: vec![Transform {
                application: Some(ApplicationMatcher {
                    reference_values: Some(get_test_reference_values()),
                    ..Default::default()
                }),
                ..Default::default()
            }],
            ..Default::default()
        }
        .encode_to_vec();

        // Construct a client message.
        let plaintext = b"plaintext";
        let blob_header = BlobHeader {
            blob_id: "blob-id".into(),
            key_id: cose_key.key_id.clone(),
            access_policy_sha256: Sha256::digest(&access_policy).to_vec(),
            ..Default::default()
        }
        .encode_to_vec();
        let (_, encapsulated_key, encrypted_symmetric_key) =
            cfc_crypto::encrypt_message(plaintext, &cose_key, &blob_header).unwrap();

        // Request access. Empty evidence will cause attestation validation to fail.
        let (_, recipient_public_key) = cfc_crypto::gen_keypair(b"key-id");
        let recipient_cwt = CoseSign1Builder::new()
            .payload(
                ClaimsSetBuilder::new()
                    .private_claim(
                        PUBLIC_KEY_CLAIM,
                        Value::from(recipient_public_key.to_vec().unwrap()),
                    )
                    .build()
                    .to_vec()
                    .unwrap(),
            )
            .create_signature(b"", |message| {
                // The MockSigner signs the key with application signing key provided by the
                // MockAttester.
                MockSigner::create().unwrap().sign(message)
            })
            .build()
            .to_vec()
            .unwrap();
        let recipient_nonce: &[u8] = b"nonce";
        assert_that!(
            ledger.authorize_access(AuthorizeAccessRequest {
                access_policy,
                blob_header: blob_header.clone(),
                encapsulated_key,
                encrypted_symmetric_key,
                recipient_public_key: recipient_cwt,
                recipient_attestation_evidence: Some(Evidence::default()),
                recipient_attestation_endorsements: Some(get_test_endorsements()),
                recipient_nonce: recipient_nonce.to_owned(),
                ..Default::default()
            }),
            err(displays_as(contains_substring(
                "attestation validation failed"
            )))
        );
    }

    #[test]
    fn test_authorize_access_invalid_recipient_key() {
        let (mut ledger, public_key) = create_ledger_service();
        let cose_key = extract_key_from_cwt(&public_key).unwrap();

        // Define an access policy that grants access.
        let recipient_tag = "tag";
        let access_policy = DataAccessPolicy {
            transforms: vec![Transform {
                application: Some(ApplicationMatcher {
                    tag: Some(recipient_tag.to_owned()),
                    ..Default::default()
                }),
                ..Default::default()
            }],
            ..Default::default()
        }
        .encode_to_vec();

        // Construct a client message.
        let blob_header = BlobHeader {
            blob_id: "blob-id".into(),
            key_id: cose_key.key_id.clone(),
            access_policy_sha256: Sha256::digest(&access_policy).to_vec(),
            ..Default::default()
        }
        .encode_to_vec();
        let (_, encapsulated_key, encrypted_symmetric_key) =
            cfc_crypto::encrypt_message(b"plaintext", &cose_key, &blob_header).unwrap();

        // Request access.
        assert_err!(
            ledger.authorize_access(AuthorizeAccessRequest {
                access_policy,
                blob_header: blob_header,
                encapsulated_key,
                encrypted_symmetric_key,
                recipient_public_key: b"invalid".into(),
                recipient_tag: recipient_tag.to_owned(),
                recipient_nonce: "nonce".into(),
                ..Default::default()
            }),
            micro_rpc::StatusCode::InvalidArgument,
            "attestation validation failed"
        );
    }

    #[test]
    fn test_authorize_access_invalid_header() {
        let (mut ledger, public_key) = create_ledger_service();
        let cose_key = extract_key_from_cwt(&public_key).unwrap();

        // Define an access policy that grants access.
        let recipient_tag = "tag";
        let access_policy = DataAccessPolicy {
            transforms: vec![Transform {
                application: Some(ApplicationMatcher {
                    tag: Some(recipient_tag.to_owned()),
                    ..Default::default()
                }),
                ..Default::default()
            }],
            ..Default::default()
        }
        .encode_to_vec();

        // Construct a client message.
        let blob_header = BlobHeader {
            blob_id: "blob-id".into(),
            key_id: cose_key.key_id.clone(),
            access_policy_sha256: Sha256::digest(&access_policy).to_vec(),
            ..Default::default()
        }
        .encode_to_vec();
        let (_, encapsulated_key, encrypted_symmetric_key) =
            cfc_crypto::encrypt_message(b"plaintext", &cose_key, &blob_header).unwrap();

        // Request access.
        assert_err!(
            ledger.authorize_access(AuthorizeAccessRequest {
                access_policy,
                blob_header: "invalid".into(),
                encapsulated_key,
                encrypted_symmetric_key,
                recipient_public_key: create_recipient_cwt(cfc_crypto::gen_keypair(b"key-id").1),
                recipient_tag: recipient_tag.to_owned(),
                recipient_nonce: "nonce".into(),
                ..Default::default()
            }),
            micro_rpc::StatusCode::InvalidArgument,
            "failed to parse blob header"
        );
    }

    #[test]
    fn test_authorize_access_invalid_access_policy_sha256() {
        let (mut ledger, public_key) = create_ledger_service();
        let cose_key = extract_key_from_cwt(&public_key).unwrap();

        // Define an access policy that grants access.
        let recipient_tag = "tag";
        let access_policy = DataAccessPolicy {
            transforms: vec![Transform {
                application: Some(ApplicationMatcher {
                    tag: Some(recipient_tag.to_owned()),
                    ..Default::default()
                }),
                ..Default::default()
            }],
            ..Default::default()
        }
        .encode_to_vec();

        // Construct a client message.
        let blob_header = BlobHeader {
            blob_id: "blob-id".into(),
            key_id: cose_key.key_id.clone(),
            access_policy_sha256: "invalid".into(),
            ..Default::default()
        }
        .encode_to_vec();
        let (_, encapsulated_key, encrypted_symmetric_key) =
            cfc_crypto::encrypt_message(b"plaintext", &cose_key, &blob_header).unwrap();

        // Request access.
        assert_err!(
            ledger.authorize_access(AuthorizeAccessRequest {
                access_policy,
                blob_header: blob_header,
                encapsulated_key,
                encrypted_symmetric_key,
                recipient_public_key: create_recipient_cwt(cfc_crypto::gen_keypair(b"key-id").1),
                recipient_tag: recipient_tag.to_owned(),
                recipient_nonce: "nonce".into(),
                ..Default::default()
            }),
            micro_rpc::StatusCode::InvalidArgument,
            "access policy does not match blob header"
        );
    }

    #[test]
    fn test_authorize_access_invalid_access_policy() {
        let (mut ledger, public_key) = create_ledger_service();
        let cose_key = extract_key_from_cwt(&public_key).unwrap();

        // Define an access policy that can't be decoded.
        let access_policy = b"invalid";

        // Construct a client message.
        let blob_header = BlobHeader {
            blob_id: "blob-id".into(),
            key_id: cose_key.key_id.clone(),
            access_policy_sha256: Sha256::digest(access_policy).to_vec(),
            ..Default::default()
        }
        .encode_to_vec();
        let (_, encapsulated_key, encrypted_symmetric_key) =
            cfc_crypto::encrypt_message(b"plaintext", &cose_key, &blob_header).unwrap();

        // Request access.
        assert_err!(
            ledger.authorize_access(AuthorizeAccessRequest {
                access_policy: access_policy.to_vec(),
                blob_header: blob_header,
                encapsulated_key,
                encrypted_symmetric_key,
                recipient_public_key: create_recipient_cwt(cfc_crypto::gen_keypair(b"key-id").1),
                recipient_tag: "tag".into(),
                recipient_nonce: "nonce".into(),
                ..Default::default()
            }),
            micro_rpc::StatusCode::InvalidArgument,
            "failed to parse access policy"
        );
    }

    #[test]
    fn test_authorize_access_application_mismatch() {
        let (mut ledger, public_key) = create_ledger_service();
        let cose_key = extract_key_from_cwt(&public_key).unwrap();

        // Define an access policy that does not grant access.
        let access_policy = DataAccessPolicy::default().encode_to_vec();

        // Construct a client message.
        let blob_header = BlobHeader {
            blob_id: "blob-id".into(),
            key_id: cose_key.key_id.clone(),
            access_policy_sha256: Sha256::digest(&access_policy).to_vec(),
            ..Default::default()
        }
        .encode_to_vec();
        let (_, encapsulated_key, encrypted_symmetric_key) =
            cfc_crypto::encrypt_message(b"plaintext", &cose_key, &blob_header).unwrap();

        // Request access.
        assert_err!(
            ledger.authorize_access(AuthorizeAccessRequest {
                access_policy,
                blob_header,
                encapsulated_key,
                encrypted_symmetric_key,
                recipient_public_key: create_recipient_cwt(cfc_crypto::gen_keypair(b"key-id").1),
                recipient_tag: "non-matching-tag".into(),
                recipient_nonce: "nonce".into(),
                ..Default::default()
            }),
            micro_rpc::StatusCode::FailedPrecondition,
            ""
        );
    }

    #[test]
    fn test_authorize_access_decryption_error() {
        let (mut ledger, public_key) = create_ledger_service();
        let cose_key = extract_key_from_cwt(&public_key).unwrap();

        // Define an access policy that grants access.
        let recipient_tag = "tag";
        let access_policy = DataAccessPolicy {
            transforms: vec![Transform {
                application: Some(ApplicationMatcher {
                    tag: Some(recipient_tag.to_owned()),
                    ..Default::default()
                }),
                ..Default::default()
            }],
            ..Default::default()
        }
        .encode_to_vec();

        // Construct a client message that was encrypted with different associated data.
        let blob_header = BlobHeader {
            blob_id: "blob-id".into(),
            key_id: cose_key.key_id.clone(),
            access_policy_sha256: Sha256::digest(&access_policy).to_vec(),
            ..Default::default()
        }
        .encode_to_vec();
        let (_, encapsulated_key, encrypted_symmetric_key) =
            cfc_crypto::encrypt_message(b"plaintext", &cose_key, b"other aad").unwrap();

        // Request access.
        assert_err!(
            ledger.authorize_access(AuthorizeAccessRequest {
                access_policy,
                blob_header: blob_header,
                encapsulated_key,
                encrypted_symmetric_key,
                recipient_public_key: create_recipient_cwt(cfc_crypto::gen_keypair(b"key-id").1),
                recipient_tag: recipient_tag.to_owned(),
                recipient_nonce: "nonce".into(),
                ..Default::default()
            }),
            micro_rpc::StatusCode::InvalidArgument,
            "failed to re-wrap symmetric key"
        );
    }

    #[test]
    fn test_authorize_access_missing_key_id() {
        let (mut ledger, public_key) = create_ledger_service();
        let cose_key = extract_key_from_cwt(&public_key).unwrap();

        // Define an access policy that grants access.
        let recipient_tag = "tag";
        let access_policy = DataAccessPolicy {
            transforms: vec![Transform {
                application: Some(ApplicationMatcher {
                    tag: Some(recipient_tag.to_owned()),
                    ..Default::default()
                }),
                ..Default::default()
            }],
            ..Default::default()
        }
        .encode_to_vec();

        // Construct a client message using a public key id that doesn't exist.
        let blob_header = BlobHeader {
            blob_id: "blob-id".into(),
            key_id: cose_key.key_id.iter().chain(b"x").cloned().collect(),
            access_policy_sha256: Sha256::digest(&access_policy).to_vec(),
            ..Default::default()
        }
        .encode_to_vec();
        let (_, encapsulated_key, encrypted_symmetric_key) =
            cfc_crypto::encrypt_message(b"plaintext", &cose_key, &blob_header).unwrap();

        // Request access.
        assert_err!(
            ledger.authorize_access(AuthorizeAccessRequest {
                access_policy,
                blob_header: blob_header,
                encapsulated_key,
                encrypted_symmetric_key,
                recipient_public_key: create_recipient_cwt(cfc_crypto::gen_keypair(b"key-id").1),
                recipient_tag: recipient_tag.to_owned(),
                recipient_nonce: "nonce".into(),
                ..Default::default()
            }),
            micro_rpc::StatusCode::NotFound,
            "public key not found"
        );
    }

    #[test]
    fn test_authorize_access_expired_key() {
        let (mut ledger, public_key) = create_ledger_service();
        let cose_key = extract_key_from_cwt(&public_key).unwrap();

        // Define an access policy that grants access.
        let recipient_tag = "tag";
        let access_policy = DataAccessPolicy {
            transforms: vec![Transform {
                application: Some(ApplicationMatcher {
                    tag: Some(recipient_tag.to_owned()),
                    ..Default::default()
                }),
                ..Default::default()
            }],
            ..Default::default()
        }
        .encode_to_vec();

        // Construct a client message.
        let blob_header = BlobHeader {
            blob_id: "blob-id".into(),
            key_id: cose_key.key_id.clone(),
            access_policy_sha256: Sha256::digest(&access_policy).to_vec(),
            ..Default::default()
        }
        .encode_to_vec();
        let (_, encapsulated_key, encrypted_symmetric_key) =
            cfc_crypto::encrypt_message(b"plaintext", &cose_key, &blob_header).unwrap();

        // Request access. Since `now` is after the key's expiration time, access should be denied.
        assert_err!(
            ledger.authorize_access(AuthorizeAccessRequest {
                now: Some(prost_types::Timestamp {
                    seconds: 1_000_000_000,
                    ..Default::default()
                }),
                access_policy,
                blob_header: blob_header,
                encapsulated_key,
                encrypted_symmetric_key,
                recipient_public_key: create_recipient_cwt(cfc_crypto::gen_keypair(b"key-id").1),
                recipient_tag: recipient_tag.to_owned(),
                recipient_nonce: "nonce".into(),
                ..Default::default()
            }),
            micro_rpc::StatusCode::NotFound,
            "public key not found"
        );
    }

    #[test]
    fn test_authorize_access_updates_budget() {
        let (mut ledger, public_key) = create_ledger_service();
        let cose_key = extract_key_from_cwt(&public_key).unwrap();
        let access_policy = DataAccessPolicy {
            transforms: vec![Transform {
                access_budget: Some(AccessBudget {
                    kind: Some(AccessBudgetKind::Times(1)),
                }),
                ..Default::default()
            }],
            ..Default::default()
        }
        .encode_to_vec();
        let plaintext = b"plaintext";
        let blob_header = BlobHeader {
            blob_id: b"blob-id".to_vec(),
            key_id: cose_key.key_id.clone(),
            access_policy_sha256: Sha256::digest(&access_policy).to_vec(),
            ..Default::default()
        }
        .encode_to_vec();
        let (_, encapsulated_key, encrypted_symmetric_key) =
            cfc_crypto::encrypt_message(plaintext, &cose_key, &blob_header).unwrap();

        // The first access should succeed.
        assert!(ledger
            .authorize_access(AuthorizeAccessRequest {
                access_policy: access_policy.clone(),
                blob_header: blob_header.clone(),
                encapsulated_key: encapsulated_key.clone(),
                encrypted_symmetric_key: encrypted_symmetric_key.clone(),
                recipient_public_key: create_recipient_cwt(cfc_crypto::gen_keypair(b"key-id").1),
                recipient_tag: "tag".to_owned(),
                recipient_nonce: b"nonce1".to_vec(),
                ..Default::default()
            })
            .is_ok());

        // But the second should fail because the budget has been exhausted.
        assert_err!(
            ledger.authorize_access(AuthorizeAccessRequest {
                access_policy,
                blob_header: blob_header.clone(),
                encapsulated_key,
                encrypted_symmetric_key,
                recipient_public_key: create_recipient_cwt(cfc_crypto::gen_keypair(b"key-id").1),
                recipient_tag: "tag".to_owned(),
                recipient_nonce: b"nonce2".to_vec(),
                ..Default::default()
            }),
            micro_rpc::StatusCode::ResourceExhausted,
            ""
        );
    }

    #[test]
    fn test_revoke_access() {
        let (mut ledger, public_key) = create_ledger_service();
        let cose_key = extract_key_from_cwt(&public_key).unwrap();
        let blob_id = b"blob-id";
        assert_eq!(
            ledger.revoke_access(RevokeAccessRequest {
                key_id: cose_key.key_id.clone(),
                blob_id: blob_id.to_vec(),
                ..Default::default()
            }),
            Ok(RevokeAccessResponse::default())
        );

        // Subsequent access should not be granted.
        let access_policy = DataAccessPolicy {
            transforms: vec![Transform::default()],
            ..Default::default()
        }
        .encode_to_vec();
        let plaintext = b"plaintext";
        let blob_header = BlobHeader {
            blob_id: blob_id.to_vec(),
            key_id: cose_key.key_id.clone(),
            access_policy_sha256: Sha256::digest(&access_policy).to_vec(),
            ..Default::default()
        }
        .encode_to_vec();
        let (_, encapsulated_key, encrypted_symmetric_key) =
            cfc_crypto::encrypt_message(plaintext, &cose_key, &blob_header).unwrap();

        assert_err!(
            ledger.authorize_access(AuthorizeAccessRequest {
                access_policy,
                blob_header: blob_header.clone(),
                encapsulated_key,
                encrypted_symmetric_key,
                recipient_public_key: create_recipient_cwt(cfc_crypto::gen_keypair(b"key-id").1),
                recipient_tag: "tag".to_owned(),
                recipient_nonce: b"nonce".to_vec(),
                ..Default::default()
            }),
            micro_rpc::StatusCode::ResourceExhausted,
            ""
        );
    }

    #[test]
    fn test_revoke_access_key_not_found() {
        let (mut ledger, public_key) = create_ledger_service();
        let cose_key = extract_key_from_cwt(&public_key).unwrap();
        assert_err!(
            ledger.revoke_access(RevokeAccessRequest {
                key_id: cose_key.key_id.iter().chain(b"x").cloned().collect(),
                blob_id: "blob-id".into(),
                ..Default::default()
            }),
            micro_rpc::StatusCode::NotFound,
            "public key not found"
        );
    }
}
