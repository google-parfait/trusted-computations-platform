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

#[cfg(all(test, feature = "std"))]

mod test {
    use prost::Message;
    use std::format;

    use tcp_integration::harness::*;
    use tcp_ledger_service::actor::LedgerActor;
    use tcp_ledger_service::fcp::confidentialcompute::{
        access_budget::Kind as AccessBudgetKind, data_access_policy::*, *,
    };
    use tcp_ledger_service::ledger::Ledger;
    use tcp_proto::runtime::endpoint::*;

    use sha2::{Digest, Sha256};

    // The proxy implementation of the Ledger
    // that makes requests via LedgerActor
    struct LedgerService {
        cluster: FakeCluster<LedgerActor>,
    }

    impl LedgerService {
        fn default() -> Self {
            let config = LedgerConfig {};
            let mut service = LedgerService {
                cluster: FakeCluster::new(config.encode_to_vec().into()),
            };
            service.start(3u64);
            service
        }

        fn start(&mut self, num_replicas: u64) {
            assert!(num_replicas > 0u64);
            self.cluster.start_node(1, true, LedgerActor::new());
            self.cluster.advance_until_elected_leader(None);
            assert!(self.leader_id() == 1);

            for i in 2u64..num_replicas {
                self.cluster.start_node(i, false, LedgerActor::new());
                self.cluster.add_node_to_cluster(i);
            }
        }

        fn leader_id(&self) -> u64 {
            self.cluster.leader_id()
        }

        fn send_request(&mut self, ledger_request: LedgerRequest) {
            self.cluster
                .send_proposal(self.leader_id(), ledger_request.encode_to_vec().into());
        }

        fn advance_until_response(&mut self) -> LedgerResponse {
            let mut ledger_response: Option<LedgerResponse> = None;
            let response_messages =
                self.cluster
                    .advance_until(&mut |envelope_out| match &envelope_out.msg {
                        Some(out_message::Msg::ExecuteProposal(response)) => {
                            if response.status
                                == ExecuteProposalStatus::ProposalStatusCompleted.into()
                            {
                                ledger_response = Some(
                                    LedgerResponse::decode(response.result_contents.as_ref())
                                        .unwrap(),
                                );
                                true
                            } else {
                                false
                            }
                        }
                        _ => false,
                    });

            assert!(!response_messages.is_empty());
            ledger_response.unwrap()
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
    }

    impl Ledger for LedgerService {
        fn create_key(
            &mut self,
            request: CreateKeyRequest,
        ) -> Result<CreateKeyResponse, micro_rpc::Status> {
            let ledger_request = LedgerRequest {
                request: Some(ledger_request::Request::CreateKey(request)),
            };
            self.send_request(ledger_request);
            let ledger_response = self.advance_until_response();
            if let Some(ledger_response::Response::CreateKey(response)) = ledger_response.response {
                Ok(response)
            } else {
                Err(LedgerService::parse_error(ledger_response))
            }
        }

        fn delete_key(
            &mut self,
            request: DeleteKeyRequest,
        ) -> Result<DeleteKeyResponse, micro_rpc::Status> {
            let ledger_request = LedgerRequest {
                request: Some(ledger_request::Request::DeleteKey(request)),
            };
            self.send_request(ledger_request);
            let ledger_response = self.advance_until_response();
            if let Some(ledger_response::Response::DeleteKey(response)) = ledger_response.response {
                Ok(response)
            } else {
                Err(LedgerService::parse_error(ledger_response))
            }
        }

        fn authorize_access(
            &mut self,
            request: AuthorizeAccessRequest,
        ) -> Result<AuthorizeAccessResponse, micro_rpc::Status> {
            let ledger_request = LedgerRequest {
                request: Some(ledger_request::Request::AuthorizeAccess(request)),
            };
            self.send_request(ledger_request);
            let ledger_response = self.advance_until_response();
            if let Some(ledger_response::Response::AuthorizeAccess(response)) =
                ledger_response.response
            {
                Ok(response)
            } else {
                Err(LedgerService::parse_error(ledger_response))
            }
        }

        fn revoke_access(
            &mut self,
            request: RevokeAccessRequest,
        ) -> Result<RevokeAccessResponse, micro_rpc::Status> {
            let ledger_request = LedgerRequest {
                request: Some(ledger_request::Request::RevokeAccess(request)),
            };
            self.send_request(ledger_request);
            let ledger_response = self.advance_until_response();
            if let Some(ledger_response::Response::RevokeAccess(response)) =
                ledger_response.response
            {
                Ok(response)
            } else {
                Err(LedgerService::parse_error(ledger_response))
            }
        }
    }

    /// Macro asserting that a result is failed with a particular code and message.
    macro_rules! assert_err {
        ($left:expr, $code:expr, $substr:expr) => {
            match (&$left, &$code, &$substr) {
                (left_val, code_val, substr_val) =>
                    assert!(
                        (*left_val).as_ref().is_err_and(
                            |err| err.code == *code_val && err.message.contains(*substr_val)),
                            "assertion failed: \
                             `(val.err().code == code && val.err().message.contains(substr)`\n\
                             val: {:?}\n\
                             code: {:?}\n\
                             substr: {:?}",
                            left_val,
                            code_val,
                            substr_val)
            }
        };
    }

    /// Helper function to create a LedgerService with one key.
    fn create_ledger_service() -> (LedgerService, Vec<u8>, u32) {
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
        let details = PublicKeyDetails::decode(response.public_key_details.as_ref()).unwrap();
        (ledger, response.public_key, details.public_key_id)
    }

    #[test]
    fn test_create_key() {
        let mut ledger = LedgerService::default();

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
        let details1 = PublicKeyDetails::decode(response1.public_key_details.as_ref()).unwrap();

        assert_eq!(response1.attestation, &[]);
        assert_eq!(
            details1.issued,
            Some(prost_types::Timestamp {
                seconds: 1000,
                ..Default::default()
            })
        );
        assert_eq!(
            details1.expiration,
            Some(prost_types::Timestamp {
                seconds: 1100,
                ..Default::default()
            })
        );

        // Since the response contains many random fields, we can't check them directly. Instead,
        // we create a second key and verify that those fields are different.
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
        let details2 = PublicKeyDetails::decode(response2.public_key_details.as_ref()).unwrap();

        assert_ne!(response1.public_key, response2.public_key);
        assert_ne!(details1.public_key_id, details2.public_key_id);
    }

    #[test]
    fn test_delete_key() {
        let (mut ledger, _, public_key_id) = create_ledger_service();
        assert_eq!(
            ledger.delete_key(DeleteKeyRequest { public_key_id }),
            Ok(DeleteKeyResponse::default())
        );

        // To verify that the key was actually deleted, we check that attempting to delete it again
        // produces an error.
        assert_err!(
            ledger.delete_key(DeleteKeyRequest { public_key_id }),
            micro_rpc::StatusCode::NotFound,
            "public key not found"
        );
    }

    #[test]
    fn test_delete_key_not_found() {
        let (mut ledger, _, public_key_id) = create_ledger_service();
        assert_err!(
            ledger.delete_key(DeleteKeyRequest {
                public_key_id: public_key_id.wrapping_add(1)
            }),
            micro_rpc::StatusCode::NotFound,
            "public key not found"
        );
    }

    #[test]
    fn test_authorize_access() {
        let (mut ledger, public_key, public_key_id) = create_ledger_service();

        // Define an access policy that grants access.
        let recipient_tag = "tag";
        let access_policy = DataAccessPolicy {
            transforms: vec![Transform {
                application: Some(ApplicationMatcher {
                    tag: Some(recipient_tag.to_owned()),
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
            public_key_id,
            access_policy_sha256: Sha256::digest(&access_policy).to_vec(),
            ..Default::default()
        }
        .encode_to_vec();
        let (ciphertext, encapsulated_key, encrypted_symmetric_key) =
            cfc_crypto::encrypt_message(plaintext, &public_key, &blob_header).unwrap();

        // Request access.
        let (recipient_private_key, recipient_public_key) = cfc_crypto::gen_keypair();
        let recipient_nonce: &[u8] = b"nonce";
        let response = ledger
            .authorize_access(AuthorizeAccessRequest {
                access_policy,
                blob_header: blob_header.clone(),
                encapsulated_key,
                encrypted_symmetric_key,
                recipient_public_key,
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
    fn test_authorize_access_invalid_header() {
        let (mut ledger, public_key, public_key_id) = create_ledger_service();

        // Define an access policy that grants access.
        let recipient_tag = "tag";
        let access_policy = DataAccessPolicy {
            transforms: vec![Transform {
                application: Some(ApplicationMatcher {
                    tag: Some(recipient_tag.to_owned()),
                }),
                ..Default::default()
            }],
            ..Default::default()
        }
        .encode_to_vec();

        // Construct a client message.
        let blob_header = BlobHeader {
            blob_id: "blob-id".into(),
            public_key_id,
            access_policy_sha256: Sha256::digest(&access_policy).to_vec(),
            ..Default::default()
        }
        .encode_to_vec();
        let (_, encapsulated_key, encrypted_symmetric_key) =
            cfc_crypto::encrypt_message(b"plaintext", &public_key, &blob_header).unwrap();

        // Request access.
        assert_err!(
            ledger.authorize_access(AuthorizeAccessRequest {
                access_policy,
                blob_header: "invalid".into(),
                encapsulated_key,
                encrypted_symmetric_key,
                recipient_public_key: cfc_crypto::gen_keypair().1,
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
        let (mut ledger, public_key, public_key_id) = create_ledger_service();

        // Define an access policy that grants access.
        let recipient_tag = "tag";
        let access_policy = DataAccessPolicy {
            transforms: vec![Transform {
                application: Some(ApplicationMatcher {
                    tag: Some(recipient_tag.to_owned()),
                }),
                ..Default::default()
            }],
            ..Default::default()
        }
        .encode_to_vec();

        // Construct a client message.
        let blob_header = BlobHeader {
            blob_id: "blob-id".into(),
            public_key_id,
            access_policy_sha256: "invalid".into(),
            ..Default::default()
        }
        .encode_to_vec();
        let (_, encapsulated_key, encrypted_symmetric_key) =
            cfc_crypto::encrypt_message(b"plaintext", &public_key, &blob_header).unwrap();

        // Request access.
        assert_err!(
            ledger.authorize_access(AuthorizeAccessRequest {
                access_policy,
                blob_header: blob_header,
                encapsulated_key,
                encrypted_symmetric_key,
                recipient_public_key: cfc_crypto::gen_keypair().1,
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
        let (mut ledger, public_key, public_key_id) = create_ledger_service();

        // Define an access policy that can't be decoded.
        let access_policy = b"invalid";

        // Construct a client message.
        let blob_header = BlobHeader {
            blob_id: "blob-id".into(),
            public_key_id,
            access_policy_sha256: Sha256::digest(access_policy).to_vec(),
            ..Default::default()
        }
        .encode_to_vec();
        let (_, encapsulated_key, encrypted_symmetric_key) =
            cfc_crypto::encrypt_message(b"plaintext", &public_key, &blob_header).unwrap();

        // Request access.
        assert_err!(
            ledger.authorize_access(AuthorizeAccessRequest {
                access_policy: access_policy.to_vec(),
                blob_header: blob_header,
                encapsulated_key,
                encrypted_symmetric_key,
                recipient_public_key: cfc_crypto::gen_keypair().1,
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
        let (mut ledger, public_key, public_key_id) = create_ledger_service();

        // Define an access policy that does not grant access.
        let access_policy = DataAccessPolicy::default().encode_to_vec();

        // Construct a client message.
        let blob_header = BlobHeader {
            blob_id: "blob-id".into(),
            public_key_id,
            access_policy_sha256: Sha256::digest(&access_policy).to_vec(),
            ..Default::default()
        }
        .encode_to_vec();
        let (_, encapsulated_key, encrypted_symmetric_key) =
            cfc_crypto::encrypt_message(b"plaintext", &public_key, &blob_header).unwrap();

        // Request access.
        assert_err!(
            ledger.authorize_access(AuthorizeAccessRequest {
                access_policy,
                blob_header,
                encapsulated_key,
                encrypted_symmetric_key,
                recipient_public_key: cfc_crypto::gen_keypair().1,
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
        let (mut ledger, public_key, public_key_id) = create_ledger_service();

        // Define an access policy that grants access.
        let recipient_tag = "tag";
        let access_policy = DataAccessPolicy {
            transforms: vec![Transform {
                application: Some(ApplicationMatcher {
                    tag: Some(recipient_tag.to_owned()),
                }),
                ..Default::default()
            }],
            ..Default::default()
        }
        .encode_to_vec();

        // Construct a client message that was encrypted with different associated data.
        let blob_header = BlobHeader {
            blob_id: "blob-id".into(),
            public_key_id,
            access_policy_sha256: Sha256::digest(&access_policy).to_vec(),
            ..Default::default()
        }
        .encode_to_vec();
        let (_, encapsulated_key, encrypted_symmetric_key) =
            cfc_crypto::encrypt_message(b"plaintext", &public_key, b"other aad").unwrap();

        // Request access.
        assert_err!(
            ledger.authorize_access(AuthorizeAccessRequest {
                access_policy,
                blob_header: blob_header,
                encapsulated_key,
                encrypted_symmetric_key,
                recipient_public_key: cfc_crypto::gen_keypair().1,
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
        let (mut ledger, public_key, public_key_id) = create_ledger_service();

        // Define an access policy that grants access.
        let recipient_tag = "tag";
        let access_policy = DataAccessPolicy {
            transforms: vec![Transform {
                application: Some(ApplicationMatcher {
                    tag: Some(recipient_tag.to_owned()),
                }),
                ..Default::default()
            }],
            ..Default::default()
        }
        .encode_to_vec();

        // Construct a client message using a public key id that doesn't exist.
        let blob_header = BlobHeader {
            blob_id: "blob-id".into(),
            public_key_id: public_key_id.wrapping_add(1),
            access_policy_sha256: Sha256::digest(&access_policy).to_vec(),
            ..Default::default()
        }
        .encode_to_vec();
        let (_, encapsulated_key, encrypted_symmetric_key) =
            cfc_crypto::encrypt_message(b"plaintext", &public_key, &blob_header).unwrap();

        // Request access.
        assert_err!(
            ledger.authorize_access(AuthorizeAccessRequest {
                access_policy,
                blob_header: blob_header,
                encapsulated_key,
                encrypted_symmetric_key,
                recipient_public_key: cfc_crypto::gen_keypair().1,
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
        let (mut ledger, public_key, public_key_id) = create_ledger_service();

        // Define an access policy that grants access.
        let recipient_tag = "tag";
        let access_policy = DataAccessPolicy {
            transforms: vec![Transform {
                application: Some(ApplicationMatcher {
                    tag: Some(recipient_tag.to_owned()),
                }),
                ..Default::default()
            }],
            ..Default::default()
        }
        .encode_to_vec();

        // Construct a client message.
        let blob_header = BlobHeader {
            blob_id: "blob-id".into(),
            public_key_id,
            access_policy_sha256: Sha256::digest(&access_policy).to_vec(),
            ..Default::default()
        }
        .encode_to_vec();
        let (_, encapsulated_key, encrypted_symmetric_key) =
            cfc_crypto::encrypt_message(b"plaintext", &public_key, &blob_header).unwrap();

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
                recipient_public_key: cfc_crypto::gen_keypair().1,
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
        let (mut ledger, public_key, public_key_id) = create_ledger_service();
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
            public_key_id,
            access_policy_sha256: Sha256::digest(&access_policy).to_vec(),
            ..Default::default()
        }
        .encode_to_vec();
        let (_, encapsulated_key, encrypted_symmetric_key) =
            cfc_crypto::encrypt_message(plaintext, &public_key, &blob_header).unwrap();

        // The first access should succeed.
        assert!(ledger
            .authorize_access(AuthorizeAccessRequest {
                access_policy: access_policy.clone(),
                blob_header: blob_header.clone(),
                encapsulated_key: encapsulated_key.clone(),
                encrypted_symmetric_key: encrypted_symmetric_key.clone(),
                recipient_public_key: cfc_crypto::gen_keypair().1,
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
                recipient_public_key: cfc_crypto::gen_keypair().1,
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
        let (mut ledger, public_key, public_key_id) = create_ledger_service();
        let blob_id = b"blob-id";
        assert_eq!(
            ledger.revoke_access(RevokeAccessRequest {
                public_key_id,
                blob_id: blob_id.to_vec(),
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
            public_key_id,
            access_policy_sha256: Sha256::digest(&access_policy).to_vec(),
            ..Default::default()
        }
        .encode_to_vec();
        let (_, encapsulated_key, encrypted_symmetric_key) =
            cfc_crypto::encrypt_message(plaintext, &public_key, &blob_header).unwrap();

        assert_err!(
            ledger.authorize_access(AuthorizeAccessRequest {
                access_policy,
                blob_header: blob_header.clone(),
                encapsulated_key,
                encrypted_symmetric_key,
                recipient_public_key: cfc_crypto::gen_keypair().1,
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
        let (mut ledger, _, public_key_id) = create_ledger_service();
        assert_err!(
            ledger.revoke_access(RevokeAccessRequest {
                public_key_id: public_key_id.wrapping_add(1),
                blob_id: "blob-id".into(),
            }),
            micro_rpc::StatusCode::NotFound,
            "public key not found"
        );
    }

    #[test]
    fn test_monotonic_time() {
        let mut ledger = LedgerService::default();
        ledger
            .create_key(CreateKeyRequest {
                now: Some(prost_types::Timestamp {
                    seconds: 1000,
                    ..Default::default()
                }),
                ..Default::default()
            })
            .unwrap();

        // Timestamps passed to the LedgerService must be non-decreasing.
        assert_err!(
            ledger.create_key(CreateKeyRequest {
                now: Some(prost_types::Timestamp {
                    seconds: 500,
                    ..Default::default()
                }),
                ..Default::default()
            }),
            micro_rpc::StatusCode::InvalidArgument,
            "time must be monotonic"
        );
        assert_err!(
            ledger.authorize_access(AuthorizeAccessRequest {
                now: Some(prost_types::Timestamp {
                    seconds: 500,
                    ..Default::default()
                }),
                ..Default::default()
            }),
            micro_rpc::StatusCode::InvalidArgument,
            "time must be monotonic"
        );
    }
}
