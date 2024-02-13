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
    use tcp_ledger_service::fcp::confidentialcompute::*;
    use tcp_ledger_service::ledger::Ledger;
    use tcp_proto::runtime::endpoint::*;

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
}
