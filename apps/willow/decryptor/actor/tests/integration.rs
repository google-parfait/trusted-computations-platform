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

extern crate prost;
extern crate tcp_integration;
extern crate tcp_proto;
extern crate willow_decryptor_service;

mod test {

    use accumulator_traits::CiphertextAccumulator;
    use aggregation_config::AggregationConfig;
    use ahe_traits::AheBase;
    use client_traits::Client;
    use default_accumulator::{CiphertextAccumulatorState, DefaultCiphertextAccumulator};
    use default_client::DefaultClient;
    use default_verifier::{DefaultVerifier, VerifierState};
    use kahe_traits::KaheBase;
    use key_rust_proto::Key as KeyProto;
    use messages::{DecryptorPublicKey, FinalizedPartialDecryption, PartialDecryptionResponse};
    use messages_rust_proto::PartialDecryptionResponse as PartialDecryptionResponseProto;
    use prost::bytes::Bytes;
    use prost::Message;
    use prost_types::Timestamp;
    use proto_serialization_traits::{FromProto, ToProto};
    use protobuf::prelude::*;
    use secure_aggregation::proto::*;
    use shell_ciphertexts_rust_proto::ShellAhePublicKey;
    use shell_kahe::ShellKahe;
    use shell_parameters::{create_shell_ahe_config, create_shell_kahe_config};
    use shell_vahe::ShellVahe;
    use std::collections::HashMap;
    use std::rc::Rc;
    use tcp_integration::harness::*;
    use tcp_proto::runtime::endpoint::out_message;
    use vahe_traits::HasVahe;
    use verifier_traits::Verifier;
    use willow_decryptor_service::actor::DecryptorActor;

    fn advance_until_response(cluster: &mut FakeCluster<DecryptorActor>) -> DecryptorResponse {
        let mut decrytpor_response: Option<DecryptorResponse> = None;
        let response_messages =
            cluster.advance_until(&mut |envelope_out| match &envelope_out.msg {
                Some(out_message::Msg::DeliverAppMessage(message)) => {
                    let response =
                        DecryptorResponse::decode(message.message_header.as_ref()).unwrap();
                    decrytpor_response = Some(response);
                    return true;
                }
                _ => false,
            });

        assert!(!response_messages.is_empty());
        decrytpor_response.unwrap()
    }

    fn setup_test_cluster() -> FakeCluster<DecryptorActor> {
        let mut cluster = FakeCluster::new(Bytes::new());
        cluster.start_node(1, true, DecryptorActor::new());
        cluster.advance_until_elected_leader(None);
        assert_eq!(cluster.leader_id(), 1);
        cluster
    }

    fn send_request(
        cluster: &mut FakeCluster<DecryptorActor>,
        correlation_id: u64,
        msg: decryptor_request::Msg,
    ) -> DecryptorResponse {
        let request = DecryptorRequest { msg: Some(msg) };
        cluster.send_app_message(
            cluster.leader_id(),
            correlation_id,
            request.encode_to_vec().into(),
            Bytes::new(),
        );
        advance_until_response(cluster)
    }

    fn expect_generate_key_response(response: DecryptorResponse) -> GenerateKeyResponse {
        match response.msg {
            Some(decryptor_response::Msg::GenerateKey(resp)) => resp,
            other => panic!("Expected GenerateKeyResponse, got {:?}", other),
        }
    }

    fn expect_decrypt_response(response: DecryptorResponse) -> DecryptResponse {
        match response.msg {
            Some(decryptor_response::Msg::Decrypt(resp)) => resp,
            other => panic!("Expected DecryptResponse, got {:?}", other),
        }
    }

    fn expect_list_keys_response(response: DecryptorResponse) -> ListKeysResponse {
        match response.msg {
            Some(decryptor_response::Msg::ListKeys(resp)) => resp,
            other => panic!("Expected ListKeysResponse, got {:?}", other),
        }
    }

    fn expect_error_response(response: DecryptorResponse) -> Status {
        match response.msg {
            Some(decryptor_response::Msg::Error(status)) => status,
            other => panic!("Expected Error response, got {:?}", other),
        }
    }

    #[test]
    fn test_generate_key() {
        let mut cluster = setup_test_cluster();

        let key_id: Vec<u8> = "key_id".into();
        let expected_session_tag = "test_session_tag".to_string();
        let expected_created_timestamp = Timestamp { seconds: 123456789, nanos: 456 };

        let response = send_request(
            &mut cluster,
            1,
            decryptor_request::Msg::GenerateKey(GenerateKeyRequest {
                key_id: key_id.clone(),
                session_tag: expected_session_tag.clone(),
                created_timestamp: Some(expected_created_timestamp.clone()),
                expiration_timestamp: None,
            }),
        );

        let gen_resp = expect_generate_key_response(response);
        let key = KeyProto::parse(&gen_resp.public_key).unwrap();
        assert_eq!(key.key_id(), key_id);
        assert!(!key.key_material().is_empty());
        assert_eq!(key.session_tag().to_str().unwrap(), expected_session_tag);
        assert!(key.has_timestamp());
        let ts = key.timestamp();
        assert_eq!(ts.seconds(), expected_created_timestamp.seconds);
        assert_eq!(ts.nanos(), expected_created_timestamp.nanos);
    }

    #[test]
    fn test_generate_key_optional_id() {
        let mut cluster = setup_test_cluster();

        let expected_session_tag = "test_session_tag".to_string();
        let expected_created_timestamp = Timestamp { seconds: 123456789, nanos: 456 };

        let response = send_request(
            &mut cluster,
            1,
            decryptor_request::Msg::GenerateKey(GenerateKeyRequest {
                key_id: vec![],
                session_tag: expected_session_tag.clone(),
                created_timestamp: Some(expected_created_timestamp.clone()),
                expiration_timestamp: None,
            }),
        );

        let gen_resp = expect_generate_key_response(response);
        assert_eq!(gen_resp.key_id.len(), 16);

        let key = KeyProto::parse(&gen_resp.public_key).unwrap();
        assert_eq!(key.key_id(), gen_resp.key_id);
        assert!(!key.key_material().is_empty());
        assert_eq!(key.session_tag().to_str().unwrap(), expected_session_tag);
        assert!(key.has_timestamp());
        let ts = key.timestamp();
        assert_eq!(ts.seconds(), expected_created_timestamp.seconds);
        assert_eq!(ts.nanos(), expected_created_timestamp.nanos);
    }

    #[test]
    fn test_generate_key_already_exists_returns_same_key() {
        let mut cluster = setup_test_cluster();

        let key_id: Vec<u8> = "key_id".into();
        let resp_1 = send_request(
            &mut cluster,
            1,
            decryptor_request::Msg::GenerateKey(GenerateKeyRequest {
                key_id: key_id.clone(),
                session_tag: "session_tag".to_string(),
                created_timestamp: None,
                expiration_timestamp: None,
            }),
        );

        let gen_resp_1 = expect_generate_key_response(resp_1);
        let key_1 = KeyProto::parse(&gen_resp_1.public_key).unwrap();
        assert_eq!(key_1.key_id(), key_id);
        assert!(!key_1.key_material().is_empty());

        let resp_2 = send_request(
            &mut cluster,
            1,
            decryptor_request::Msg::GenerateKey(GenerateKeyRequest {
                key_id: key_id.clone(),
                session_tag: "session_tag".to_string(),
                created_timestamp: None,
                expiration_timestamp: None,
            }),
        );

        let gen_resp_2 = expect_generate_key_response(resp_2);
        let key_2 = KeyProto::parse(&gen_resp_2.public_key).unwrap();
        assert_eq!(key_2.key_id(), key_id);
        assert!(!key_2.key_material().is_empty());

        assert_eq!(key_1.key_material(), key_2.key_material());
    }

    #[test]
    fn test_generate_key_and_decrypt() {
        // Step 1: Generate Key
        let mut cluster = setup_test_cluster();

        let key_id = "key_id";
        let resp = send_request(
            &mut cluster,
            1,
            decryptor_request::Msg::GenerateKey(GenerateKeyRequest {
                key_id: key_id.into(),
                session_tag: "session_tag".to_string(),
                created_timestamp: None,
                expiration_timestamp: None,
            }),
        );

        let gen_resp = expect_generate_key_response(resp);
        let key = KeyProto::parse(&gen_resp.public_key).unwrap();
        let public_key_bytes = key.key_material();

        // Step 2: Encrypt a message using the public key
        let default_id = String::from("default");
        let max_number_of_decryptors = 1;
        let aggregation_config = AggregationConfig {
            vector_lengths_and_bounds: HashMap::from([(default_id.clone(), (16, 10))]),
            max_number_of_decryptors: max_number_of_decryptors,
            max_number_of_clients: 1,
            max_decryptor_dropouts: 0,
            key_id: key_id.into(),
        };

        // Create common KAHE/VAHE instances.
        let kahe = Rc::new(
            ShellKahe::new(
                create_shell_kahe_config(&aggregation_config).unwrap(),
                key_id.as_bytes(),
            )
            .unwrap(),
        );
        let vahe = Rc::new(
            ShellVahe::new(
                create_shell_ahe_config(max_number_of_decryptors).unwrap(),
                key_id.as_bytes(),
            )
            .unwrap(),
        );

        // Create client.
        let client =
            DefaultClient::new_with_randomly_generated_seed(Rc::clone(&kahe), Rc::clone(&vahe))
                .unwrap();

        // Create accumulator.
        let accumulator =
            DefaultCiphertextAccumulator { kahe: Rc::clone(&kahe), vahe: Rc::clone(&vahe) };
        let mut accumulator_state = CiphertextAccumulatorState::default();

        // Create verifier.
        let verifier = DefaultVerifier { vahe: Rc::clone(&vahe) };
        let mut verifier_state = VerifierState::default();

        let public_key_proto = ShellAhePublicKey::parse(&public_key_bytes).unwrap();
        let public_key: DecryptorPublicKey<ShellVahe> =
            DecryptorPublicKey::<ShellVahe>::from_proto(public_key_proto, verifier.vahe()).unwrap();

        let client_plaintext = HashMap::from([(
            default_id.clone(),
            vec![1, 2, 3, 4, 5, 6, 7, 8, 7, 6, 5, 4, 3, 2, 1],
        )]);
        let nonce = vec![0u8; 16];
        let client_message = client
            .create_client_message(
                &ShellKahe::plaintext_as_slice(&client_plaintext),
                &public_key,
                &nonce,
            )
            .unwrap();

        let (ciphertext_contribution, decryption_request_contribution) =
            accumulator.split_client_message(client_message).unwrap();

        verifier.verify_and_include(decryption_request_contribution, &mut verifier_state).unwrap();
        accumulator
            .accumulate_ciphertext_contribution(ciphertext_contribution, &mut accumulator_state)
            .unwrap();

        // Verifier creates the partial decryption request.
        let pd_ct = verifier.create_partial_decryption_request(verifier_state).unwrap();
        let pd_ct_proto = pd_ct.to_proto(&verifier).unwrap();
        let pd_ct_bytes = pd_ct_proto.serialize().unwrap().into();

        // Step 3: Decrypt the message
        let resp = send_request(
            &mut cluster,
            2,
            decryptor_request::Msg::Decrypt(DecryptRequest {
                decryption_request: pd_ct_bytes,
                public_key: "".into(), // Deprecated
                key_id: key_id.into(),
                session_tag: "session_tag".to_string(),
                current_timestamp: None,
            }),
        );

        let decrypt_resp = expect_decrypt_response(resp);
        let pd_proto =
            PartialDecryptionResponseProto::parse(&decrypt_resp.decryption_response).unwrap();
        let pd = PartialDecryptionResponse::from_proto(pd_proto, &accumulator).unwrap();

        // Accumulator recovers the aggregation result.
        let finalized_pd =
            FinalizedPartialDecryption { partial_decryption_sum: pd.partial_decryption };
        let aggregation_result =
            accumulator.recover_aggregation_result(&accumulator_state, &finalized_pd).unwrap();

        let client_plaintext_length = client_plaintext.get(default_id.as_str()).unwrap().len();
        assert_eq!(
            aggregation_result.get(default_id.as_str()).unwrap()[..client_plaintext_length],
            client_plaintext.get(default_id.as_str()).unwrap()[..]
        )
    }

    #[test]
    fn test_decrypt_invalid_key_id() {
        // Step 1: Generate Key
        let mut cluster = setup_test_cluster();

        let key_id = "key_id";
        let resp = send_request(
            &mut cluster,
            1,
            decryptor_request::Msg::GenerateKey(GenerateKeyRequest {
                key_id: key_id.into(),
                session_tag: "session_tag".to_string(),
                created_timestamp: None,
                expiration_timestamp: None,
            }),
        );

        let gen_resp = expect_generate_key_response(resp);
        let key = KeyProto::parse(&gen_resp.public_key).unwrap();
        let public_key_bytes = key.key_material();

        // Step 2: Encrypt a message using the public key
        let default_id = String::from("default");
        let max_number_of_decryptors = 1;
        let aggregation_config = AggregationConfig {
            vector_lengths_and_bounds: HashMap::from([(default_id.clone(), (16, 10))]),
            max_number_of_decryptors: max_number_of_decryptors,
            max_number_of_clients: 1,
            max_decryptor_dropouts: 0,
            key_id: key_id.into(),
        };

        // Create common KAHE/VAHE instances.
        let kahe = Rc::new(
            ShellKahe::new(
                create_shell_kahe_config(&aggregation_config).unwrap(),
                key_id.as_bytes(),
            )
            .unwrap(),
        );
        let vahe = Rc::new(
            ShellVahe::new(
                create_shell_ahe_config(max_number_of_decryptors).unwrap(),
                key_id.as_bytes(),
            )
            .unwrap(),
        );

        // Create client.
        let client =
            DefaultClient::new_with_randomly_generated_seed(Rc::clone(&kahe), Rc::clone(&vahe))
                .unwrap();

        // Create accumulator.
        let accumulator =
            DefaultCiphertextAccumulator { kahe: Rc::clone(&kahe), vahe: Rc::clone(&vahe) };
        let mut accumulator_state = CiphertextAccumulatorState::default();

        // Create verifier.
        let verifier = DefaultVerifier { vahe: Rc::clone(&vahe) };
        let mut verifier_state = VerifierState::default();

        let public_key_proto = ShellAhePublicKey::parse(&public_key_bytes).unwrap();
        let public_key: DecryptorPublicKey<ShellVahe> =
            DecryptorPublicKey::<ShellVahe>::from_proto(public_key_proto, verifier.vahe()).unwrap();

        let client_plaintext = HashMap::from([(
            default_id.clone(),
            vec![1, 2, 3, 4, 5, 6, 7, 8, 7, 6, 5, 4, 3, 2, 1],
        )]);
        let nonce = vec![0u8; 16];
        let client_message = client
            .create_client_message(
                &ShellKahe::plaintext_as_slice(&client_plaintext),
                &public_key,
                &nonce,
            )
            .unwrap();

        let (ciphertext_contribution, decryption_request_contribution) =
            accumulator.split_client_message(client_message).unwrap();

        verifier.verify_and_include(decryption_request_contribution, &mut verifier_state).unwrap();
        accumulator
            .accumulate_ciphertext_contribution(ciphertext_contribution, &mut accumulator_state)
            .unwrap();

        // Verifier creates the partial decryption request.
        let pd_ct = verifier.create_partial_decryption_request(verifier_state).unwrap();
        let pd_ct_proto = pd_ct.to_proto(&verifier).unwrap();
        let pd_ct_bytes = pd_ct_proto.serialize().unwrap().into();

        // Step 3: Attempt to Decrypt the message with invalid key id
        let key_id = "unknown key id";
        let resp = send_request(
            &mut cluster,
            2,
            decryptor_request::Msg::Decrypt(DecryptRequest {
                decryption_request: pd_ct_bytes,
                public_key: "".into(), // Deprecated
                key_id: key_id.into(),
                session_tag: "session_tag".to_string(),
                current_timestamp: None,
            }),
        );

        let status = expect_error_response(resp);
        let (error_code, error_message) = (status.code, status.message);

        assert_eq!(error_code, 9);
        assert_eq!(
            error_message,
            "Key pair not found for given key id: \\x75\\x6e\\x6b\\x6e\\x6f\\x77\\x6e\\x20\\x6b\\x65\\x79\\x20\\x69\\x64"
        );
    }

    #[test]
    fn test_attempt_at_second_decryption_fails() {
        // Step 1: Generate Key
        let mut cluster = setup_test_cluster();

        let key_id = "key_id";
        let resp = send_request(
            &mut cluster,
            1,
            decryptor_request::Msg::GenerateKey(GenerateKeyRequest {
                key_id: key_id.into(),
                session_tag: "session_tag".to_string(),
                created_timestamp: None,
                expiration_timestamp: None,
            }),
        );

        let gen_resp = expect_generate_key_response(resp);
        let key = KeyProto::parse(&gen_resp.public_key).unwrap();
        let public_key_bytes = key.key_material();

        // Step 2: Encrypt a message using the public key
        let default_id = String::from("default");
        let max_number_of_decryptors = 1;
        let aggregation_config = AggregationConfig {
            vector_lengths_and_bounds: HashMap::from([(default_id.clone(), (16, 10))]),
            max_number_of_decryptors: max_number_of_decryptors,
            max_number_of_clients: 1,
            max_decryptor_dropouts: 0,
            key_id: key_id.into(),
        };

        // Create common KAHE/VAHE instances.
        let kahe = Rc::new(
            ShellKahe::new(
                create_shell_kahe_config(&aggregation_config).unwrap(),
                key_id.as_bytes(),
            )
            .unwrap(),
        );
        let vahe = Rc::new(
            ShellVahe::new(
                create_shell_ahe_config(max_number_of_decryptors).unwrap(),
                key_id.as_bytes(),
            )
            .unwrap(),
        );

        // Create client.
        let client =
            DefaultClient::new_with_randomly_generated_seed(Rc::clone(&kahe), Rc::clone(&vahe))
                .unwrap();

        // Create accumulator.
        let accumulator =
            DefaultCiphertextAccumulator { kahe: Rc::clone(&kahe), vahe: Rc::clone(&vahe) };
        let mut accumulator_state = CiphertextAccumulatorState::default();

        // Create verifier.
        let verifier = DefaultVerifier { vahe: Rc::clone(&vahe) };
        let mut verifier_state = VerifierState::default();

        let public_key_proto = ShellAhePublicKey::parse(&public_key_bytes).unwrap();
        let public_key: DecryptorPublicKey<ShellVahe> =
            DecryptorPublicKey::<ShellVahe>::from_proto(public_key_proto, verifier.vahe()).unwrap();

        let client_plaintext = HashMap::from([(
            default_id.clone(),
            vec![1, 2, 3, 4, 5, 6, 7, 8, 7, 6, 5, 4, 3, 2, 1],
        )]);
        let nonce = vec![0u8; 16];
        let client_message = client
            .create_client_message(
                &ShellKahe::plaintext_as_slice(&client_plaintext),
                &public_key,
                &nonce,
            )
            .unwrap();

        let (ciphertext_contribution, decryption_request_contribution) =
            accumulator.split_client_message(client_message).unwrap();

        verifier.verify_and_include(decryption_request_contribution, &mut verifier_state).unwrap();
        accumulator
            .accumulate_ciphertext_contribution(ciphertext_contribution, &mut accumulator_state)
            .unwrap();

        // Verifier creates the partial decryption request.
        let pd_ct = verifier.create_partial_decryption_request(verifier_state).unwrap();
        let pd_ct_proto = pd_ct.to_proto(&verifier).unwrap();
        let pd_ct_bytes = pd_ct_proto.serialize().unwrap().into();

        // Step 3: Decrypt the message
        let decrypt_msg = decryptor_request::Msg::Decrypt(DecryptRequest {
            decryption_request: pd_ct_bytes,
            public_key: "".into(), // Deprecated
            key_id: key_id.into(),
            session_tag: "session_tag".to_string(),
            current_timestamp: None,
        });

        let resp_1 = send_request(&mut cluster, 2, decrypt_msg.clone());
        let _decrypt_resp = expect_decrypt_response(resp_1);

        // Step 4: Send second decryption request which should fail
        let resp_2 = send_request(&mut cluster, 2, decrypt_msg);
        let status = expect_error_response(resp_2);
        let (error_code, error_message) = (status.code, status.message);

        assert_eq!(error_code, 9);
        assert_eq!(
            error_message,
            "Key pair not found for given key id: \\x6b\\x65\\x79\\x5f\\x69\\x64"
        );
    }

    #[test]
    fn test_list_keys() {
        let mut cluster = setup_test_cluster();

        let key_id_1: Vec<u8> = "key_id_1".into();
        let key_id_2: Vec<u8> = "key_id_2".into();
        let key_id_3: Vec<u8> = "key_id_3".into();

        // 1. Generate key 1 with session_tag_1 (timestamp: 200)
        let resp_1 = send_request(
            &mut cluster,
            1,
            decryptor_request::Msg::GenerateKey(GenerateKeyRequest {
                key_id: key_id_1.clone(),
                session_tag: "session_tag_1".to_string(),
                created_timestamp: Some(Timestamp { seconds: 200, nanos: 0 }),
                expiration_timestamp: None,
            }),
        );
        let key_1_bytes = expect_generate_key_response(resp_1).public_key;

        // 2. Generate key 2 with session_tag_1 (timestamp: 100)
        let resp_2 = send_request(
            &mut cluster,
            2,
            decryptor_request::Msg::GenerateKey(GenerateKeyRequest {
                key_id: key_id_2.clone(),
                session_tag: "session_tag_1".to_string(),
                created_timestamp: Some(Timestamp { seconds: 100, nanos: 0 }),
                expiration_timestamp: None,
            }),
        );
        let key_2_bytes = expect_generate_key_response(resp_2).public_key;

        // 3. Generate key 3 with session_tag_2
        let resp_3 = send_request(
            &mut cluster,
            3,
            decryptor_request::Msg::GenerateKey(GenerateKeyRequest {
                key_id: key_id_3.clone(),
                session_tag: "session_tag_2".to_string(),
                created_timestamp: None,
                expiration_timestamp: None,
            }),
        );
        let key_3_bytes = expect_generate_key_response(resp_3).public_key;

        // 4. List keys for session_tag_1
        let resp_list_1 = send_request(
            &mut cluster,
            4,
            decryptor_request::Msg::ListKeys(ListKeysRequest {
                session_tag: "session_tag_1".to_string(),
                current_timestamp: None,
            }),
        );
        let public_keys_1 = expect_list_keys_response(resp_list_1).public_keys;
        assert_eq!(public_keys_1.len(), 2);
        // Assert sorting order: key 2 (timestamp 100) must be first, key 1 (timestamp
        // 200) second.
        assert_eq!(public_keys_1[0], key_2_bytes);
        assert_eq!(public_keys_1[1], key_1_bytes);

        // 5. List keys for session_tag_2
        let resp_list_2 = send_request(
            &mut cluster,
            5,
            decryptor_request::Msg::ListKeys(ListKeysRequest {
                session_tag: "session_tag_2".to_string(),
                current_timestamp: None,
            }),
        );
        let public_keys_2 = expect_list_keys_response(resp_list_2).public_keys;
        assert_eq!(public_keys_2.len(), 1);
        assert_eq!(public_keys_2[0], key_3_bytes);
    }

    #[test]
    fn test_list_keys_unknown_session_tag_returns_empty() {
        let mut cluster = setup_test_cluster();

        let resp = send_request(
            &mut cluster,
            1,
            decryptor_request::Msg::ListKeys(ListKeysRequest {
                session_tag: "unknown_session_tag".to_string(),
                current_timestamp: None,
            }),
        );
        let public_keys = expect_list_keys_response(resp).public_keys;
        assert!(public_keys.is_empty());
    }

    #[test]
    fn test_list_keys_empty_session_tag_returns_error() {
        let mut cluster = setup_test_cluster();

        let resp = send_request(
            &mut cluster,
            1,
            decryptor_request::Msg::ListKeys(ListKeysRequest {
                session_tag: "".to_string(),
                current_timestamp: None,
            }),
        );
        let status = expect_error_response(resp);
        assert_eq!(status.code, 3); // StatusCode::InvalidArgument
        assert_eq!(status.message, "Session tag cannot be empty");
    }
}
