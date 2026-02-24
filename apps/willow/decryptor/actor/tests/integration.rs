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

    use aggregation_config::AggregationConfig;
    use ahe_traits::AheBase;
    use client_traits::SecureAggregationClient;
    use kahe_traits::KaheBase;
    use key_rust_proto::Key as KeyProto;
    use messages::{DecryptorPublicKeyShare, PartialDecryptionResponse};
    use messages_rust_proto::PartialDecryptionResponse as PartialDecryptionResponseProto;
    use prost::bytes::Bytes;
    use prost::Message;
    use proto_serialization_traits::{FromProto, ToProto};
    use protobuf::prelude::*;
    use secure_aggregation::proto::*;
    use server_traits::SecureAggregationServer;
    use shell_ciphertexts_rust_proto::ShellAhePublicKeyShare;
    use shell_kahe::ShellKahe;
    use shell_parameters::{create_shell_ahe_config, create_shell_kahe_config};
    use shell_vahe::ShellVahe;
    use std::collections::HashMap;
    use std::rc::Rc;
    use tcp_integration::harness::*;
    use tcp_proto::runtime::endpoint::out_message;
    use verifier_traits::SecureAggregationVerifier;
    use willow_decryptor_service::actor::DecryptorActor;
    use willow_v1_client::WillowV1Client;
    use willow_v1_decryptor::WillowV1Decryptor;
    use willow_v1_server::{ServerState, WillowV1Server};
    use willow_v1_verifier::{VerifierState, WillowV1Verifier};

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

    #[test]
    fn test_generate_key() {
        let mut cluster = FakeCluster::new(Bytes::new());

        cluster.start_node(1, true, DecryptorActor::new());
        cluster.advance_until_elected_leader(None);
        assert!(cluster.leader_id() == 1);

        let key_id: Vec<u8> = "key_id".into();
        let decryptor_generate_key_request = DecryptorRequest {
            msg: Some(decryptor_request::Msg::GenerateKey(GenerateKeyRequest {
                key_id: key_id.clone(),
            })),
        };

        cluster.send_app_message(
            cluster.leader_id(),
            1,
            decryptor_generate_key_request.encode_to_vec().into(),
            Bytes::new(),
        );

        let decyrptor_generate_key_response = advance_until_response(&mut cluster);
        let public_key: Option<Bytes> = decyrptor_generate_key_response.msg.and_then(|msg| {
            if let decryptor_response::Msg::GenerateKey(generate_key_response) = msg {
                Some(generate_key_response.public_key.clone().into())
            } else {
                None
            }
        });

        assert!(public_key.is_some());

        let key = KeyProto::parse(&public_key.unwrap()).unwrap();
        assert_eq!(key.key_id(), key_id);
        assert!(!key.key_material().is_empty());
    }

    #[test]
    fn test_generate_key_already_exists_returns_same_key() {
        let mut cluster = FakeCluster::new(Bytes::new());

        cluster.start_node(1, true, DecryptorActor::new());
        cluster.advance_until_elected_leader(None);
        assert!(cluster.leader_id() == 1);

        let key_id: Vec<u8> = "key_id".into();
        let decryptor_generate_key_request = DecryptorRequest {
            msg: Some(decryptor_request::Msg::GenerateKey(GenerateKeyRequest {
                key_id: key_id.clone(),
            })),
        };

        cluster.send_app_message(
            cluster.leader_id(),
            1,
            decryptor_generate_key_request.encode_to_vec().into(),
            Bytes::new(),
        );

        let decyrptor_generate_key_response = advance_until_response(&mut cluster);
        let public_key: Option<Bytes> = decyrptor_generate_key_response.msg.and_then(|msg| {
            if let decryptor_response::Msg::GenerateKey(generate_key_response) = msg {
                Some(generate_key_response.public_key.clone().into())
            } else {
                None
            }
        });

        assert!(public_key.is_some());

        let key_1 = KeyProto::parse(&public_key.unwrap()).unwrap();
        assert_eq!(key_1.key_id(), key_id);
        assert!(!key_1.key_material().is_empty());

        let decryptor_generate_key_request = DecryptorRequest {
            msg: Some(decryptor_request::Msg::GenerateKey(GenerateKeyRequest {
                key_id: key_id.clone(),
            })),
        };

        cluster.send_app_message(
            cluster.leader_id(),
            1,
            decryptor_generate_key_request.encode_to_vec().into(),
            Bytes::new(),
        );

        let decyrptor_generate_key_response = advance_until_response(&mut cluster);
        let public_key_2: Option<Bytes> = decyrptor_generate_key_response.msg.and_then(|msg| {
            if let decryptor_response::Msg::GenerateKey(generate_key_response) = msg {
                Some(generate_key_response.public_key.clone().into())
            } else {
                None
            }
        });

        assert!(public_key_2.is_some());

        let key_2 = KeyProto::parse(&public_key_2.unwrap()).unwrap();
        assert_eq!(key_2.key_id(), key_id);
        assert!(!key_2.key_material().is_empty());

        assert_eq!(key_1.key_material(), key_2.key_material());
    }

    #[test]
    fn test_generate_key_and_decrypt() {
        // Step 1: Generate Key
        let mut cluster = FakeCluster::new(Bytes::new());

        cluster.start_node(1, true, DecryptorActor::new());
        cluster.advance_until_elected_leader(None);
        assert!(cluster.leader_id() == 1);

        let key_id = "key_id";
        let decryptor_generate_key_request = DecryptorRequest {
            msg: Some(decryptor_request::Msg::GenerateKey(GenerateKeyRequest {
                key_id: key_id.into(),
            })),
        };

        cluster.send_app_message(
            cluster.leader_id(),
            1,
            decryptor_generate_key_request.encode_to_vec().into(),
            Bytes::new(),
        );

        let decyrptor_generate_key_response = advance_until_response(&mut cluster);
        let public_key: Option<Bytes> = decyrptor_generate_key_response.msg.and_then(|msg| {
            if let decryptor_response::Msg::GenerateKey(generate_key_response) = msg {
                Some(generate_key_response.public_key.clone().into())
            } else {
                None
            }
        });

        assert!(public_key.is_some());

        let key = KeyProto::parse(&public_key.unwrap()).unwrap();
        let public_key_share_bytes = key.key_material();

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
            WillowV1Client::new_with_randomly_generated_seed(Rc::clone(&kahe), Rc::clone(&vahe))
                .unwrap();

        // Create decryptor
        let decryptor =
            WillowV1Decryptor::new_with_randomly_generated_seed(Rc::clone(&vahe)).unwrap();

        // Create server.
        let server = WillowV1Server {
            kahe: Rc::clone(&kahe),
            vahe: Rc::clone(&vahe),
        };
        let mut server_state = ServerState::default();

        // Create verifier.
        let verifier = WillowV1Verifier {
            vahe: Rc::clone(&vahe),
        };
        let mut verifier_state = VerifierState::default();

        let public_key_share_proto =
            ShellAhePublicKeyShare::parse(&public_key_share_bytes).unwrap();
        let public_key_share: DecryptorPublicKeyShare<ShellVahe> =
            DecryptorPublicKeyShare::<ShellVahe>::from_proto(
                public_key_share_proto,
                &decryptor.vahe.as_ref(),
            )
            .unwrap();

        server
            .handle_decryptor_public_key_share(public_key_share, "Decryptor 0", &mut server_state)
            .unwrap();
        let public_key = server.create_decryptor_public_key(&server_state).unwrap();

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
            server.split_client_message(client_message).unwrap();

        verifier
            .verify_and_include(decryption_request_contribution, &mut verifier_state)
            .unwrap();
        server
            .handle_ciphertext_contribution(ciphertext_contribution, &mut server_state)
            .unwrap();

        // Verifier creates the partial decryption request.
        let pd_ct = verifier
            .create_partial_decryption_request(verifier_state)
            .unwrap();
        let pd_ct_proto = pd_ct.to_proto(&verifier).unwrap();
        let pd_ct_bytes = pd_ct_proto.serialize().unwrap().into();

        // Step 3: Decrypt the message
        let decryptor_decrypt_request = DecryptorRequest {
            msg: Some(decryptor_request::Msg::Decrypt(DecryptRequest {
                decryption_request: pd_ct_bytes,
                public_key: "".into(), // Deprecated
                key_id: key_id.into(),
            })),
        };

        cluster.send_app_message(
            cluster.leader_id(),
            2,
            decryptor_decrypt_request.encode_to_vec().into(),
            Bytes::new(),
        );

        let decryptor_decrypt_response = advance_until_response(&mut cluster);
        let pd_bytes: Option<Bytes> = decryptor_decrypt_response.msg.and_then(|msg| {
            if let decryptor_response::Msg::Decrypt(decrypt_response) = msg {
                Some(decrypt_response.decryption_response.clone().into())
            } else {
                None
            }
        });

        assert!(pd_bytes.is_some());

        let pd_proto = PartialDecryptionResponseProto::parse(&pd_bytes.unwrap()).unwrap();
        let pd: PartialDecryptionResponse<ShellVahe> =
            PartialDecryptionResponse::from_proto(pd_proto, &decryptor).unwrap();

        // Server handles the partial decryption.
        server
            .handle_partial_decryption(pd, &mut server_state)
            .unwrap();

        // Server recovers the aggregation result.
        let aggregation_result = server.recover_aggregation_result(&server_state).unwrap();

        let client_plaintext_length = client_plaintext.get(default_id.as_str()).unwrap().len();
        assert_eq!(
            aggregation_result.get(default_id.as_str()).unwrap()[..client_plaintext_length],
            client_plaintext.get(default_id.as_str()).unwrap()[..]
        )
    }

    #[test]
    fn test_decrypt_invalid_key_id() {
        // Step 1: Generate Key
        let mut cluster = FakeCluster::new(Bytes::new());

        cluster.start_node(1, true, DecryptorActor::new());
        cluster.advance_until_elected_leader(None);
        assert!(cluster.leader_id() == 1);

        let key_id = "key_id";
        let decryptor_generate_key_request = DecryptorRequest {
            msg: Some(decryptor_request::Msg::GenerateKey(GenerateKeyRequest {
                key_id: key_id.into(),
            })),
        };

        cluster.send_app_message(
            cluster.leader_id(),
            1,
            decryptor_generate_key_request.encode_to_vec().into(),
            Bytes::new(),
        );

        let decyrptor_generate_key_response = advance_until_response(&mut cluster);
        let public_key: Option<Bytes> = decyrptor_generate_key_response.msg.and_then(|msg| {
            if let decryptor_response::Msg::GenerateKey(generate_key_response) = msg {
                Some(generate_key_response.public_key.clone().into())
            } else {
                None
            }
        });

        assert!(public_key.is_some());

        let key = KeyProto::parse(&public_key.unwrap()).unwrap();
        let public_key_share_bytes = key.key_material();

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
            WillowV1Client::new_with_randomly_generated_seed(Rc::clone(&kahe), Rc::clone(&vahe))
                .unwrap();

        // Create server.
        let server = WillowV1Server {
            kahe: Rc::clone(&kahe),
            vahe: Rc::clone(&vahe),
        };
        let mut server_state = ServerState::default();

        // Create verifier.
        let verifier = WillowV1Verifier {
            vahe: Rc::clone(&vahe),
        };
        let mut verifier_state = VerifierState::default();

        let public_key_share_proto =
            ShellAhePublicKeyShare::parse(&public_key_share_bytes).unwrap();
        let public_key_share: DecryptorPublicKeyShare<ShellVahe> =
            DecryptorPublicKeyShare::<ShellVahe>::from_proto(
                public_key_share_proto,
                &server.vahe.as_ref(),
            )
            .unwrap();

        server
            .handle_decryptor_public_key_share(public_key_share, "Decryptor 0", &mut server_state)
            .unwrap();
        let public_key = server.create_decryptor_public_key(&server_state).unwrap();

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
            server.split_client_message(client_message).unwrap();

        verifier
            .verify_and_include(decryption_request_contribution, &mut verifier_state)
            .unwrap();
        server
            .handle_ciphertext_contribution(ciphertext_contribution, &mut server_state)
            .unwrap();

        // Verifier creates the partial decryption request.
        let pd_ct = verifier
            .create_partial_decryption_request(verifier_state)
            .unwrap();
        let pd_ct_proto = pd_ct.to_proto(&verifier).unwrap();
        let pd_ct_bytes = pd_ct_proto.serialize().unwrap().into();

        // Step 3: Attempt to Decrypt the message with invalid key id
        let key_id = "unknown key id";
        let decryptor_decrypt_request = DecryptorRequest {
            msg: Some(decryptor_request::Msg::Decrypt(DecryptRequest {
                decryption_request: pd_ct_bytes,
                public_key: "".into(), // Deprecated
                key_id: key_id.into(),
            })),
        };

        cluster.send_app_message(
            cluster.leader_id(),
            2,
            decryptor_decrypt_request.encode_to_vec().into(),
            Bytes::new(),
        );

        let decryptor_decrypt_response = advance_until_response(&mut cluster);
        let (error_code, error_message) = match decryptor_decrypt_response.msg {
            Some(decryptor_response::Msg::Error(error)) => (error.code, error.message),
            Some(_) => (0, "".to_string()),
            None => (0, "".to_string()),
        };

        assert_eq!(error_code, 9);
        assert_eq!(
            error_message,
            format!("Key pair not found for given {} key id", key_id)
        );
    }

    #[test]
    fn test_attempt_at_second_decryption_fails() {
        // Step 1: Generate Key
        let mut cluster = FakeCluster::new(Bytes::new());

        cluster.start_node(1, true, DecryptorActor::new());
        cluster.advance_until_elected_leader(None);
        assert!(cluster.leader_id() == 1);

        let key_id = "key_id";
        let decryptor_generate_key_request = DecryptorRequest {
            msg: Some(decryptor_request::Msg::GenerateKey(GenerateKeyRequest {
                key_id: key_id.into(),
            })),
        };

        cluster.send_app_message(
            cluster.leader_id(),
            1,
            decryptor_generate_key_request.encode_to_vec().into(),
            Bytes::new(),
        );

        let decyrptor_generate_key_response = advance_until_response(&mut cluster);
        let public_key: Option<Bytes> = decyrptor_generate_key_response.msg.and_then(|msg| {
            if let decryptor_response::Msg::GenerateKey(generate_key_response) = msg {
                Some(generate_key_response.public_key.clone().into())
            } else {
                None
            }
        });

        assert!(public_key.is_some());

        let key = KeyProto::parse(&public_key.unwrap()).unwrap();
        let public_key_share_bytes = key.key_material();

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
            WillowV1Client::new_with_randomly_generated_seed(Rc::clone(&kahe), Rc::clone(&vahe))
                .unwrap();

        // Create server.
        let server = WillowV1Server {
            kahe: Rc::clone(&kahe),
            vahe: Rc::clone(&vahe),
        };
        let mut server_state = ServerState::default();

        // Create verifier.
        let verifier = WillowV1Verifier {
            vahe: Rc::clone(&vahe),
        };
        let mut verifier_state = VerifierState::default();

        let public_key_share_proto =
            ShellAhePublicKeyShare::parse(&public_key_share_bytes).unwrap();
        let public_key_share: DecryptorPublicKeyShare<ShellVahe> =
            DecryptorPublicKeyShare::<ShellVahe>::from_proto(
                public_key_share_proto,
                &server.vahe.as_ref(),
            )
            .unwrap();

        server
            .handle_decryptor_public_key_share(public_key_share, "Decryptor 0", &mut server_state)
            .unwrap();
        let public_key = server.create_decryptor_public_key(&server_state).unwrap();

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
            server.split_client_message(client_message).unwrap();

        verifier
            .verify_and_include(decryption_request_contribution, &mut verifier_state)
            .unwrap();
        server
            .handle_ciphertext_contribution(ciphertext_contribution, &mut server_state)
            .unwrap();

        // Verifier creates the partial decryption request.
        let pd_ct = verifier
            .create_partial_decryption_request(verifier_state)
            .unwrap();
        let pd_ct_proto = pd_ct.to_proto(&verifier).unwrap();
        let pd_ct_bytes = pd_ct_proto.serialize().unwrap().into();

        // Step 3: Decrypt the message
        let decryptor_decrypt_request = DecryptorRequest {
            msg: Some(decryptor_request::Msg::Decrypt(DecryptRequest {
                decryption_request: pd_ct_bytes,
                public_key: "".into(), // Deprecated
                key_id: key_id.into(),
            })),
        };

        cluster.send_app_message(
            cluster.leader_id(),
            2,
            decryptor_decrypt_request.encode_to_vec().into(),
            Bytes::new(),
        );

        let decryptor_decrypt_response = advance_until_response(&mut cluster);
        let pd_bytes: Option<Bytes> = decryptor_decrypt_response.msg.and_then(|msg| {
            if let decryptor_response::Msg::Decrypt(decrypt_response) = msg {
                Some(decrypt_response.decryption_response.clone().into())
            } else {
                None
            }
        });

        assert!(pd_bytes.is_some());

        // Step 4: Send second decryption request which should fail
        cluster.send_app_message(
            cluster.leader_id(),
            2,
            decryptor_decrypt_request.encode_to_vec().into(),
            Bytes::new(),
        );

        let decryptor_decrypt_response = advance_until_response(&mut cluster);
        let (error_code, error_message) = match decryptor_decrypt_response.msg {
            Some(decryptor_response::Msg::Error(error)) => (error.code, error.message),
            Some(_) => (0, "".to_string()),
            None => (0, "".to_string()),
        };

        assert_eq!(error_code, 9);
        assert_eq!(
            error_message,
            format!("Key pair not found for given {} key id", key_id)
        );
    }
}
