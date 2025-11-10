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

    use prost::bytes::Bytes;
    use prost::Message;
    use secure_aggregation::proto::*;
    use tcp_integration::harness::*;
    use tcp_proto::runtime::endpoint::out_message;
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

    #[test]
    fn test_generate_key_and_decrypt() {
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
        let public_key = match decyrptor_generate_key_response.msg {
            Some(decryptor_response::Msg::GenerateKey(generate_key_response)) => {
                generate_key_response.public_key.clone().into()
            }
            Some(_) => Bytes::new(),
            None => Bytes::new(),
        };

        assert_ne!(public_key, Bytes::new());

        let request = "message";
        let decryptor_decrypt_request = DecryptorRequest {
            msg: Some(decryptor_request::Msg::Decrypt(DecryptRequest {
                decryption_request: request.into(),
                public_key: "".into(),
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
        let decryption_response = match decryptor_decrypt_response.msg {
            Some(decryptor_response::Msg::Decrypt(decrypt_response)) => {
                decrypt_response.decryption_response.clone().into()
            }
            Some(_) => Bytes::new(),
            None => Bytes::new(),
        };

        assert_eq!(decryption_response, request);
    }

    #[test]
    fn test_decrypt_invalid_key_id() {
        let mut cluster = FakeCluster::new(Bytes::new());

        cluster.start_node(1, true, DecryptorActor::new());
        cluster.advance_until_elected_leader(None);
        assert!(cluster.leader_id() == 1);

        let request = "message";
        let key_id = "unknown key id";
        let decryptor_decrypt_request = DecryptorRequest {
            msg: Some(decryptor_request::Msg::Decrypt(DecryptRequest {
                decryption_request: request.into(),
                public_key: "".into(),
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
}
