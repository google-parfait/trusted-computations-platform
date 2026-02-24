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

use crate::apps::willow::decryptor::service::{
    decryptor_event, DecryptEvent, DecryptorEvent, DecryptorSnapshot, GenerateKeyEvent,
    SnapshotKeyPair,
};
use ahe_traits::AheBase;
use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::{boxed::Box, vec::Vec};
use decryptor_traits::SecureAggregationDecryptor;
use key_rust_proto::Key as KeyProto;
use messages::PartialDecryptionRequest;
use messages_rust_proto::{
    DecryptorStateProto, PartialDecryptionRequest as PartialDecryptionRequestProto,
};
use micro_rpc::StatusCode;
use oak_proto_rust::oak::attestation::v1::{
    binary_reference_value, kernel_binary_reference_value, reference_values, text_reference_value,
    ApplicationLayerReferenceValues, BinaryReferenceValue, InsecureReferenceValues,
    KernelBinaryReferenceValue, KernelLayerReferenceValues, OakRestrictedKernelReferenceValues,
    ReferenceValues, RootLayerReferenceValues, SkipVerification, TextReferenceValue,
};
use prost::{bytes::Bytes, Message};
use proto_serialization_traits::{FromProto, ToProto};
use protobuf::prelude::*;
use secure_aggregation::proto::{
    decryptor_request, decryptor_response, DecryptRequest, DecryptResponse, DecryptorRequest,
    DecryptorResponse, GenerateKeyRequest, GenerateKeyResponse, Status,
};
use shell_parameters::create_shell_ahe_config;
use shell_vahe::ShellVahe;
use slog::{debug, warn};
use std::rc::Rc;
use tcp_runtime::model::{
    Actor, ActorCommand, ActorContext, ActorError, ActorEvent, ActorEventContext, CommandOutcome,
    EventOutcome,
};
use willow_v1_decryptor::{DecryptorState, WillowV1Decryptor};

#[derive(PartialEq)]
struct KeyPair {
    public_key_share: Bytes,
    decryptor_state: Bytes,
}

pub struct DecryptorActor {
    reference_values: ReferenceValues,
    context: Option<Box<dyn ActorContext>>,
    key_pairs: BTreeMap<Vec<u8>, KeyPair>,
}

const MAX_NUMBER_OF_DECRYPTORS: i64 = 1;

impl DecryptorActor {
    pub fn new() -> Self {
        let skip = BinaryReferenceValue {
            r#type: Some(binary_reference_value::Type::Skip(
                SkipVerification::default(),
            )),
        };
        Self::new_with_reference_values(ReferenceValues {
            r#type: Some(reference_values::Type::OakRestrictedKernel(
                OakRestrictedKernelReferenceValues {
                    root_layer: Some(RootLayerReferenceValues {
                        insecure: Some(InsecureReferenceValues::default()),
                        ..Default::default()
                    }),
                    kernel_layer: Some(KernelLayerReferenceValues {
                        kernel: Some(KernelBinaryReferenceValue {
                            r#type: Some(kernel_binary_reference_value::Type::Skip(
                                SkipVerification::default(),
                            )),
                        }),
                        kernel_cmd_line_text: Some(TextReferenceValue {
                            r#type: Some(text_reference_value::Type::Skip(
                                SkipVerification::default(),
                            )),
                        }),
                        init_ram_fs: Some(skip.clone()),
                        memory_map: Some(skip.clone()),
                        acpi: Some(skip.clone()),
                        ..Default::default()
                    }),
                    application_layer: Some(ApplicationLayerReferenceValues {
                        binary: Some(skip.clone()),
                        configuration: Some(skip.clone()),
                    }),
                },
            )),
        })
    }

    pub fn new_with_reference_values(reference_values: ReferenceValues) -> Self {
        DecryptorActor {
            reference_values,
            context: None,
            key_pairs: BTreeMap::new(),
        }
    }

    fn get_context(&mut self) -> &mut dyn ActorContext {
        self.context
            .as_mut()
            .expect("Context is initialized")
            .as_mut()
    }

    fn process_generate_key_command(
        &mut self,
        correlation_id: u64,
        generate_key_request: GenerateKeyRequest,
    ) -> Result<CommandOutcome, ActorError> {
        let key_id: Vec<u8> = generate_key_request.key_id;
        if self.key_pairs.contains_key(&key_id) {
            let public_key_share = self
                .key_pairs
                .get(&key_id)
                .unwrap()
                .public_key_share
                .clone();
            let mut key = KeyProto::default();
            key.set_key_id(key_id.clone());
            key.set_key_material(public_key_share.to_vec());
            return Ok(CommandOutcome::with_command(ActorCommand::with_header(
                correlation_id,
                &DecryptorResponse {
                    msg: Some(decryptor_response::Msg::GenerateKey(GenerateKeyResponse {
                        public_key: key.serialize().unwrap().into(),
                    })),
                },
            )));
        }

        let key_pair = self.create_public_key_share(key_id.clone());

        return Ok(CommandOutcome::with_event(ActorEvent::with_proto(
            correlation_id,
            &DecryptorEvent {
                event: Some(decryptor_event::Event::GenerateKeyEvent(GenerateKeyEvent {
                    public_key_share: key_pair.public_key_share.to_vec(),
                    private_key_share: key_pair.decryptor_state.to_vec(),
                    key_id: key_id.into(),
                })),
            },
        )));
    }

    fn process_decrypt_command(
        &mut self,
        correlation_id: u64,
        decrypt_request: DecryptRequest,
    ) -> Result<CommandOutcome, ActorError> {
        let request = decrypt_request.decryption_request;
        let key_id: Vec<u8> = decrypt_request.key_id;
        let key_pair = self.get_key_pair(&key_id);

        if key_pair == None {
            return self.command_err(
                correlation_id,
                StatusCode::FailedPrecondition as i32,
                format!(
                    "Key pair not found for given {} key id",
                    String::from_utf8(key_id.to_vec()).expect("Invalid UTF-8")
                ),
            );
        }

        let decryptor_state = &key_pair.unwrap().decryptor_state.to_vec();
        let decryption_response = self.decrypt(
            key_id.clone().into(),
            request.into(),
            decryptor_state.clone().into(),
        );

        match decryption_response {
            Ok(response) => {
                return Ok(CommandOutcome::with_event(ActorEvent::with_proto(
                    correlation_id,
                    &DecryptorEvent {
                        event: Some(decryptor_event::Event::DecryptEvent(DecryptEvent {
                            key_id: key_id.into(),
                            decryption_response: response.to_vec(),
                        })),
                    },
                )));
            }
            Err(status) => {
                return self.command_err(correlation_id, status.code, status.message);
            }
        }
    }

    fn process_generate_key_event(
        &mut self,
        context: ActorEventContext,
        correlation_id: u64,
        generate_key_event: GenerateKeyEvent,
    ) -> Result<EventOutcome, ActorError> {
        let public_key_share: Bytes = generate_key_event.public_key_share.into();
        let decryptor_state: Bytes = generate_key_event.private_key_share.into();
        // TODO: Add garbage collection for unused key pairs.
        self.key_pairs.insert(
            generate_key_event.key_id.clone().into(),
            KeyPair {
                public_key_share: public_key_share.clone(),
                decryptor_state: decryptor_state,
            },
        );

        if context.owned {
            let mut key = KeyProto::default();
            key.set_key_id(generate_key_event.key_id.clone());
            key.set_key_material(public_key_share.to_vec());
            return Ok(EventOutcome::with_command(ActorCommand::with_header(
                correlation_id,
                &DecryptorResponse {
                    msg: Some(decryptor_response::Msg::GenerateKey(GenerateKeyResponse {
                        public_key: key.serialize().unwrap().into(),
                    })),
                },
            )));
        };

        Ok(EventOutcome::with_none())
    }

    fn process_decrypt_event(
        &mut self,
        context: ActorEventContext,
        correlation_id: u64,
        decrypt_event: DecryptEvent,
    ) -> Result<EventOutcome, ActorError> {
        self.key_pairs.remove(&decrypt_event.key_id[..]);

        if context.owned {
            return Ok(EventOutcome::with_command(ActorCommand::with_header(
                correlation_id,
                &DecryptorResponse {
                    msg: Some(decryptor_response::Msg::Decrypt(DecryptResponse {
                        decryption_response: decrypt_event.decryption_response,
                    })),
                },
            )));
        };

        Ok(EventOutcome::with_none())
    }

    fn create_public_key_share(&self, key_id: Vec<u8>) -> KeyPair {
        let mut decryptor_state = DecryptorState::default();
        let decryptor = self.create_willow_v1_decryptor(key_id);

        let public_key_share_proto = decryptor
            .create_public_key_share(&mut decryptor_state)
            .unwrap()
            .to_proto(&decryptor.vahe.as_ref())
            .unwrap();
        let decryptor_state_proto = decryptor_state.to_proto(&decryptor).unwrap();

        return KeyPair {
            public_key_share: public_key_share_proto.serialize().unwrap().into(),
            decryptor_state: decryptor_state_proto.serialize().unwrap().into(),
        };
    }

    fn get_key_pair(&self, key_id: &Vec<u8>) -> Option<&KeyPair> {
        return self.key_pairs.get(key_id);
    }

    fn decrypt(
        &self,
        key_id: Vec<u8>,
        request_bytes: Bytes,
        decryptor_state_bytes: Bytes,
    ) -> Result<Bytes, Status> {
        let decryptor = self.create_willow_v1_decryptor(key_id);

        let decryptor_state_proto = DecryptorStateProto::parse(&decryptor_state_bytes).unwrap();
        let decryptor_state =
            DecryptorState::from_proto(decryptor_state_proto, &decryptor).unwrap();

        let request_proto = PartialDecryptionRequestProto::parse(&request_bytes).unwrap();
        let request = PartialDecryptionRequest::from_proto(request_proto, &decryptor).unwrap();

        let partial_decryption = decryptor
            .handle_partial_decryption_request(request, &decryptor_state)
            .unwrap();
        let partial_decryption_proto = partial_decryption.to_proto(&decryptor).unwrap();

        return Ok(partial_decryption_proto.serialize().unwrap().into());
    }

    fn command_err(
        &mut self,
        correlation_id: u64,
        code: i32,
        message: String,
    ) -> Result<CommandOutcome, ActorError> {
        return Ok(CommandOutcome::with_command(ActorCommand::with_header(
            correlation_id,
            &DecryptorResponse {
                msg: Some(decryptor_response::Msg::Error(Status {
                    code: code,
                    message: message,
                })),
            },
        )));
    }

    fn event_err(
        &mut self,
        correlation_id: u64,
        code: i32,
        message: String,
    ) -> Result<EventOutcome, ActorError> {
        return Ok(EventOutcome::with_command(ActorCommand::with_header(
            correlation_id,
            &DecryptorResponse {
                msg: Some(decryptor_response::Msg::Error(Status {
                    code: code,
                    message: message,
                })),
            },
        )));
    }

    fn create_willow_v1_decryptor(&self, key_id: Vec<u8>) -> WillowV1Decryptor<ShellVahe> {
        let vahe = Rc::new(
            ShellVahe::new(
                create_shell_ahe_config(MAX_NUMBER_OF_DECRYPTORS).unwrap(),
                &key_id,
            )
            .unwrap(),
        );
        WillowV1Decryptor::new_with_randomly_generated_seed(Rc::clone(&vahe)).unwrap()
    }
}

impl Actor for DecryptorActor {
    fn on_init(&mut self, context: Box<dyn ActorContext>) -> Result<(), ActorError> {
        self.context = Some(context);

        Ok(())
    }

    fn on_shutdown(&mut self) {}

    fn on_save_snapshot(&mut self) -> Result<Bytes, ActorError> {
        let mut snapshot = DecryptorSnapshot {
            key_pairs: Vec::<SnapshotKeyPair>::new(),
        };

        for (key_id, key_pair) in &self.key_pairs {
            snapshot.key_pairs.push(SnapshotKeyPair {
                public_key_share: key_pair.public_key_share.clone(),
                private_key_share: key_pair.decryptor_state.clone(),
                key_id: key_id.clone().into(),
            });
        }

        Ok(snapshot.encode_to_vec().into())
    }

    fn on_load_snapshot(&mut self, snapshot: Bytes) -> Result<(), ActorError> {
        debug!(self.get_context().logger(), "Loading snapshot");

        let snapshot =
            DecryptorSnapshot::decode(snapshot).map_err(|_| ActorError::SnapshotLoading)?;

        self.key_pairs.clear();
        for key_pair in snapshot.key_pairs {
            self.key_pairs.insert(
                key_pair.key_id.into(),
                KeyPair {
                    public_key_share: key_pair.public_key_share,
                    decryptor_state: key_pair.private_key_share,
                },
            );
        }

        Ok(())
    }

    fn on_process_command(
        &mut self,
        command: Option<ActorCommand>,
    ) -> Result<CommandOutcome, ActorError> {
        if command.is_none() {
            return Ok(CommandOutcome::with_none());
        }
        let command = command.unwrap();

        let decryptor_request =
            DecryptorRequest::decode(command.header.clone()).map_err(|error| {
                warn!(
                    self.get_context().logger(),
                    "DecryptorActor: request cannot be parsed: {}", error
                );
                ActorError::Internal
            })?;

        debug!(
            self.get_context().logger(),
            "DecryptorActor: handling {} command",
            request_name(&decryptor_request)
        );

        if !self.get_context().leader() {
            // Not a leader.
            warn!(
                self.get_context().logger(),
                "DecryptorActor: command {} rejected: not a leader",
                request_name(&decryptor_request)
            );
            return self.command_err(
                command.correlation_id,
                StatusCode::FailedPrecondition as i32,
                "Node is not the leader".to_string(),
            );
        }

        match decryptor_request.msg {
            Some(decryptor_request::Msg::GenerateKey(generate_key_request)) => {
                return self
                    .process_generate_key_command(command.correlation_id, generate_key_request);
            }
            Some(decryptor_request::Msg::Decrypt(decrypt_request)) => {
                return self.process_decrypt_command(command.correlation_id, decrypt_request);
            }
            _ => {
                warn!(
                    self.get_context().logger(),
                    "DecryptorActor: unknown request {:?}", decryptor_request
                );
                return self.command_err(
                    command.correlation_id,
                    StatusCode::InvalidArgument as i32,
                    format!("DecryptorActor: unknown request {:?}", decryptor_request),
                );
            }
        };
    }

    fn on_apply_event(
        &mut self,
        context: ActorEventContext,
        event: ActorEvent,
    ) -> Result<EventOutcome, ActorError> {
        let decryptor_event = DecryptorEvent::decode(event.contents).map_err(|error| {
            warn!(
                self.get_context().logger(),
                "DecryptorActor: request cannot be parsed: {}", error
            );
            ActorError::Internal
        })?;

        debug!(
            self.get_context().logger(),
            "DecryptorActor: handling {} event",
            event_name(&decryptor_event)
        );

        match decryptor_event.event {
            Some(decryptor_event::Event::GenerateKeyEvent(generate_key_event)) => {
                return self.process_generate_key_event(
                    context,
                    event.correlation_id,
                    generate_key_event,
                );
            }
            Some(decryptor_event::Event::DecryptEvent(decrypt_event)) => {
                return self.process_decrypt_event(context, event.correlation_id, decrypt_event);
            }
            _ => {
                warn!(
                    self.get_context().logger(),
                    "DecryptorActor: unknown event {:?}", decryptor_event
                );
                return self.event_err(
                    event.correlation_id,
                    StatusCode::InvalidArgument as i32,
                    format!("DecryptorActor: unknown event {:?}", decryptor_event),
                );
            }
        }
    }

    fn get_reference_values(&self) -> ReferenceValues {
        self.reference_values.clone()
    }
}

fn request_name(request: &DecryptorRequest) -> &'static str {
    match request.msg {
        Some(decryptor_request::Msg::GenerateKey(_)) => "GenerateKey",
        Some(decryptor_request::Msg::Decrypt(_)) => "Decrypt",
        _ => "Unknown",
    }
}

fn event_name(request: &DecryptorEvent) -> &'static str {
    match request.event {
        Some(decryptor_event::Event::GenerateKeyEvent(_)) => "GenerateKey",
        _ => "Unknown",
    }
}
