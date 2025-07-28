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
    decryptor_event, decryptor_request, decryptor_response, DecryptResponse, DecryptorEvent,
    DecryptorRequest, DecryptorResponse, DecryptorSnapshot, GenerateKeyEvent, GenerateKeyResponse,
    SnapshotKeyPair, Status,
};
use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::{boxed::Box, vec::Vec};
use micro_rpc::StatusCode;
use oak_proto_rust::oak::attestation::v1::{
    binary_reference_value, kernel_binary_reference_value, reference_values, text_reference_value,
    ApplicationLayerReferenceValues, BinaryReferenceValue, InsecureReferenceValues,
    KernelBinaryReferenceValue, KernelLayerReferenceValues, OakRestrictedKernelReferenceValues,
    ReferenceValues, RootLayerReferenceValues, SkipVerification, TextReferenceValue,
};
use prost::{bytes::Bytes, Message};
use slog::{debug, warn};
use tcp_runtime::model::{
    Actor, ActorCommand, ActorContext, ActorError, ActorEvent, ActorEventContext, CommandOutcome,
    EventOutcome,
};

pub struct DecryptorActor {
    reference_values: ReferenceValues,
    context: Option<Box<dyn ActorContext>>,
    key_pairs: BTreeMap<Bytes, Bytes>,
}

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

    // TODO: Replace with the actual Willow library once open-sourced.
    fn create_public_key_share(&mut self) -> Bytes {
        return "symmetric key".into();
    }

    fn get_private_key(&mut self, public_key: &Bytes) -> Option<Bytes> {
        return self.key_pairs.get(public_key).map(|key| key.clone());
    }

    // TODO: Replace with the actual Willow library once open-sourced.
    fn decrypt(&mut self, request: Bytes) -> Bytes {
        return request;
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

        for (public_key, private_key) in &self.key_pairs {
            snapshot.key_pairs.push(SnapshotKeyPair {
                public_key_share: public_key.clone(),
                private_key_share: private_key.clone(),
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
            self.key_pairs
                .insert(key_pair.public_key_share, key_pair.private_key_share);
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
            Some(decryptor_request::Msg::GenerateKey(_)) => {
                let key = self.create_public_key_share();

                return Ok(CommandOutcome::with_event(ActorEvent::with_proto(
                    command.correlation_id,
                    &DecryptorEvent {
                        event: Some(decryptor_event::Event::GenerateKeyEvent(GenerateKeyEvent {
                            public_key_share: key.to_vec(),
                            private_key_share: key.to_vec(),
                        })),
                    },
                )));
            }
            Some(decryptor_request::Msg::Decrypt(decrypt_request)) => {
                let request = decrypt_request.decryption_request;
                let public_key: Bytes = decrypt_request.public_key.into();
                let private_key = self.get_private_key(&public_key);

                if private_key == None {
                    return self.command_err(
                        command.correlation_id,
                        StatusCode::FailedPrecondition as i32,
                        format!(
                            "Key pair not found for given {} public key",
                            String::from_utf8(public_key.to_vec()).expect("Invalid UTF-8")
                        ),
                    );
                }

                return Ok(CommandOutcome::with_command(ActorCommand::with_header(
                    command.correlation_id,
                    &DecryptorResponse {
                        msg: Some(decryptor_response::Msg::Decrypt(DecryptResponse {
                            decryption_response: self.decrypt(request.into()).to_vec(),
                        })),
                    },
                )));
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

        let public_key: Bytes;
        match decryptor_event.event {
            Some(decryptor_event::Event::GenerateKeyEvent(generate_key_event)) => {
                public_key = generate_key_event.public_key_share.clone().into();
                // TODO: Add garbage collection for key pairs.
                self.key_pairs.insert(
                    generate_key_event.public_key_share.into(),
                    generate_key_event.private_key_share.into(),
                );
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

        if context.owned {
            return Ok(EventOutcome::with_command(ActorCommand::with_header(
                event.correlation_id,
                &DecryptorResponse {
                    msg: Some(decryptor_response::Msg::GenerateKey(GenerateKeyResponse {
                        public_key: public_key.to_vec(),
                    })),
                },
            )));
        }

        Ok(EventOutcome::with_none())
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
