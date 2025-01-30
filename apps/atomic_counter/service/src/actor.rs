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

use crate::apps::atomic_counter::service::{
    atomic_counter_in_message, atomic_counter_out_message, counter_request, counter_response,
    AtomicCounterInMessage, AtomicCounterOutMessage, CounterCompareAndSwapRequest,
    CounterCompareAndSwapResponse, CounterConfig, CounterRequest, CounterResponse, CounterSnapshot,
    CounterSnapshotValue, CounterStatus,
};
use alloc::{
    boxed::Box,
    collections::BTreeMap,
    string::{String, ToString},
};
use hashbrown::HashMap;
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

pub struct CounterValue {
    value: i64,
    payload: Bytes,
}

pub struct CounterActor {
    reference_values: ReferenceValues,
    context: Option<Box<dyn ActorContext>>,
    values: HashMap<String, CounterValue>,
}

impl CounterActor {
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
        CounterActor {
            reference_values,
            context: None,
            values: HashMap::new(),
        }
    }

    fn get_context(&mut self) -> &mut dyn ActorContext {
        self.context
            .as_mut()
            .expect("Context is initialized")
            .as_mut()
    }

    fn apply_compare_and_swap(
        &mut self,
        index: u64,
        counter_name: &String,
        compare_and_swap_request: &CounterCompareAndSwapRequest,
        payload: Bytes,
    ) -> CounterResponse {
        debug!(
            self.get_context().logger(),
            "Applying at index #{} compare and swap command {:?}", index, compare_and_swap_request
        );

        let mut response = CounterResponse {
            status: CounterStatus::Unspecified.into(),
            op: None,
        };
        let mut compare_and_swap_response = CounterCompareAndSwapResponse {
            ..Default::default()
        };

        let existing_value_ref = self.values.entry_ref(counter_name);
        let existing_value = existing_value_ref.or_insert_with(|| CounterValue {
            value: 0,
            payload: Bytes::new(),
        });
        compare_and_swap_response.old_value = existing_value.value;
        if existing_value.value == compare_and_swap_request.expected_value {
            existing_value.value = compare_and_swap_request.new_value;
            existing_value.payload = payload;

            response.status = CounterStatus::Success.into();
            compare_and_swap_response.new_value = compare_and_swap_request.new_value;
        } else {
            response.status = CounterStatus::InvalidArgumentError.into();
        }
        response.op = Some(counter_response::Op::CompareAndSwap(
            compare_and_swap_response,
        ));

        response
    }
}

impl Actor for CounterActor {
    fn on_init(&mut self, context: Box<dyn ActorContext>) -> Result<(), ActorError> {
        self.context = Some(context);
        self.values = HashMap::new();

        let config = CounterConfig::decode(self.get_context().config().as_ref())
            .map_err(|_| ActorError::ConfigLoading)?;

        for (counter_name, value) in config.initial_values {
            self.values.insert(
                counter_name,
                CounterValue {
                    value,
                    payload: Bytes::new(),
                },
            );
        }

        Ok(())
    }

    fn on_shutdown(&mut self) {}

    fn on_save_snapshot(&mut self) -> Result<Bytes, ActorError> {
        debug!(self.get_context().logger(), "Saving snapshot");

        let mut snapshot = CounterSnapshot {
            values: BTreeMap::new(),
        };

        for (name, value) in &self.values {
            snapshot.values.insert(
                name.to_string(),
                CounterSnapshotValue {
                    value: value.value,
                    payload: value.payload.clone(),
                },
            );
        }

        Ok(snapshot.encode_to_vec().into())
    }

    fn on_load_snapshot(&mut self, snapshot: Bytes) -> Result<(), ActorError> {
        debug!(self.get_context().logger(), "Loading snapshot");

        let snapshot =
            CounterSnapshot::decode(snapshot).map_err(|_| ActorError::SnapshotLoading)?;

        for (name, value) in snapshot.values {
            self.values.insert(
                name,
                CounterValue {
                    value: value.value,
                    payload: value.payload,
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
        let mut response = CounterResponse {
            ..Default::default()
        };
        let mut status = CounterStatus::Success;

        match AtomicCounterInMessage::decode(command.header.clone()) {
            Ok(in_message) => match in_message.msg {
                Some(msg) => {
                    match msg {
                        atomic_counter_in_message::Msg::CounterRequest(mut request) => {
                            debug!(
                                self.get_context().logger(),
                                "Processing #{} command", request.name
                            );

                            if request.op.is_none() {
                                status = CounterStatus::InvalidOperationError;

                                warn!(
                                    self.get_context().logger(),
                                    "Rejecting #{} command: unknown op", request.name
                                );
                            }

                            if !self.get_context().leader() {
                                status = CounterStatus::Rejected;

                                warn!(
                                    self.get_context().logger(),
                                    "Rejecting #{} command: not a leader", request.name
                                );
                            }

                            if let CounterStatus::Success = status {
                                // Clear out context so that it is not replicated.
                                request.context = Bytes::new();
                                return Ok(CommandOutcome::with_event(ActorEvent::with_proto(
                                    command.correlation_id,
                                    &request,
                                )));
                            }
                        }
                    }
                }
                None => {
                    status = CounterStatus::InvalidOperationError;
                }
            },
            Err(e) => {
                warn!(self.get_context().logger(), "Rejecting command: {}", e);
                status = CounterStatus::InvalidOperationError;
            }
        }

        response.status = status.into();
        Ok(CommandOutcome::with_command(ActorCommand::with_header(
            command.correlation_id,
            &AtomicCounterOutMessage {
                msg: Some(atomic_counter_out_message::Msg::CounterResponse(response)),
            },
        )))
    }

    fn on_apply_event(
        &mut self,
        context: ActorEventContext,
        event: ActorEvent,
    ) -> Result<EventOutcome, ActorError> {
        let request =
            CounterRequest::decode(event.contents.clone()).map_err(|_| ActorError::Internal)?;

        let op = request.op.unwrap();

        let response = match op {
            counter_request::Op::CompareAndSwap(ref compare_and_swap_request) => self
                .apply_compare_and_swap(
                    context.index,
                    &request.name,
                    compare_and_swap_request,
                    request.payload,
                ),
        };

        if context.owned {
            return Ok(EventOutcome::with_command(ActorCommand::with_header(
                event.correlation_id,
                &AtomicCounterOutMessage {
                    msg: Some(atomic_counter_out_message::Msg::CounterResponse(response)),
                },
            )));
        }

        Ok(EventOutcome::with_none())
    }

    fn get_reference_values(&self) -> ReferenceValues {
        self.reference_values.clone()
    }
}
