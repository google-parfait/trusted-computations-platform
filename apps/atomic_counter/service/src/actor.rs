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
    counter_request, counter_response, CounterCompareAndSwapRequest, CounterCompareAndSwapResponse,
    CounterConfig, CounterRequest, CounterResponse, CounterSnapshot, CounterSnapshotValue,
    CounterStatus,
};
use alloc::{
    boxed::Box,
    collections::BTreeMap,
    string::{String, ToString},
};
use hashbrown::HashMap;
use prost::{bytes::Bytes, Message};
use slog::{debug, warn};
use tcp_runtime::model::{Actor, ActorContext, ActorError, CommandOutcome, EventOutcome};

pub struct CounterValue {
    value: i64,
    payload: Bytes,
}

pub struct CounterActor {
    context: Option<Box<dyn ActorContext>>,
    values: HashMap<String, CounterValue>,
}

impl CounterActor {
    pub fn new() -> Self {
        CounterActor {
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
        id: u64,
        counter_name: &String,
        compare_and_swap_request: &CounterCompareAndSwapRequest,
        payload: Bytes,
    ) -> CounterResponse {
        debug!(
            self.get_context().logger(),
            "Applying at index #{} #{} compare and swap command {:?}",
            index,
            id,
            compare_and_swap_request
        );

        let mut response = CounterResponse {
            id,
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

    fn on_process_command(&mut self, command: Bytes) -> Result<CommandOutcome, ActorError> {
        let mut response = CounterResponse {
            ..Default::default()
        };
        let mut status = CounterStatus::Success;

        match CounterRequest::decode(command.clone()) {
            Ok(mut request) => {
                debug!(
                    self.get_context().logger(),
                    "Processing #{} command", request.id
                );

                response.id = request.id;
                if request.op.is_none() {
                    status = CounterStatus::InvalidOperationError;

                    warn!(
                        self.get_context().logger(),
                        "Rejecting #{} command: unknown op", request.id
                    );
                }

                if !self.get_context().leader() {
                    status = CounterStatus::Rejected;

                    warn!(
                        self.get_context().logger(),
                        "Rejecting #{} command: not a leader", request.id
                    );
                }

                // Clear out context so that it is not replicated.
                request.context = Bytes::new();
                if let CounterStatus::Success = status {
                    return Ok(CommandOutcome::Event(request.encode_to_vec().into()));
                }
            }
            Err(e) => {
                warn!(self.get_context().logger(), "Rejecting command: {}", e);
                status = CounterStatus::InvalidOperationError;
            }
        }

        response.status = status.into();
        Ok(CommandOutcome::Response(response.encode_to_vec().into()))
    }

    fn on_apply_event(&mut self, index: u64, event: Bytes) -> Result<EventOutcome, ActorError> {
        let request = CounterRequest::decode(event).map_err(|_| ActorError::Internal)?;

        let op = request.op.unwrap();

        let response = match op {
            counter_request::Op::CompareAndSwap(ref compare_and_swap_request) => self
                .apply_compare_and_swap(
                    index,
                    request.id,
                    &request.name,
                    compare_and_swap_request,
                    request.payload,
                ),
        };

        if self.get_context().leader() {
            return Ok(EventOutcome::Response(response.encode_to_vec().into()));
        }

        Ok(EventOutcome::None)
    }
}
