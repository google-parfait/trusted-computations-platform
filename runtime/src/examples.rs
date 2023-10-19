// Copyright 2023 The Trusted Computations Platform Authors.
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

use alloc::{
    boxed::Box,
    collections::BTreeMap,
    string::{String, ToString},
    vec::Vec,
};
use hashbrown::HashMap;
use prost::Message;
use slog::{debug, warn};
use tcp_proto::examples::atomic_counter::{
    counter_request, counter_response, CounterCompareAndSwapRequest, CounterCompareAndSwapResponse,
    CounterConfig, CounterRequest, CounterResponse, CounterSnapshot, CounterStatus,
};

use crate::model::{Actor, ActorContext, ActorError, CommandOutcome, EventOutcome};

pub struct CounterActor {
    context: Option<Box<dyn ActorContext>>,
    values: HashMap<String, i64>,
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
        id: u64,
        counter_name: &String,
        compare_and_swap_request: &CounterCompareAndSwapRequest,
    ) -> CounterResponse {
        debug!(
            self.get_context().logger(),
            "Applying #{} compare and swap command {:?}", id, compare_and_swap_request
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
        let existing_value = existing_value_ref.or_insert(0);
        compare_and_swap_response.old_value = *existing_value;
        if *existing_value == compare_and_swap_request.expected_value {
            *existing_value = compare_and_swap_request.new_value;

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

        for (counter_name, counter_value) in config.initial_values {
            self.values.insert(counter_name, counter_value);
        }

        Ok(())
    }

    fn on_shutdown(&mut self) {}

    fn on_save_snapshot(&mut self) -> Result<Vec<u8>, ActorError> {
        let mut snapshot = CounterSnapshot {
            values: BTreeMap::new(),
        };

        for (counter_name, counter_value) in &self.values {
            snapshot
                .values
                .insert(counter_name.to_string(), *counter_value);
        }

        Ok(snapshot.encode_to_vec())
    }

    fn on_load_snapshot(&mut self, snapshot: &[u8]) -> Result<(), ActorError> {
        let snapshot =
            CounterSnapshot::decode(snapshot).map_err(|_| ActorError::SnapshotLoading)?;

        for (counter_name, counter_value) in snapshot.values {
            self.values.insert(counter_name, counter_value);
        }

        Ok(())
    }

    fn on_process_command(&mut self, command: &[u8]) -> Result<CommandOutcome, ActorError> {
        let mut response = CounterResponse {
            ..Default::default()
        };
        let mut status = CounterStatus::Success;

        match CounterRequest::decode(command) {
            Ok(request) => {
                debug!(
                    self.get_context().logger(),
                    "Processing #{} command", request.id
                );

                response.id = request.id;
                if request.op.is_none() {
                    status = CounterStatus::InvalidArgumentError;

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

                if let CounterStatus::Success = status {
                    return Ok(CommandOutcome::Event(command.to_vec()));
                }
            }
            Err(e) => {
                warn!(self.get_context().logger(), "Rejecting command: {}", e);
                status = CounterStatus::InvalidArgumentError;
            }
        }

        response.status = status.into();
        Ok(CommandOutcome::Response(response.encode_to_vec()))
    }

    fn on_apply_event(&mut self, _index: u64, event: &[u8]) -> Result<EventOutcome, ActorError> {
        let request = CounterRequest::decode(event).map_err(|_| ActorError::Internal)?;

        let op = request.op.unwrap();

        let response = match op {
            counter_request::Op::CompareAndSwap(ref compare_and_swap_request) => {
                self.apply_compare_and_swap(request.id, &request.name, compare_and_swap_request)
            }
        };

        if self.get_context().leader() {
            return Ok(EventOutcome::Response(response.encode_to_vec()));
        }

        Ok(EventOutcome::None)
    }
}
