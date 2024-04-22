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

use alloc::boxed::Box;
use prost::bytes::Bytes;
use slog::debug;
use tcp_runtime::model::{
    Actor, ActorCommand, ActorContext, ActorError, ActorEvent, ActorEventContext, CommandOutcome,
    EventOutcome,
};

pub struct TabletCacheActor {
    context: Option<Box<dyn ActorContext>>,
}

impl TabletCacheActor {
    pub fn new() -> Self {
        TabletCacheActor { context: None }
    }

    fn get_context(&mut self) -> &mut dyn ActorContext {
        self.context
            .as_mut()
            .expect("Context is initialized")
            .as_mut()
    }
}

impl Actor for TabletCacheActor {
    fn on_init(&mut self, _context: Box<dyn ActorContext>) -> Result<(), ActorError> {
        debug!(self.get_context().logger(), "Initializing");

        Err(ActorError::Internal)
    }

    fn on_shutdown(&mut self) {}

    fn on_save_snapshot(&mut self) -> Result<Bytes, ActorError> {
        debug!(self.get_context().logger(), "Saving snapshot");

        Err(ActorError::Internal)
    }

    fn on_load_snapshot(&mut self, _snapshot: Bytes) -> Result<(), ActorError> {
        debug!(self.get_context().logger(), "Loading snapshot");

        Err(ActorError::Internal)
    }

    fn on_process_command(&mut self, _command: ActorCommand) -> Result<CommandOutcome, ActorError> {
        Err(ActorError::Internal)
    }

    fn on_apply_event(
        &mut self,
        _context: ActorEventContext,
        _event: ActorEvent,
    ) -> Result<EventOutcome, ActorError> {
        Err(ActorError::Internal)
    }
}
