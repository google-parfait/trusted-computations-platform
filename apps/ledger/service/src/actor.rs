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

use crate::ledger::LedgerService;
use alloc::boxed::Box;
use prost::bytes::Bytes;
use tcp_runtime::model::{Actor, ActorContext, ActorError, CommandOutcome, EventOutcome};

pub struct LedgerActor {
    context: Option<Box<dyn ActorContext>>,
    ledger: LedgerService,
}

impl LedgerActor {
    pub fn new() -> Self {
        LedgerActor {
            context: None,
            ledger: LedgerService::new(),
        }
    }

    fn get_context(&mut self) -> &mut dyn ActorContext {
        self.context
            .as_mut()
            .expect("Context is initialized")
            .as_mut()
    }
}

impl Actor for LedgerActor {
    /// Handles actor initialization. If error is returned the actor is considered
    /// in unknown state and is destroyed.
    fn on_init(&mut self, context: Box<dyn ActorContext>) -> Result<(), ActorError> {
        self.context = Some(context);
        // TODO: error if already initialized
        Ok(())
    }

    /// Handles actor shutdown. After this method call completes the actor
    /// is destroyed.
    fn on_shutdown(&mut self) {}

    /// Handles creation of the actor state snapshot. If error is returned the actor
    /// is considered is unknown state and is destroyed.
    fn on_save_snapshot(&mut self) -> Result<Bytes, ActorError> {
        Err(ActorError::Internal)
    }

    /// Handles restoration of the actor state from snapshot. If error is returned the actor
    /// is considered is unknown state and is destroyed.
    fn on_load_snapshot(&mut self, snapshot: Bytes) -> Result<(), ActorError> {
        Err(ActorError::Internal)
    }

    /// Handles processing of a command by the actor. Command represents an intent of a
    /// consumer (e.g. request to update actor state). The command processing logic may
    /// decide to immediately respond (e.g. the command validation failed and cannot be
    /// executed) or to propose an event for replication by the consensus module (e.g. the
    /// event to update actor state once replicated).
    fn on_process_command(&mut self, command: Bytes) -> Result<CommandOutcome, ActorError> {
        Err(ActorError::Internal)
    }

    /// Handles committed events by applying them to the actor state. Event represents
    /// a state transition of the actor and may result in messages being sent to the
    /// consumer (e.g. response to the command that generated this event).
    fn on_apply_event(&mut self, index: u64, event: Bytes) -> Result<EventOutcome, ActorError> {
        Err(ActorError::Internal)
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;
    use tcp_runtime::mock::MockActorContext;

    #[test]
    fn create_actor() {
        let mut mock_context = Box::new(MockActorContext::new());
        mock_context.expect_id().return_const(0u64);

        let mut actor = LedgerActor::new();
        assert_eq!(actor.on_init(mock_context), Ok(()));
        assert_eq!(actor.get_context().id(), 0u64);
    }
}
