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

use crate::attestation;
use crate::fcp::confidentialcompute::*;
use crate::ledger::{Ledger, LedgerService};

use alloc::{boxed::Box, format, vec};
use prost::{bytes::Bytes, Message};
use tcp_runtime::model::{Actor, ActorContext, ActorError, CommandOutcome, EventOutcome};

use slog::warn;

pub struct LedgerActor {
    context: Option<Box<dyn ActorContext>>,
    ledger: Box<dyn Ledger>,
}

impl LedgerActor {
    pub fn new() -> Self {
        LedgerActor {
            context: None,
            ledger: Box::new(LedgerService::new()),
        }
    }

    fn get_context(&mut self) -> &mut dyn ActorContext {
        self.context
            .as_mut()
            .expect("Context is initialized")
            .as_mut()
    }

    fn parse_request(&mut self, bytes: &Bytes) -> Result<LedgerRequest, micro_rpc::Status> {
        let request = LedgerRequest::decode(bytes.clone()).map_err(|error| {
            warn!(
                self.get_context().logger(),
                "LedgerRequest cannot be parsed: {}", error
            );
            micro_rpc::Status::new_with_message(
                micro_rpc::StatusCode::InvalidArgument,
                "LedgerRequest cannot be parsed",
            )
        })?;

        if request.request.is_none() {
            warn!(self.get_context().logger(), "Unknown request {:?}", request);
            return Err(micro_rpc::Status::new_with_message(
                micro_rpc::StatusCode::InvalidArgument,
                "Unknown request",
            ));
        }
        Ok(request)
    }

    // Handles the actor command and returns the command outcome or the status to be promptly
    // returned to the untrusted side.
    fn handle_command(&mut self, command: Bytes) -> Result<CommandOutcome, micro_rpc::Status> {
        let mut request = self.parse_request(&command)?;

        if !self.get_context().leader() {
            // Not a leader.
            warn!(
                self.get_context().logger(),
                "Command {:?} rejected: not a leader", request
            );
            return Err(micro_rpc::Status::new_with_message(
                micro_rpc::StatusCode::Unavailable,
                "Command rejected",
            ));
        }

        if let Some(ledger_request::Request::AuthorizeAccess(ref mut authorize_access_request)) =
            request.request
        {
            // Special case for the AuthorizeAccess where the attestation is performed
            // as prerequisite for executing the rest of the command.
            attestation::verify_attestation(
                &authorize_access_request.recipient_public_key,
                &authorize_access_request.recipient_attestation,
                &authorize_access_request.recipient_tag,
            )
            .map_err(|err| {
                micro_rpc::Status::new_with_message(
                    micro_rpc::StatusCode::InvalidArgument,
                    format!("attestation validation failed: {:?}", err),
                )
            })?;

            // Empty out the attestation field
            authorize_access_request.recipient_attestation = vec![];
            // Encode the remaining request as the event.
            return Ok(CommandOutcome::Event(request.encode_to_vec().into()));
        }

        // In all other cases delegate to processing the command as the event.
        Ok(CommandOutcome::Event(command))
    }

    fn handle_event(
        &mut self,
        _index: u64,
        event: Bytes,
    ) -> Result<EventOutcome, micro_rpc::Status> {
        let request = self.parse_request(&event)?;
        let response_data = match request.request {
            Some(ledger_request::Request::AuthorizeAccess(authorize_access_request)) => {
                let response = self.ledger.authorize_access(authorize_access_request)?;
                response.encode_to_vec()
            }
            Some(ledger_request::Request::CreateKey(create_key_request)) => {
                let response = self.ledger.create_key(create_key_request)?;
                response.encode_to_vec()
            }
            Some(ledger_request::Request::DeleteKey(delete_key_request)) => {
                let response = self.ledger.delete_key(delete_key_request)?;
                response.encode_to_vec()
            }
            Some(ledger_request::Request::RevokeAccess(revoke_access_request)) => {
                let response = self.ledger.revoke_access(revoke_access_request)?;
                response.encode_to_vec()
            }
            _ => {
                return Err(micro_rpc::Status::new_with_message(
                    micro_rpc::StatusCode::InvalidArgument,
                    "Unexpected event type",
                ));
            }
        };

        Ok(EventOutcome::Response(response_data.into()))
    }
}

impl LedgerResponse {
    fn with_error(error: micro_rpc::Status) -> Self {
        LedgerResponse {
            response: Some(ledger_response::Response::Error(crate::micro_rpc::Status {
                code: error.code as i32,
                message: error.message.into(),
            })),
        }
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
    fn on_load_snapshot(&mut self, _snapshot: Bytes) -> Result<(), ActorError> {
        Err(ActorError::Internal)
    }

    /// Handles processing of a command by the actor. Command represents an intent of a
    /// consumer (e.g. request to update actor state). The command processing logic may
    /// decide to immediately respond (e.g. the command validation failed and cannot be
    /// executed) or to propose an event for replication by the consensus module (e.g. the
    /// event to update actor state once replicated).
    fn on_process_command(&mut self, command: Bytes) -> Result<CommandOutcome, ActorError> {
        self.handle_command(command).or_else(|err| {
            Ok(CommandOutcome::Response(
                LedgerResponse::with_error(err).encode_to_vec().into(),
            ))
        })
    }

    /// Handles committed events by applying them to the actor state. Event represents
    /// a state transition of the actor and may result in messages being sent to the
    /// consumer (e.g. response to the command that generated this event).
    fn on_apply_event(&mut self, index: u64, event: Bytes) -> Result<EventOutcome, ActorError> {
        self.handle_event(index, event).or_else(|err| {
            Ok(EventOutcome::Response(
                LedgerResponse::with_error(err).encode_to_vec().into(),
            ))
        })
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
