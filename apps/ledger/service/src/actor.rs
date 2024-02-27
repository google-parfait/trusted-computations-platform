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

use crate::fcp::confidentialcompute::*;
use crate::ledger::{Ledger, LedgerService};

use alloc::{boxed::Box, format, vec};
use prost::{bytes::Bytes, Message};
use tcp_runtime::model::{Actor, ActorContext, ActorError, CommandOutcome, EventOutcome};

use slog::{debug, error, warn};

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

    // Handles the actor command and returns the command outcome or the status to be promptly
    // returned to the untrusted side.
    fn handle_command(&mut self, command: Bytes) -> Result<CommandOutcome, micro_rpc::Status> {
        let ledger_request = LedgerRequest::decode(command.clone()).map_err(|error| {
            warn!(
                self.get_context().logger(),
                "LedgerActor: request cannot be parsed: {}", error
            );
            micro_rpc::Status::new_with_message(
                micro_rpc::StatusCode::InvalidArgument,
                "LedgerRequest cannot be parsed",
            )
        })?;

        debug!(
            self.get_context().logger(),
            "LedgerActor: handling {} command",
            ledger_request.name()
        );

        if !self.get_context().leader() {
            // Not a leader.
            warn!(
                self.get_context().logger(),
                "LedgerActor: command {} rejected: not a leader",
                ledger_request.name()
            );
            return Err(micro_rpc::Status::new_with_message(
                micro_rpc::StatusCode::Unavailable,
                "Command rejected",
            ));
        }

        let event = match ledger_request.request {
            Some(ledger_request::Request::AuthorizeAccess(mut authorize_access_request)) => {
                // Special case for the AuthorizeAccess where the attestation is performed
                // as prerequisite for executing the rest of the command.
                LedgerService::verify_attestation(&authorize_access_request).map_err(|error| {
                    micro_rpc::Status::new_with_message(
                        micro_rpc::StatusCode::InvalidArgument,
                        format!("attestation validation failed: {:?}", error),
                    )
                })?;
                // Empty out the attestation field
                authorize_access_request.recipient_attestation = vec![];
                ledger_event::Event::AuthorizeAccess(authorize_access_request)
            }
            Some(ledger_request::Request::CreateKey(create_key_request)) => {
                // Special case for the CreateKey where the public/private keypair
                // has to be created in advance and replicated so that exactly the
                // same keypair is stored on every replica.
                let create_key_event = self.ledger.produce_create_key_event(create_key_request)?;
                ledger_event::Event::CreateKey(create_key_event)
            }
            Some(ledger_request::Request::DeleteKey(delete_key_request)) => {
                // In this case the original request is replicated as the event.
                ledger_event::Event::DeleteKey(delete_key_request)
            }
            Some(ledger_request::Request::RevokeAccess(revoke_access_request)) => {
                // In this case the original request is replicated as the event.
                ledger_event::Event::RevokeAccess(revoke_access_request)
            }
            _ => {
                warn!(
                    self.get_context().logger(),
                    "LedgerActor: unknown request {:?}", ledger_request
                );
                return Err(micro_rpc::Status::new_with_message(
                    micro_rpc::StatusCode::InvalidArgument,
                    "LedgerActor: unexpected request type",
                ));
            }
        };

        Ok(CommandOutcome::Event(
            LedgerEvent { event: Some(event) }.encode_to_vec().into(),
        ))
    }

    fn handle_event(
        &mut self,
        index: u64,
        event: Bytes,
    ) -> Result<EventOutcome, micro_rpc::Status> {
        let ledger_event = LedgerEvent::decode(event.clone()).map_err(|error| {
            warn!(
                self.get_context().logger(),
                "LedgerActor: event cannot be parsed: {}", error
            );
            micro_rpc::Status::new_with_message(
                micro_rpc::StatusCode::InvalidArgument,
                "LedgerRequest cannot be parsed",
            )
        })?;

        debug!(
            self.get_context().logger(),
            "LedgerActor: handling event at index {}: {}",
            index,
            ledger_event.name()
        );

        let response = match ledger_event.event {
            Some(ledger_event::Event::AuthorizeAccess(authorize_access_request)) => {
                let authorize_access_response =
                    self.ledger.authorize_access(authorize_access_request)?;
                if !self.get_context().leader() {
                    return Ok(EventOutcome::None);
                }
                ledger_response::Response::AuthorizeAccess(authorize_access_response)
            }
            Some(ledger_event::Event::CreateKey(create_key_event)) => {
                let create_key_response = self.ledger.apply_create_key_event(create_key_event)?;
                if !self.get_context().leader() {
                    return Ok(EventOutcome::None);
                }
                ledger_response::Response::CreateKey(create_key_response)
            }
            Some(ledger_event::Event::DeleteKey(delete_key_request)) => {
                let delete_key_response = self.ledger.delete_key(delete_key_request)?;
                if !self.get_context().leader() {
                    return Ok(EventOutcome::None);
                }
                ledger_response::Response::DeleteKey(delete_key_response)
            }
            Some(ledger_event::Event::RevokeAccess(revoke_access_request)) => {
                let revoke_access_response = self.ledger.revoke_access(revoke_access_request)?;
                if !self.get_context().leader() {
                    return Ok(EventOutcome::None);
                }
                ledger_response::Response::RevokeAccess(revoke_access_response)
            }
            _ => {
                warn!(
                    self.get_context().logger(),
                    "LedgerActor: unknown event {:?}", ledger_event
                );
                return Err(micro_rpc::Status::new_with_message(
                    micro_rpc::StatusCode::InvalidArgument,
                    "LedgerActor: unexpected event type",
                ));
            }
        };

        Ok(EventOutcome::Response(
            LedgerResponse {
                response: Some(response),
            }
            .encode_to_vec()
            .into(),
        ))
    }
}

impl LedgerRequest {
    fn name(self: &Self) -> &'static str {
        match self.request {
            Some(ledger_request::Request::AuthorizeAccess(_)) => "AuthorizeAccess",
            Some(ledger_request::Request::CreateKey(_)) => "CreateKey",
            Some(ledger_request::Request::DeleteKey(_)) => "DeleteKey",
            Some(ledger_request::Request::RevokeAccess(_)) => "RevokeAccess",
            _ => "Unknown",
        }
    }
}

impl LedgerEvent {
    fn name(self: &Self) -> &'static str {
        match self.event {
            Some(ledger_event::Event::AuthorizeAccess(_)) => "AuthorizeAccess",
            Some(ledger_event::Event::CreateKey(_)) => "CreateKey",
            Some(ledger_event::Event::DeleteKey(_)) => "DeleteKey",
            Some(ledger_event::Event::RevokeAccess(_)) => "RevokeAccess",
            _ => "Unknown",
        }
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
        if self.context.is_some() {
            error!(
                self.get_context().logger(),
                "LedgerActor: already initialized"
            );
            return Err(ActorError::Internal);
        }

        self.context = Some(context);
        debug!(self.get_context().logger(), "LedgerActor: initializing");

        let _ = LedgerConfig::decode(self.get_context().config().as_ref())
            .map_err(|_| ActorError::ConfigLoading)?;
        // TODO: use the config.

        Ok(())
    }

    /// Handles actor shutdown. After this method call completes the actor
    /// is destroyed.
    fn on_shutdown(&mut self) {}

    /// Handles creation of the actor state snapshot. If error is returned the actor
    /// is considered is unknown state and is destroyed.
    fn on_save_snapshot(&mut self) -> Result<Bytes, ActorError> {
        debug!(self.get_context().logger(), "LedgerActor: saving snapshot");
        let snapshot = self.ledger.save_snapshot().map_err(|error| {
            error!(
                self.get_context().logger(),
                "LedgerActor: failed to save snapshot: {}", error
            );
            ActorError::Internal
        })?;
        Ok(snapshot.encode_to_vec().into())
    }

    /// Handles restoration of the actor state from snapshot. If error is returned the actor
    /// is considered is unknown state and is destroyed.
    fn on_load_snapshot(&mut self, snapshot: Bytes) -> Result<(), ActorError> {
        debug!(self.get_context().logger(), "LedgerActor: loading snapshot");
        let snapshot = LedgerSnapshot::decode(snapshot).map_err(|error| {
            error!(
                self.get_context().logger(),
                "LedgerActor: failed to decode snapshot: {}", error
            );
            ActorError::SnapshotLoading
        })?;
        self.ledger.load_snapshot(snapshot).map_err(|error| {
            error!(
                self.get_context().logger(),
                "LedgerActor: failed to load snapshot: {}", error
            );
            ActorError::SnapshotLoading
        })?;
        Ok(())
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
    use tcp_runtime::logger::log::create_logger;
    use tcp_runtime::mock::MockActorContext;

    fn create_actor() -> LedgerActor {
        let config = LedgerConfig {};
        let mut mock_context = Box::new(MockActorContext::new());
        mock_context.expect_logger().return_const(create_logger());
        mock_context.expect_id().return_const(0u64);
        mock_context
            .expect_config()
            .return_const::<Bytes>(config.encode_to_vec().into());

        let mut actor = LedgerActor::new();
        assert_eq!(actor.on_init(mock_context), Ok(()));
        actor
    }

    #[test]
    fn test_create_actor() {
        let mut actor = create_actor();
        assert_eq!(actor.get_context().id(), 0u64);
    }

    #[test]
    fn test_save_snapshot() {
        let mut actor = create_actor();
        let snapshot = LedgerSnapshot {
            current_time: Some(prost_types::Timestamp::default()),
            ..Default::default()
        };
        assert_eq!(
            actor.on_save_snapshot().unwrap(),
            Into::<Bytes>::into(snapshot.encode_to_vec())
        );
    }

    #[test]
    fn test_load_snapshot() {
        let mut actor = create_actor();
        let snapshot = LedgerSnapshot {
            current_time: Some(prost_types::Timestamp::default()),
            ..Default::default()
        };
        assert_eq!(
            actor.on_load_snapshot(snapshot.encode_to_vec().into()),
            Ok(())
        );
    }
}
