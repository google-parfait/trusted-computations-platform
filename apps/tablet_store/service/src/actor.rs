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

use crate::actor::{tablet_store_in_message::*, tablet_store_out_message::*};
use crate::apps::tablet_store::service::*;
use alloc::boxed::Box;
use alloc::format;
use alloc::string::String;
use alloc::string::ToString;
use alloc::vec::Vec;
use hashbrown::HashMap;
use prost::{bytes::Bytes, Message};
use slog::{debug, warn};
use tcp_runtime::model::{
    Actor, ActorCommand, ActorContext, ActorError, ActorEvent, ActorEventContext, CommandOutcome,
    EventOutcome,
};

impl ExecuteTabletOpsError {
    fn with_status(status: ExecuteTabletOpsStatus, diagnostic_message: String) -> OutMsg {
        OutMsg::ExecuteTabletOpsError(ExecuteTabletOpsError {
            status: status.into(),
            diagnostic_message,
        })
    }
}

struct Table {
    config: TableConfig,
    tablets: HashMap<u32, TabletMetadata>,
}

impl Table {
    fn create(config: &TableConfig) -> Table {
        Table {
            config: config.clone(),
            tablets: HashMap::new(),
        }
    }

    fn load_snapshot(&mut self, snapshot: TableSnapshot) {
        self.tablets.clear();
        for table_tablet in snapshot.table_tablets {
            self.tablets.insert(table_tablet.tablet_id, table_tablet);
        }
    }

    fn save_snapshot(&self) -> TableSnapshot {
        let mut table_tablets = Vec::with_capacity(self.tablets.len());
        for tablet_metadata in self.tablets.values() {
            table_tablets.push(tablet_metadata.clone());
        }

        TableSnapshot {
            table_name: self.config.table_name.clone(),
            table_tablets,
        }
    }
}

pub struct TabletStoreActor {
    context: Option<Box<dyn ActorContext>>,
    config: TabletStoreConfig,
    tables: HashMap<String, Table>,
}

impl TabletStoreActor {
    pub fn new() -> Self {
        TabletStoreActor {
            context: None,
            config: TabletStoreConfig::default(),
            tables: HashMap::new(),
        }
    }

    fn get_context(&mut self) -> &mut dyn ActorContext {
        self.context
            .as_mut()
            .expect("Context is initialized")
            .as_mut()
    }
}

impl TabletStoreActor {
    fn create_error_outcome(
        &mut self,
        diagnostic_message: String,
        correlation_id: u64,
        status: ExecuteTabletOpsStatus,
    ) -> Result<CommandOutcome, ActorError> {
        warn!(self.get_context().logger(), "{}", diagnostic_message);

        Ok(CommandOutcome::with_command(ActorCommand::with_header(
            correlation_id,
            &TabletStoreOutMessage {
                out_msg: Some(ExecuteTabletOpsError::with_status(
                    status,
                    diagnostic_message,
                )),
            },
        )))
    }

    fn create_success_outcome(
        &self,
        correlation_id: u64,
        out_header: OutMsg,
        out_payload: Bytes,
    ) -> Result<CommandOutcome, ActorError> {
        Ok(CommandOutcome::with_command(
            ActorCommand::with_header_and_payload(
                correlation_id,
                &TabletStoreOutMessage {
                    out_msg: Some(out_header),
                },
                out_payload,
            ),
        ))
    }

    fn on_process_tablets_request(&mut self, _request: TabletsRequest) -> (OutMsg, Bytes) {
        (
            ExecuteTabletOpsError::with_status(
                ExecuteTabletOpsStatus::InvalidOperation,
                "Error".to_string(),
            ),
            Bytes::new(),
        )
    }
}

impl Actor for TabletStoreActor {
    fn on_init(&mut self, context: Box<dyn ActorContext>) -> Result<(), ActorError> {
        self.context = Some(context);
        self.config = TabletStoreConfig::decode(self.get_context().config().as_ref())
            .map_err(|_| ActorError::ConfigLoading)?;

        for table_config in &self.config.table_configs {
            self.tables
                .insert(table_config.table_name.clone(), Table::create(table_config));
        }

        debug!(self.get_context().logger(), "Initialized");

        Ok(())
    }

    fn on_shutdown(&mut self) {}

    fn on_save_snapshot(&mut self) -> Result<Bytes, ActorError> {
        debug!(self.get_context().logger(), "Saving snapshot");

        let mut table_snapshots = Vec::with_capacity(self.tables.len());
        for table in self.tables.values() {
            table_snapshots.push(table.save_snapshot());
        }
        let snapshot = TabletStoreSnapshot { table_snapshots };

        Ok(snapshot.encode_to_vec().into())
    }

    fn on_load_snapshot(&mut self, snapshot: Bytes) -> Result<(), ActorError> {
        debug!(self.get_context().logger(), "Loading snapshot");

        let snapshot =
            TabletStoreSnapshot::decode(snapshot).map_err(|_| ActorError::SnapshotLoading)?;

        for table_snapshot in snapshot.table_snapshots {
            let table = self
                .tables
                .get_mut(&table_snapshot.table_name)
                .ok_or(ActorError::SnapshotLoading)?;
            table.load_snapshot(table_snapshot);
        }

        Ok(())
    }

    fn on_process_command(&mut self, command: ActorCommand) -> Result<CommandOutcome, ActorError> {
        if !self.get_context().leader() {
            return self.create_error_outcome(
                "Rejecting command: not a leader".into(),
                command.correlation_id,
                ExecuteTabletOpsStatus::InvalidOperation,
            );
        }

        let in_header = match TabletStoreInMessage::decode(command.header.clone()) {
            Ok(in_message) => in_message.in_msg,
            Err(e) => {
                return self.create_error_outcome(
                    format!("Rejecting command: {}", e),
                    command.correlation_id,
                    ExecuteTabletOpsStatus::InvalidOperation,
                );
            }
        };

        let (out_header, out_payload) = match in_header {
            Some(oneof) => match oneof {
                InMsg::ExecuteTabletOpsRequest(_execute_tablet_ops_request) => {
                    match TabletsRequest::decode(command.payload.clone()) {
                        Ok(tablets_request) => self.on_process_tablets_request(tablets_request),
                        Err(e) => {
                            return self.create_error_outcome(
                                format!("Rejecting command: {}", e),
                                command.correlation_id,
                                ExecuteTabletOpsStatus::InvalidOperation,
                            );
                        }
                    }
                }
            },
            None => {
                return self.create_error_outcome(
                    "Rejecting command: message is not set".into(),
                    command.correlation_id,
                    ExecuteTabletOpsStatus::InvalidOperation,
                );
            }
        };

        self.create_success_outcome(command.correlation_id, out_header, out_payload)
    }

    fn on_apply_event(
        &mut self,
        _context: ActorEventContext,
        _event: ActorEvent,
    ) -> Result<EventOutcome, ActorError> {
        Err(ActorError::Internal)
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;
    use alloc::vec;
    use tcp_runtime::logger::log::create_logger;
    use tcp_runtime::mock::MockActorContext;

    fn create_actor_config() -> TabletStoreConfig {
        TabletStoreConfig {
            table_configs: vec![TableConfig {
                table_name: "A".to_string(),
                max_tablet_size: 1024,
                min_tablet_size: 512,
                initial_tablet_count: 4,
            }],
        }
    }

    fn create_actor() -> TabletStoreActor {
        let config = create_actor_config();
        let mut mock_context = Box::new(MockActorContext::new());
        mock_context.expect_logger().return_const(create_logger());
        mock_context.expect_id().return_const(0u64);
        mock_context
            .expect_config()
            .return_const::<Bytes>(config.encode_to_vec().into());

        let mut actor = TabletStoreActor::new();
        assert_eq!(actor.on_init(mock_context), Ok(()));
        actor
    }

    #[test]
    fn test_create_actor() {
        let mut actor = create_actor();

        assert_eq!(actor.get_context().id(), 0u64);
    }

    #[test]
    fn test_load_save_snapshot() {
        let mut actor = create_actor();

        let snapshot = TabletStoreSnapshot {
            table_snapshots: vec![TableSnapshot {
                table_name: "A".to_string(),
                table_tablets: vec![TabletMetadata {
                    tablet_id: 1,
                    tablet_version: 2,
                    deleted: false,
                    blob_encryption_key: Bytes::new(),
                    blob_size: 128,
                    blob_hash: Bytes::new(),
                    blob_uri: "U".to_string(),
                }],
            }],
        };

        actor
            .on_load_snapshot(snapshot.encode_to_vec().into())
            .unwrap();

        assert_eq!(actor.on_save_snapshot().unwrap(), snapshot.encode_to_vec());
    }
}
