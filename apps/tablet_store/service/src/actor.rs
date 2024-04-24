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

use crate::actor::{
    tablet_op::*, tablet_op_result::*, tablet_store_in_message::*, tablet_store_out_message::*,
};
use crate::apps::tablet_store::service::*;
use alloc::boxed::Box;
use alloc::format;
use alloc::string::String;
use alloc::string::ToString;
use alloc::vec::Vec;
use core::mem::swap;
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

struct TableMetadata {
    config: TableConfig,
    tablets: HashMap<u32, TabletMetadata>,
}

impl TableMetadata {
    fn create(config: &TableConfig) -> TableMetadata {
        TableMetadata {
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
        table_tablets.sort_by(|a, b| a.tablet_id.cmp(&b.tablet_id));

        TableSnapshot {
            table_name: self.config.table_name.clone(),
            table_tablets,
        }
    }

    fn prepare_tablet_op(&self, tablet_op: &Op) -> TabletOpResult {
        let mut op_result = TabletOpResult {
            status: TabletOpStatus::Failed.into(),
            ..Default::default()
        };

        op_result.op_result = Some(match tablet_op {
            Op::ListTablet(list_tablet_op) => {
                let mut negate = false;
                let (mut tablet_from, mut tablet_to) =
                    (list_tablet_op.tablet_id_from, list_tablet_op.tablet_id_to);
                if tablet_from > tablet_to {
                    negate = true;
                    swap(&mut tablet_to, &mut tablet_from);
                }

                let mut listed_tablets = Vec::new();
                for (tablet_id, tablet_metadata) in &self.tablets {
                    if negate ^ (*tablet_id >= tablet_from && *tablet_id < tablet_to) {
                        listed_tablets.push(tablet_metadata.clone());
                    }
                }

                op_result.status = TabletOpStatus::Succeeded.into();
                OpResult::ListTablet(ListTabletResult {
                    tablets: listed_tablets,
                })
            }
            Op::CheckTablet(check_tablet_op) => {
                let mut check_tablet_result = CheckTabletResult::default();
                if let Some(existing_tablet) = self.tablets.get(&check_tablet_op.tablet_id) {
                    if existing_tablet.tablet_version == check_tablet_op.tablet_version {
                        op_result.status = TabletOpStatus::Succeeded.into();
                    }
                    check_tablet_result.tablet_version = existing_tablet.tablet_version;
                }
                OpResult::CheckTablet(check_tablet_result)
            }
            Op::UpdateTablet(update_tablet_op) => {
                let mut update_tablet_result = UpdateTabletResult::default();
                if let Some(updated_tablet) = &update_tablet_op.tablet_metadata {
                    if let Some(existing_tablet) = self.tablets.get(&updated_tablet.tablet_id) {
                        if updated_tablet.tablet_version == existing_tablet.tablet_version + 1 {
                            op_result.status = TabletOpStatus::Succeeded.into();
                        }
                        update_tablet_result.existing_tablet = Some(existing_tablet.clone());
                    }
                }
                OpResult::UpdateTablet(update_tablet_result)
            }
            Op::AddTablet(add_tablet_op) => todo!(),
            Op::RemoveTablet(remove_tablet_op) => todo!(),
        });

        op_result
    }

    fn commit_tablet_op(
        &mut self,
        tablet_op: Op,
        tablet_op_prepare_result: TabletOpResult,
    ) -> TabletOpResult {
        let mut op_result = tablet_op_prepare_result;

        op_result.op_result = Some(match tablet_op {
            Op::ListTablet(list_tablet_op) => op_result.op_result.unwrap(),
            Op::CheckTablet(check_tablet_op) => op_result.op_result.unwrap(),
            Op::UpdateTablet(update_tablet_op) => {
                let updated_tablet = update_tablet_op.tablet_metadata.unwrap();
                self.tablets
                    .insert(updated_tablet.tablet_id, updated_tablet);

                op_result.op_result.unwrap()
            }
            Op::AddTablet(_) => todo!(),
            Op::RemoveTablet(_) => todo!(),
        });

        op_result
    }
}

pub struct TabletStoreActor {
    context: Option<Box<dyn ActorContext>>,
    config: TabletStoreConfig,
    tables: HashMap<String, TableMetadata>,
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
        owned: bool,
        correlation_id: u64,
        out_header: OutMsg,
        out_payload: Bytes,
    ) -> Result<EventOutcome, ActorError> {
        let mut commands = Vec::new();
        if owned {
            commands.push(ActorCommand::with_header_and_payload(
                correlation_id,
                &TabletStoreOutMessage {
                    out_msg: Some(out_header),
                },
                out_payload,
            ));
        }
        Ok(EventOutcome::with_commands(commands))
    }

    fn on_apply_tablets_request(&mut self, request: TabletsRequest) -> (OutMsg, Bytes) {
        let mut all_succeeded = true;
        let mut tablet_op_prepare_results = Vec::new();
        for tablet_op in &request.tablet_ops {
            let tablet_op_result = self.prepare_tablet_op(tablet_op);
            all_succeeded &= tablet_op_result.status == TabletOpStatus::Succeeded as i32;
            tablet_op_prepare_results.push(tablet_op_result);
        }

        let mut tablet_op_results = Vec::new();
        if all_succeeded {
            for (tablet_op, tablet_op_prepare_result) in request
                .tablet_ops
                .into_iter()
                .zip(tablet_op_prepare_results.into_iter())
            {
                tablet_op_results.push(self.commit_tablet_op(tablet_op, tablet_op_prepare_result));
            }
        } else {
            tablet_op_results = tablet_op_prepare_results;
        }

        let tablets_request_status = if all_succeeded {
            TabletsRequestStatus::Succeeded
        } else {
            TabletsRequestStatus::Failed
        };

        let tablets_response = TabletsResponse {
            status: tablets_request_status.into(),
            tablet_results: tablet_op_results,
        };

        (
            OutMsg::ExecuteTabletOpsResponse(ExecuteTabletOpsResponse {}),
            tablets_response.encode_to_vec().into(),
        )
    }

    fn prepare_tablet_op(&mut self, tablet_op: &TabletOp) -> TabletOpResult {
        let table_opt = self.tables.get(&tablet_op.table_name);
        if table_opt.is_none() || tablet_op.op.is_none() {
            return TabletOpResult {
                status: TabletOpStatus::Invalid.into(),
                op_result: None,
            };
        }
        table_opt
            .unwrap()
            .prepare_tablet_op(tablet_op.op.as_ref().unwrap())
    }

    fn commit_tablet_op(
        &mut self,
        tablet_op: TabletOp,
        tablet_op_prepare_result: TabletOpResult,
    ) -> TabletOpResult {
        let table = self.tables.get_mut(&tablet_op.table_name).unwrap();
        table.commit_tablet_op(tablet_op.op.unwrap(), tablet_op_prepare_result)
    }
}

impl Actor for TabletStoreActor {
    fn on_init(&mut self, context: Box<dyn ActorContext>) -> Result<(), ActorError> {
        self.context = Some(context);
        self.config = TabletStoreConfig::decode(self.get_context().config().as_ref())
            .map_err(|_| ActorError::ConfigLoading)?;

        for table_config in &self.config.table_configs {
            self.tables.insert(
                table_config.table_name.clone(),
                TableMetadata::create(table_config),
            );
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
                ExecuteTabletOpsStatus::Rejected,
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

        let actor_event = match in_header {
            Some(oneof) => match oneof {
                InMsg::ExecuteTabletOpsRequest(_execute_tablet_ops_request) => {
                    match TabletsRequest::decode(command.payload.clone()) {
                        Ok(tablets_request) => command.payload,
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

        Ok(CommandOutcome::with_event(ActorEvent::with_bytes(
            command.correlation_id,
            actor_event,
        )))
    }

    fn on_apply_event(
        &mut self,
        context: ActorEventContext,
        event: ActorEvent,
    ) -> Result<EventOutcome, ActorError> {
        let tablets_request =
            TabletsRequest::decode(event.contents.clone()).map_err(|_| ActorError::Internal)?;

        let (out_header, out_payload) = self.on_apply_tablets_request(tablets_request);

        self.create_success_outcome(context.owned, event.correlation_id, out_header, out_payload)
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;
    use alloc::vec;
    use tcp_proto::runtime::endpoint::out_message;
    use tcp_runtime::logger::log::create_logger;
    use tcp_runtime::mock::MockActorContext;

    static TABLE_NAME: &str = "A";
    const TABLET_ID_1: u32 = 10;
    const TABLET_VERSION_1: u32 = 5;
    const TABLET_ID_2: u32 = 20;
    const TABLET_VERSION_2: u32 = 7;

    const CORRELATION_ID_1: u64 = 11;

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

    fn create_tablet_metadata(tablet_id: u32, tablet_version: u32) -> TabletMetadata {
        TabletMetadata {
            tablet_id,
            tablet_version,
            deleted: false,
            blob_encryption_key: Bytes::new(),
            blob_size: 128,
            blob_hash: Bytes::new(),
            blob_uri: format!("{}", tablet_id),
        }
    }

    fn create_actor_snapshot() -> TabletStoreSnapshot {
        TabletStoreSnapshot {
            table_snapshots: vec![TableSnapshot {
                table_name: TABLE_NAME.to_string(),
                table_tablets: vec![
                    create_tablet_metadata(TABLET_ID_1, TABLET_VERSION_1),
                    create_tablet_metadata(TABLET_ID_2, TABLET_VERSION_2),
                ],
            }],
        }
    }

    fn create_list_tablet_op(
        table_name: String,
        tablet_id_from: u32,
        tablet_id_to: u32,
    ) -> TabletOp {
        TabletOp {
            table_name,
            op: Some(Op::ListTablet(ListTabletOp {
                tablet_id_from,
                tablet_id_to,
            })),
        }
    }

    fn create_check_tablet_op(table_name: String, tablet_id: u32, tablet_version: u32) -> TabletOp {
        TabletOp {
            table_name,
            op: Some(Op::CheckTablet(CheckTabletOp {
                tablet_id,
                tablet_version,
            })),
        }
    }

    fn create_update_tablet_op(table_name: String, tablet_metadata: TabletMetadata) -> TabletOp {
        TabletOp {
            table_name,
            op: Some(Op::UpdateTablet(UpdateTabletOp {
                tablet_metadata: Some(tablet_metadata),
            })),
        }
    }

    fn create_check_tablet_result(status: TabletOpStatus, tablet_version: u32) -> TabletOpResult {
        TabletOpResult {
            status: status.into(),
            op_result: Some(OpResult::CheckTablet(CheckTabletResult { tablet_version })),
        }
    }

    fn create_update_tablet_result(
        status: TabletOpStatus,
        tablet_metadata: TabletMetadata,
    ) -> TabletOpResult {
        TabletOpResult {
            status: status.into(),
            op_result: Some(OpResult::UpdateTablet(UpdateTabletResult {
                existing_tablet: Some(tablet_metadata),
            })),
        }
    }

    fn create_list_tablet_result(
        status: TabletOpStatus,
        tablets: Vec<TabletMetadata>,
    ) -> TabletOpResult {
        TabletOpResult {
            status: status.into(),
            op_result: Some(OpResult::ListTablet(ListTabletResult { tablets })),
        }
    }

    fn create_execute_tablet_ops_request(
        correlation_id: u64,
        tablet_ops: Vec<TabletOp>,
    ) -> ActorCommand {
        let execute_tablet_ops_request = TabletStoreInMessage {
            in_msg: Some(InMsg::ExecuteTabletOpsRequest(ExecuteTabletOpsRequest {
                sender_node_id: 1,
            })),
        };
        let tablets_request = TabletsRequest { tablet_ops };
        ActorCommand::with_header_and_payload(
            correlation_id,
            &execute_tablet_ops_request,
            tablets_request.encode_to_vec().into(),
        )
    }

    fn create_execute_tablet_ops_response(
        status: TabletsRequestStatus,
        tablet_results: Vec<TabletOpResult>,
    ) -> TabletsResponse {
        TabletsResponse {
            status: status.into(),
            tablet_results,
        }
    }

    fn decode_execute_tablet_ops_response(
        command: ActorCommand,
    ) -> (ExecuteTabletOpsResponse, TabletsResponse) {
        let out_message = TabletStoreOutMessage::decode(command.header.clone()).unwrap();
        let tablets_response = TabletsResponse::decode(command.payload.clone()).unwrap();

        if let Some(OutMsg::ExecuteTabletOpsResponse(execute_tablet_ops_response)) =
            out_message.out_msg
        {
            (execute_tablet_ops_response, tablets_response)
        } else {
            panic!("Unexpected response");
        }
    }

    fn create_actor(mut mock_context: MockActorContext) -> TabletStoreActor {
        let config = create_actor_config();
        mock_context.expect_logger().return_const(create_logger());
        mock_context.expect_id().return_const(0u64);
        mock_context
            .expect_config()
            .return_const::<Bytes>(config.encode_to_vec().into());

        let mut actor = TabletStoreActor::new();
        assert_eq!(actor.on_init(Box::new(mock_context)), Ok(()));
        actor
    }

    #[test]
    fn test_create_actor() {
        let mock_context = MockActorContext::new();

        let mut actor = create_actor(mock_context);

        assert_eq!(actor.get_context().id(), 0u64);
    }

    #[test]
    fn test_load_save_snapshot() {
        let mock_context = MockActorContext::new();

        let mut actor = create_actor(mock_context);
        let snapshot = create_actor_snapshot();

        actor
            .on_load_snapshot(snapshot.encode_to_vec().into())
            .unwrap();

        assert_eq!(actor.on_save_snapshot().unwrap(), snapshot.encode_to_vec());
    }

    #[test]
    fn test_list_tablet_success() {
        let mut mock_context = MockActorContext::new();
        mock_context.expect_leader().return_const(true);

        let mut actor = create_actor(mock_context);
        let snapshot = create_actor_snapshot();

        actor
            .on_load_snapshot(snapshot.encode_to_vec().into())
            .unwrap();

        let command_outcome = actor
            .on_process_command(create_execute_tablet_ops_request(
                CORRELATION_ID_1,
                vec![create_list_tablet_op(
                    TABLE_NAME.to_string(),
                    TABLET_ID_1 - 1,
                    TABLET_ID_2,
                )],
            ))
            .unwrap();

        let event_outcome = actor
            .on_apply_event(
                ActorEventContext {
                    index: 1,
                    owned: true,
                },
                command_outcome.event.unwrap(),
            )
            .unwrap();

        assert_eq!(event_outcome.commands.len(), 1);
        let response_command = event_outcome.commands[0].clone();
        assert_eq!(response_command.correlation_id, CORRELATION_ID_1);

        let (execute_tablet_ops_response, tablets_response) =
            decode_execute_tablet_ops_response(response_command);

        assert_eq!(
            tablets_response,
            create_execute_tablet_ops_response(
                TabletsRequestStatus::Succeeded,
                vec![create_list_tablet_result(
                    TabletOpStatus::Succeeded,
                    vec![create_tablet_metadata(TABLET_ID_1, TABLET_VERSION_1),]
                )]
            )
        );
    }

    #[test]
    fn test_check_tablet_success() {
        let mut mock_context = MockActorContext::new();
        mock_context.expect_leader().return_const(true);

        let mut actor = create_actor(mock_context);
        let snapshot = create_actor_snapshot();

        actor
            .on_load_snapshot(snapshot.encode_to_vec().into())
            .unwrap();

        let command_outcome = actor
            .on_process_command(create_execute_tablet_ops_request(
                CORRELATION_ID_1,
                vec![create_check_tablet_op(
                    TABLE_NAME.to_string(),
                    TABLET_ID_1,
                    TABLET_VERSION_1,
                )],
            ))
            .unwrap();

        let event_outcome = actor
            .on_apply_event(
                ActorEventContext {
                    index: 1,
                    owned: true,
                },
                command_outcome.event.unwrap(),
            )
            .unwrap();

        assert_eq!(event_outcome.commands.len(), 1);
        let response_command = event_outcome.commands[0].clone();
        assert_eq!(response_command.correlation_id, CORRELATION_ID_1);

        let (execute_tablet_ops_response, tablets_response) =
            decode_execute_tablet_ops_response(response_command);

        assert_eq!(
            tablets_response,
            create_execute_tablet_ops_response(
                TabletsRequestStatus::Succeeded,
                vec![create_check_tablet_result(
                    TabletOpStatus::Succeeded,
                    TABLET_VERSION_1
                )]
            )
        );
    }

    #[test]
    fn test_update_tablet_success() {
        let mut mock_context = MockActorContext::new();
        mock_context.expect_leader().return_const(true);

        let mut actor = create_actor(mock_context);
        let snapshot = create_actor_snapshot();

        actor
            .on_load_snapshot(snapshot.encode_to_vec().into())
            .unwrap();

        let command_outcome = actor
            .on_process_command(create_execute_tablet_ops_request(
                CORRELATION_ID_1,
                vec![create_update_tablet_op(
                    TABLE_NAME.to_string(),
                    create_tablet_metadata(TABLET_ID_1, TABLET_VERSION_1 + 1),
                )],
            ))
            .unwrap();

        let event_outcome = actor
            .on_apply_event(
                ActorEventContext {
                    index: 1,
                    owned: true,
                },
                command_outcome.event.unwrap(),
            )
            .unwrap();

        assert_eq!(event_outcome.commands.len(), 1);
        let response_command = event_outcome.commands[0].clone();
        assert_eq!(response_command.correlation_id, CORRELATION_ID_1);

        let (execute_tablet_ops_response, tablets_response) =
            decode_execute_tablet_ops_response(response_command);

        assert_eq!(
            tablets_response,
            create_execute_tablet_ops_response(
                TabletsRequestStatus::Succeeded,
                vec![create_update_tablet_result(
                    TabletOpStatus::Succeeded,
                    create_tablet_metadata(TABLET_ID_1, TABLET_VERSION_1)
                )]
            )
        );
    }

    #[test]
    fn test_multiple_ops_success() {
        let mut mock_context = MockActorContext::new();
        mock_context.expect_leader().return_const(true);

        let mut actor = create_actor(mock_context);
        let snapshot = create_actor_snapshot();

        actor
            .on_load_snapshot(snapshot.encode_to_vec().into())
            .unwrap();

        let command_outcome = actor
            .on_process_command(create_execute_tablet_ops_request(
                CORRELATION_ID_1,
                vec![
                    create_check_tablet_op(TABLE_NAME.to_string(), TABLET_ID_1, TABLET_VERSION_1),
                    create_update_tablet_op(
                        TABLE_NAME.to_string(),
                        create_tablet_metadata(TABLET_ID_1, TABLET_VERSION_1 + 1),
                    ),
                ],
            ))
            .unwrap();

        let event_outcome = actor
            .on_apply_event(
                ActorEventContext {
                    index: 1,
                    owned: true,
                },
                command_outcome.event.unwrap(),
            )
            .unwrap();

        assert_eq!(event_outcome.commands.len(), 1);
        let response_command = event_outcome.commands[0].clone();
        assert_eq!(response_command.correlation_id, CORRELATION_ID_1);

        let (execute_tablet_ops_response, tablets_response) =
            decode_execute_tablet_ops_response(response_command);

        assert_eq!(
            tablets_response,
            create_execute_tablet_ops_response(
                TabletsRequestStatus::Succeeded,
                vec![
                    create_check_tablet_result(TabletOpStatus::Succeeded, TABLET_VERSION_1),
                    create_update_tablet_result(
                        TabletOpStatus::Succeeded,
                        create_tablet_metadata(TABLET_ID_1, TABLET_VERSION_1)
                    )
                ]
            )
        );
    }

    #[test]
    fn test_multiple_ops_failure() {
        let mut mock_context = MockActorContext::new();
        mock_context.expect_leader().return_const(true);

        let mut actor = create_actor(mock_context);
        let snapshot = create_actor_snapshot();

        actor
            .on_load_snapshot(snapshot.encode_to_vec().into())
            .unwrap();

        let command_outcome = actor
            .on_process_command(create_execute_tablet_ops_request(
                CORRELATION_ID_1,
                vec![
                    create_list_tablet_op(TABLE_NAME.to_string(), TABLET_ID_1 - 1, TABLET_ID_2),
                    create_check_tablet_op(
                        TABLE_NAME.to_string(),
                        TABLET_ID_1,
                        TABLET_VERSION_1 - 1,
                    ),
                    create_update_tablet_op(
                        TABLE_NAME.to_string(),
                        create_tablet_metadata(TABLET_ID_1, TABLET_VERSION_1 - 1),
                    ),
                ],
            ))
            .unwrap();

        let event_outcome = actor
            .on_apply_event(
                ActorEventContext {
                    index: 1,
                    owned: true,
                },
                command_outcome.event.unwrap(),
            )
            .unwrap();

        assert_eq!(event_outcome.commands.len(), 1);
        let response_command = event_outcome.commands[0].clone();
        assert_eq!(response_command.correlation_id, CORRELATION_ID_1);

        let (execute_tablet_ops_response, tablets_response) =
            decode_execute_tablet_ops_response(response_command);

        assert_eq!(
            tablets_response,
            create_execute_tablet_ops_response(
                TabletsRequestStatus::Failed,
                vec![
                    create_list_tablet_result(
                        TabletOpStatus::Succeeded,
                        vec![create_tablet_metadata(TABLET_ID_1, TABLET_VERSION_1),]
                    ),
                    create_check_tablet_result(TabletOpStatus::Failed, TABLET_VERSION_1),
                    create_update_tablet_result(
                        TabletOpStatus::Failed,
                        create_tablet_metadata(TABLET_ID_1, TABLET_VERSION_1)
                    )
                ]
            )
        );
    }
}
