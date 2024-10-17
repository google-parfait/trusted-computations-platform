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
use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::mem::swap;
use hashbrown::{HashMap, HashSet};
use oak_proto_rust::oak::attestation::v1::{
    binary_reference_value, kernel_binary_reference_value, reference_values, text_reference_value,
    ApplicationLayerReferenceValues, BinaryReferenceValue, InsecureReferenceValues,
    KernelBinaryReferenceValue, KernelLayerReferenceValues, OakRestrictedKernelReferenceValues,
    ReferenceValues, RootLayerReferenceValues, SkipVerification, TextReferenceValue,
};
use prost::{bytes::Bytes, Message};
use rand::{rngs::OsRng, RngCore};
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
    tablets: BTreeMap<u32, TabletMetadata>,
}

impl TableMetadata {
    fn create(config: &TableConfig, configurator: &mut dyn TabletConfigurator) -> TableMetadata {
        let configured_tablets = configurator.generate(config.initial_tablet_count);
        let mut tablets = BTreeMap::new();
        for tablet_id in configured_tablets {
            tablets.insert(
                tablet_id,
                TabletMetadata {
                    tablet_id,
                    ..Default::default()
                },
            );
        }

        TableMetadata {
            config: config.clone(),
            tablets,
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

    fn find_tablets(&self, key_hash_from: u32, key_hash_to: u32) -> Vec<TabletMetadata> {
        let mut seen_tablet_ids = HashSet::new();
        let mut listed_tablets = Vec::new();

        let mut key_hash_intervals = Vec::new();

        if key_hash_from < key_hash_to {
            // The range doesn't wrap around zero, hence all tablets
            // can be found in one shot.
            key_hash_intervals.push((key_hash_from, key_hash_to));
        } else {
            // Range wraps around zero and therefore we split it into
            // two subranges.
            key_hash_intervals.push((key_hash_from, u32::MAX));
            key_hash_intervals.push((0, key_hash_to));
        }

        for (key_hash_from, key_hash_to) in key_hash_intervals {
            let mut found_last = false;
            // Starting from the first tablet id that equal or larger than range start
            for (tablet_id, tablet_metadata) in self.tablets.range(key_hash_from..) {
                // Check if we have seen that tablet id before due to wrap around.
                // and remember its metadata if needed.
                if seen_tablet_ids.insert(*tablet_id) {
                    listed_tablets.push(tablet_metadata.clone());
                }
                // If current tablet fully covers the end of the range
                if *tablet_id >= key_hash_to {
                    // Remember that and break.
                    found_last = true;
                    break;
                }
            }

            // It is possible that we haven't found the last tablet covering the
            // end of the range due to wrap around zero.
            if !found_last {
                if let Some((tablet_id, tablet_metadata)) = self.tablets.first_key_value() {
                    // If so, wee need to remember the very first tablet after zero
                    // wrap around.
                    if seen_tablet_ids.insert(*tablet_id) {
                        listed_tablets.push(tablet_metadata.clone());
                    }
                }
            }
        }

        listed_tablets
    }

    fn prepare_tablet_op(&self, table_name: String, tablet_op: &Op) -> TabletOpResult {
        let mut op_result = TabletOpResult {
            table_name,
            status: TabletOpStatus::Failed.into(),
            ..Default::default()
        };

        op_result.op_result = Some(match tablet_op {
            Op::ListTablet(list_tablet_op) => {
                // In order to execute list op we need to find all tablets that are
                // responsible for the given range. These tablets maybe outside of the
                // range and must be found by traversing the consistent hashing
                // ring clockwise, and possible wrap around zero.
                let listed_tablets =
                    self.find_tablets(list_tablet_op.key_hash_from, list_tablet_op.key_hash_to);

                op_result.status = TabletOpStatus::Succeeded.into();
                OpResult::ListTablet(ListTabletResult {
                    key_hash_from: list_tablet_op.key_hash_from,
                    key_hash_to: list_tablet_op.key_hash_to,
                    tablets: listed_tablets,
                })
            }
            Op::CheckTablet(check_tablet_op) => {
                let mut check_tablet_result = CheckTabletResult::default();
                if let Some(existing_tablet) = self.tablets.get(&check_tablet_op.tablet_id) {
                    if existing_tablet.tablet_version == check_tablet_op.tablet_version {
                        op_result.status = TabletOpStatus::Succeeded.into();
                    } else {
                        check_tablet_result.existing_tablet = Some(existing_tablet.clone());
                    }
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
            Op::AddTablet(_add_tablet_op) => todo!(),
            Op::RemoveTablet(_remove_tablet_op) => todo!(),
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
            Op::ListTablet(_list_tablet_op) => op_result.op_result.unwrap(),
            Op::CheckTablet(_check_tablet_op) => op_result.op_result.unwrap(),
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

pub trait TabletConfigurator {
    fn generate(&mut self, initial_tablet_count: u32) -> Vec<u32>;
}

pub struct RandomTabletConfigurator {}

impl TabletConfigurator for RandomTabletConfigurator {
    fn generate(&mut self, initial_tablet_count: u32) -> Vec<u32> {
        let tablet_count: usize = initial_tablet_count.try_into().unwrap();
        let mut tablet_ids = HashSet::with_capacity(tablet_count);
        while tablet_ids.len() < tablet_count {
            tablet_ids.insert(OsRng.next_u32());
        }
        tablet_ids.into_iter().collect()
    }
}

pub struct TabletStoreActor<C: TabletConfigurator> {
    configurator: C,
    context: Option<Box<dyn ActorContext>>,
    config: TabletStoreConfig,
    tables: HashMap<String, TableMetadata>,
}

impl<C: TabletConfigurator> TabletStoreActor<C> {
    pub fn new(configurator: C) -> Self {
        TabletStoreActor {
            configurator,
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
                table_name: tablet_op.table_name.clone(),
                status: TabletOpStatus::Invalid.into(),
                op_result: None,
            };
        }
        table_opt
            .unwrap()
            .prepare_tablet_op(tablet_op.table_name.clone(), tablet_op.op.as_ref().unwrap())
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

impl<C: TabletConfigurator> Actor for TabletStoreActor<C> {
    fn on_init(&mut self, context: Box<dyn ActorContext>) -> Result<(), ActorError> {
        self.context = Some(context);
        self.config = TabletStoreConfig::decode(self.get_context().config().as_ref())
            .map_err(|_| ActorError::ConfigLoading)?;

        for table_config in &self.config.table_configs {
            self.tables.insert(
                table_config.table_name.clone(),
                TableMetadata::create(table_config, &mut self.configurator),
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

    fn on_process_command(
        &mut self,
        command: Option<ActorCommand>,
    ) -> Result<CommandOutcome, ActorError> {
        if command.is_none() {
            return Ok(CommandOutcome::with_none());
        }
        let command = command.unwrap();

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
                        Ok(_tablets_request) => command.payload,
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

    fn get_reference_values(&self) -> ReferenceValues {
        let skip = BinaryReferenceValue {
            r#type: Some(binary_reference_value::Type::Skip(
                SkipVerification::default(),
            )),
        };
        ReferenceValues {
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
        }
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    extern crate mockall;

    use super::*;
    use alloc::vec;
    use mockall::{mock, predicate::*};
    use tcp_proto::runtime::endpoint::out_message;
    use tcp_runtime::logger::log::create_logger;
    use tcp_runtime::mock::MockActorContext;

    static TABLE_NAME: &str = "A";
    const TABLET_ID_1: u32 = 10;
    const TABLET_VERSION_1: u32 = 5;
    const TABLET_ID_2: u32 = 20;
    const TABLET_VERSION_2: u32 = 7;
    const INITIAL_TABLET_COUNT: u32 = 3;

    const CORRELATION_ID_1: u64 = 11;

    mock! {
        TabletConfigurator {
        }

        impl TabletConfigurator for TabletConfigurator {
            fn generate(&mut self, initial_tablet_count: u32) -> Vec<u32>;
        }
    }

    fn create_actor_config() -> TabletStoreConfig {
        TabletStoreConfig {
            table_configs: vec![TableConfig {
                table_name: "A".to_string(),
                max_tablet_size: 1024,
                min_tablet_size: 512,
                initial_tablet_count: INITIAL_TABLET_COUNT,
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

    fn create_list_tablet_op(table_name: String, key_hash_from: u32, key_hash_to: u32) -> TabletOp {
        TabletOp {
            table_name,
            op: Some(Op::ListTablet(ListTabletOp {
                key_hash_from,
                key_hash_to,
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

    fn create_check_tablet_result(
        table_name: String,
        status: TabletOpStatus,
        tablet_metadata: Option<TabletMetadata>,
    ) -> TabletOpResult {
        TabletOpResult {
            table_name,
            status: status.into(),
            op_result: Some(OpResult::CheckTablet(CheckTabletResult {
                existing_tablet: tablet_metadata,
            })),
        }
    }

    fn create_update_tablet_result(
        table_name: String,
        status: TabletOpStatus,
        tablet_metadata: TabletMetadata,
    ) -> TabletOpResult {
        TabletOpResult {
            table_name,
            status: status.into(),
            op_result: Some(OpResult::UpdateTablet(UpdateTabletResult {
                existing_tablet: Some(tablet_metadata),
            })),
        }
    }

    fn create_list_tablet_result(
        table_name: String,
        status: TabletOpStatus,
        key_hash_from: u32,
        key_hash_to: u32,
        tablets: Vec<TabletMetadata>,
    ) -> TabletOpResult {
        TabletOpResult {
            table_name,
            status: status.into(),
            op_result: Some(OpResult::ListTablet(ListTabletResult {
                key_hash_from,
                key_hash_to,
                tablets,
            })),
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

    fn create_actor(
        mut mock_context: MockActorContext,
    ) -> TabletStoreActor<MockTabletConfigurator> {
        let config = create_actor_config();
        mock_context.expect_logger().return_const(create_logger());
        mock_context.expect_id().return_const(0u64);
        mock_context
            .expect_config()
            .return_const::<Bytes>(config.encode_to_vec().into());

        let mut mock_tablet_configurator = MockTabletConfigurator::new();
        mock_tablet_configurator
            .expect_generate()
            .with(eq(INITIAL_TABLET_COUNT))
            .return_const(vec![1, 2, 3]);

        let mut actor = TabletStoreActor::new(mock_tablet_configurator);
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
            .on_process_command(Some(create_execute_tablet_ops_request(
                CORRELATION_ID_1,
                vec![create_list_tablet_op(
                    TABLE_NAME.to_string(),
                    TABLET_ID_1 - 1,
                    TABLET_ID_2 + 1,
                )],
            )))
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
                    TABLE_NAME.to_string(),
                    TabletOpStatus::Succeeded,
                    TABLET_ID_1 - 1,
                    TABLET_ID_2 + 1,
                    vec![
                        create_tablet_metadata(TABLET_ID_1, TABLET_VERSION_1),
                        create_tablet_metadata(TABLET_ID_2, TABLET_VERSION_2),
                    ]
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
            .on_process_command(Some(create_execute_tablet_ops_request(
                CORRELATION_ID_1,
                vec![create_check_tablet_op(
                    TABLE_NAME.to_string(),
                    TABLET_ID_1,
                    TABLET_VERSION_1,
                )],
            )))
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
                    TABLE_NAME.to_string(),
                    TabletOpStatus::Succeeded,
                    None
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
            .on_process_command(Some(create_execute_tablet_ops_request(
                CORRELATION_ID_1,
                vec![create_update_tablet_op(
                    TABLE_NAME.to_string(),
                    create_tablet_metadata(TABLET_ID_1, TABLET_VERSION_1 + 1),
                )],
            )))
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
                    TABLE_NAME.to_string(),
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
            .on_process_command(Some(create_execute_tablet_ops_request(
                CORRELATION_ID_1,
                vec![
                    create_check_tablet_op(TABLE_NAME.to_string(), TABLET_ID_1, TABLET_VERSION_1),
                    create_update_tablet_op(
                        TABLE_NAME.to_string(),
                        create_tablet_metadata(TABLET_ID_1, TABLET_VERSION_1 + 1),
                    ),
                ],
            )))
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
                    create_check_tablet_result(
                        TABLE_NAME.to_string(),
                        TabletOpStatus::Succeeded,
                        None
                    ),
                    create_update_tablet_result(
                        TABLE_NAME.to_string(),
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
            .on_process_command(Some(create_execute_tablet_ops_request(
                CORRELATION_ID_1,
                vec![
                    create_list_tablet_op(TABLE_NAME.to_string(), TABLET_ID_2 + 1, TABLET_ID_2 + 2),
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
            )))
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
                        TABLE_NAME.to_string(),
                        TabletOpStatus::Succeeded,
                        TABLET_ID_2 + 1,
                        TABLET_ID_2 + 2,
                        vec![create_tablet_metadata(TABLET_ID_1, TABLET_VERSION_1),]
                    ),
                    create_check_tablet_result(
                        TABLE_NAME.to_string(),
                        TabletOpStatus::Failed,
                        Some(create_tablet_metadata(TABLET_ID_1, TABLET_VERSION_1))
                    ),
                    create_update_tablet_result(
                        TABLE_NAME.to_string(),
                        TabletOpStatus::Failed,
                        create_tablet_metadata(TABLET_ID_1, TABLET_VERSION_1)
                    )
                ]
            )
        );
    }
}
