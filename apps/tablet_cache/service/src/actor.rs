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

use crate::{
    apps::tablet_cache::service::{
        tablet_cache_in_message::*, tablet_cache_out_message::OutMsg, TabletCacheConfig,
        TabletCacheInMessage, TabletCacheOutMessage, TransactionManagerConfig,
    },
    store, transaction,
};
use alloc::boxed::Box;
use oak_proto_rust::oak::attestation::v1::{
    binary_reference_value, kernel_binary_reference_value, reference_values, text_reference_value,
    ApplicationLayerReferenceValues, BinaryReferenceValue, InsecureReferenceValues,
    KernelBinaryReferenceValue, KernelLayerReferenceValues, OakRestrictedKernelReferenceValues,
    ReferenceValues, RootLayerReferenceValues, SkipVerification, TextReferenceValue,
};
use prost::{bytes::Bytes, Message};
use slog::{debug, o};
use tcp_runtime::model::{
    Actor, ActorCommand, ActorContext, ActorError, ActorEvent, ActorEventContext, CommandOutcome,
    EventOutcome,
};
use tcp_tablet_store_service::apps::tablet_store::service::TabletsResponse;

pub struct TabletCacheActor<
    T: transaction::TabletTransactionManager<Bytes>,
    S: store::KeyValueStore,
> {
    transaction_manager: T,
    key_value_store: S,
    context: Option<Box<dyn ActorContext>>,
}

impl<T: transaction::TabletTransactionManager<Bytes>, S: store::KeyValueStore>
    TabletCacheActor<T, S>
{
    pub fn new(transaction_manager: T, key_value_store: S) -> Self {
        TabletCacheActor {
            transaction_manager,
            key_value_store,
            context: None,
        }
    }

    fn get_context(&mut self) -> &mut dyn ActorContext {
        self.context
            .as_mut()
            .expect("Context is initialized")
            .as_mut()
    }

    fn command_with_proto<M: Message + Sized>(
        correlation_id: u64,
        out_header: OutMsg,
        out_payload: M,
    ) -> ActorCommand {
        Self::command_with_bytes(
            correlation_id,
            out_header,
            out_payload.encode_to_vec().into(),
        )
    }

    fn command_with_bytes(
        correlation_id: u64,
        out_header: OutMsg,
        out_payload: Bytes,
    ) -> ActorCommand {
        ActorCommand::with_header_and_payload(
            correlation_id,
            &TabletCacheOutMessage {
                out_msg: Some(out_header),
            },
            out_payload,
        )
    }
}

impl<T: transaction::TabletTransactionManager<Bytes>, S: store::KeyValueStore> Actor
    for TabletCacheActor<T, S>
{
    fn on_init(&mut self, context: Box<dyn ActorContext>) -> Result<(), ActorError> {
        self.context = Some(context);

        let config = TabletCacheConfig::decode(self.get_context().config().as_ref())
            .map_err(|_| ActorError::ConfigLoading)?;

        let key_value_store_logger = self.get_context().logger().new(o!("type" => "store"));
        self.key_value_store
            .init(key_value_store_logger, config.store_config.unwrap());

        let transaction_manager_logger = self.get_context().logger().new(o!("type" => "manager"));
        self.transaction_manager.init(
            transaction_manager_logger,
            config.transaction_manager_config.unwrap(),
        );

        debug!(self.get_context().logger(), "Initialized");

        Ok(())
    }

    fn on_shutdown(&mut self) {}

    fn on_save_snapshot(&mut self) -> Result<Bytes, ActorError> {
        Ok(Bytes::new())
    }

    fn on_load_snapshot(&mut self, _snapshot: Bytes) -> Result<(), ActorError> {
        Ok(())
    }

    fn on_process_command(
        &mut self,
        command: Option<ActorCommand>,
    ) -> Result<CommandOutcome, ActorError> {
        if let Some(command) = command {
            let in_header = match TabletCacheInMessage::decode(command.header.clone()) {
                Ok(in_message) => in_message.in_msg,
                Err(_) => {
                    return Err(ActorError::Internal);
                }
            };

            match in_header {
                Some(oneof) => match oneof {
                    InMsg::PutKeyRequest(request) => {
                        self.key_value_store
                            .process_request(store::KeyValueRequest::Put(
                                command.correlation_id,
                                request,
                            ))
                    }
                    InMsg::GetKeyRequest(request) => {
                        self.key_value_store
                            .process_request(store::KeyValueRequest::Get(
                                command.correlation_id,
                                request,
                            ))
                    }
                    InMsg::LoadTabletResponse(response) => self
                        .transaction_manager
                        .process_in_message(transaction::InMessage::LoadTabletResponse(
                            command.correlation_id,
                            response,
                            command.payload,
                        )),
                    InMsg::StoreTabletResponse(response) => self
                        .transaction_manager
                        .process_in_message(transaction::InMessage::StoreTabletResponse(
                            command.correlation_id,
                            response,
                        )),
                    InMsg::ExecuteTabletOpsResponse(response) => {
                        let tablets_response = TabletsResponse::decode(command.payload).unwrap();
                        self.transaction_manager.process_in_message(
                            transaction::InMessage::ExecuteTabletOpsResponse(
                                command.correlation_id,
                                response,
                                tablets_response,
                            ),
                        )
                    }
                    InMsg::ExecuteTabletOpsError(error) => self
                        .transaction_manager
                        .process_in_message(transaction::InMessage::ExecuteTabletOpsError(
                            command.correlation_id,
                            error,
                        )),
                },
                None => {
                    return Err(ActorError::Internal);
                }
            };
        }

        let instant = self.get_context().instant();
        self.key_value_store
            .make_progress(instant, &mut self.transaction_manager);

        let transaction_out_commands = self
            .transaction_manager
            .take_out_messages()
            .into_iter()
            .map(|m| match m {
                transaction::OutMessage::LoadTabletRequest(correlation_id, load_tablet_request) => {
                    Self::command_with_bytes(
                        correlation_id,
                        OutMsg::LoadTabletRequest(load_tablet_request),
                        Bytes::new(),
                    )
                }
                transaction::OutMessage::StoreTabletRequest(
                    correlation_id,
                    store_tablet_request,
                    payload,
                ) => Self::command_with_bytes(
                    correlation_id,
                    OutMsg::StoreTabletRequest(store_tablet_request),
                    payload,
                ),
                transaction::OutMessage::ExecuteTabletOpsRequest(
                    correlation_id,
                    execute_tablet_ops_tequest,
                    tablets_request,
                ) => Self::command_with_proto(
                    correlation_id,
                    OutMsg::ExecuteTabletOpsRequest(execute_tablet_ops_tequest),
                    tablets_request,
                ),
            });

        let store_out_commands =
            self.key_value_store
                .take_responses()
                .into_iter()
                .map(|r| match r {
                    store::KeyValueResponse::Put(correlation_id, put_response) => {
                        Self::command_with_proto(
                            correlation_id,
                            OutMsg::PutKeyResponse(put_response),
                            Bytes::new(),
                        )
                    }
                    store::KeyValueResponse::Get(correlation_id, get_response) => {
                        Self::command_with_proto(
                            correlation_id,
                            OutMsg::GetKeyResponse(get_response),
                            Bytes::new(),
                        )
                    }
                });

        let out_commands = transaction_out_commands.chain(store_out_commands).collect();

        Ok(CommandOutcome::with_commands(out_commands))
    }

    fn on_apply_event(
        &mut self,
        _context: ActorEventContext,
        _event: ActorEvent,
    ) -> Result<EventOutcome, ActorError> {
        Ok(EventOutcome::with_none())
    }

    fn get_reference_values(&self) -> oak_proto_rust::oak::attestation::v1::ReferenceValues {
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
