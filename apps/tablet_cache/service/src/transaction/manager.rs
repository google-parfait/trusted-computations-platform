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

use core::cell::RefCell;

use alloc::{boxed::Box, rc::Rc, vec::Vec};
use tcp_tablet_store_service::apps::tablet_store::service::{
    tablet_op_result::OpResult, TabletsRequest,
};

use crate::apps::tablet_cache::service::ExecuteTabletOpsRequest;

use super::{
    coordinator::{
        DefaultTabletTransactionCoordinator, TabletTransactionCoordinator,
        TabletTransactionCoordinatorInMessage, TabletTransactionCoordinatorOutMessage,
    },
    data::{
        DefaultTabletDataCache, TabletDataCache, TabletDataCacheInMessage,
        TabletDataCacheOutMessage,
    },
    metadata::{
        DefaultTabletMetadataCache, TabletMetadataCache, TabletMetadataCacheInMessage,
        TabletMetadataCacheOutMessage,
    },
    InMessage, OutMessage, ProcessHandler, ResolveHandler, TableQuery, TabletTransaction,
    TabletTransactionCommit, TabletTransactionContext, TabletTransactionManager,
    TabletTransactionOutcome,
};

pub struct DefaultTabletTransactionManager<T> {
    core: Rc<RefCell<TabletTransactionManagerCore<T>>>,
}

impl<T> DefaultTabletTransactionManager<T> {
    pub fn create(
        transaction_coordinator: Box<dyn TabletTransactionCoordinator<T>>,
        metadata_cache: Box<dyn TabletMetadataCache>,
        data_cache: Box<dyn TabletDataCache<T>>,
    ) -> Self {
        Self {
            core: Rc::new(RefCell::new(TabletTransactionManagerCore::<T>::create(
                transaction_coordinator,
                metadata_cache,
                data_cache,
            ))),
        }
    }
}

impl<T: 'static> TabletTransactionManager<T> for DefaultTabletTransactionManager<T> {
    fn init(&mut self, _capacity: u64) {
        todo!()
    }

    fn make_progress(&mut self, instant: u64) {
        self.core.borrow_mut().make_progress(instant)
    }

    fn process_in_message(&mut self, message: InMessage) {
        self.core.borrow_mut().process_in_message(message)
    }

    fn take_out_messages(&mut self) -> Vec<OutMessage> {
        self.core.borrow_mut().take_out_messages()
    }
}

impl<T: 'static> TabletTransactionContext<T> for DefaultTabletTransactionManager<T> {
    fn resolve(&mut self, _queries: Vec<TableQuery>, _handler: Box<ResolveHandler>) {
        todo!()
    }

    fn start_transaction(&mut self) -> Box<dyn TabletTransaction<T>> {
        Box::new(DefaultTabletTransaction::create(
            self.core.borrow_mut().create_transaction(),
            self.core.clone(),
        ))
    }
}

struct DefaultTabletTransaction<T> {
    transaction_id: u64,
    transaction_outcome: Option<TabletTransactionOutcome>,
    core: Rc<RefCell<TabletTransactionManagerCore<T>>>,
}

impl<T> DefaultTabletTransaction<T> {
    fn create(transaction_id: u64, core: Rc<RefCell<TabletTransactionManagerCore<T>>>) -> Self {
        Self {
            transaction_id,
            transaction_outcome: None,
            core,
        }
    }
}

impl<T: 'static> TabletTransaction<T> for DefaultTabletTransaction<T> {
    fn get_id(&self) -> u64 {
        self.transaction_id
    }

    fn process(&mut self, queries: Vec<TableQuery>, handler: Box<ProcessHandler<T>>) {
        self.core
            .borrow_mut()
            .process_transaction(self.transaction_id, queries, handler)
    }

    fn has_pending_process(&self) -> bool {
        self.core
            .borrow()
            .has_transaction_pending_process(self.transaction_id)
    }

    fn commit(self: Box<Self>) -> Box<dyn TabletTransactionCommit> {
        self.core
            .borrow_mut()
            .commit_transaction(self.transaction_id);
        self
    }

    fn abort(self: Box<Self>) {
        self.core
            .borrow_mut()
            .abort_transaction(self.transaction_id)
    }
}

impl<T> TabletTransactionCommit for DefaultTabletTransaction<T> {
    fn check_result(&mut self) -> Option<TabletTransactionOutcome> {
        if self.transaction_outcome.is_none() {
            self.transaction_outcome = self
                .core
                .borrow_mut()
                .check_transaction_result(self.transaction_id);
        }
        self.transaction_outcome
    }
}

// Manages tablet transaction execution. Coordinates metadata and data
// loading and updating.
struct TabletTransactionManagerCore<T> {
    transaction_coordinator: Box<dyn TabletTransactionCoordinator<T>>,
    metadata_cache: Box<dyn TabletMetadataCache>,
    data_cache: Box<dyn TabletDataCache<T>>,
}

// Delegates processing to metadata cache, data cache and transaction coordinator.
impl<T> TabletTransactionManagerCore<T> {
    fn create(
        transaction_coordinator: Box<dyn TabletTransactionCoordinator<T>>,
        metadata_cache: Box<dyn TabletMetadataCache>,
        data_cache: Box<dyn TabletDataCache<T>>,
    ) -> Self {
        Self {
            transaction_coordinator,
            metadata_cache,
            data_cache,
        }
    }

    fn make_progress(&mut self, instant: u64) {
        self.metadata_cache.make_progress(instant);
        self.data_cache.make_progress(instant);
        self.transaction_coordinator.make_progress(
            instant,
            &mut *self.metadata_cache,
            &mut *self.data_cache,
        );
    }

    fn process_transaction(
        &mut self,
        transaction_id: u64,
        queries: Vec<TableQuery>,
        handler: Box<ProcessHandler<T>>,
    ) {
        self.transaction_coordinator
            .process_transaction(transaction_id, queries, handler)
    }

    fn create_transaction(&mut self) -> u64 {
        self.transaction_coordinator.create_transaction()
    }

    fn has_transaction_pending_process(&self, transaction_id: u64) -> bool {
        self.transaction_coordinator
            .has_transaction_pending_process(transaction_id)
    }

    fn commit_transaction(&mut self, transaction_id: u64) {
        self.transaction_coordinator
            .commit_transaction(transaction_id)
    }

    fn abort_transaction(&mut self, transaction_id: u64) {
        self.transaction_coordinator
            .abort_transaction(transaction_id)
    }

    fn check_transaction_result(
        &mut self,
        transaction_id: u64,
    ) -> Option<TabletTransactionOutcome> {
        self.transaction_coordinator
            .check_transaction_result(transaction_id)
    }

    fn process_in_message(&mut self, message: InMessage) {
        match message {
            InMessage::LoadTabletResponse(correlation_id, load_tablet_response, tablet_data) => {
                self.data_cache
                    .process_in_message(TabletDataCacheInMessage::LoadResponse(
                        correlation_id,
                        load_tablet_response,
                        tablet_data,
                    ))
            }
            InMessage::StoreTabletResponse(correletion_id, store_tablet_respose) => self
                .data_cache
                .process_in_message(TabletDataCacheInMessage::StoreResponse(
                    correletion_id,
                    store_tablet_respose,
                )),
            InMessage::ExecuteTabletOpsResponse(
                correlation_id,
                _execute_ops_response,
                tablets_response,
            ) => {
                let mut list_op_results = Vec::new();
                let mut execute_op_results = Vec::new();

                for tablet_op_result in tablets_response.tablet_results {
                    if let Some(op_result) = &tablet_op_result.op_result {
                        if let OpResult::ListTablet(_) = op_result {
                            list_op_results.push(tablet_op_result);
                        } else {
                            execute_op_results.push(tablet_op_result);
                        }
                    }
                }

                if !list_op_results.is_empty() {
                    self.metadata_cache.process_in_message(
                        TabletMetadataCacheInMessage::ListResponse(correlation_id, list_op_results),
                    );
                }

                if !execute_op_results.is_empty() {
                    self.transaction_coordinator.process_in_message(
                        TabletTransactionCoordinatorInMessage::ExecuteTabletOpsResponse(
                            correlation_id,
                            execute_op_results,
                        ),
                    );
                }
            }
        }
    }

    fn take_out_messages(&mut self) -> Vec<OutMessage> {
        let mut out_messages = Vec::new();

        for transaction_out_message in self.transaction_coordinator.take_out_messages() {
            out_messages.push(match transaction_out_message {
                TabletTransactionCoordinatorOutMessage::ExecuteTabletOpsRequest(
                    correlation_id,
                    execute_ops,
                ) => OutMessage::ExecuteTabletOpsRequest(
                    correlation_id,
                    ExecuteTabletOpsRequest::default(),
                    TabletsRequest {
                        tablet_ops: execute_ops,
                    },
                ),
            });
        }

        for metadata_out_message in self.metadata_cache.take_out_messages() {
            out_messages.push(match metadata_out_message {
                TabletMetadataCacheOutMessage::ListRequest(correlation_id, list_ops) => {
                    OutMessage::ExecuteTabletOpsRequest(
                        correlation_id,
                        ExecuteTabletOpsRequest::default(),
                        TabletsRequest {
                            tablet_ops: list_ops,
                        },
                    )
                }
            });
        }

        for data_out_message in self.data_cache.take_out_messages() {
            out_messages.push(match data_out_message {
                TabletDataCacheOutMessage::LoadRequest(correlation_id, load_tablet_request) => {
                    OutMessage::LoadTabletRequest(correlation_id, load_tablet_request)
                }
                TabletDataCacheOutMessage::StoreRequest(
                    correlation_id,
                    store_tablet_request,
                    tablet_data,
                ) => OutMessage::StoreTabletRequest(
                    correlation_id,
                    store_tablet_request,
                    tablet_data,
                ),
            });
        }

        out_messages
    }
}
