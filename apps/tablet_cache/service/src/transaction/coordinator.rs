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

use core::mem;

use alloc::{boxed::Box, vec::Vec};
use hashbrown::HashMap;
use prost::bytes::Bytes;
use tcp_tablet_store_service::apps::tablet_store::service::{
    tablet_op, tablet_op_result, CheckTabletOp, TabletMetadata, TabletOp, TabletOpResult,
    TabletOpStatus, TabletsRequestStatus, UpdateTabletOp,
};

use crate::apps::tablet_cache::service::TabletDataStorageStatus;

use super::{
    data::{TabletData, TabletDataCache},
    metadata::TabletMetadataCache,
    result::ResultHandle,
    ProcessHandler, TableQuery, Tablet, TabletTransactionOutcome,
};

// Transaction coordinator incoming messages.
#[derive(PartialEq, Debug, Clone)]
pub enum TabletTransactionCoordinatorInMessage {
    // Response from Tablet Store to execute tablet ops as a single transaction.
    ExecuteTabletOpsResponse(u64, Vec<TabletOpResult>),
}

// Transaction coordinator outgoing messages.
#[derive(PartialEq, Debug, Clone)]
pub enum TabletTransactionCoordinatorOutMessage {
    // Request to Tablet Store to execute tablet ops as a single transaction.
    ExecuteTabletOpsRequest(u64, Vec<TabletOp>),
}

// Coordinates transaction execution. Depends on Tablet Metadata Cache to resolve
// metadata of the affected by transaction tablets, on Tablet Data Cache to
// load existing and store processed version of the tablet data in the Tablet
// Data Storage.
//
// Type parameter T represents a union type for the tablet data representation. For example
// it can be a protobuf message with a oneof representing specific tables.
pub trait TabletTransactionCoordinator<T> {
    // Advances internal state machine of the Tablet Transaction Coordinator.
    fn make_progress(
        &mut self,
        instant: u64,
        metadata_cache: &mut dyn TabletMetadataCache,
        data_cache: &mut dyn TabletDataCache<T>,
    );

    // Processes incoming messages. Incoming message may contain tablets ops execution responses
    // coming from Tablet Store.
    fn process_in_message(
        &mut self,
        metadata_cache: &mut dyn TabletMetadataCache,
        in_message: TabletTransactionCoordinatorInMessage,
    );

    // Take outgoing messages. Outoing message may contain tablets ops execution requests that
    // must be sent to Tablet Store.
    fn take_out_messages(&mut self) -> Vec<TabletTransactionCoordinatorOutMessage>;

    // Creates new transaction state and returns its id.
    fn create_transaction(&mut self) -> u64;

    // Requests to process given queries with the given handler within the context of the
    // transaction with given id. The handler will be called only when all affected by the
    // queries tablets are loaded.
    fn process_transaction(
        &mut self,
        transaction_id: u64,
        queries: Vec<TableQuery>,
        handler: Box<ProcessHandler<T>>,
    );

    // Checks if transaction with given id has any pending processing.
    fn has_transaction_pending_process(&self, transaction_id: u64) -> bool;

    // Requests to commit transaction with given id.
    fn commit_transaction(&mut self, transaction_id: u64);

    // Requests to abort transaction with given id.
    fn abort_transaction(&mut self, transaction_id: u64);

    // Checks the outcome of a transaction with given id. Returns none if
    // the outcome is still unknown.
    fn check_transaction_result(&mut self, transaction_id: u64)
        -> Option<TabletTransactionOutcome>;
}

pub struct DefaultTabletTransactionCoordinator<T> {
    // Counter that is used to produce unique correlation id for outgoing
    // messages.
    correlation_counter: u64,
    // Counter that is used to produce unique transaction id.
    transaction_counter: u64,
    // Maps transaction id to its current state.
    transactions: HashMap<u64, TabletTransactionState<T>>,
    // Maps correlation id that has been used to create Tablet Store request
    // and corresponding transction id.
    correlations: HashMap<u64, u64>,
    // Stash of outgoing messages waiting to be sent out.
    out_messages: Vec<TabletTransactionCoordinatorOutMessage>,
}

impl<T> DefaultTabletTransactionCoordinator<T> {
    pub fn create(correlation_counter: u64) -> Self {
        Self {
            correlation_counter,
            transaction_counter: 1,
            transactions: HashMap::new(),
            correlations: HashMap::new(),
            out_messages: Vec::new(),
        }
    }

    fn transaction_stash_request(&mut self, transaction_id: u64, tablet_ops: Vec<TabletOp>) {
        self.correlation_counter += 1;

        self.out_messages.push(
            TabletTransactionCoordinatorOutMessage::ExecuteTabletOpsRequest(
                self.correlation_counter,
                tablet_ops,
            ),
        );
        // Map execute tablet ops request to the transaction id, so that response can later
        // be correlated.
        self.correlations
            .insert(self.correlation_counter, transaction_id);
    }
}

impl<T> TabletTransactionCoordinator<T> for DefaultTabletTransactionCoordinator<T> {
    fn make_progress(
        &mut self,
        instant: u64,
        metadata_cache: &mut dyn TabletMetadataCache,
        data_cache: &mut dyn TabletDataCache<T>,
    ) {
        for transaction in self.transactions.values_mut() {
            match transaction {
                // Make progress on each pending transaction.
                TabletTransactionState::Preparing(transaction_state) => {
                    transaction_state.make_progress(instant, metadata_cache, data_cache);
                }
                // Do nothing for committing or completed transaction.
                _ => {}
            }
        }
    }

    fn process_in_message(
        &mut self,
        metadata_cache: &mut dyn TabletMetadataCache,
        in_message: TabletTransactionCoordinatorInMessage,
    ) {
        match in_message {
            TabletTransactionCoordinatorInMessage::ExecuteTabletOpsResponse(
                correlation_id,
                tablet_op_results,
            ) => {
                if let Some(transaction_id) = self.correlations.remove(&correlation_id) {
                    // Transaction may be aborted before execute ops response is received therefore
                    // we need to check that transaction is still waiting trying to commit.
                    if let Some(transaction) = self.transactions.get_mut(&transaction_id) {
                        if let TabletTransactionState::Committing(transaction_state) = transaction {
                            let (transaction_outcome, metadata_to_update_cache) =
                                transaction_state.complete(tablet_op_results);
                            *transaction = TabletTransactionState::Completed(transaction_outcome);

                            for (tablet_metadata, conflict) in metadata_to_update_cache {
                                metadata_cache.update_tablet(tablet_metadata, conflict);
                            }
                        }
                    }
                }
            }
        }
    }

    fn take_out_messages(&mut self) -> Vec<TabletTransactionCoordinatorOutMessage> {
        mem::take(&mut self.out_messages)
    }

    fn create_transaction(&mut self) -> u64 {
        self.transaction_counter += 1;
        let transaction_id = self.transaction_counter;

        // Transactions start in preparing state where all local processing will happen.
        self.transactions.insert(
            transaction_id,
            TabletTransactionState::Preparing(PreparingTabletTransactionState::create(
                transaction_id,
            )),
        );

        // Generated unique transaction id is subsequently used for all interactions with
        // transaction coordinator.
        transaction_id
    }

    fn process_transaction(
        &mut self,
        transaction_id: u64,
        queries: Vec<TableQuery>,
        handler: Box<ProcessHandler<T>>,
    ) {
        // Transaction interface ensures that this method can only be called when
        // transaction is present.
        let transaction = self.transactions.get_mut(&transaction_id).unwrap();
        match transaction {
            TabletTransactionState::Preparing(transaction_state) => {
                // Initiate a new tablet processing, which starts in pending state.
                transaction_state.init_pending(queries, handler);
            }
            _ => panic!("Cannot alter transaction after commit has been initiated"),
        }
    }

    fn has_transaction_pending_process(&self, transaction_id: u64) -> bool {
        // Transaction interface ensures that this method can only be called when
        // transaction is present.
        let transaction = self.transactions.get(&transaction_id).unwrap();
        match transaction {
            TabletTransactionState::Preparing(transaction_state) => {
                // Process goes through resolution, loading, handler invocation, storing. Only after
                // all these stages have been completed or an error have been encountered it will
                // stop being considered pending.
                transaction_state.is_active()
            }
            _ => false,
        }
    }

    fn commit_transaction(&mut self, transaction_id: u64) {
        // Transaction interface ensures that this method can only be called when
        // transaction is present.
        let transaction = self.transactions.get(&transaction_id).unwrap();
        // Generate new transaction state which can be committing or failed.
        let updated_transaction = match transaction {
            TabletTransactionState::Preparing(transaction_state) => {
                // Transaction cannot be committed until all processing has completed.
                assert!(
                    !transaction_state.is_active(),
                    "Cannot commit transaction with pending processing"
                );
                // Completion in preparing state goes over results of each process call.
                match transaction_state.complete() {
                    // Try to commit transaction if all processing succeeded.
                    PreparingTabletTransactionOutcome::Succeeded(tablet_ops) => {
                        // Stash outgoing message to commit transaction to the Tablet Store.
                        self.transaction_stash_request(transaction_id, tablet_ops.clone());
                        // Wait for the outcome.
                        TabletTransactionState::Committing(
                            CommittingTabletTransactionState::create(tablet_ops),
                        )
                    }
                    // Fail transaction if any of the processing failed.
                    PreparingTabletTransactionOutcome::Failed => {
                        TabletTransactionState::Completed(TabletTransactionOutcome::Failed)
                    }
                }
            }
            _ => panic!("Cannot commit transaction after commit has been initiated"),
        };
        // Switch transaction to the next state.
        self.transactions
            .insert(transaction_id, updated_transaction);
    }

    fn abort_transaction(&mut self, transaction_id: u64) {
        // Remove transaction and let Tablet Metadata Cache and Tablet Data Caches
        // clean themselve eventually up.
        self.transactions.remove(&transaction_id);
    }

    fn check_transaction_result(
        &mut self,
        transaction_id: u64,
    ) -> Option<TabletTransactionOutcome> {
        // Transaction interface ensures that this method can only be called when
        // transaction is present.
        let transaction = self.transactions.get(&transaction_id).unwrap();
        let transaction_outcome = match transaction {
            TabletTransactionState::Preparing(_) => {
                panic!("Cannot check result while transaction is preparing")
            }
            TabletTransactionState::Committing(_) => None,
            TabletTransactionState::Completed(transaction_outcome) => {
                Some(transaction_outcome.clone())
            }
        };

        // Clean up transaction state once the outcome is determined.
        if transaction_outcome.is_some() {
            self.transactions.remove(&transaction_id);
        }

        // Outcome will be stored in the transaction commit object and owned
        // by the transaction creator.
        transaction_outcome
    }
}

// Tracks current state of a single tablet transaction.
enum TabletTransactionState<T> {
    // Transaction prepares by resolving, loading, processing and storing
    // processed tablets, generates respective tablet ops to update metadata.
    Preparing(PreparingTabletTransactionState<T>),
    // Transaction attempts to commit prepared tablet ops.
    Committing(CommittingTabletTransactionState),
    // Transaction has been completed either with a successful commit,
    // failure to commit or local processing failure.
    Completed(TabletTransactionOutcome),
}

// Outcomes of the transaction preparing phase.
#[derive(PartialEq, Debug, Clone)]
enum PreparingTabletTransactionOutcome {
    // Preparing or in other words local processing has succeeded and
    // this list of tablet ops represents required Tablet Store changes.
    Succeeded(Vec<TabletOp>),
    // Preparing has failed.
    Failed,
}

struct PreparingTabletTransactionState<T> {
    // Identifies transaction this state describes.
    transaction_id: u64,
    // Holds state of all pending requests to process tablets as part of this transaction.
    process_requests: Vec<TabletProcessState<T>>,
}

impl<T> PreparingTabletTransactionState<T> {
    fn create(transaction_id: u64) -> Self {
        Self {
            transaction_id,
            process_requests: Vec::new(),
        }
    }

    fn make_progress(
        &mut self,
        _instant: u64,
        metadata_cache: &mut dyn TabletMetadataCache,
        data_cache: &mut dyn TabletDataCache<T>,
    ) {
        // Advance state of each process.
        for process_state in &mut self.process_requests {
            // Attempt to advance process to the next state.
            let status = match &mut process_state.status {
                TabletProcessStatus::Pending(process_queries) => {
                    // Initiate affected tablets resolution and switch to resolve result resolving state
                    // waiting for completion.
                    let resolve_result = metadata_cache.resolve_tablets(process_queries);
                    Some(TabletProcessStatus::Resolving(resolve_result))
                }
                TabletProcessStatus::Resolving(resolve_result) => {
                    if let Some(resolve_outcome) = resolve_result.check_result() {
                        // Resolve has completed, move to loading or failed state depending on the
                        // resolve outcome.
                        match resolve_outcome {
                            Ok(resolve_values) => {
                                let mut resolved_metadata =
                                    Vec::with_capacity(resolve_values.len());

                                for (query, metadata) in resolve_values {
                                    // Start tracking state of the affected tablet.
                                    process_state.tablets.insert(
                                        create_tablet_key(&metadata),
                                        TabletState::create(query, metadata.clone()),
                                    );
                                    resolved_metadata.push(metadata);
                                }
                                // Initiate affected tablets loading through Tablet Data Cache and switch to
                                // loading state waiting for completion.
                                let load_result = data_cache.load_tablets(&resolved_metadata);
                                Some(TabletProcessStatus::Loading(load_result))
                            }
                            Err(_) => {
                                // Resolving failed, switch to failed state.
                                Some(TabletProcessStatus::Failed)
                            }
                        }
                    } else {
                        // Resolving hasn't completed, stay in resolving state.
                        None
                    }
                }
                TabletProcessStatus::Loading(load_result) => {
                    if let Some(load_outcome) = load_result.check_result() {
                        // Load has completed, move to storing or failed state depending on the
                        // load outcome.
                        match load_outcome {
                            Ok(load_values) => {
                                let mut tablet_refs = Vec::with_capacity(load_values.len());

                                for (metadata, data) in load_values {
                                    // Set loaded tablet data in corresponding tablet state that we look up
                                    // using metadata.
                                    let tablet_state = process_state
                                        .tablets
                                        .get_mut(&create_tablet_key(&metadata))
                                        .unwrap();
                                    tablet_state.tablet_init(data);
                                }

                                // Create collection of  mutable references that process handler will consume.
                                for tablet_state in process_state.tablets.values_mut() {
                                    tablet_refs.push(tablet_state.tablet_mut());
                                }

                                // Invoke tablet process handler.
                                (process_state.handler)(self.transaction_id, tablet_refs);

                                let mut tablet_writes = Vec::new();

                                // Collect which tablets needs to be stored in Tablet Data Storage.
                                for tablet_state in process_state.tablets.values_mut() {
                                    if let Some(tablet_write) = tablet_state.tablet_prepare() {
                                        tablet_writes.push(tablet_write);
                                    }
                                }

                                // Initiate store for the updated tablets through Tablet Data Cache and switch to storing
                                // state waiting for completion.
                                let store_result = data_cache.store_tablets(tablet_writes);
                                Some(TabletProcessStatus::Storing(store_result))
                            }
                            Err(_) => {
                                // Loading failed, switch to failed state.
                                Some(TabletProcessStatus::Failed)
                            }
                        }
                    } else {
                        // Loading hasn't completed, stay in loading state.
                        None
                    }
                }
                TabletProcessStatus::Storing(store_result) => {
                    if let Some(store_outcome) = store_result.check_result() {
                        // Storing has completed, move to completed or failed state depending on the outcome.
                        match store_outcome {
                            Ok(_) => Some(TabletProcessStatus::Completed),
                            Err(_) => Some(TabletProcessStatus::Failed),
                        }
                    } else {
                        // Storing hasn't completed, stay in storing state.
                        None
                    }
                }
                TabletProcessStatus::Completed => None,
                TabletProcessStatus::Failed => None,
            };

            // Perform the actual switch to the next state if needed.
            if status.is_some() {
                process_state.status = status.unwrap();
            }
        }
    }

    fn init_pending(&mut self, queries: Vec<TableQuery>, handler: Box<ProcessHandler<T>>) {
        self.process_requests.push(TabletProcessState {
            status: TabletProcessStatus::Pending(queries),
            handler,
            tablets: HashMap::new(),
        });
    }

    fn is_active(&self) -> bool {
        for process_state in &self.process_requests {
            let TabletProcessStatus::Completed = process_state.status else {
                return true;
            };
        }
        false
    }

    fn complete(&self) -> PreparingTabletTransactionOutcome {
        let mut tablet_ops = Vec::new();

        for process_state in &self.process_requests {
            if let TabletProcessStatus::Failed = process_state.status {
                // Fail transaction preparation if any of the processes failed.
                return PreparingTabletTransactionOutcome::Failed;
            }

            for tablet_state in process_state.tablets.values() {
                // For each of the affected tablets generate corresponding tablet op.
                tablet_ops.push(tablet_state.get_tablet_op());
            }
        }

        // Succeed transaction preparation with corresponding Tablet Store ops collected.
        PreparingTabletTransactionOutcome::Succeeded(tablet_ops)
    }
}

#[derive(Default, Debug, Clone)]
struct CommittingTabletTransactionState {
    tablet_ops: Vec<TabletOp>,
}

impl CommittingTabletTransactionState {
    fn create(tablet_ops: Vec<TabletOp>) -> Self {
        Self { tablet_ops }
    }

    fn complete(
        &self,
        tablet_op_results: Vec<TabletOpResult>,
    ) -> (TabletTransactionOutcome, Vec<(TabletMetadata, bool)>) {
        // Technically we need to check that tablet ops correspond to tablet results
        // but for the time being we are doing a simple check of that all tablet ops
        // succeeded.
        let mut metadata_to_update_cache = Vec::new();
        let mut transaction_outcome = TabletTransactionOutcome::Succeeded;
        for (tablet_op, tablet_op_result) in self.tablet_ops.iter().zip(tablet_op_results.iter()) {
            let op_succeeded = tablet_op_result.status == TabletOpStatus::Succeeded as i32;
            if !op_succeeded {
                transaction_outcome = TabletTransactionOutcome::Failed;
            }
            match (&tablet_op.op, &tablet_op_result.op_result) {
                (
                    Some(tablet_op::Op::CheckTablet(check_tablet_op)),
                    Some(tablet_op_result::OpResult::CheckTablet(check_tablet_op_result)),
                ) => {
                    if !op_succeeded {
                        metadata_to_update_cache.push((
                            check_tablet_op_result
                                .existing_tablet
                                .as_ref()
                                .unwrap()
                                .clone(),
                            true,
                        ));
                    }
                }
                (
                    Some(tablet_op::Op::UpdateTablet(update_tablet_op)),
                    Some(tablet_op_result::OpResult::UpdateTablet(update_tablet_op_result)),
                ) => {
                    if !op_succeeded {
                        metadata_to_update_cache.push((
                            update_tablet_op_result
                                .existing_tablet
                                .as_ref()
                                .unwrap()
                                .clone(),
                            true,
                        ));
                    } else {
                        metadata_to_update_cache.push((
                            update_tablet_op.tablet_metadata.as_ref().unwrap().clone(),
                            false,
                        ));
                    }
                }
                _ => {
                    panic!("Unexpected tablet op and result combination");
                }
            }
        }
        (transaction_outcome, metadata_to_update_cache)
    }
}

// Creates tablet key that consists of tablet id and its version.
fn create_tablet_key(metadata: &TabletMetadata) -> u64 {
    (metadata.tablet_id as u64) << 32 | (metadata.tablet_version as u64)
}

// Tracks state of a tablet affected by a transaction.
#[derive(Clone)]
struct TabletState<T> {
    // Query that affected the tablet.
    query: TableQuery,
    // Tablet metadata and data, along with tracking if this tablet was updated.
    tablet: Tablet<T>,
}

impl<T> TabletState<T> {
    fn create(query: TableQuery, metadata: TabletMetadata) -> Self {
        Self {
            query,
            tablet: Tablet::<T>::create(metadata),
        }
    }

    // Gets mutable reference to the tablet and query so that it can be passed to the
    // process handler.
    fn tablet_mut(&mut self) -> (TableQuery, &mut Tablet<T>) {
        (self.query.clone(), &mut self.tablet)
    }

    // Inits tablet state with data loaded from Tablet Data Cache.
    fn tablet_init(&mut self, data: TabletData<T>) {
        // Note that we only assign loaded data to avoid marking it as dirty.
        self.tablet.contents = Some(data);
    }

    // Prepares tablet op to be executed and optionally returns updated metadata along
    // with the data to be written to the Tablet Data Storage.
    fn tablet_prepare(&mut self) -> Option<(&mut TabletMetadata, T)> {
        if let Some(updated_contents) = self.tablet.take_updated_contents() {
            Some((self.tablet.get_metadata_mut(), updated_contents))
        } else {
            None
        }
    }

    // Gets tablet op that must be executed as part of the transaction.
    fn get_tablet_op(&self) -> TabletOp {
        let tablet_metadata = self.tablet.get_metadata().clone();
        let op = if self.tablet.is_dirty() {
            // Tablet has been written, therefore the metadata has already been
            // updated to the new version.
            tablet_op::Op::UpdateTablet(UpdateTabletOp {
                tablet_metadata: Some(tablet_metadata),
            })
        } else {
            // Tablet has been read, generate op that ensures that the tablet
            // hasn't changed since.
            tablet_op::Op::CheckTablet(CheckTabletOp {
                tablet_id: tablet_metadata.tablet_id,
                tablet_version: tablet_metadata.tablet_version,
            })
        };
        TabletOp {
            table_name: self.query.get_table_name().clone(),
            op: Some(op),
        }
    }
}

struct TabletProcessState<T> {
    status: TabletProcessStatus<T>,
    // Handler that will be called to process tablets.
    handler: Box<ProcessHandler<T>>,
    // Maps tablet key that of tablet id and its version to the tablet state.
    tablets: HashMap<u64, TabletState<T>>,
}

enum TabletProcessStatus<T> {
    Pending(Vec<TableQuery>),
    // Table queries are being resolved into a set of affected tablets.
    Resolving(ResultHandle<Vec<(TableQuery, TabletMetadata)>, TabletsRequestStatus>),
    // Affected by table queries tablets are being loaded into the tablet
    // data cache from storage.
    Loading(ResultHandle<Vec<(TabletMetadata, TabletData<T>)>, TabletDataStorageStatus>),
    // Affected by table queries tablets were processed and new versions
    // of tablet data is being stored in the storage.
    Storing(ResultHandle<(), TabletDataStorageStatus>),
    // Processing have been completed and respective tablet ops have been
    // generated.
    Completed,
    Failed,
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;
    use crate::mock::*;
    use crate::transaction::result::{create_eventual_result, ResultSource};
    use mockall::predicate::*;
    use tcp_tablet_store_service::apps::tablet_store::service::{
        tablet_op_result, UpdateTabletResult,
    };

    const TABLE_NAME: &'static str = "map";
    const TABLET_TRANSACTION_ID_1: u64 = 1;
    const TABLE_QUERY_1: u64 = 1;
    const TABLE_QUERY_2: u64 = 2;
    const TABLET_ID_1: u32 = 1;
    const TABLET_VERSION_1: u32 = 5;
    const TABLET_VERSION_2: u32 = 6;
    const TABLET_DATA_VERSION_1: &'static str = "t1 v1";
    const TABLET_DATA_VERSION_2: &'static str = "t1 v2";
    const CORRELATION_ID_1: u64 = 1;
    const CORRELATION_ID_2: u64 = 2;
    const CORRELATION_ID_3: u64 = 3;
    const KEY_HASH_1: u32 = 1;
    const KEY_HASH_2: u32 = 2;

    fn create_transaction_coordinator() -> DefaultTabletTransactionCoordinator<Bytes> {
        DefaultTabletTransactionCoordinator::create(0)
    }

    fn create_resolve_source_and_handle() -> (
        ResultHandle<Vec<(TableQuery, TabletMetadata)>, TabletsRequestStatus>,
        ResultSource<Vec<(TableQuery, TabletMetadata)>, TabletsRequestStatus>,
    ) {
        create_eventual_result()
    }

    fn create_load_source_and_handle() -> (
        ResultHandle<Vec<(TabletMetadata, TabletData<Bytes>)>, TabletDataStorageStatus>,
        ResultSource<Vec<(TabletMetadata, TabletData<Bytes>)>, TabletDataStorageStatus>,
    ) {
        create_eventual_result()
    }

    fn create_store_source_and_handle() -> (
        ResultHandle<(), TabletDataStorageStatus>,
        ResultSource<(), TabletDataStorageStatus>,
    ) {
        create_eventual_result()
    }

    fn create_table_query(query_id: u64, key_hashes: Vec<u32>) -> TableQuery {
        TableQuery::create(query_id, TABLE_NAME.to_string(), key_hashes)
    }

    fn create_tablet_metadata(tablet_id: u32, tablet_version: u32) -> TabletMetadata {
        TabletMetadata {
            tablet_id,
            tablet_version,
            ..Default::default()
        }
    }

    fn create_update_tablet_op(table_name: String, tablet_metadata: TabletMetadata) -> TabletOp {
        TabletOp {
            table_name,
            op: Some(tablet_op::Op::UpdateTablet(UpdateTabletOp {
                tablet_metadata: Some(tablet_metadata),
            })),
        }
    }

    fn create_update_tablet_result(
        tablet_op_status: TabletOpStatus,
        tablet_metadata: Option<TabletMetadata>,
    ) -> TabletOpResult {
        TabletOpResult {
            status: tablet_op_status.into(),
            op_result: Some(tablet_op_result::OpResult::UpdateTablet(
                UpdateTabletResult {
                    existing_tablet: tablet_metadata,
                },
            )),
        }
    }

    struct TabletMetadataCacheBuilder {
        mock_tablet_metadata_cache: MockTabletMetadataCache,
    }

    impl TabletMetadataCacheBuilder {
        fn new() -> Self {
            Self {
                mock_tablet_metadata_cache: MockTabletMetadataCache::new(),
            }
        }

        fn expect_resolve_tablets(
            &mut self,
            expected_queries: Vec<TableQuery>,
            result_handle: ResultHandle<Vec<(TableQuery, TabletMetadata)>, TabletsRequestStatus>,
        ) -> &mut Self {
            self.mock_tablet_metadata_cache
                .expect_resolve_tablets()
                .times(1)
                .with(eq(expected_queries))
                .return_once_st(move |_| result_handle);

            self
        }

        fn expect_update_tablet(
            &mut self,
            tablet_metadata: TabletMetadata,
            conflict: bool,
        ) -> &mut Self {
            self.mock_tablet_metadata_cache
                .expect_update_tablet()
                .times(1)
                .with(eq(tablet_metadata), eq(conflict))
                .return_const(());

            self
        }

        fn take(self) -> MockTabletMetadataCache {
            self.mock_tablet_metadata_cache
        }
    }

    struct TabletDataCacheBuilder {
        mock_tablet_data_cache: MockTabletDataCache<Bytes>,
    }

    impl TabletDataCacheBuilder {
        fn new() -> Self {
            Self {
                mock_tablet_data_cache: MockTabletDataCache::new(),
            }
        }

        fn expect_load_tablets(
            &mut self,
            expected_metadata: Vec<TabletMetadata>,
            result_handle: ResultHandle<
                Vec<(TabletMetadata, TabletData<Bytes>)>,
                TabletDataStorageStatus,
            >,
        ) -> &mut Self {
            self.mock_tablet_data_cache
                .expect_load_tablets()
                .times(1)
                .with(eq(expected_metadata))
                .return_once_st(move |_| result_handle);

            self
        }

        fn expect_store_tablets(
            &mut self,
            expected_data: Vec<(TabletMetadata, Bytes, TabletMetadata)>,
            result_handle: ResultHandle<(), TabletDataStorageStatus>,
        ) -> &mut Self {
            self.mock_tablet_data_cache
                .expect_store_tablets()
                .times(1)
                .return_once_st(move |mut data| {
                    assert_eq!(expected_data.len(), data.len());

                    for ((exp_metadata, exp_data, upd_metadata), (metadata, data)) in
                        expected_data.into_iter().zip(data.iter_mut())
                    {
                        assert_eq!(exp_metadata, **metadata);
                        assert_eq!(exp_data, *data);
                        *(*metadata) = upd_metadata;
                    }

                    result_handle
                });

            self
        }

        fn take(self) -> MockTabletDataCache<Bytes> {
            self.mock_tablet_data_cache
        }
    }

    struct TranactionCoordinatorLoop {
        transaction_coordinator: DefaultTabletTransactionCoordinator<Bytes>,
        metadata_cache: MockTabletMetadataCache,
        data_cache: MockTabletDataCache<Bytes>,
    }

    impl TranactionCoordinatorLoop {
        fn create(
            transaction_coordinator: DefaultTabletTransactionCoordinator<Bytes>,
            metadata_cache: MockTabletMetadataCache,
            data_cache: MockTabletDataCache<Bytes>,
        ) -> Self {
            Self {
                transaction_coordinator,
                metadata_cache,
                data_cache,
            }
        }

        fn get_mut(&mut self) -> &mut DefaultTabletTransactionCoordinator<Bytes> {
            &mut self.transaction_coordinator
        }

        fn execute_step(
            &mut self,
            instant: u64,
            in_message: Option<TabletTransactionCoordinatorInMessage>,
        ) -> Vec<TabletTransactionCoordinatorOutMessage> {
            self.transaction_coordinator.make_progress(
                instant,
                &mut self.metadata_cache,
                &mut self.data_cache,
            );

            let out_messages = self.transaction_coordinator.take_out_messages();

            if in_message.is_some() {
                self.transaction_coordinator
                    .process_in_message(&mut self.metadata_cache, in_message.unwrap());
            }

            out_messages
        }
    }

    #[test]
    fn test_end_to_end_success() {
        let transaction_coordinator = create_transaction_coordinator();

        let table_query_1 = create_table_query(TABLE_QUERY_1, vec![KEY_HASH_1, KEY_HASH_2]);
        let table_query_1_copy = table_query_1.clone();
        let tablet_metadata_1_v_1 = create_tablet_metadata(TABLET_ID_1, TABLET_VERSION_1);
        let tablet_metadata_1_v_1_copy = tablet_metadata_1_v_1.clone();
        let tablet_metadata_1_v_2 = create_tablet_metadata(TABLET_ID_1, TABLET_VERSION_2);
        let tablet_data_1_v_1 = Bytes::from(TABLET_DATA_VERSION_1);
        let tablet_data_1_v_1_copy = tablet_data_1_v_1.clone();
        let tablet_data_1_v_2 = Bytes::from(TABLET_DATA_VERSION_2);
        let tablet_data_1_v_2_copy = tablet_data_1_v_2.clone();

        let mut metadata_cache_builder = TabletMetadataCacheBuilder::new();
        let (resolve_result_handle_1, mut resolve_result_source_1) =
            create_resolve_source_and_handle();
        metadata_cache_builder
            .expect_resolve_tablets(vec![table_query_1.clone()], resolve_result_handle_1)
            .expect_update_tablet(tablet_metadata_1_v_2.clone(), false);
        let metadata_cache = metadata_cache_builder.take();

        let mut data_cache_builder = TabletDataCacheBuilder::new();
        let (load_result_handle_1, mut load_result_source_1) = create_load_source_and_handle();
        data_cache_builder
            .expect_load_tablets(vec![tablet_metadata_1_v_1.clone()], load_result_handle_1);
        let (store_result_handle_1, mut store_result_source_1) = create_store_source_and_handle();
        data_cache_builder.expect_store_tablets(
            vec![(
                tablet_metadata_1_v_1.clone(),
                tablet_data_1_v_2.clone(),
                tablet_metadata_1_v_2.clone(),
            )],
            store_result_handle_1,
        );
        let data_cache = data_cache_builder.take();

        let mut transaction_loop =
            TranactionCoordinatorLoop::create(transaction_coordinator, metadata_cache, data_cache);

        let transaction_id_1 = transaction_loop.get_mut().create_transaction();

        transaction_loop.get_mut().process_transaction(
            transaction_id_1,
            vec![table_query_1.clone()],
            Box::new(move |transaction_id, mut tablets| {
                assert_eq!(transaction_id_1, transaction_id);
                assert_eq!(1, tablets.len());

                let (table_query, tablet) = tablets.pop().unwrap();
                assert_eq!(table_query_1_copy, table_query);
                assert_eq!(tablet_metadata_1_v_1_copy, tablet.get_metadata().clone());
                assert_eq!(tablet_data_1_v_1_copy, tablet.get_contents());

                tablet.set_contents(tablet_data_1_v_2_copy.clone());
            }),
        );

        assert!(transaction_loop
            .get_mut()
            .has_transaction_pending_process(transaction_id_1));

        assert!(transaction_loop.execute_step(1, None).is_empty());

        resolve_result_source_1
            .set_result(vec![(table_query_1.clone(), tablet_metadata_1_v_1.clone())]);

        assert!(transaction_loop.execute_step(2, None).is_empty());

        load_result_source_1.set_result(vec![(
            tablet_metadata_1_v_1.clone(),
            TabletData::create(tablet_data_1_v_1.clone()),
        )]);

        assert!(transaction_loop.execute_step(3, None).is_empty());

        store_result_source_1.set_result(());

        assert!(transaction_loop.execute_step(4, None).is_empty());

        assert!(!transaction_loop
            .get_mut()
            .has_transaction_pending_process(transaction_id_1));

        transaction_loop
            .get_mut()
            .commit_transaction(transaction_id_1);

        assert!(transaction_loop
            .get_mut()
            .check_transaction_result(transaction_id_1)
            .is_none());

        assert_eq!(
            vec![
                TabletTransactionCoordinatorOutMessage::ExecuteTabletOpsRequest(
                    CORRELATION_ID_1,
                    vec![create_update_tablet_op(
                        TABLE_NAME.to_string(),
                        tablet_metadata_1_v_2.clone()
                    )]
                )
            ],
            transaction_loop.execute_step(
                5,
                Some(
                    TabletTransactionCoordinatorInMessage::ExecuteTabletOpsResponse(
                        CORRELATION_ID_1,
                        vec![create_update_tablet_result(TabletOpStatus::Succeeded, None)]
                    )
                )
            )
        );

        assert_eq!(
            Some(TabletTransactionOutcome::Succeeded),
            transaction_loop
                .get_mut()
                .check_transaction_result(transaction_id_1)
        );
    }
}
