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

use core::{cell::RefCell, clone::Clone, mem};

use alloc::{boxed::Box, rc::Rc, string::String, vec::Vec};
use prost::bytes::Bytes;
use tcp_tablet_store_service::apps::tablet_store::service::{
    tablet_op, tablet_op_result::OpResult, CheckTabletOp, TabletMetadata, TabletOp, TabletOpResult,
    TabletOpStatus, TabletsRequest, TabletsRequestStatus, TabletsResponse, UpdateTabletOp,
};

use crate::apps::tablet_cache::service::{
    ExecuteTabletOpsRequest, ExecuteTabletOpsResponse, LoadTabletRequest, LoadTabletResponse,
    StoreTabletRequest, StoreTabletResponse, TabletDataStorageStatus,
};
use hashbrown::{HashMap, HashSet};

// Messages that may go into the transaction manager.
#[derive(PartialEq, Debug, Clone)]
pub enum InMessage {
    // Response to tablet loading from data storage along with tablet contents and correlation id.
    LoadTabletResponse(u64, LoadTabletResponse, Bytes),
    // Response to tablet storing into data storage along with correlation id.
    StoreTabletResponse(u64, StoreTabletResponse),
    // Response to tablet ops executing in tablet store along with tablets response and correlation id.
    ExecuteTabletOpsResponse(u64, ExecuteTabletOpsResponse, TabletsResponse),
}

// Messages that may go from the transction manager.
#[derive(PartialEq, Debug, Clone)]
pub enum OutMessage {
    // Request to load tablet from data storage along with correlation id.
    LoadTabletRequest(u64, LoadTabletRequest),
    // Request to store tablet into data storage along with tablet contents and correlation id.
    StoreTabletRequest(u64, StoreTabletRequest, Bytes),
    // Request to execute tablet ops in tablet store alogn with tablets request and correlation id.
    ExecuteTabletOpsRequest(u64, ExecuteTabletOpsRequest, TabletsRequest),
}

// Transaction manager is responsible for providing efficient cache for the
// tablet metadata and contents, transactional support for tablet processing.
// Essentially transaction manager abstracts mapping of keys to tablets which
// requires execution of list ops in tablet store, loading current and storing
// new version of tablet data in data storage. Transaction manager acts as
// an adapter for the tablet store that is responsible for transactional
// management of the tablet metadata and tablet data storage that is responsible
// for the tablet data storage.
pub trait TabletTransactionManager: TabletTransactionContext {
    // Initializes transaction manager with tablet cache capacity.
    fn init(&mut self, cache_capacity: u64);

    // Advances internal state machine of the transaction manager. Essentially
    // it tries to make progress on all pending tablet resolutions and transactions.
    fn make_progress(&mut self, instant: u64);

    // Processes incoming message, which maybe load or store tablet
    // result, outcome of the tablet ops execution.
    fn process_in_message(&mut self, message: InMessage);

    // Takes outgoing messages to be send out, which maybe requests to
    // load or store tablet, execute tablet ops.
    fn take_out_messages(&mut self) -> Vec<OutMessage>;
}

pub type ResolveHandler = dyn FnMut(Vec<(TableQuery, TabletDescriptor)>) -> ();

// Provides ability to map keys to tablets and initiate tablet transactions.
pub trait TabletTransactionContext {
    // Requests to map keys in a given table to corresponding tablets.
    // Provided handler will be called once resolution is complete.
    fn resolve(&mut self, queries: Vec<TableQuery>, handler: Box<ResolveHandler>);

    // Starts a new transaction. Multiple concurrent transactions may coexist.
    fn start_transaction(&mut self) -> Box<dyn TabletTransaction>;
}

// Provides succint tablet metadata and contents. Enables transaction to
// update it. If tablet contents has only been read, transaction manager
// will produce a check tablet operation to make sure its version hasn't
// changed. If tablet contens has been updated, transaction manager
// will produce an update tablet operation.
#[derive(Default, PartialEq, Debug, Clone)]
pub struct Tablet {
    tablet_metadata: TabletMetadata,
    tablet_contents: Bytes,
    is_dirty: bool,
}

impl Tablet {
    pub fn create(tablet_metadata: TabletMetadata, tablet_contents: Bytes) -> Tablet {
        Tablet {
            tablet_metadata,
            tablet_contents,
            is_dirty: false,
        }
    }

    // Gets tablet id.
    pub fn get_id(&self) -> u32 {
        self.tablet_metadata.tablet_id
    }

    fn get_metadata(&self) -> &TabletMetadata {
        &self.tablet_metadata
    }

    // Gets metadata describing this tablet.
    fn get_metadata_mut(&mut self) -> &mut TabletMetadata {
        &mut self.tablet_metadata
    }

    // Gets tablet contents.
    pub fn get_contents(&self) -> Bytes {
        self.tablet_contents.clone()
    }

    // Updates tablet contents.
    pub fn set_contents(&mut self, contents: Bytes) {
        self.tablet_contents = contents;
        self.is_dirty = true;
    }

    // Indicates if tablet contents has been updated.
    pub fn is_dirty(&self) -> bool {
        self.is_dirty
    }
}

// Provides short description of tablet. Used during key to tablet mapping.
#[derive(Default, PartialEq, Debug, Clone)]
pub struct TabletDescriptor {
    tablet_id: u32,
    cache_ready: bool,
}

impl TabletDescriptor {
    pub fn create(tablet_id: u32, cache_ready: bool) -> TabletDescriptor {
        TabletDescriptor {
            tablet_id,
            cache_ready,
        }
    }

    // Gets tablet id.
    pub fn get_id(&self) -> u32 {
        self.tablet_id
    }

    // Gets indicator suggesting if tablet contents is currently in cache.
    pub fn cache_ready(&self) -> bool {
        self.cache_ready
    }
}

// Represents a query for a given set of keys (or rather their hashes) in a
// table. Key hashes must be mapped to corresponding tablets and then the
// tablet data must be loaded trhough the cache and passed to the transaction
// for processing.
#[derive(Default, PartialEq, Debug, Clone)]
pub struct TableQuery {
    query_id: u64,
    table_name: String,
    key_hashes: HashSet<u32>,
}

impl TableQuery {
    pub fn create(query_id: u64, table_name: String, key_hashes: Vec<u32>) -> TableQuery {
        let mut key_hash_set = HashSet::with_capacity(key_hashes.len());
        for key_hash in key_hashes {
            key_hash_set.insert(key_hash);
        }
        TableQuery {
            query_id,
            table_name,
            key_hashes: key_hash_set,
        }
    }

    // Gets query id.
    pub fn get_id(&self) -> u64 {
        self.query_id
    }

    // Gets name of the table to query.
    pub fn get_table_name(&self) -> &String {
        &self.table_name
    }

    // Gets set of key hashes to query.
    pub fn get_key_hashes(&self) -> &HashSet<u32> {
        &self.key_hashes
    }
}

pub type ProcessHandler = dyn FnMut(u64, Vec<(TableQuery, &mut Tablet)>) -> ();

// Represents a tablet processing transaction. Transaction records reads and writes
// made to a set of tablets and then on commit turns them into set of check and
// update tablet ops. Once created the consumer may request several times to
// process tablets where processing may result in updated tablet data. Updated
// tablet will result in an update tablet op, otherwise check tablet op.
pub trait TabletTransaction {
    fn get_id(&self) -> u64;

    // Requests to process tablets covered by the given query. Essentially the
    // contents for the covered tabelts must be loaded into cache. Once available
    // provided handler can be called to allow consumer read and write tablet data.
    fn process(&mut self, queries: Vec<TableQuery>, handler: Box<ProcessHandler>);

    // Indicates if transaction has any pending process requests.
    fn has_pending_process(&self) -> bool;

    // Requests to commit transaction. Essentially all reads and writes recorded
    // during transaction are conveted into tablet ops that will be sent out to
    // the tablet store for execution.
    fn commit(self: Box<Self>) -> Box<dyn TabletTransactionCommit>;

    // Requests to abort transaction. Essentially uncommitted changes including new
    // versions of tablets must be discarded.
    fn abort(self: Box<Self>);
}

// Represents transaction commit handle. Can be used to check status.
pub trait TabletTransactionCommit {
    // Checks the status of the transaction. Return none if no
    // outcome is known and the outcome otherwise.
    fn check_result(&mut self) -> Option<TabletTransactionOutcome>;
}

// Indicates outcome of a transaction.
#[derive(PartialEq, Debug, Clone, Copy)]
pub enum TabletTransactionOutcome {
    // Transaction has been successfully committed to the Tablet Store.
    Succeeded,
    // Transaction may have failed during local execution or failed to
    // commit to the Tablet Store.
    Failed,
}

const TRANSACTION_COORDINATOR_CORRELATION_COUNTER: u64 = 1 << 56;

pub struct SimpleTabletTransactionManager {
    core: Rc<RefCell<TabletTransactionManagerCore>>,
}

impl SimpleTabletTransactionManager {
    pub fn create(data_cache_capacity: u64) -> Self {
        Self {
            core: Rc::new(RefCell::new(TabletTransactionManagerCore::create(
                Box::new(SimpleTabletTransactionCoordinator::create(
                    TRANSACTION_COORDINATOR_CORRELATION_COUNTER,
                )),
                Box::new(SimpleTabletMetadataCache::create()),
                Box::new(SimpleTabletDataCache::create(data_cache_capacity)),
            ))),
        }
    }
}

impl TabletTransactionManager for SimpleTabletTransactionManager {
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

impl TabletTransactionContext for SimpleTabletTransactionManager {
    fn resolve(&mut self, _queries: Vec<TableQuery>, _handler: Box<ResolveHandler>) {
        todo!()
    }

    fn start_transaction(&mut self) -> Box<dyn TabletTransaction> {
        Box::new(SimpleTabletTransaction::create(
            self.core.borrow_mut().create_transaction(),
            self.core.clone(),
        ))
    }
}

struct SimpleTabletTransaction {
    transaction_id: u64,
    transaction_outcome: Option<TabletTransactionOutcome>,
    core: Rc<RefCell<TabletTransactionManagerCore>>,
}

impl SimpleTabletTransaction {
    fn create(transaction_id: u64, core: Rc<RefCell<TabletTransactionManagerCore>>) -> Self {
        Self {
            transaction_id,
            transaction_outcome: None,
            core,
        }
    }
}

impl TabletTransaction for SimpleTabletTransaction {
    fn get_id(&self) -> u64 {
        self.transaction_id
    }

    fn process(&mut self, queries: Vec<TableQuery>, handler: Box<ProcessHandler>) {
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

impl TabletTransactionCommit for SimpleTabletTransaction {
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
struct TabletTransactionManagerCore {
    transaction_coordinator: Box<dyn TabletTransactionCoordinator>,
    metadata_cache: Box<dyn TabletMetadataCache>,
    data_cache: Box<dyn TabletDataCache>,
}

// Delegates processing to metadata cache, data cache and transaction coordinator.
impl TabletTransactionManagerCore {
    fn create(
        transaction_coordinator: Box<dyn TabletTransactionCoordinator>,
        metadata_cache: Box<dyn TabletMetadataCache>,
        data_cache: Box<dyn TabletDataCache>,
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
        handler: Box<ProcessHandler>,
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
pub trait TabletTransactionCoordinator {
    // Advances internal state machine of the Tablet Transaction Coordinator.
    fn make_progress(
        &mut self,
        instant: u64,
        metadata_cache: &mut dyn TabletMetadataCache,
        data_cache: &mut dyn TabletDataCache,
    );

    // Processes incoming messages. Incoming message may contain tablets ops execution responses
    // coming from Tablet Store.
    fn process_in_message(&mut self, in_message: TabletTransactionCoordinatorInMessage);

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
        handler: Box<ProcessHandler>,
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

#[derive(Default)]
struct SimpleTabletTransactionCoordinator {
    // Counter that is used to produce unique correlation id for outgoing
    // messages.
    correlation_counter: u64,
    // Counter that is used to produce unique transaction id.
    transaction_counter: u64,
    // Maps transaction id to its current state.
    transactions: HashMap<u64, TabletTransactionState>,
    // Maps correlation id that has been used to create Tablet Store request
    // and corresponding transction id.
    correlations: HashMap<u64, u64>,
    // Stash of outgoing messages waiting to be sent out.
    out_messages: Vec<TabletTransactionCoordinatorOutMessage>,
}

impl SimpleTabletTransactionCoordinator {
    fn create(correlation_counter: u64) -> Self {
        Self {
            correlation_counter,
            ..Default::default()
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

impl TabletTransactionCoordinator for SimpleTabletTransactionCoordinator {
    fn make_progress(
        &mut self,
        instant: u64,
        metadata_cache: &mut dyn TabletMetadataCache,
        data_cache: &mut dyn TabletDataCache,
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

    fn process_in_message(&mut self, in_message: TabletTransactionCoordinatorInMessage) {
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
                            *transaction = TabletTransactionState::Completed(
                                transaction_state.complete(tablet_op_results),
                            );
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
        handler: Box<ProcessHandler>,
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
enum TabletTransactionState {
    // Transaction prepares by resolving, loading, processing and storing
    // processed tablets, generates respective tablet ops to update metadata.
    Preparing(PreparingTabletTransactionState),
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

#[derive(Default)]
struct PreparingTabletTransactionState {
    // Identifies transaction this state describes.
    transaction_id: u64,
    // Holds state of all pending requests to process tablets as part of this transaction.
    process_requests: Vec<TabletProcessState>,
}

impl PreparingTabletTransactionState {
    fn create(transaction_id: u64) -> Self {
        Self {
            transaction_id,
            ..Default::default()
        }
    }

    fn make_progress(
        &mut self,
        _instant: u64,
        metadata_cache: &mut dyn TabletMetadataCache,
        data_cache: &mut dyn TabletDataCache,
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
                                        TabletState::create_key(&metadata),
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
                                        .get_mut(&TabletState::create_key(&metadata))
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
                                let store_result = data_cache.store_tablets(&mut tablet_writes);
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

    fn init_pending(&mut self, queries: Vec<TableQuery>, handler: Box<ProcessHandler>) {
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

    fn complete(&self, tablet_op_results: Vec<TabletOpResult>) -> TabletTransactionOutcome {
        // Technically we need to check that tablet ops correspond to tablet results
        // but for the time being we are doing a simple check of that all tablet ops
        // succeeded.
        for tablet_op_result in tablet_op_results {
            if tablet_op_result.status != TabletOpStatus::Succeeded as i32 {
                return TabletTransactionOutcome::Failed;
            }
        }
        TabletTransactionOutcome::Succeeded
    }
}

// Tracks state of a tablet affected by a transaction.
#[derive(Default, Debug, Clone)]
struct TabletState {
    // Query that affected the tablet.
    query: TableQuery,
    // Tablet metadata and data, along with tracking if this tablet was updated.
    tablet: Tablet,
}

impl TabletState {
    fn create(query: TableQuery, metadata: TabletMetadata) -> Self {
        Self {
            query,
            tablet: Tablet::create(metadata, Bytes::new()),
        }
    }

    // Creates tablet key that consists of tablet id and its version.
    fn create_key(metadata: &TabletMetadata) -> u64 {
        (metadata.tablet_id as u64) << 32 | (metadata.tablet_version as u64)
    }

    // Gets mutable reference to the tablet and query so that it can be passed to the
    // process handler.
    fn tablet_mut(&mut self) -> (TableQuery, &mut Tablet) {
        (self.query.clone(), &mut self.tablet)
    }

    // Inits tablet state with data loaded from Tablet Data Cache.
    fn tablet_init(&mut self, data: Bytes) {
        // Note that we only assign loaded data to avoid marking it as dirty.
        self.tablet.tablet_contents = data;
    }

    // Prepares tablet op to be executed and optionally returns updated metadata along
    // with the data to be written to the Tablet Data Storage.
    fn tablet_prepare(&mut self) -> Option<(&mut TabletMetadata, Bytes)> {
        if self.tablet.is_dirty() {
            let tablet_contents = self.tablet.get_contents();
            Some((self.tablet.get_metadata_mut(), tablet_contents))
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

struct TabletProcessState {
    status: TabletProcessStatus,
    // Handler that will be called to process tablets.
    handler: Box<ProcessHandler>,
    // Maps tablet key that of tablet id and its version to the tablet state.
    tablets: HashMap<u64, TabletState>,
}

enum TabletProcessStatus {
    Pending(Vec<TableQuery>),
    // Table queries are being resolved into a set of affected tablets.
    Resolving(ResultHandle<Vec<(TableQuery, TabletMetadata)>, TabletsRequestStatus>),
    // Affected by table queries tablets are being loaded into the tablet
    // data cache from storage.
    Loading(ResultHandle<Vec<(TabletMetadata, Bytes)>, TabletDataStorageStatus>),
    // Affected by table queries tablets were processed and new versions
    // of tablet data is being stored in the storage.
    Storing(ResultHandle<(), TabletDataStorageStatus>),
    // Processing have been completed and respective tablet ops have been
    // generated.
    Completed,
    Failed,
}

#[derive(PartialEq, Debug, Clone)]
pub enum TabletMetadataCacheInMessage {
    ListResponse(u64, Vec<TabletOpResult>),
}

#[derive(PartialEq, Debug, Clone)]
pub enum TabletMetadataCacheOutMessage {
    ListRequest(u64, Vec<TabletOp>),
}

// Maintains last known state of the tablets metadata. Requests listing
// of tablets from Tablet Store to resolve metadata of unknown tablets.
pub trait TabletMetadataCache {
    // Advances internal state machine of the tablet metadata cache.
    fn make_progress(&mut self, instant: u64);

    // Requests to resolve tablets that given set of the table queries affect. Returned
    // result handle must be checked for the operation completion. The operation is
    // completed only when all affected tablets are resolved.
    fn resolve_tablets(
        &mut self,
        queries: &Vec<TableQuery>,
    ) -> ResultHandle<Vec<(TableQuery, TabletMetadata)>, TabletsRequestStatus>;

    // Instructs cache to update tablet metadata. Metadata maybe updated after
    // transaction execution.
    fn update_tablet(&mut self, metadata: TabletMetadata);

    // Processes incoming messages. Incoming message may contain tablets list responses.
    fn process_in_message(&mut self, in_message: TabletMetadataCacheInMessage);

    // Takes outgoing messages. Outgoing message may contain tablet list requests.
    fn take_out_messages(&mut self) -> Vec<TabletMetadataCacheOutMessage>;
}

struct SimpleTabletMetadataCache {}

impl SimpleTabletMetadataCache {
    fn create() -> Self {
        Self {}
    }
}

impl TabletMetadataCache for SimpleTabletMetadataCache {
    fn make_progress(&mut self, _instant: u64) {
        todo!()
    }

    fn resolve_tablets(
        &mut self,
        _queries: &Vec<TableQuery>,
    ) -> ResultHandle<Vec<(TableQuery, TabletMetadata)>, TabletsRequestStatus> {
        todo!()
    }

    fn update_tablet(&mut self, _metadata: TabletMetadata) {
        todo!()
    }

    fn process_in_message(&mut self, _in_message: TabletMetadataCacheInMessage) {
        todo!()
    }

    fn take_out_messages(&mut self) -> Vec<TabletMetadataCacheOutMessage> {
        todo!()
    }
}

#[derive(PartialEq, Debug, Clone)]
pub enum TabletDataCacheInMessage {
    LoadResponse(u64, LoadTabletResponse, Bytes),
    StoreResponse(u64, StoreTabletResponse),
}

#[derive(PartialEq, Debug, Clone)]
pub enum TabletDataCacheOutMessage {
    LoadRequest(u64, LoadTabletRequest),
    StoreRequest(u64, StoreTabletRequest, Bytes),
}

// Maintains cache of recently used tablet data. Tablet data cache follows soft capacity
// limit but may temporarily grow larger than configured.
pub trait TabletDataCache {
    // Advances internal state machine of the tablet data cache.
    fn make_progress(&mut self, instant: u64);

    // Requests to load and cache tablet data described by provided metadata. Returned result
    // handle must be checked for the operation completion. The operation is completed only when
    // all requested tablets are loaded. Returned tablet data is already decrypted and verified,
    // along with its metadata.
    fn load_tablets(
        &mut self,
        metadata: &Vec<TabletMetadata>,
    ) -> ResultHandle<Vec<(TabletMetadata, Bytes)>, TabletDataStorageStatus>;

    // Requests to store and cache provided tablet data. Returned result handle must be
    // checked for the operation completion. The operation is completed only when all requested
    // tablets are stored. The tablet data must be provided not-encrypted along with
    // the metadata of the preivous version of the tablet. Provided metadata is updated to
    // reflect new version of the tablet.
    fn store_tablets(
        &mut self,
        data: &mut Vec<(&mut TabletMetadata, Bytes)>,
    ) -> ResultHandle<(), TabletDataStorageStatus>;

    // Processes incoming messages. Message may contain load or store tablet responses.
    fn process_in_message(&mut self, in_message: TabletDataCacheInMessage);

    // Takes outgoing messages. Message may contain load or store tablet requests.
    fn take_out_messages(&mut self) -> Vec<TabletDataCacheOutMessage>;
}

struct SimpleTabletDataCache {}

impl SimpleTabletDataCache {
    // Creates new tablet data cache with given capacity. Configured capacity is considered
    // a soft limit. Tablet data cache may grow larger temporarily than requested capacity.
    fn create(cache_capacity: u64) -> Self {
        Self {}
    }
}

impl TabletDataCache for SimpleTabletDataCache {
    fn make_progress(&mut self, _instant: u64) {
        todo!()
    }

    fn load_tablets(
        &mut self,
        _metadata: &Vec<TabletMetadata>,
    ) -> ResultHandle<Vec<(TabletMetadata, Bytes)>, TabletDataStorageStatus> {
        todo!()
    }

    fn store_tablets(
        &mut self,
        _data: &mut Vec<(&mut TabletMetadata, Bytes)>,
    ) -> ResultHandle<(), TabletDataStorageStatus> {
        todo!()
    }

    fn process_in_message(&mut self, _in_message: TabletDataCacheInMessage) {
        todo!()
    }

    fn take_out_messages(&mut self) -> Vec<TabletDataCacheOutMessage> {
        todo!()
    }
}

pub fn create_eventual_result<T: Clone, E: Clone>() -> (ResultHandle<T, E>, ResultSource<T, E>) {
    let core = Rc::new(RefCell::new(ResultCore::<T, E> {
        result: None,
        error: None,
    }));
    (
        ResultHandle::<T, E> { core: core.clone() },
        ResultSource::<T, E> { core },
    )
}

// Holds shared state of the result handler and source.
struct ResultCore<T: Clone, E: Clone> {
    result: Option<T>,
    error: Option<E>,
}

// Enables method caller to later check if the result is available.
pub struct ResultHandle<T: Clone, E: Clone> {
    core: Rc<RefCell<ResultCore<T, E>>>,
}

impl<T: Clone, E: Clone> ResultHandle<T, E> {
    fn check_result(&self) -> Option<Result<T, E>> {
        let core = self.core.borrow_mut();
        if core.result.is_some() {
            Some(Ok(core.result.as_ref().unwrap().clone()))
        } else if core.error.is_some() {
            Some(Err(core.error.as_ref().unwrap().clone()))
        } else {
            None
        }
    }
}

// Enables method logic to later set the result to either a value or an error.
pub struct ResultSource<T: Clone, E: Clone> {
    core: Rc<RefCell<ResultCore<T, E>>>,
}

impl<T: Clone, E: Clone> ResultSource<T, E> {
    fn set_result(&mut self, result: T) {
        let mut core = self.core.borrow_mut();
        assert!(core.error.is_none() && core.result.is_none());
        core.result = Some(result);
    }

    fn set_error(&mut self, error: E) {
        let mut core = self.core.borrow_mut();
        assert!(core.error.is_none() && core.result.is_none());
        core.error = Some(error);
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;
    use crate::mock::*;
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

    fn create_transaction_coordinator() -> SimpleTabletTransactionCoordinator {
        SimpleTabletTransactionCoordinator::create(0)
    }

    fn create_resolve_source_and_handle() -> (
        ResultHandle<Vec<(TableQuery, TabletMetadata)>, TabletsRequestStatus>,
        ResultSource<Vec<(TableQuery, TabletMetadata)>, TabletsRequestStatus>,
    ) {
        create_eventual_result()
    }

    fn create_load_source_and_handle() -> (
        ResultHandle<Vec<(TabletMetadata, Bytes)>, TabletDataStorageStatus>,
        ResultSource<Vec<(TabletMetadata, Bytes)>, TabletDataStorageStatus>,
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

        fn take(self) -> MockTabletMetadataCache {
            self.mock_tablet_metadata_cache
        }
    }

    struct TabletDataCacheBuilder {
        mock_tablet_data_cache: MockTabletDataCache,
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
            result_handle: ResultHandle<Vec<(TabletMetadata, Bytes)>, TabletDataStorageStatus>,
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
                .return_once_st(move |data| {
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

        fn take(self) -> MockTabletDataCache {
            self.mock_tablet_data_cache
        }
    }

    struct TranactionCoordinatorLoop {
        transaction_coordinator: SimpleTabletTransactionCoordinator,
        metadata_cache: MockTabletMetadataCache,
        data_cache: MockTabletDataCache,
    }

    impl TranactionCoordinatorLoop {
        fn create(
            transaction_coordinator: SimpleTabletTransactionCoordinator,
            metadata_cache: MockTabletMetadataCache,
            data_cache: MockTabletDataCache,
        ) -> Self {
            Self {
                transaction_coordinator,
                metadata_cache,
                data_cache,
            }
        }

        fn get_mut(&mut self) -> &mut SimpleTabletTransactionCoordinator {
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
                    .process_in_message(in_message.unwrap());
            }

            out_messages
        }
    }

    #[test]
    fn test_end_to_end_success() {
        let transaction_coordinator: SimpleTabletTransactionCoordinator =
            create_transaction_coordinator();

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
            .expect_resolve_tablets(vec![table_query_1.clone()], resolve_result_handle_1);
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
            tablet_data_1_v_1.clone(),
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
