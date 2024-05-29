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

use core::{
    cell::RefCell,
    hash::{Hash, Hasher},
    mem,
};

use ahash::AHasher;
use alloc::{boxed::Box, rc::Rc, string::String, vec::Vec};
use hashbrown::HashMap;

use crate::{
    apps::tablet_cache::service::{
        GetKeyRequest, GetKeyResponse, PutKeyRequest, PutKeyResponse, TabletContents,
    },
    transaction,
};

use prost::{bytes::Bytes, Message};

// Key value store requests.
#[derive(PartialEq, Debug, Clone)]
pub enum KeyValueRequest {
    // Put request along with its correlation id.
    Put(u64, PutKeyRequest),
    // Get request along with its correlation id.
    Get(u64, GetKeyRequest),
}

// Key value store responses.
#[derive(PartialEq, Debug, Clone)]
pub enum KeyValueResponse {
    // Put response along with its correlation id.
    Put(u64, PutKeyResponse),
    // Get response along with its correlation id.
    Get(u64, GetKeyResponse),
}

// Key value store interface. The interaction with it should proceed as a loop
// where at each iteration we first call process request, followed by make progress,
// finishing with take responses. The latter may not have responses at the time of
// calling. Therefore we will continue this loop until app is terminated. Some iterations
// will produce responses.
pub trait KeyValueStore {
    // Periodically called with the current instant and reference to the transaction
    // context. Key value store may start a new transaction after enough consumer
    // requests has been batched together, process consumer requests, commit
    // transaction, check transaction result and produce consumer responses.
    fn make_progress(
        &mut self,
        instant: u64,
        transaction_context: &mut dyn transaction::TabletTransactionContext,
    );

    // Accepts consumer request for processing. The actual processing will likely
    // to happen later, after multiple requests are batched together and the
    // corresponding transaction has been committed. The response for this
    // request will eventually be available through the take responses method.
    fn process_request(&mut self, request: KeyValueRequest);

    // Takes any ready to be sent out to the consumer responses.
    fn take_responses(&mut self) -> Vec<KeyValueResponse>;
}

// Simple key value store implementation that targets the following scenario.
// Each put or get request is independent and is expected to be routed to a
// random cache node. In order to amortize the cost per request this
// implementation aims to reduce read and write amplification from and to
// tablet data storage. Specifically, this implementation organizes individual
// put and get requests into coarse transactions such that fewer tablets
// were loaded and stored at any point in time and hence reduce the amplification.
// This implementation uses simple strategy that waits for a number of requests
// for a single tablet before processing. It also prevents multiple concurrent
// transactions against the same tablet to avoid unnecessary transaction failures.
// This implementation should be viewed as demo and reference.
pub struct SimpleKeyValueStore {
    core: Rc<RefCell<SimpleKeyValueStoreCore>>,
}

impl SimpleKeyValueStore {
    // Creates key value store with configured single table, minimum
    // number of requests to wait before trying to resolve which tablets
    // they touch, minimum number of requests to wait on a single tablet
    // before processing them.
    pub fn create(
        table_name: String,
        min_pending_before_resolve: usize,
        min_pending_before_process: usize,
    ) -> SimpleKeyValueStore {
        SimpleKeyValueStore {
            core: Rc::new(RefCell::new(SimpleKeyValueStoreCore::new(
                table_name,
                min_pending_before_resolve,
                min_pending_before_process,
            ))),
        }
    }
}

impl KeyValueStore for SimpleKeyValueStore {
    fn make_progress(
        &mut self,
        _instant: u64,
        transaction_context: &mut dyn transaction::TabletTransactionContext,
    ) {
        let mut core = self.core.borrow_mut();

        let mut core_clone = self.core.clone();
        // If enough pending requests have accumulated initiate resolution of
        // the affected tablets.
        core.maybe_resolve_tablets(
            transaction_context,
            Box::new(move |results| core_clone.borrow_mut().handle_query_resolve(results)),
        );

        core_clone = self.core.clone();
        // If enough pending requests has accumulated on some tablets initiate a
        // transaction covering the tablets that passed the threshold.
        core.maybe_start_transaction(
            transaction_context,
            Box::new(move |transaction_id, results| {
                core_clone
                    .borrow_mut()
                    .handle_query_process(transaction_id, results)
            }),
        );

        // Try to commit transactions where all local processing has been completed.
        // In other words all process handlers have been called.
        core.maybe_commit_transactions();

        // Check the state of transactions with pending commits. For transactions
        // where commit has been confirmed produce responses. For transactions
        // where commit has been rejected enqueue corresponding requests for retry.
        core.maybe_finalize_or_retry_transactions();
    }

    fn process_request(&mut self, request: KeyValueRequest) {
        // Stash request for later processing.
        self.core.borrow_mut().append_request(request)
    }

    fn take_responses(&mut self) -> Vec<KeyValueResponse> {
        // Take responses produced as a result of request processing.
        self.core.borrow_mut().take_responses()
    }
}

// Holds mutable shared state of the key value store.
struct SimpleKeyValueStoreCore {
    table_accessor: TableAccessor,
    request_tracker: RequestTracker,
    tablet_trackers: HashMap<u32, TabletTracker>,
    transaction_trackers: HashMap<u64, TransactionTracker>,
    responses: Vec<KeyValueResponse>,
    min_pending_before_process: usize,
}

impl SimpleKeyValueStoreCore {
    fn new(
        table_name: String,
        min_pending_before_resolve: usize,
        min_pending_before_process: usize,
    ) -> SimpleKeyValueStoreCore {
        SimpleKeyValueStoreCore {
            table_accessor: TableAccessor::create(table_name),
            request_tracker: RequestTracker::create(min_pending_before_resolve),
            tablet_trackers: HashMap::new(),
            transaction_trackers: HashMap::new(),
            responses: Vec::new(),
            min_pending_before_process,
        }
    }

    fn handle_query_resolve(
        &mut self,
        results: Vec<(transaction::TableQuery, transaction::TabletDescriptor)>,
    ) {
        // Associate resolved requests with corresponding tablets.
        for (table_query, tablet_descriptor) in results {
            // Create tracker for the previously unseen tablet.
            let tablet_tracker = self
                .tablet_trackers
                .entry(tablet_descriptor.get_id())
                .or_insert(TabletTracker::create(self.min_pending_before_process));
            // Move resolved requests as pending to the tablet they affect.
            tablet_tracker.append_pending_requests(
                self.request_tracker
                    .take_resolved_requests(table_query.get_id()),
            );
        }
    }

    fn handle_query_process(
        &mut self,
        transaction_id: u64,
        results: Vec<(transaction::TableQuery, &mut transaction::Tablet)>,
    ) {
        // Do actual request processing.
        if let Some(transaction_tracker) = self.transaction_trackers.get_mut(&transaction_id) {
            // For each table query and corresponding tablet
            for (table_query, mut tablet) in results {
                if let Some(tablet_tracker) = self.tablet_trackers.get_mut(&tablet.get_id()) {
                    // Deserialize tablet contents and process requests that are associated with
                    // the table query. Store processing results comprising or original request
                    // and produced response next to the transaction.
                    transaction_tracker.append_process_results(tablet_tracker.process_table_query(
                        &self.table_accessor,
                        &table_query,
                        &mut tablet,
                    ));
                }
            }
        }
    }

    fn maybe_resolve_tablets(
        &mut self,
        transaction_context: &mut dyn transaction::TabletTransactionContext,
        handler: Box<transaction::ResolveHandler>,
    ) {
        // Initiate resolution of affected tablets if there are enough pending requests.
        let resolve_queries = self
            .request_tracker
            .collect_resolve_queries(&mut self.table_accessor);

        if !resolve_queries.is_empty() {
            transaction_context.resolve(resolve_queries, handler);
        }
    }

    fn maybe_start_transaction(
        &mut self,
        transaction_context: &mut dyn transaction::TabletTransactionContext,
        handler: Box<transaction::ProcessHandler>,
    ) {
        let mut queries = Vec::new();
        let mut tablet_ids = Vec::new();
        // For each of the tablets check if there are enough pending requests and if
        // yes collect corresponding table queries.
        for (tablet_id, tablet_tracker) in &mut self.tablet_trackers {
            if tablet_tracker.collect_process_queries(&mut self.table_accessor, &mut queries) {
                tablet_ids.push(*tablet_id);
            }
        }

        // Initiate transaction if there are tablets that passed minimum pending
        // requests threshold.
        if !queries.is_empty() {
            let mut transaction = transaction_context.start_transaction();
            // Transaction maybe committed once provided handler has been executed.
            transaction.process(queries, handler);

            self.transaction_trackers.insert(
                transaction.get_id(),
                TransactionTracker::create(tablet_ids, transaction),
            );
        }
    }

    fn maybe_commit_transactions(&mut self) {
        // Check if there are any transactions with all local processing completed.
        for transaction_tracker in self.transaction_trackers.values_mut() {
            transaction_tracker.maybe_commit_transaction();
        }
    }

    fn maybe_finalize_or_retry_transactions(&mut self) {
        let mut completed_transactions = Vec::new();
        let mut affected_tablet_ids = Vec::new();
        let mut failed_requests = Vec::new();
        for (transaction_id, transaction_tracker) in &mut self.transaction_trackers {
            if transaction_tracker.maybe_finalize_transaction(
                &mut affected_tablet_ids,
                &mut failed_requests,
                &mut self.responses,
            ) {
                completed_transactions.push(*transaction_id);
            }
        }

        // Mark tablets affected by completed transactions as no longer
        // having a transaction such that a new transaction can be issued
        // against them.
        for tablet_id in affected_tablet_ids {
            if let Some(tablet_tracker) = self.tablet_trackers.get_mut(&tablet_id) {
                tablet_tracker.complete_transaction();
            }
        }

        // Clear all completed transactions and associated state.
        for transaction_id in completed_transactions {
            self.transaction_trackers.remove(&transaction_id);
        }
    }

    fn append_request(&mut self, request: KeyValueRequest) {
        // Stash request until enough pending requests have accumulated.
        self.request_tracker.append_pending_request(request)
    }

    fn take_responses(&mut self) -> Vec<KeyValueResponse> {
        mem::take(&mut self.responses)
    }
}

// Encapsulates logic of how keys are hashed into consistent hashing
// ring and how table query ids are generated.
struct TableAccessor {
    table_name: String,
    query_counter: u64,
}

impl TableAccessor {
    fn create(table_name: String) -> TableAccessor {
        TableAccessor {
            table_name,
            query_counter: 0,
        }
    }

    fn get_name(&self) -> &String {
        &self.table_name
    }

    fn hash_key(&self, key: &String) -> u32 {
        let mut hasher = AHasher::default();
        key.hash(&mut hasher);
        hasher.finish() as u32
    }

    fn get_next_id(&mut self) -> u64 {
        self.query_counter += 1;
        self.query_counter
    }
}

// Tracks requests that are not associated with any tablet yet.
struct RequestTracker {
    min_pending: usize,
    pending_requests: Vec<KeyValueRequest>,
    waiting_resolution_requests: HashMap<u64, Vec<KeyValueRequest>>,
}

impl RequestTracker {
    fn create(min_pending: usize) -> RequestTracker {
        RequestTracker {
            min_pending,
            pending_requests: Vec::new(),
            waiting_resolution_requests: HashMap::new(),
        }
    }

    fn append_pending_request(&mut self, request: KeyValueRequest) {
        // Stash request until enough have accumulated.
        self.pending_requests.push(request)
    }

    fn collect_resolve_queries(
        &mut self,
        table_accessor: &mut TableAccessor,
    ) -> Vec<transaction::TableQuery> {
        let mut queries = Vec::new();

        // If minimum pending requests threshold has been reached, create
        // table query with these requests and resolve which tablets they
        // affect.
        if self.pending_requests.len() >= self.min_pending {
            let query = create_table_query(table_accessor, &self.pending_requests);
            self.waiting_resolution_requests
                .insert(query.get_id(), mem::take(&mut self.pending_requests));
            queries.push(query);
        }

        queries
    }

    fn take_resolved_requests(&mut self, table_query_id: u64) -> Vec<KeyValueRequest> {
        // Resolved requests are taken for processing within a transaction.
        self.waiting_resolution_requests
            .remove(&table_query_id)
            .unwrap_or(Vec::new())
    }
}

// Tracks requests for a particular tablet.
struct TabletTracker {
    min_pending: usize,
    // Indicates if there is an active transaction affecting this tablet.
    has_transaction: bool,
    // Requests that are not part of any transaction and have not been
    // processed. When requested processing pending requests are moved
    // to waiting processing map.
    pending_requests: Vec<KeyValueRequest>,
    // Requests that are part of the current transaction but processing
    // handler have not yet been called. When processed requests are
    // moved to the corresponding transaction tracker.
    waiting_processing_requests: HashMap<u64, Vec<KeyValueRequest>>,
}

impl TabletTracker {
    fn create(min_pending: usize) -> TabletTracker {
        TabletTracker {
            min_pending,
            has_transaction: false,
            pending_requests: Vec::new(),
            waiting_processing_requests: HashMap::new(),
        }
    }

    fn append_pending_requests(&mut self, mut requests: Vec<KeyValueRequest>) {
        // Stash request until enough have accumulated or current transaction
        // has completed.
        self.pending_requests.append(&mut requests)
    }

    fn collect_process_queries(
        &mut self,
        table_accessor: &mut TableAccessor,
        queries: &mut Vec<transaction::TableQuery>,
    ) -> bool {
        // If minimum pending threshold has been reached and there is no
        // active transaction, create table query with these requests to
        // process within a transaction.
        if self.pending_requests.len() >= self.min_pending && !self.has_transaction {
            self.has_transaction = true;
            let query = create_table_query(table_accessor, &self.pending_requests);
            self.waiting_processing_requests
                .insert(query.get_id(), mem::take(&mut self.pending_requests));
            queries.push(query);
            true
        } else {
            false
        }
    }

    fn process_table_query(
        &mut self,
        table_accessor: &TableAccessor,
        table_query: &transaction::TableQuery,
        tablet: &mut transaction::Tablet,
    ) -> Vec<(KeyValueRequest, KeyValueResponse)> {
        // Deserialize tablet contents to execute requests against.
        let mut tablet_contents = TabletContents::decode(tablet.get_contents()).unwrap();

        let mut results = Vec::new();

        // Lookup original requests to be executed via unique table query id.
        if let Some(tablet_requests) = self
            .waiting_processing_requests
            .get_mut(&table_query.get_id())
        {
            let mut tablet_updated = false;
            for request in mem::take(tablet_requests) {
                let (update, response) = match &request {
                    KeyValueRequest::Put(correlation_id, put_request) => (
                        true,
                        Self::process_put_request(
                            *correlation_id,
                            put_request,
                            table_accessor,
                            table_query,
                            &mut tablet_contents,
                        ),
                    ),
                    KeyValueRequest::Get(correlation_id, get_request) => (
                        false,
                        Self::process_get_request(
                            *correlation_id,
                            get_request,
                            table_accessor,
                            table_query,
                            &mut tablet_contents,
                        ),
                    ),
                };
                // Tablet has been updated if put request has been processed.
                tablet_updated |= update && response.is_some();
                // Collect result if request has been processed and stash it otherwise
                // for later processing.
                if response.is_some() {
                    results.push((request, response.unwrap()));
                } else {
                    tablet_requests.push(request);
                }
            }

            // Produce new tablet contents if needed.
            if tablet_updated {
                tablet.set_contents(tablet_contents.encode_to_vec().into());
            }
        }

        results
    }

    fn process_put_request(
        correlation_id: u64,
        put_request: &PutKeyRequest,
        table_accessor: &TableAccessor,
        table_query: &transaction::TableQuery,
        tablet_contents: &mut TabletContents,
    ) -> Option<KeyValueResponse> {
        let key_hash = table_accessor.hash_key(&put_request.key);
        if table_query.get_key_hashes().contains(&key_hash) {
            let existing_value = tablet_contents
                .dictionary
                .insert(put_request.key.clone(), put_request.value.clone());
            Some(KeyValueResponse::Put(
                correlation_id,
                PutKeyResponse {
                    existed: existing_value.is_some(),
                },
            ))
        } else {
            None
        }
    }

    fn process_get_request(
        correlation_id: u64,
        get_request: &GetKeyRequest,
        table_accessor: &TableAccessor,
        table_query: &transaction::TableQuery,
        tablet_contents: &mut TabletContents,
    ) -> Option<KeyValueResponse> {
        let key_hash = table_accessor.hash_key(&get_request.key);
        if table_query.get_key_hashes().contains(&key_hash) {
            let existing_value = tablet_contents.dictionary.get(&get_request.key);
            Some(KeyValueResponse::Get(
                correlation_id,
                GetKeyResponse {
                    existed: existing_value.is_some(),
                    value: existing_value.map_or(Bytes::new(), |v| v.clone()),
                },
            ))
        } else {
            None
        }
    }

    fn complete_transaction(&mut self) {
        self.has_transaction = false;
    }
}

// Tracks requests for a particular transaction.
struct TransactionTracker {
    tablet_ids: Vec<u32>,
    requests: Vec<KeyValueRequest>,
    responses: Vec<KeyValueResponse>,
    transaction: Option<Box<dyn transaction::TabletTransaction>>,
    waiting_commit: Option<Box<dyn transaction::TabletTransactionCommit>>,
}

impl TransactionTracker {
    fn create(
        tablet_ids: Vec<u32>,
        transaction: Box<dyn transaction::TabletTransaction>,
    ) -> TransactionTracker {
        TransactionTracker {
            tablet_ids,
            requests: Vec::new(),
            responses: Vec::new(),
            transaction: Some(transaction),
            waiting_commit: None,
        }
    }

    fn append_process_results(&mut self, results: Vec<(KeyValueRequest, KeyValueResponse)>) {
        // Store orinal requests and local responses until transaction is committed.
        for (request, response) in results {
            self.requests.push(request);
            self.responses.push(response);
        }
    }

    fn maybe_commit_transaction(&mut self) {
        // Commit transaction if all requested processing has completed.
        if self.waiting_commit.is_none()
            && self
                .transaction
                .as_ref()
                .is_some_and(|t| !t.has_pending_process())
        {
            let transaction = mem::take(&mut self.transaction).unwrap();
            self.waiting_commit = Some(transaction.commit());
        }
    }

    fn maybe_finalize_transaction(
        &mut self,
        affected_tablet_ids: &mut Vec<u32>,
        failed_requests: &mut Vec<KeyValueRequest>,
        succeeded_responses: &mut Vec<KeyValueResponse>,
    ) -> bool {
        // If transaction has completed successfully, collect responses. Otherwise
        // collect failed requests for retry.
        if let Some(transaction_outcome) =
            self.waiting_commit.as_mut().and_then(|c| c.check_result())
        {
            match transaction_outcome {
                transaction::TabletTransactionOutcome::Succeeded => {
                    succeeded_responses.append(&mut self.responses)
                }
                transaction::TabletTransactionOutcome::Failed => {
                    failed_requests.append(&mut self.requests)
                }
            }
            affected_tablet_ids.append(&mut self.tablet_ids);
            true
        } else {
            false
        }
    }
}

fn create_table_query(
    table_accessor: &mut TableAccessor,
    requests: &Vec<KeyValueRequest>,
) -> transaction::TableQuery {
    let mut hashes = Vec::new();

    for request in requests {
        let hash = match &request {
            KeyValueRequest::Put(_, put_request) => table_accessor.hash_key(&put_request.key),
            KeyValueRequest::Get(_, get_request) => table_accessor.hash_key(&get_request.key),
        };
        hashes.push(hash);
    }

    transaction::TableQuery::create(
        table_accessor.get_next_id(),
        table_accessor.get_name().clone(),
        hashes,
    )
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use core::default;

    use tcp_runtime::util::raft::create_empty_raft_entry;
    use tcp_tablet_store_service::apps::tablet_store::service::TabletMetadata;

    use super::*;
    use crate::mock::*;
    use mockall::predicate::*;

    const TABLE_NAME: &'static str = "map";
    const TABLET_TRANSACTION_ID_1: u64 = 1;
    const TABLE_QUERY_1: u64 = 1;
    const TABLE_QUERY_2: u64 = 2;
    const TABLET_ID_1: u32 = 1;
    const CORRELATION_ID_1: u64 = 1;
    const CORRELATION_ID_2: u64 = 2;
    const CORRELATION_ID_3: u64 = 3;
    const KEY_1: &'static str = "key 1";
    const KEY_2: &'static str = "key 2";
    const KEY_3: &'static str = "key 3";
    const VALUE_0: &'static str = "value 0";
    const VALUE_1: &'static str = "value 1";
    const VALUE_2: &'static str = "value 2";

    fn create_store(
        min_pending_before_resolve: usize,
        min_pending_before_process: usize,
    ) -> SimpleKeyValueStore {
        SimpleKeyValueStore::create(
            TABLE_NAME.to_string(),
            min_pending_before_resolve,
            min_pending_before_process,
        )
    }

    fn create_table_accessor() -> TableAccessor {
        TableAccessor::create(TABLE_NAME.to_string())
    }

    fn create_put_request(key: &str, value: &str) -> PutKeyRequest {
        PutKeyRequest {
            key: key.to_string(),
            value: Bytes::copy_from_slice(value.as_bytes()),
        }
    }

    fn create_put_response(existed: bool) -> PutKeyResponse {
        PutKeyResponse { existed }
    }

    fn create_get_request(key: &str) -> GetKeyRequest {
        GetKeyRequest {
            key: key.to_string(),
        }
    }

    fn create_get_response(existed: bool, value: &str) -> GetKeyResponse {
        GetKeyResponse {
            existed,
            value: Bytes::copy_from_slice(value.as_bytes()),
        }
    }

    fn create_table_query(
        query_id: u64,
        keys: Vec<String>,
        table_accessor: &TableAccessor,
    ) -> transaction::TableQuery {
        transaction::TableQuery::create(
            query_id,
            TABLE_NAME.to_string(),
            keys.into_iter()
                .map(|k| table_accessor.hash_key(&k))
                .collect(),
        )
    }

    fn create_tablet_descriptor(tablet_id: u32) -> transaction::TabletDescriptor {
        transaction::TabletDescriptor::create(tablet_id, false)
    }

    fn create_tablet(tablet_id: u32, tablet_contents: &TabletContents) -> transaction::Tablet {
        transaction::Tablet::create(
            TabletMetadata {
                tablet_id,
                ..Default::default()
            },
            tablet_contents.encode_to_vec().into(),
        )
    }

    fn create_tablet_contents(key_values: Vec<(String, String)>) -> TabletContents {
        let mut tablet_contents = TabletContents::default();
        for (key, value) in key_values {
            tablet_contents
                .dictionary
                .insert(key, Bytes::copy_from_slice(value.as_bytes()));
        }
        tablet_contents
    }

    struct TabletTransactinoContextBuilder {
        mock_transaction_context: MockTabletTransactionContext,
        resolve_handler: Rc<RefCell<Box<transaction::ResolveHandler>>>,
    }

    impl TabletTransactinoContextBuilder {
        fn new() -> Self {
            Self {
                mock_transaction_context: MockTabletTransactionContext::new(),
                resolve_handler: Rc::new(RefCell::new(Box::new(|_| panic!()))),
            }
        }

        fn expect_resolve(&mut self, queries: Vec<transaction::TableQuery>) -> &mut Self {
            let resolve_handler_clone = self.resolve_handler.clone();
            self.mock_transaction_context
                .expect_resolve()
                .with(eq(queries), always())
                .return_once_st(move |q, h| {
                    *resolve_handler_clone.borrow_mut() = h;
                });
            self
        }

        fn expect_start_transaction(&mut self, transaction: MockTabletTransaction) -> &mut Self {
            self.mock_transaction_context
                .expect_start_transaction()
                .return_once_st(move || Box::new(transaction));
            self
        }

        fn take(
            self,
        ) -> (
            MockTabletTransactionContext,
            Box<transaction::ResolveHandler>,
        ) {
            let resolve_handler = self.resolve_handler;
            (
                self.mock_transaction_context,
                Box::new(move |results| resolve_handler.borrow_mut()(results)),
            )
        }
    }

    struct TabletTransactionBuilder {
        mock_transaction: MockTabletTransaction,
        process_handler: Rc<RefCell<Box<transaction::ProcessHandler>>>,
    }

    impl TabletTransactionBuilder {
        fn new() -> Self {
            Self {
                mock_transaction: MockTabletTransaction::new(),
                process_handler: Rc::new(RefCell::new(Box::new(|_, _| panic!()))),
            }
        }

        fn expect_get_id(&mut self, transaction_id: u64) -> &mut Self {
            self.mock_transaction
                .expect_get_id()
                .return_const(transaction_id);
            self
        }

        fn expect_process(&mut self, queries: Vec<transaction::TableQuery>) -> &mut Self {
            let process_handler_clone = self.process_handler.clone();
            self.mock_transaction
                .expect_process()
                .with(eq(queries), always())
                .return_once_st(move |q, h| {
                    *process_handler_clone.borrow_mut() = h;
                });
            self
        }

        fn expect_has_pending_process(&mut self, has_pending_process: bool) -> &mut Self {
            self.mock_transaction
                .expect_has_pending_process()
                .times(1)
                .return_const(has_pending_process);
            self
        }

        fn expect_commit(&mut self, commit_transaction: MockTabletTransactionCommit) -> &mut Self {
            self.mock_transaction
                .expect_commit()
                .return_once_st(move || Box::new(commit_transaction));
            self
        }

        fn take(self) -> (MockTabletTransaction, Box<transaction::ProcessHandler>) {
            let process_handler = self.process_handler;
            (
                self.mock_transaction,
                Box::new(move |transaction_id, results| {
                    process_handler.borrow_mut()(transaction_id, results)
                }),
            )
        }
    }

    struct TabletTransactionCommitBuilder {
        mock_commit_transaction: MockTabletTransactionCommit,
    }

    impl TabletTransactionCommitBuilder {
        fn new() -> Self {
            Self {
                mock_commit_transaction: MockTabletTransactionCommit::new(),
            }
        }

        fn expect_check_result(
            &mut self,
            transaction_outcome: Option<transaction::TabletTransactionOutcome>,
        ) -> &mut Self {
            self.mock_commit_transaction
                .expect_check_result()
                .times(1)
                .return_once_st(move || transaction_outcome);
            self
        }

        fn take(self) -> MockTabletTransactionCommit {
            self.mock_commit_transaction
        }
    }

    #[test]
    fn test_end_to_end_success() {
        let table_accessor = create_table_accessor();

        let table_query_1 = create_table_query(
            TABLE_QUERY_1,
            vec![KEY_1.to_string(), KEY_2.to_string(), KEY_3.to_string()],
            &table_accessor,
        );

        let table_query_2 = create_table_query(
            TABLE_QUERY_2,
            vec![KEY_1.to_string(), KEY_2.to_string(), KEY_3.to_string()],
            &table_accessor,
        );

        let mut commit_transaction_builder = TabletTransactionCommitBuilder::new();
        commit_transaction_builder
            .expect_check_result(Some(transaction::TabletTransactionOutcome::Succeeded));
        let mut commit_transaction = commit_transaction_builder.take();

        let mut transaction_builder = TabletTransactionBuilder::new();
        transaction_builder
            .expect_get_id(TABLET_TRANSACTION_ID_1)
            .expect_process(vec![table_query_2.clone()])
            .expect_has_pending_process(true)
            .expect_has_pending_process(false)
            .expect_commit(commit_transaction);
        let (mut transaction, mut process_handler) = transaction_builder.take();

        let mut transaction_context_builder = TabletTransactinoContextBuilder::new();
        transaction_context_builder
            .expect_resolve(vec![table_query_1.clone()])
            .expect_start_transaction(transaction);
        let (mut transaction_context, mut resolve_handler) = transaction_context_builder.take();

        let mut store = create_store(3, 3);

        store.process_request(KeyValueRequest::Put(
            CORRELATION_ID_1,
            create_put_request(KEY_1, VALUE_1),
        ));
        store.process_request(KeyValueRequest::Put(
            CORRELATION_ID_2,
            create_put_request(KEY_2, VALUE_2),
        ));
        store.process_request(KeyValueRequest::Get(
            CORRELATION_ID_3,
            create_get_request(KEY_3),
        ));
        store.make_progress(1, &mut transaction_context);

        assert!(store.take_responses().is_empty());

        let tablet_descriptor_1 = create_tablet_descriptor(TABLET_ID_1);

        resolve_handler(vec![(table_query_1.clone(), tablet_descriptor_1.clone())]);

        store.make_progress(2, &mut transaction_context);

        assert!(store.take_responses().is_empty());

        let tablet_contents_1 =
            create_tablet_contents(vec![(KEY_1.to_string(), VALUE_0.to_string())]);
        let mut tablet_1 = create_tablet(TABLET_ID_1, &tablet_contents_1);

        process_handler(
            TABLET_TRANSACTION_ID_1,
            vec![(table_query_2.clone(), &mut tablet_1)],
        );

        store.make_progress(3, &mut transaction_context);

        assert_eq!(
            vec![
                KeyValueResponse::Put(CORRELATION_ID_1, create_put_response(true)),
                KeyValueResponse::Put(CORRELATION_ID_2, create_put_response(false)),
                KeyValueResponse::Get(CORRELATION_ID_3, create_get_response(false, ""))
            ],
            store.take_responses()
        );
    }
}
