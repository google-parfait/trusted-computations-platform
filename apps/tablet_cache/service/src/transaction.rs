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

use alloc::{boxed::Box, string::String, vec::Vec};
use prost::bytes::Bytes;
use tcp_tablet_store_service::apps::tablet_store::service::{
    TabletMetadata, TabletsRequest, TabletsResponse,
};

use crate::apps::tablet_cache::service::{
    ExecuteTabletOpsRequest, ExecuteTabletOpsResponse, LoadTabletRequest, LoadTabletResponse,
    StoreTabletRequest, StoreTabletResponse,
};
use hashbrown::HashSet;

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

    // Processes incoming message, which maybe load or store tablet
    // result, outcome of the tablet ops execution.
    fn process_in_message(&mut self, message: InMessage);

    // Takes outgoing messages to be send out, which maybe requests to
    // load or store tablet, execute tablet ops.
    fn take_out_messages(&mut self) -> Vec<OutMessage>;
}

// Provides ability to map keys to tablets and initiate tablet transactions.
pub trait TabletTransactionContext {
    // Requests to map keys in a given table to corresponding tablets.
    // Provided handler will be called once resolution is complete.
    fn resolve(
        &mut self,
        query: TableQuery,
        handler: Box<dyn FnMut(Vec<(TableQuery, TabletDescriptor)>) -> ()>,
    );

    // Starts a new transaction. Multiple concurrent transactions may coexist.
    fn start_transaction(&mut self) -> TabletTransaction;
}

// Provides succint tablet metadata and contents. Enables transaction to
// update it. If tablet contents has only been read, transaction manager
// will produce a check tablet operation to make sure its version hasn't
// changed. If tablet contens has been updated, transaction manager
// will produce an update tablet operation.
#[derive(Default, PartialEq, Debug, Clone)]
pub struct Tablet {}

impl Tablet {
    // Gets tablet id.
    pub fn get_id(&self) -> u32 {
        todo!()
    }

    // Gets tablet contents.
    pub fn get_contents(&self) -> Bytes {
        todo!()
    }

    // Updates tablet contents.
    pub fn set_contents(&mut self, blob: Bytes) {
        todo!()
    }
}

// Provides short description of tablet. Used during key to tablet mapping.
struct TabletDescriptor {}

impl TabletDescriptor {
    // Gets tablet id.
    pub fn get_id(&self) -> u32 {
        todo!()
    }

    // Gets indicator suggesting if tablet contents is currently in cache.
    pub fn cache_ready(&self) -> bool {
        todo!()
    }
}

// Represents a query for a given set of keys (or rather their hashes) in a
// table. Key hashes must be mapped to corresponding tablets and then the
// tablet data must be loaded trhough the cache and passed to the transaction
// for processing.
#[derive(Default, PartialEq, Debug, Clone)]
pub struct TableQuery {}

impl TableQuery {
    pub fn create(table_name: String, key_hashes: Vec<u32>) -> TableQuery {
        todo!()
    }

    // Gets name of the table to query.
    pub fn get_name(&self) -> &String {
        todo!()
    }

    // Gets set of key hashes to query.
    pub fn get_key_hashes(&self) -> &HashSet<u32> {
        todo!()
    }
}

// Represents a tablet processing transaction. Transaction records reads and writes
// made to a set of tablets and then on commit turns them into set of check and
// update tablet ops. Once created the consumer may request several times to
// process tablets where processing may result in updated tablet data. Updated
// tablet will result in an update tablet op, otherwise check tablet op.
#[derive(Default, PartialEq, Debug, Clone)]
pub struct TabletTransaction {}

impl TabletTransaction {
    // Requests to process tablets covered by the given query. Essentially the
    // contents for the covered tabelts must be loaded into cache. Once available
    // provided handler can be called to allow consumer read and write tablet data.
    pub fn process(
        &mut self,
        queries: Vec<TableQuery>,
        handler: Box<dyn FnMut(Vec<(TableQuery, Tablet)>) -> ()>,
    ) {
        todo!()
    }

    // Requests to commit transaction. Essentially all reads and writes recorded
    // during transaction are conveted into tablet ops that will be sent out to
    // the tablet store for execution.
    pub fn commit(self) -> TabletTransactionCommit {
        todo!()
    }

    // Requests to abort transaction. Essentially uncommitted changes including new
    // versions of tablets must be discarded.
    pub fn abort(self) {
        todo!()
    }

    // Indicates if transaction has any pending process requests.
    pub fn has_pending_process(&self) -> bool {
        todo!()
    }
}

// Represents transaction commit handle. Can be used to check status.
#[derive(Default, PartialEq, Debug, Clone)]
pub struct TabletTransactionCommit {}

impl TabletTransactionCommit {
    // Checks the status of the transaction. Return none if no
    // outcome is known and the outcome otherwise.
    pub fn check_result(&mut self) -> Option<TabletTransactionOutcome> {
        todo!()
    }
}

pub enum TabletTransactionOutcome {
    Succeeded,
    Failed,
}

pub struct SimpleTabletTransactionManager {}

impl SimpleTabletTransactionManager {
    pub fn new() -> SimpleTabletTransactionManager {
        SimpleTabletTransactionManager {}
    }
}

impl TabletTransactionContext for SimpleTabletTransactionManager {
    fn resolve(
        &mut self,
        query: TableQuery,
        handler: Box<dyn FnMut(Vec<(TableQuery, TabletDescriptor)>) -> ()>,
    ) {
        todo!()
    }

    fn start_transaction(&mut self) -> TabletTransaction {
        todo!()
    }
}

impl TabletTransactionManager for SimpleTabletTransactionManager {
    fn init(&mut self, capacity: u64) {
        todo!()
    }

    fn take_out_messages(&mut self) -> Vec<OutMessage> {
        todo!()
    }

    fn process_in_message(&mut self, message: InMessage) {
        todo!()
    }
}
