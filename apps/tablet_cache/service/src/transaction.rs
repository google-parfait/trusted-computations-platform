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

use alloc::{
    boxed::Box,
    collections::{BTreeMap, BTreeSet},
    rc::Rc,
    string::String,
    vec::Vec,
};
use data::TabletData;
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

pub mod coordinator;
pub mod data;
pub mod manager;
pub mod metadata;
pub mod result;

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
//
// Type parameter T represents a union type for the tablet data representation. For example
// it can be a protobuf message with a oneof representing specific tables.
pub trait TabletTransactionManager<T>: TabletTransactionContext<T> {
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
//
// Type parameter T represents a union type for the tablet data representation. For example
// it can be a protobuf message with a oneof representing specific tables.
pub trait TabletTransactionContext<T> {
    // Requests to map keys in a given table to corresponding tablets.
    // Provided handler will be called once resolution is complete.
    fn resolve(&mut self, queries: Vec<TableQuery>, handler: Box<ResolveHandler>);

    // Starts a new transaction. Multiple concurrent transactions may coexist.
    fn start_transaction(&mut self) -> Box<dyn TabletTransaction<T>>;
}

// Provides succint tablet metadata and contents. Enables transaction to
// update it. If tablet contents has only been read, transaction manager
// will produce a check tablet operation to make sure its version hasn't
// changed. If tablet contens has been updated, transaction manager
// will produce an update tablet operation.
#[derive(Clone)]
//
// Type parameter T represents a union type for the tablet data representation. For example
// it can be a protobuf message with a oneof representing specific tables.
pub struct Tablet<T> {
    metadata: TabletMetadata,
    contents: Option<TabletData<T>>,
    updated_contents: Option<T>,
    is_dirty: bool,
}

impl<T> Tablet<T> {
    pub fn create(tablet_metadata: TabletMetadata) -> Tablet<T> {
        Tablet {
            metadata: tablet_metadata,
            contents: None,
            updated_contents: None,
            is_dirty: false,
        }
    }

    pub fn create_with_contents(tablet_metadata: TabletMetadata, tablet_contents: T) -> Tablet<T> {
        Tablet {
            metadata: tablet_metadata,
            contents: Some(TabletData::create(tablet_contents)),
            updated_contents: None,
            is_dirty: false,
        }
    }

    // Gets tablet id.
    pub fn get_id(&self) -> u32 {
        self.metadata.tablet_id
    }

    fn get_metadata(&self) -> &TabletMetadata {
        &self.metadata
    }

    // Gets metadata describing this tablet.
    fn get_metadata_mut(&mut self) -> &mut TabletMetadata {
        &mut self.metadata
    }

    // Gets tablet contents.
    pub fn get_contents(&self) -> &T {
        self.contents.as_ref().unwrap()
    }

    pub fn set_contents(&mut self, contents: T) {
        self.is_dirty = true;
        self.updated_contents = Some(contents);
    }

    pub fn take_updated_contents(&mut self) -> Option<T> {
        mem::take(&mut self.updated_contents)
    }

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
    key_hashes: BTreeSet<u32>,
}

impl TableQuery {
    pub fn create(query_id: u64, table_name: String, key_hashes: Vec<u32>) -> TableQuery {
        let mut key_hash_set = BTreeSet::new();
        for key_hash in key_hashes {
            key_hash_set.insert(key_hash);
        }
        TableQuery {
            query_id,
            table_name,
            key_hashes: key_hash_set,
        }
    }

    pub fn create_from(&self, key_hashes: Vec<u32>) -> TableQuery {
        Self::create(self.query_id, self.table_name.clone(), key_hashes)
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
    pub fn get_key_hashes(&self) -> &BTreeSet<u32> {
        &self.key_hashes
    }
}

pub type ProcessHandler<T> = dyn FnMut(u64, Vec<(TableQuery, &mut Tablet<T>)>) -> ();

// Represents a tablet processing transaction. Transaction records reads and writes
// made to a set of tablets and then on commit turns them into set of check and
// update tablet ops. Once created the consumer may request several times to
// process tablets where processing may result in updated tablet data. Updated
// tablet will result in an update tablet op, otherwise check tablet op.
//
// Type parameter T represents a union type for the tablet data representation. For example
// it can be a protobuf message with a oneof representing specific tables.
pub trait TabletTransaction<T> {
    fn get_id(&self) -> u64;

    // Requests to process tablets covered by the given query. Essentially the
    // contents for the covered tabelts must be loaded into cache. Once available
    // provided handler can be called to allow consumer read and write tablet data.
    fn process(&mut self, queries: Vec<TableQuery>, handler: Box<ProcessHandler<T>>);

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
