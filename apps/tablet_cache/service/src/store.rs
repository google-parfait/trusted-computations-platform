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

use alloc::{rc::Rc, vec::Vec};

use crate::{
    apps::tablet_cache::service::{GetKeyRequest, GetKeyResponse, PutKeyRequest, PutKeyResponse},
    transaction,
};

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

pub struct SimpleKeyValueStore {
    core: Rc<RefCell<SimpleKeyValueStoreCore>>,
}

impl SimpleKeyValueStore {
    pub fn new() -> SimpleKeyValueStore {
        todo!();
    }
}

impl KeyValueStore for SimpleKeyValueStore {
    fn make_progress(
        &mut self,
        instant: u64,
        transaction_context: &mut dyn transaction::TabletTransactionContext,
    ) {
        todo!();
    }

    fn process_request(&mut self, request: KeyValueRequest) {
        todo!()
    }

    fn take_responses(&mut self) -> Vec<KeyValueResponse> {
        todo!()
    }
}

struct SimpleKeyValueStoreCore {}

impl SimpleKeyValueStoreCore {
    fn handle_query_resolve(&mut self, results: Vec<(transaction::TableQuery, u32)>) {
        todo!()
    }

    fn handle_query_process(
        &mut self,
        results: Vec<(transaction::TableQuery, transaction::Tablet)>,
    ) {
        todo!()
    }
}
