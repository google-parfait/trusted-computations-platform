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

#![cfg(feature = "std")]

extern crate mockall;

use crate::transaction::{
    TableQuery, Tablet, TabletDescriptor, TabletTransaction, TabletTransactionCommit,
    TabletTransactionContext, TabletTransactionOutcome,
};
use mockall::mock;

mock! {
    pub TabletTransactionContext {
    }

    impl TabletTransactionContext for TabletTransactionContext {
        fn resolve(
            &mut self,
            queries: Vec<TableQuery>,
            handler: Box<dyn FnMut(Vec<(TableQuery, TabletDescriptor)>) -> ()>,
        );

        fn start_transaction(&mut self) -> Box<dyn TabletTransaction>;
    }
}

mock! {
    pub TabletTransaction {
    }

    impl TabletTransaction for TabletTransaction {
        fn get_id(&self) -> u64;

        fn process(
            &mut self,
            queries: Vec<TableQuery>,
            handler: Box<dyn FnMut(u64, Vec<(TableQuery, &mut Tablet)>) -> ()>,
        );

        fn has_pending_process(&self) -> bool;

        fn commit(self: Box<Self>) -> Box<dyn TabletTransactionCommit>;

        fn abort(self: Box<Self>);
    }
}

mock! {
    pub TabletTransactionCommit {
    }

    impl TabletTransactionCommit for TabletTransactionCommit {
        fn check_result(&mut self) -> Option<TabletTransactionOutcome>;
    }
}
