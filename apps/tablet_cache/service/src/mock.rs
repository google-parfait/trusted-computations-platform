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

use crate::apps::tablet_cache::service::*;
use crate::transaction::{coordinator::*, data::*, manager::*, metadata::*, result::*, *};
use mockall::mock;
use prost::bytes::Bytes;
use tcp_tablet_store_service::apps::tablet_store::service::*;

mock! {
    pub TabletTransactionContext<T> {
    }

    impl<T> TabletTransactionContext<T> for TabletTransactionContext<T> {
        fn resolve(
            &mut self,
            queries: Vec<TableQuery>,
            handler: Box<dyn FnMut(Vec<(TableQuery, TabletDescriptor)>) -> ()>,
        );

        fn start_transaction(&mut self) -> Box<dyn TabletTransaction<T>>;
    }
}

mock! {
    pub TabletTransaction<T> {
    }

    impl<T> TabletTransaction<T> for TabletTransaction<T> {
        fn get_id(&self) -> u64;

        fn process(
            &mut self,
            queries: Vec<TableQuery>,
            handler: Box<dyn FnMut(u64, Vec<(TableQuery, &mut Tablet<T>)>) -> ()>,
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

mock! {
    pub TabletDataCache<T> {
    }

    impl<T> TabletDataCache<T> for TabletDataCache<T> {
        fn make_progress(&mut self, instant: u64);

        fn load_tablets(
            &mut self,
            metadata: &Vec<TabletMetadata>,
        ) -> ResultHandle<Vec<(TabletMetadata, TabletData<T>)>, TabletDataStorageStatus>;

        fn store_tablets<'a>(
            &mut self,
            data: Vec<(&'a mut TabletMetadata, T)>,
        ) -> ResultHandle<(), TabletDataStorageStatus>;

        fn process_in_message(&mut self, in_message: TabletDataCacheInMessage);

        fn take_out_messages(&mut self) -> Vec<TabletDataCacheOutMessage>;
    }
}

mock! {
    pub TabletMetadataCache {
    }

    impl TabletMetadataCache for TabletMetadataCache {
        fn make_progress(&mut self, instant: u64);

        fn resolve_tablets(
            &mut self,
            queries: &Vec<TableQuery>,
        ) -> ResultHandle<Vec<(TableQuery, TabletMetadata)>, TabletsRequestStatus>;

        fn update_tablet(&mut self, table_name: String, tablet_metadata: TabletMetadata, conflict: bool);

        fn process_in_message(&mut self, in_message: TabletMetadataCacheInMessage);

        fn take_out_messages(&mut self) -> Vec<TabletMetadataCacheOutMessage>;
    }
}

mock! {
    pub TabletTransactionCoordinator<T> {
    }

    impl<T> TabletTransactionCoordinator<T> for TabletTransactionCoordinator<T> {
        fn make_progress(
            &mut self,
            instant: u64,
            metadata_cache: &mut dyn TabletMetadataCache,
            data_cache: &mut dyn TabletDataCache<T>,
        );

        fn process_in_message(&mut self, metadata_cache: &mut dyn TabletMetadataCache, in_message: TabletTransactionCoordinatorInMessage);

        fn take_out_messages(&mut self) -> Vec<TabletTransactionCoordinatorOutMessage>;

        fn create_transaction(&mut self) -> u64;

        fn process_transaction(
            &mut self,
            transaction_id: u64,
            queries: Vec<TableQuery>,
            handler: Box<ProcessHandler<T>>,
        );

        fn has_transaction_pending_process(&self, transaction_id: u64) -> bool;

        fn commit_transaction(&mut self, transaction_id: u64);

        fn abort_transaction(&mut self, transaction_id: u64);

        fn check_transaction_result(&mut self, transaction_id: u64)
            -> Option<TabletTransactionOutcome>;
    }
}
