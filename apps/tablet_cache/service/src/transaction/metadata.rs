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

use alloc::vec::Vec;
use tcp_tablet_store_service::apps::tablet_store::service::{
    TabletMetadata, TabletOp, TabletOpResult, TabletsRequestStatus,
};

use super::{result::ResultHandle, TableQuery};

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
    fn update_tablet(&mut self, metadata: TabletMetadata, conflict: bool);

    // Processes incoming messages. Incoming message may contain tablets list responses.
    fn process_in_message(&mut self, in_message: TabletMetadataCacheInMessage);

    // Takes outgoing messages. Outgoing message may contain tablet list requests.
    fn take_out_messages(&mut self) -> Vec<TabletMetadataCacheOutMessage>;
}

pub struct DefaultTabletMetadataCache {}

impl DefaultTabletMetadataCache {
    pub fn create() -> Self {
        Self {}
    }
}

impl TabletMetadataCache for DefaultTabletMetadataCache {
    fn make_progress(&mut self, _instant: u64) {
        todo!()
    }

    fn resolve_tablets(
        &mut self,
        _queries: &Vec<TableQuery>,
    ) -> ResultHandle<Vec<(TableQuery, TabletMetadata)>, TabletsRequestStatus> {
        todo!()
    }

    fn update_tablet(&mut self, _metadata: TabletMetadata, _conflict: bool) {
        todo!()
    }

    fn process_in_message(&mut self, _in_message: TabletMetadataCacheInMessage) {
        todo!()
    }

    fn take_out_messages(&mut self) -> Vec<TabletMetadataCacheOutMessage> {
        todo!()
    }
}
