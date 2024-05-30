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
use prost::bytes::Bytes;
use tcp_tablet_store_service::apps::tablet_store::service::TabletMetadata;

use crate::apps::tablet_cache::service::{
    LoadTabletRequest, LoadTabletResponse, StoreTabletRequest, StoreTabletResponse,
    TabletDataStorageStatus,
};

use super::result::ResultHandle;

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

pub struct DefaultTabletDataCache {}

impl DefaultTabletDataCache {
    // Creates new tablet data cache with given capacity. Configured capacity is considered
    // a soft limit. Tablet data cache may grow larger temporarily than requested capacity.
    pub fn create(cache_capacity: u64) -> Self {
        Self {}
    }
}

impl TabletDataCache for DefaultTabletDataCache {
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
