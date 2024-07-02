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

use alloc::{
    collections::BTreeSet,
    fmt::format,
    string::{String, ToString},
    vec::Vec,
};
use hashbrown::{hash_map::Entry, HashMap, HashSet};
use slog::Logger;
use tcp_runtime::logger::log::create_logger;
use tcp_tablet_store_service::apps::tablet_store::service::{
    tablet_op::{self, Op},
    tablet_op_result, ExecuteTabletOpsRequest, ListTabletOp, ListTabletResult, TabletMetadata,
    TabletOp, TabletOpResult, TabletOpStatus, TabletsRequestStatus,
};

use super::{
    result::{create_eventual_result, ResultHandle, ResultSource},
    TableQuery,
};

#[cfg(feature = "std")]
fn println(msg: String) {
    std::println!("{}", msg);
}

#[cfg(not(feature = "std"))]
fn println(msg: String) {}

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
    // Initializes tablet metadata cache.
    fn init(&mut self, logger: Logger);

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
    fn update_tablet(
        &mut self,
        table_name: String,
        tablet_metadata: TabletMetadata,
        conflict: bool,
    );

    // Processes incoming messages. Incoming message may contain tablets list responses.
    fn process_in_message(&mut self, in_message: TabletMetadataCacheInMessage);

    // Takes outgoing messages. Outgoing message may contain tablet list requests.
    fn take_out_messages(&mut self) -> Vec<TabletMetadataCacheOutMessage>;
}

pub struct DefaultTabletMetadataCache {
    logger: Logger,
    correlation_counter: u64,
    resolve_request_counter: u64,
    tables: HashMap<String, TableMetadata>,
    resolve_requests: HashMap<u64, TabletResolve>,
    out_messages: Vec<TabletMetadataCacheOutMessage>,
}

impl DefaultTabletMetadataCache {
    pub fn create(correlation_counter: u64, table_configs: &HashMap<String, u32>) -> Self {
        let mut tables = HashMap::new();
        for (table_name, region_size) in table_configs {
            tables.insert(
                table_name.clone(),
                TableMetadata::create(table_name.clone(), *region_size),
            );
        }
        Self {
            logger: create_logger(),
            correlation_counter,
            resolve_request_counter: 1,
            tables,
            resolve_requests: HashMap::new(),
            out_messages: Vec::new(),
        }
    }
}

impl TabletMetadataCache for DefaultTabletMetadataCache {
    fn init(&mut self, logger: Logger) {
        self.logger = logger;
    }

    fn make_progress(&mut self, _instant: u64) {
        let mut list_ops = Vec::new();
        for table_metadata in self.tables.values_mut() {
            table_metadata.prepare_list_op(&mut list_ops);
        }

        if !list_ops.is_empty() {
            self.correlation_counter += 1;
            self.out_messages
                .push(TabletMetadataCacheOutMessage::ListRequest(
                    self.correlation_counter,
                    list_ops,
                ));
        }
    }

    fn resolve_tablets(
        &mut self,
        queries: &Vec<TableQuery>,
    ) -> ResultHandle<Vec<(TableQuery, TabletMetadata)>, TabletsRequestStatus> {
        self.resolve_request_counter += 1;
        let (resolve_request, resolve_handle) =
            TabletResolve::create(self.resolve_request_counter, queries, &mut self.tables);
        self.resolve_requests
            .insert(self.resolve_request_counter, resolve_request);

        resolve_handle
    }

    fn update_tablet(
        &mut self,
        table_name: String,
        tablet_metadata: TabletMetadata,
        conflict: bool,
    ) {
        if let Some(table_metadata) = self.tables.get_mut(&table_name) {
            table_metadata.update_tablet(tablet_metadata, conflict);
        }
    }

    fn process_in_message(&mut self, in_message: TabletMetadataCacheInMessage) {
        match in_message {
            TabletMetadataCacheInMessage::ListResponse(correlation_id, list_op_results) => {
                for list_op_result in list_op_results {
                    if let Some(tablet_op_result::OpResult::ListTablet(list_tablet_result)) =
                        list_op_result.op_result
                    {
                        if let Some(table_metadata) =
                            self.tables.get_mut(&list_op_result.table_name)
                        {
                            let op_succeeded =
                                list_op_result.status == TabletOpStatus::Succeeded as i32;

                            // Update tablets covered by the region.
                            let (table_region_idx, resolve_requests_to_notify) = table_metadata
                                .update_region(
                                    list_tablet_result.tablet_id_from,
                                    if op_succeeded {
                                        Some(list_tablet_result.tablets)
                                    } else {
                                        None
                                    },
                                );
                            // Notify interested resolve requests.
                            for resolve_request_id in resolve_requests_to_notify {
                                if let Some(resolve_request) =
                                    self.resolve_requests.get_mut(&resolve_request_id)
                                {
                                    resolve_request.process_results_fresh(
                                        &list_op_result.table_name,
                                        table_region_idx,
                                        table_metadata,
                                    );
                                }
                            }
                        }
                    } else {
                        panic!("Unexpected op result, expected list op results.");
                    }
                }
            }
        }
    }

    fn take_out_messages(&mut self) -> Vec<TabletMetadataCacheOutMessage> {
        mem::take(&mut self.out_messages)
    }
}

// Tracks state of the table region cache.
enum TableRegionState {
    Stale(Vec<u64>, bool),
    Fresh,
}

// Maintains cache for a contiguous region of a consistent hashing ring for a table.
// Regions
struct TableRegion {
    // Current state of the region.
    state: TableRegionState,
    // Ids of the tablets that are responsible for the keys from this region.
    tablet_ids: BTreeSet<u32>,
}

impl TableRegion {
    fn create() -> Self {
        Self {
            state: TableRegionState::Stale(Vec::new(), false),
            tablet_ids: BTreeSet::new(),
        }
    }

    // Prepare list tablets op if the region is in stale state and there is no indicator
    // that the op has been prepared before. Provided from and to range identifies the
    // region boundaries.
    fn maybe_prepare_list_op(&mut self, region_from: u32, region_to: u32) -> Option<tablet_op::Op> {
        if let TableRegionState::Stale(resolve_requests, prepared_op) = &mut self.state {
            if !*prepared_op && !resolve_requests.is_empty() {
                *prepared_op = true;
                return Some(tablet_op::Op::ListTablet(ListTabletOp {
                    tablet_id_from: region_from,
                    tablet_id_to: region_to,
                }));
            }
        }
        None
    }

    // Gets list of tablets ids that are responsible for the keys in this region.
    // If the region is stale, then none is returned.
    fn maybe_fresh_tablet_ids(&self) -> Option<&BTreeSet<u32>> {
        match self.state {
            TableRegionState::Stale(_, _) => None,
            TableRegionState::Fresh => Some(&self.tablet_ids),
        }
    }

    // Marks region as stale and in the process resets prepared op indicator.
    // Used either when the region transition from fresh to stale state, or
    // when op processing resulted in an error and needs to be retried.
    fn mark_stale(&mut self) {
        self.state = TableRegionState::Stale(
            match &mut self.state {
                TableRegionState::Stale(resolve_requests, _) => mem::take(resolve_requests),
                TableRegionState::Fresh => Vec::new(),
            },
            false,
        );
        self.tablet_ids.clear();
    }

    // Marks region as fresh and in the process collects resolve requests that are
    // awaiting notification for the region to become fresh.
    fn mark_fresh(&mut self, tablet_ids: Vec<u32>, resolve_requests_to_notify: &mut Vec<u64>) {
        if let TableRegionState::Stale(registered_resolve_requests, _) = &self.state {
            for registered_resolve_request in registered_resolve_requests {
                resolve_requests_to_notify.push(*registered_resolve_request);
            }
        }
        self.state = TableRegionState::Fresh;
        self.tablet_ids = BTreeSet::from_iter(tablet_ids.into_iter());
    }

    // Registers resolve request to be notified when region becomes fresh.
    fn register_pending_query(&mut self, resolve_request_id: u64) {
        match &mut self.state {
            TableRegionState::Stale(resolve_request_ids, _) => {
                resolve_request_ids.push(resolve_request_id);
            }
            TableRegionState::Fresh => {
                panic!("Pending queries can only be registered when region is not fresh");
            }
        }
    }
}

// Tracks cached tablet metadata for a particular table.
struct TableMetadata {
    table_name: String,
    // Controls the size of the contiguous regions of the consistent hashing ring
    // storing tablets for the table.
    region_size: u32,
    // Maps the index of the hash region to its state.
    regions: HashMap<u32, TableRegion>,
    // Maps tablet id to its metadata. Only the latest known version of the
    // tablet metadata is stored.
    tablets: HashMap<u32, TabletMetadata>,
}

impl TableMetadata {
    // Prefills table regions and marks them all as stale.
    fn create(table_name: String, region_size: u32) -> Self {
        let regions_count = u32::MAX / region_size;
        let mut regions = HashMap::with_capacity(regions_count as usize);
        for region_idx in 0..regions_count {
            // Regions are identified by the starting position on the consistent hashing ring.
            regions.insert(region_idx, TableRegion::create());
        }
        Self {
            table_name,
            region_size,
            regions,
            tablets: HashMap::new(),
        }
    }

    fn prepare_list_op(&mut self, list_ops: &mut Vec<TabletOp>) {
        for (table_region_idx, table_region) in &mut self.regions {
            let (table_region_from, table_region_to) =
                Self::compute_table_region_bounds(self.region_size, *table_region_idx);
            if let Some(list_op) =
                table_region.maybe_prepare_list_op(table_region_from, table_region_to)
            {
                list_ops.push(TabletOp {
                    table_name: self.table_name.clone(),
                    op: Some(list_op),
                })
            }
        }
    }

    fn insert_latest_tablet(
        tablets: &mut HashMap<u32, TabletMetadata>,
        tablet_metadata: TabletMetadata,
    ) {
        match tablets.entry(tablet_metadata.tablet_id) {
            Entry::Occupied(mut e) => {
                let latest_tablet_metadata = e.get_mut();
                if latest_tablet_metadata.tablet_version < tablet_metadata.tablet_version {
                    *latest_tablet_metadata = tablet_metadata;
                }
            }
            Entry::Vacant(mut e) => {
                e.insert(tablet_metadata);
            }
        }
    }

    fn update_tablet(&mut self, tablet_metadata: TabletMetadata, conflict: bool) {
        let tablet_id = tablet_metadata.tablet_id;
        Self::insert_latest_tablet(&mut self.tablets, tablet_metadata);

        let table_region_idx = Self::map_table_region(self.region_size, tablet_id);
        if let Some(table_region) = self.regions.get_mut(&table_region_idx) {
            if conflict {
                table_region.mark_stale();
            }
        }
    }

    fn update_region(
        &mut self,
        table_region_start: u32,
        tablets: Option<Vec<TabletMetadata>>,
    ) -> (u32, Vec<u64>) {
        let table_region_idx = Self::map_table_region(self.region_size, table_region_start);
        let mut resolve_requests_to_notify = Vec::new();
        if let Some(table_region) = self.regions.get_mut(&table_region_idx) {
            if let Some(tablets) = tablets {
                let mut tablet_ids = Vec::new();
                // Store latest version of the tablet metadata.
                for tablet_metadata in tablets {
                    tablet_ids.push(tablet_metadata.tablet_id);
                    Self::insert_latest_tablet(&mut self.tablets, tablet_metadata);
                }
                // Mark region fresh and notify registered resolve requests.
                table_region.mark_fresh(tablet_ids, &mut resolve_requests_to_notify);
            } else {
                // Mark region stale again due to a failed list op and therefore trigger
                // another list op to be sent to the Tablet Store.
                table_region.mark_stale();
            }
        }
        (table_region_idx, resolve_requests_to_notify)
    }

    fn register_pending_query(&mut self, resolve_request_id: u64, table_region_idx: u32) {
        if let Some(table_region) = self.regions.get_mut(&table_region_idx) {
            table_region.register_pending_query(resolve_request_id);
        }
    }

    fn try_resolve_pending_query(
        &self,
        table_region_idx: u32,
        table_query: &TableQuery,
    ) -> Option<Vec<(TableQuery, TabletMetadata)>> {
        if let Some(table_region) = self.regions.get(&table_region_idx) {
            if let Some(fresh_tablet_ids) = table_region.maybe_fresh_tablet_ids() {
                // Note that tablet ids must contain at least one entry. It may be the only entry on
                // the whole consistent hashing ring.
                let mut tablet_ids_it = fresh_tablet_ids.iter().cycle();
                let mut curr_tablet_id = *tablet_ids_it.next().unwrap();
                let mut curr_key_hashes = Vec::new();
                // Merge two sorted lists of tablet ids and key hashes. Key hashes are handled by
                // a tablet that is clockwise on the consistent hashing ring.
                let mut resolve_result = Vec::new();
                for key_hash in table_query.get_key_hashes() {
                    if *key_hash > curr_tablet_id {
                        if !curr_key_hashes.is_empty() {
                            resolve_result.push((
                                table_query.create_from(mem::take(&mut curr_key_hashes)),
                                self.tablets.get(&curr_tablet_id).unwrap().clone(),
                            ));
                        }
                        curr_tablet_id = *tablet_ids_it.next().unwrap();
                    } else {
                        curr_key_hashes.push(*key_hash);
                    }
                }
                if !curr_key_hashes.is_empty() {
                    resolve_result.push((
                        table_query.create_from(mem::take(&mut curr_key_hashes)),
                        self.tablets.get(&curr_tablet_id).unwrap().clone(),
                    ));
                }

                Some(resolve_result)
            } else {
                None
            }
        } else {
            panic!("Unexpected tablet region index");
        }
    }

    // Splits original tablet query into multiple where each is mapped to
    // a single region.
    fn split_and_map_query(&self, query: &TableQuery, result: &mut Vec<(TableQuery, u32)>) {
        if query.get_key_hashes().is_empty() {
            return;
        }

        // Compute start region.
        let mut region_idx =
            Self::map_table_region(self.region_size, *query.get_key_hashes().first().unwrap());
        let (mut region_start, mut region_end) =
            Self::compute_table_region_bounds(self.region_size, region_idx);
        let mut region_key_hashes = Vec::new();

        // Split original table query and map it to a region start position.
        for key_hash in query.get_key_hashes() {
            while *key_hash > region_end {
                if !region_key_hashes.is_empty() {
                    result.push((
                        query.create_from(mem::take(&mut region_key_hashes)),
                        region_idx,
                    ));
                }
                region_idx += 1;
                (region_start, region_end) =
                    Self::compute_table_region_bounds(self.region_size, region_idx);
            }

            region_key_hashes.push(*key_hash);
        }

        if !region_key_hashes.is_empty() {
            result.push((query.create_from(region_key_hashes), region_idx));
        }
    }

    fn map_table_region(region_size: u32, hash_value: u32) -> u32 {
        hash_value / region_size
    }

    // Computes lower and upper inclusive bounds of the region with given id.
    fn compute_table_region_bounds(region_size: u32, region_idx: u32) -> (u32, u32) {
        let region_start = region_idx * region_size;
        // Compute inclusive upper bound and do not overflow in case of the very
        // last region.
        let region_end = if region_start > u32::MAX - region_size {
            u32::MAX
        } else {
            region_start + region_size - 1
        };
        (region_start, region_end)
    }
}

// Tracks pending request to resolve tablets.
struct TabletResolve {
    result_source: ResultSource<Vec<(TableQuery, TabletMetadata)>, TabletsRequestStatus>,
    // Maps table name and region index to a pending table query.
    pending_table_queries: HashMap<(String, u32), TableQuery>,
    // Maps table name and tablet id to resolve result builder.
    results: HashMap<(String, u32), TabletResolveResult>,
}

impl TabletResolve {
    // Creates new tablet resolve request with already pre-split per table and region queries.
    fn create(
        resolve_request_id: u64,
        queries: &Vec<TableQuery>,
        tables: &mut HashMap<String, TableMetadata>,
    ) -> (
        Self,
        ResultHandle<Vec<(TableQuery, TabletMetadata)>, TabletsRequestStatus>,
    ) {
        let (result_handle, result_source) =
            create_eventual_result::<Vec<(TableQuery, TabletMetadata)>, TabletsRequestStatus>();

        let mut tablet_resolve = Self {
            result_source,
            pending_table_queries: HashMap::new(),
            results: HashMap::new(),
        };

        // Split original table queries based on region boundaries.
        let mut split_queries = Vec::new();
        for query in queries {
            tables
                .get(query.get_table_name())
                .unwrap()
                .split_and_map_query(query, &mut split_queries);
        }

        // Try to resolve each of the resulting queries against the current
        // state of the corresponding region.
        for (table_query, table_region_idx) in split_queries {
            let mut table_metadata = tables.get_mut(table_query.get_table_name()).unwrap();
            if let Some(table_query_result) =
                table_metadata.try_resolve_pending_query(table_region_idx, &table_query)
            {
                // If region state is currently fresh, accumulate partial resolve results.
                tablet_resolve.append_results(table_query_result);
            } else {
                // Otherwise register pending query and wait for the corresponding region
                // state to become fresh.
                table_metadata.register_pending_query(resolve_request_id, table_region_idx);
                tablet_resolve.pending_table_queries.insert(
                    (table_query.get_table_name().clone(), table_region_idx),
                    table_query,
                );
            }
        }
        // Try to produce results if there are no more pending queries.
        tablet_resolve.maybe_resolve_results();

        (tablet_resolve, result_handle)
    }

    fn append_results(&mut self, table_query_result: Vec<(TableQuery, TabletMetadata)>) {
        for (table_query, tablet_metadata) in table_query_result {
            let result = self
                .results
                .entry((
                    table_query.get_table_name().clone(),
                    tablet_metadata.tablet_id,
                ))
                .or_insert(TabletResolveResult::create(
                    table_query.get_id(),
                    table_query.get_table_name().clone(),
                    tablet_metadata,
                ));
            result.append_key_hashes(table_query.get_key_hashes());
        }
    }

    fn maybe_resolve_results(&mut self) {
        if self.pending_table_queries.is_empty() {
            let mut results = Vec::new();
            for (_, tablet_resolve_result) in mem::take(&mut self.results) {
                results.push(tablet_resolve_result.take_result());
            }
            self.result_source.set_result(results);
        }
    }

    fn process_results_fresh(
        &mut self,
        table_name: &String,
        table_region_idx: u32,
        table_metadata: &TableMetadata,
    ) {
        // Remove pending query now that corresponding region state is fresh.
        if let Some(pending_table_query) = self
            .pending_table_queries
            .remove(&(table_name.clone(), table_region_idx))
        {
            // Resolve pending query into a number of sub-queries that are mapped
            // to particular tablets.
            if let Some(table_query_result) =
                table_metadata.try_resolve_pending_query(table_region_idx, &pending_table_query)
            {
                // Append resolved results so that they can be propagated to the result handle
                // holder.
                self.append_results(table_query_result);
            } else {
                panic!("The query is not resolved whereas the table region is fresh");
            }
        }

        // Try to produce results if there are no more pending queries.
        self.maybe_resolve_results();
    }
}

struct TabletResolveResult {
    table_query_id: u64,
    table_name: String,
    tablet_metadata: TabletMetadata,
    key_hashes: Vec<u32>,
}

impl TabletResolveResult {
    fn create(table_query_id: u64, table_name: String, tablet_metadata: TabletMetadata) -> Self {
        Self {
            table_query_id,
            table_name,
            tablet_metadata,
            key_hashes: Vec::new(),
        }
    }

    fn append_key_hashes(&mut self, key_hashes: &BTreeSet<u32>) {
        for key_hash in key_hashes {
            self.key_hashes.push(*key_hash);
        }
    }

    fn take_result(self) -> (TableQuery, TabletMetadata) {
        (
            TableQuery::create(self.table_query_id, self.table_name, self.key_hashes),
            self.tablet_metadata,
        )
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use tcp_proto::runtime::endpoint::in_message;

    use super::*;

    const TABLE_NAME: &'static str = "A";
    const TABLE_QUERY_1: u64 = 1;
    const TABLE_REGION_SIZE: u32 = u32::MAX / 8;

    const KEY_HASH_1: u32 = 1;
    const KEY_HASH_2: u32 = 2;
    const KEY_HASH_3: u32 = TABLE_REGION_SIZE + 1;
    const KEY_HASH_4: u32 = TABLE_REGION_SIZE + 2;

    const TABLET_ID_1: u32 = KEY_HASH_2 + 1;
    const TABLET_VERSION_1: u32 = 3;
    const TABLET_ID_2: u32 = KEY_HASH_4 + 1;
    const TABLET_VERSION_2: u32 = 5;

    const CORRELATION_ID_1: u64 = 1;
    const CORRELATION_ID_2: u64 = 2;

    fn create_tablet_metadata_cache(
        table_name: String,
        region_size: u32,
    ) -> DefaultTabletMetadataCache {
        let mut table_configs = HashMap::new();
        table_configs.insert(table_name, region_size);
        DefaultTabletMetadataCache::create(0, &table_configs)
    }

    fn create_table_query(query_id: u64, table_name: String, key_hashes: Vec<u32>) -> TableQuery {
        TableQuery::create(query_id, TABLE_NAME.to_string(), key_hashes)
    }

    fn create_tablet_metadata(tablet_id: u32, tablet_version: u32) -> TabletMetadata {
        TabletMetadata {
            tablet_id,
            tablet_version,
            ..Default::default()
        }
    }

    fn create_list_op(table_name: String, tablet_id_from: u32, tablet_id_to: u32) -> TabletOp {
        TabletOp {
            table_name,
            op: Some(tablet_op::Op::ListTablet(ListTabletOp {
                tablet_id_from,
                tablet_id_to,
            })),
        }
    }

    fn create_list_op_result(
        table_name: String,
        tablet_id_from: u32,
        tablet_id_to: u32,
        tablet_op_status: TabletOpStatus,
        tablets: Vec<TabletMetadata>,
    ) -> TabletOpResult {
        TabletOpResult {
            table_name,
            status: tablet_op_status.into(),
            op_result: Some(tablet_op_result::OpResult::ListTablet(ListTabletResult {
                tablet_id_from,
                tablet_id_to,
                tablets,
            })),
        }
    }

    struct TabletMetadataCacheLoop {
        tablet_metadata_cache: DefaultTabletMetadataCache,
    }

    impl TabletMetadataCacheLoop {
        fn create(tablet_metadata_cache: DefaultTabletMetadataCache) -> Self {
            Self {
                tablet_metadata_cache,
            }
        }

        fn get_mut(&mut self) -> &mut DefaultTabletMetadataCache {
            &mut self.tablet_metadata_cache
        }

        fn execute_step(
            &mut self,
            instant: u64,
            in_message: Option<TabletMetadataCacheInMessage>,
        ) -> Vec<TabletMetadataCacheOutMessage> {
            self.tablet_metadata_cache.make_progress(instant);

            let out_messages = self.tablet_metadata_cache.take_out_messages();

            if in_message.is_some() {
                self.tablet_metadata_cache
                    .process_in_message(in_message.unwrap());
            }

            out_messages
        }
    }

    #[test]
    fn test_resolve_tablets_success() {
        let tablet_metadata_cache =
            create_tablet_metadata_cache(TABLE_NAME.to_string(), TABLE_REGION_SIZE);
        let mut tablet_metadata_cache_loop = TabletMetadataCacheLoop::create(tablet_metadata_cache);

        let table_query_1 = create_table_query(
            TABLE_QUERY_1,
            TABLE_NAME.to_string(),
            vec![KEY_HASH_1, KEY_HASH_2, KEY_HASH_3, KEY_HASH_4],
        );

        let resolve_result_1 = tablet_metadata_cache_loop
            .get_mut()
            .resolve_tablets(&vec![table_query_1.clone()]);

        assert!(resolve_result_1.check_result().is_none());

        assert_eq!(
            vec![TabletMetadataCacheOutMessage::ListRequest(
                CORRELATION_ID_1,
                vec![
                    create_list_op(TABLE_NAME.to_string(), 0, TABLE_REGION_SIZE - 1),
                    create_list_op(
                        TABLE_NAME.to_string(),
                        TABLE_REGION_SIZE,
                        TABLE_REGION_SIZE * 2 - 1
                    )
                ]
            )],
            tablet_metadata_cache_loop.execute_step(
                1,
                Some(TabletMetadataCacheInMessage::ListResponse(
                    CORRELATION_ID_1,
                    vec![
                        create_list_op_result(
                            TABLE_NAME.to_string(),
                            0,
                            TABLE_REGION_SIZE - 1,
                            TabletOpStatus::Succeeded,
                            vec![create_tablet_metadata(TABLET_ID_1, TABLET_VERSION_1)]
                        ),
                        create_list_op_result(
                            TABLE_NAME.to_string(),
                            TABLE_REGION_SIZE,
                            TABLE_REGION_SIZE * 2 - 1,
                            TabletOpStatus::Succeeded,
                            vec![create_tablet_metadata(TABLET_ID_2, TABLET_VERSION_2)]
                        )
                    ]
                ))
            )
        );

        assert!(tablet_metadata_cache_loop.execute_step(2, None).is_empty());

        assert_eq!(
            Some(Ok(vec![
                (
                    create_table_query(
                        TABLE_QUERY_1,
                        TABLE_NAME.to_string(),
                        vec![KEY_HASH_1, KEY_HASH_2],
                    ),
                    create_tablet_metadata(TABLET_ID_1, TABLET_VERSION_1)
                ),
                (
                    create_table_query(
                        TABLE_QUERY_1,
                        TABLE_NAME.to_string(),
                        vec![KEY_HASH_3, KEY_HASH_4],
                    ),
                    create_tablet_metadata(TABLET_ID_2, TABLET_VERSION_2)
                )
            ])),
            resolve_result_1.check_result()
        );
    }
}
