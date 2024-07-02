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

use core::{cell::RefCell, mem, ops::Deref};

use alloc::{
    boxed::Box,
    format,
    rc::Rc,
    string::{String, ToString},
    vec::Vec,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use hashbrown::{
    hash_map::Entry::{Occupied, Vacant},
    HashMap, HashSet,
};
use prost::bytes::Bytes;
use sha2::{Digest, Sha256};
use slog::Logger;
use tcp_runtime::logger::log::create_logger;
use tcp_tablet_store_service::apps::tablet_store::service::TabletMetadata;

use crate::apps::tablet_cache::service::{
    LoadTabletRequest, LoadTabletResponse, StoreTabletRequest, StoreTabletResponse,
    TabletDataStorageStatus,
};

use super::result::{create_eventual_result, create_result_from_error, ResultHandle, ResultSource};

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
//
// Type parameter T represents a variant type for the deserialized tablet data. For example
// it can be a protobuf message with a oneof representing specific tables or a Rust enum type
// where each variant represents specific table. Note that a single cache instance is used
// to store tablets for various tables.
pub trait TabletDataCache<T> {
    // Initializes tablet data cache.
    fn init(&mut self, logger: Logger);

    // Advances internal state machine of the tablet data cache.
    fn make_progress(&mut self, instant: u64);

    // Requests to load and cache tablet data described by provided metadata. Returned result
    // handle must be checked for the operation completion. The operation is completed only when
    // all requested tablets are loaded. Returned tablet data is already decrypted and verified,
    // along with its metadata.
    fn load_tablets(
        &mut self,
        metadata: &Vec<TabletMetadata>,
    ) -> ResultHandle<Vec<(TabletMetadata, TabletData<T>)>, TabletDataStorageStatus>;

    // Requests to store and cache provided tablet data. Returned result handle must be
    // checked for the operation completion. The operation is completed only when all requested
    // tablets are stored. The tablet data must be provided not-encrypted along with
    // the metadata of the preivous version of the tablet. Provided metadata is updated to
    // reflect new version of the tablet.
    fn store_tablets(
        &mut self,
        data: Vec<(&mut TabletMetadata, T)>,
    ) -> ResultHandle<(), TabletDataStorageStatus>;

    // Processes incoming messages. Message may contain load or store tablet responses.
    fn process_in_message(&mut self, in_message: TabletDataCacheInMessage);

    // Takes outgoing messages. Message may contain load or store tablet requests.
    fn take_out_messages(&mut self) -> Vec<TabletDataCacheOutMessage>;
}

// Provides a readonly shared access to the strongly typed tablet data.
// Type parameter T represents a variant type for the deserialized tablet data.
#[derive(Debug, PartialEq)]
pub struct TabletData<T> {
    data: Rc<T>,
}

impl<T> TabletData<T> {
    pub fn create(t: T) -> Self {
        Self { data: Rc::new(t) }
    }
}

impl<T> Deref for TabletData<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        self.data.as_ref()
    }
}

impl<T> Clone for TabletData<T> {
    fn clone(&self) -> Self {
        Self {
            data: self.data.clone(),
        }
    }
}

// Represents serializer that is used to serialize and deserialize tablet
// data during storing and loading, to measure tablet data size for the
// purpose of tablet data cache bookkeeping.
// Type parameter T represents a variant type for the deserialized tablet data.
pub trait TabletDataSerializer<T> {
    fn serialize(&self, tablet_value: &T) -> Result<Bytes, ()>;

    fn deserialize(&self, table_name: &String, tablet_data: Bytes) -> Result<T, ()>;

    fn get_size(&self, tablet_value: &T) -> usize;
}

// Serializer for the tablet data represented by raw bytes.
pub struct BytesTabletDataSerializer {}

impl TabletDataSerializer<Bytes> for BytesTabletDataSerializer {
    fn serialize(&self, tablet_value: &Bytes) -> Result<Bytes, ()> {
        Ok(tablet_value.clone())
    }

    fn deserialize(&self, table_name: &String, tablet_data: Bytes) -> Result<Bytes, ()> {
        Ok(tablet_data)
    }

    fn get_size(&self, tablet_value: &Bytes) -> usize {
        tablet_value.len()
    }
}

// Formats blob uri using a combination of tablet id, tablet version and blob hash to construct
// a unique tablet blob uri.
fn format_blob_uri(tablet_id: u32, tablet_version: u32, blob_hash: Bytes) -> String {
    format!(
        "{}_{}_{}",
        tablet_id,
        tablet_version,
        URL_SAFE_NO_PAD.encode(&blob_hash)
    )
}

// Tablet cache id:
//   * uri - data storage uri that uniquely identifies tablet data. Note that tablet
// id and version is not sufficiently unique in cache context as concurrent transactions
// may attempt to create the same version of the tablet but different data. Therefore
// we rely on uniqueness of the storage uris.
//
// Tablet cache entry attributes:
//   * tablet cache id - uniquely identifies tablet data in the cache.
//   * tablet metadata - the metadata describing the tablet.
//   * operation (load / store / cache / error) - current operation being executed against the
// tablet where load and store operations contain respective correlation ids, cache
// operation contains actual data and tablet cache descriptor.
//   * tablet batch ids - list of tablet batches that are interested in this tablet.
//
// Tablet cache descriptor attributes:
//   * last access time (instant) - timestamp when tablet has been last accessed.
//   * locked (true / false) - locked means tablet is being referenced by a pending
// tablet batch operation and cannot be evicted from cache. Must be updated when status
// of corresponding tablet batch operation changes.
//
// Tablet cache map attributes:
//   * tablet cache id -> tablet cache entry
//
// Tablet batch attributes:
//   * tablet batch id - uniquely identifies a batch of tablets that are loaded or
// stored together.
//   * tablet cache ids - list of ids for the tablets that are part of the batch.
//   * operation (load / store) - current operation being executed for the tablet
// batch and containing corresponding result source.
//   * num remaining tablets - number of tablets that are not yet cached. Once all
// tablets have been cached the operation associated with the batch can be completed
// and tablet batch association can be removed.
//
// Tablet batch map attributes:
//   * tablet batch id -> tablet batch
//
// Tablet op map attributes:
//   * correlation id -> tablet cache id
//
// Loading tablet batch (happens in response to external call to load tablets):
//   * Generate new tablet batch id.
//   * Generate cache id for each tablet from its metadata.
//   * Get or insert a tablet cache entry based on tablet cache id.
//   * Register tablet batch id in tablet cache entry so that the tablet cache entry
// cannot be evicted from cache while batch is being loaded.
//   * Consult with the tablet cache policy which if any tablet cache entries must
// now be evicted and evict them.
//   * Count and remember number of not yet cached tablets in the tablet batch.
//
// Storing tablet batch (happens in response to external call to store tablets):
//   * Generate new tablet batch id.
//   * Generate new version of the metadata for each of the affected tablets.
//   * Generate cache id for each tablet from its new metadata.
//   * Get or insert a tablet cache entry based on tablet cache id.
//   * Register tablet batch id in tablet cache entry so that the tablet cache entry
// cannot be evicted from cache while batch is being stored.
//   * Consult with the tablet cache policy which if any tablet cache entries must
// now be evicted.
//   * Count and remember number of not yet cached tablets in the tablet batch.
//
// Processing tablet cache messages (happens in response to incoming messages):
//   * Lookup tablet cache entry id using correlation id in the tablet op map.
//   * Process incoming message in the context of looked up tablet cache entry.
// If incoming message request represents success switch entry to the cache
// operation, otherwise to error.
//   * Notify all tablet cache batches registered with the tablet cache entry
// about state change and allow the batch to react to it. Tablet batch may complete
// successfully if all tablets have been cached, unsuccessfully if loading or storing
// has failed, or remain uncompleted if more tablets must be cached.
//
// Maintaining tablet cache (happens in response to making progress):
//   * Consult with the tablet data cache policy if any of the cache entries must be
// evicted.
//   * Evict indicated cache entries.
//
// Type parameter T represents a variant type for the deserialized tablet data.
pub struct DefaultTabletDataCache<T> {
    logger: Logger,
    correlation_counter: u64,
    batch_counter: u64,
    cache_capacity: u64,
    tablet_serializer: Box<dyn TabletDataSerializer<T>>,
    tablet_cache_policy: Box<dyn TabletDataCachePolicy<T>>,
    tablet_cache_entries: HashMap<TabletCacheKey, TabletCacheEntry<T>>,
    tablet_batches: HashMap<u64, TabletBatch<T>>,
    tablet_operations: HashMap<u64, TabletCacheKey>,
    out_messages: Vec<TabletDataCacheOutMessage>,
}

impl<T> DefaultTabletDataCache<T> {
    // Creates new tablet data cache with given capacity. Configured capacity is considered
    // a soft limit. Tablet data cache may grow larger temporarily than requested capacity.
    pub fn create(
        correlation_counter: u64,
        cache_capacity: u64,
        tablet_serializer: Box<dyn TabletDataSerializer<T>>,
        tablet_cache_policy: Box<dyn TabletDataCachePolicy<T>>,
    ) -> Self {
        Self {
            logger: create_logger(),
            correlation_counter,
            batch_counter: 0,
            cache_capacity,
            tablet_serializer,
            tablet_cache_policy,
            tablet_cache_entries: HashMap::new(),
            tablet_batches: HashMap::new(),
            tablet_operations: HashMap::new(),
            out_messages: Vec::new(),
        }
    }
}

impl<T> DefaultTabletDataCache<T> {
    fn register_pending_cache_entries(
        &mut self,
        tablet_batch: &mut TabletBatch<T>,
        tablet_cache_keys: &Vec<TabletCacheKey>,
    ) {
        // Register batch with each of the tablet cache entries it affects such that
        // when tablet cache entry is ready the corresponding tablet batch can be
        // notified.
        for tablet_cache_key in tablet_cache_keys {
            if let Some(tablet_cache_entry) = self.tablet_cache_entries.get_mut(tablet_cache_key) {
                tablet_batch.add_pending_cache_entry(tablet_cache_entry);
            }
        }
    }

    fn prepare_tablet_write(
        &self,
        tablet_metadata: &mut TabletMetadata,
        tablet_value: &T,
    ) -> Result<Bytes, ()> {
        let tablet_contents = self.tablet_serializer.serialize(tablet_value)?;
        // Create new version of the tablet metadata.
        tablet_metadata.tablet_version += 1;
        tablet_metadata.blob_size = tablet_contents.len() as u32;
        tablet_metadata.blob_hash = Sha256::digest(&tablet_contents).to_vec().into();
        // To ensure the tablet uri is unique use composite name based on tablet
        // id, version and content hash.
        tablet_metadata.blob_uri = format_blob_uri(
            tablet_metadata.tablet_id,
            tablet_metadata.tablet_version,
            tablet_metadata.blob_hash.clone(),
        );

        Ok(tablet_contents)
    }

    fn prepare_tablet_read(
        &self,
        tablet_metadata: &TabletMetadata,
        tablet_contents: Bytes,
    ) -> Result<T, ()> {
        // Currently table name is not propagated to the serializer, will be
        // added later.
        let tablet_value = self
            .tablet_serializer
            .deserialize(&"todo".to_string(), tablet_contents)?;

        Ok(tablet_value)
    }
}

impl<T> TabletDataCache<T> for DefaultTabletDataCache<T> {
    fn init(&mut self, logger: Logger) {
        self.logger = logger;
    }

    fn make_progress(&mut self, instant: u64) {
        let mut failed_tablet_cache_entries = Vec::new();

        // For every tablet cache entry that has become ready, notify corresponding
        // tablet batches.
        for (tablet_cache_key, tablet_cache_entry) in &mut self.tablet_cache_entries {
            for tablet_batch_id in tablet_cache_entry.take_waiting_batches() {
                self.tablet_batches
                    .get_mut(&tablet_batch_id)
                    .unwrap()
                    .resolve_pending_cache_entry(tablet_cache_entry);
            }

            if let TabletCacheEntryState::Error = tablet_cache_entry.get_state() {
                failed_tablet_cache_entries.push(tablet_cache_key.clone());
            }
        }

        // Remove all tablet batches that have been completed.
        self.tablet_batches
            .retain(|_, tablet_batch| !tablet_batch.is_ready());

        // Remove all failed tablet cache entries given that all corresponding
        // tablet batches have already been notified.
        for failed_tablet_cache_key in failed_tablet_cache_entries {
            self.tablet_cache_entries.remove(&failed_tablet_cache_key);
        }

        // Consult with tablet cache policy and evict entries from tablet cache.
        for evicted_tablet_cache_key in
            self.tablet_cache_policy
                .evict(instant, self.cache_capacity, &self.tablet_cache_entries)
        {
            self.tablet_cache_entries.remove(&evicted_tablet_cache_key);
        }
    }

    fn load_tablets(
        &mut self,
        tablets_metadata: &Vec<TabletMetadata>,
    ) -> ResultHandle<Vec<(TabletMetadata, TabletData<T>)>, TabletDataStorageStatus> {
        let mut tablet_cache_keys = Vec::with_capacity(tablets_metadata.len());
        for tablet_metadata in tablets_metadata {
            let tablet_cache_key = TabletCacheKey::from(tablet_metadata);
            tablet_cache_keys.push(tablet_cache_key.clone());

            if let Vacant(map_entry) = self.tablet_cache_entries.entry(tablet_cache_key.clone()) {
                // Create new tablet cache entry and corresponding storage request if the tablet
                // is not being maintained by the cache.
                self.correlation_counter += 1;

                self.tablet_operations
                    .insert(self.correlation_counter, tablet_cache_key);

                let (tablet_cache_entry, load_tablet_request) =
                    TabletCacheEntry::<T>::with_load_state(
                        self.correlation_counter,
                        tablet_metadata,
                    );

                self.out_messages.push(load_tablet_request);
                map_entry.insert(tablet_cache_entry);
            }
        }

        self.batch_counter += 1;
        let (mut tablet_batch, result_handle) =
            TabletBatch::<T>::with_load_state(self.batch_counter);

        // Process immediately available tablet cache entries or register for the notification
        // on when the tablet cache entry is ready.
        self.register_pending_cache_entries(&mut tablet_batch, &tablet_cache_keys);

        // If tablet batch is not ready or in other words not all tablet cache
        // entries are ready, record batch for future notifications when tablet
        // cache entries become ready.
        if !tablet_batch.is_ready() {
            self.tablet_batches.insert(self.batch_counter, tablet_batch);
        }

        result_handle
    }

    fn store_tablets(
        &mut self,
        mut tablets_data: Vec<(&mut TabletMetadata, T)>,
    ) -> ResultHandle<(), TabletDataStorageStatus> {
        // Prepare serialized tablet contents and new version of the tablet metadata,
        // return early if preparation fails for any of the tablets.
        let mut tablets_contents = Vec::with_capacity(tablets_data.len());
        for (tablet_metadata, tablet_value) in &mut tablets_data {
            if let Ok(tablet_data) = self.prepare_tablet_write(*tablet_metadata, tablet_value) {
                tablets_contents.push(tablet_data);
            } else {
                return create_result_from_error(TabletDataStorageStatus::Failed);
            }
        }

        let mut tablet_cache_keys = Vec::with_capacity(tablets_data.len());
        for ((tablet_metadata, tablet_value), tablet_contents) in
            tablets_data.into_iter().zip(tablets_contents.into_iter())
        {
            let tablet_cache_key = TabletCacheKey::from(tablet_metadata);
            tablet_cache_keys.push(tablet_cache_key.clone());

            match self.tablet_cache_entries.entry(tablet_cache_key.clone()) {
                Vacant(map_entry) => {
                    // Create new tablet cache entry and corresponding storage request if the tablet
                    // is not being maintained by the cache.
                    self.correlation_counter += 1;

                    self.tablet_operations
                        .insert(self.correlation_counter, tablet_cache_key);

                    let (tablet_cache_entry, store_tablet_request) =
                        TabletCacheEntry::<T>::with_store_state(
                            self.correlation_counter,
                            tablet_metadata,
                            tablet_value,
                            tablet_contents,
                        );

                    self.out_messages.push(store_tablet_request);
                    map_entry.insert(tablet_cache_entry);
                }
                Occupied(map_entry) => {
                    // Any new tablet cache write must be unique as once created tablets
                    // are immutable.
                    panic!("Cache entry with given cache id already exists");
                }
            }
        }
        self.batch_counter += 1;
        let (mut tablet_batch, result_handle) =
            TabletBatch::<T>::with_store_state(self.batch_counter);
        // Process immediately available tablet cache entries or register for the notification
        // on when the tablet cache entry is ready.
        self.register_pending_cache_entries(&mut tablet_batch, &tablet_cache_keys);

        // If tablet batch is not ready or in other words not all tablet cache
        // entries are ready, record batch for future notifications when tablet
        // cache entries become ready.
        if !tablet_batch.is_ready() {
            self.tablet_batches.insert(self.batch_counter, tablet_batch);
        }

        result_handle
    }

    fn process_in_message(&mut self, in_message: TabletDataCacheInMessage) {
        match in_message {
            TabletDataCacheInMessage::LoadResponse(
                correlation_id,
                load_tablet_response,
                tablet_contents,
            ) => {
                if let Some(tablet_cache_key) = self.tablet_operations.remove(&correlation_id) {
                    // Prepare loaded raw tablet contents to enter the cache in deserialized form.
                    let tablet_value = self.prepare_tablet_read(
                        self.tablet_cache_entries
                            .get(&tablet_cache_key)
                            .unwrap()
                            .get_metadata(),
                        tablet_contents,
                    );

                    // Delegate tablet loading response to the corresponding tablet cache entry. Note
                    // that notifications to the tablet batches happens later when making progress.
                    self.tablet_cache_entries
                        .get_mut(&tablet_cache_key)
                        .unwrap()
                        .process_load_response(load_tablet_response, tablet_value);
                }
            }
            TabletDataCacheInMessage::StoreResponse(correlation_id, store_tablet_response) => {
                if let Some(tablet_cache_key) = self.tablet_operations.remove(&correlation_id) {
                    // Delegate tablet storing response to the corresponding tablet cache entry. Note
                    // that notifications to the tablet batches happens later when making progress.
                    self.tablet_cache_entries
                        .get_mut(&tablet_cache_key)
                        .unwrap()
                        .process_store_response(store_tablet_response);
                }
            }
        }
    }

    fn take_out_messages(&mut self) -> Vec<TabletDataCacheOutMessage> {
        mem::take(&mut self.out_messages)
    }
}

// Policy that decides which entries can be evicted from the cache.
// Type parameter T represents a variant type for the deserialized tablet data.
pub trait TabletDataCachePolicy<T> {
    // Decides which entries can be evicted from the cache given the maximum cache size.
    // Note that only ready cache entries can be evicted. Cache entries that are still
    // loading or storing cannot be evicted. Both pending and ready entries contribute
    // to the cache usage (e.g. size of a tablet still being loaded is counted towards
    // used space).
    fn evict(
        &mut self,
        instant: u64,
        tablet_cache_size: u64,
        tablet_cache_entries: &HashMap<TabletCacheKey, TabletCacheEntry<T>>,
    ) -> Vec<TabletCacheKey>;
}

// Default policy never evicts anything. Useful only for testing or demos.
pub struct DefaultTabletDataCachePolicy<T> {
    dummy: Option<T>,
}

impl<T> DefaultTabletDataCachePolicy<T> {
    pub fn new() -> Self {
        Self { dummy: None }
    }
}

impl<T> TabletDataCachePolicy<T> for DefaultTabletDataCachePolicy<T> {
    fn evict(
        &mut self,
        instant: u64,
        tablet_cache_size: u64,
        tablet_cache_entries: &HashMap<TabletCacheKey, TabletCacheEntry<T>>,
    ) -> Vec<TabletCacheKey> {
        Vec::new()
    }
}

// Uniquely identifies tablet cache entry.
#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Hash)]
struct TabletCacheKey {
    // Uri of the blob in Tablet Data Storage.
    uri: String,
}

impl TabletCacheKey {
    fn from(tablet_metadata: &TabletMetadata) -> Self {
        Self {
            uri: tablet_metadata.blob_uri.clone(),
        }
    }
}

// Represents state of the tablet cache entry. Load and store are pending states, whereas
// cache and error are ready states. Tablet cache entries in error state are immdediatly
// removed from the cache after corresponding tablet batches are notified.
// Type parameter T represents a variant type for the deserialized tablet data.
enum TabletCacheEntryState<T> {
    Load,
    Store(TabletData<T>),
    Cache(TabletData<T>),
    Error,
}

// Tablet cache entry that keeps track of its state and dependent tablet batches.
// Type parameter T represents a variant type for the deserialized tablet data.
struct TabletCacheEntry<T> {
    // The metadata describing the tablet.
    tablet_metadata: TabletMetadata,
    // The state of the tablet where load and store states indicate pending loading or
    // storing from or to Tablet Data Storage, cache state indicates the tablet has
    // been successfully cached, error state means cache entry failed to load or store.
    cache_entry_state: TabletCacheEntryState<T>,
    // The list of tablet batches that are interested in this tablet.
    tablet_batch_ids: Vec<u64>,
}

impl<T> TabletCacheEntry<T> {
    fn with_load_state(
        correlation_id: u64,
        tablet_metadata: &TabletMetadata,
    ) -> (Self, TabletDataCacheOutMessage) {
        (
            Self {
                tablet_metadata: tablet_metadata.clone(),
                cache_entry_state: TabletCacheEntryState::Load,
                tablet_batch_ids: Vec::new(),
            },
            TabletDataCacheOutMessage::LoadRequest(
                correlation_id,
                LoadTabletRequest {
                    blob_uri: tablet_metadata.blob_uri.clone(),
                },
            ),
        )
    }

    fn with_store_state(
        correlation_id: u64,
        tablet_metadata: &TabletMetadata,
        tablet_value: T,
        tablet_contents: Bytes,
    ) -> (Self, TabletDataCacheOutMessage) {
        (
            Self {
                tablet_metadata: tablet_metadata.clone(),
                cache_entry_state: TabletCacheEntryState::Store(TabletData::<T>::create(
                    tablet_value,
                )),
                tablet_batch_ids: Vec::new(),
            },
            TabletDataCacheOutMessage::StoreRequest(
                correlation_id,
                StoreTabletRequest {
                    blob_uri: tablet_metadata.blob_uri.clone(),
                },
                tablet_contents,
            ),
        )
    }

    fn get_metadata(&self) -> &TabletMetadata {
        &self.tablet_metadata
    }

    fn get_state(&self) -> &TabletCacheEntryState<T> {
        &self.cache_entry_state
    }

    fn register_waiting_batch(&mut self, tablet_batch_id: u64) {
        self.tablet_batch_ids.push(tablet_batch_id);
    }

    fn take_waiting_batches(&mut self) -> Vec<u64> {
        match &self.cache_entry_state {
            TabletCacheEntryState::Cache(_) | TabletCacheEntryState::Error => {
                mem::take(&mut self.tablet_batch_ids)
            }
            _ => Vec::new(),
        }
    }

    fn process_load_response(
        &mut self,
        load_tablet_response: LoadTabletResponse,
        tablet_value: Result<T, ()>,
    ) {
        if let TabletCacheEntryState::Load = &self.cache_entry_state {
            match TabletDataStorageStatus::from_i32(load_tablet_response.status) {
                Some(TabletDataStorageStatus::Succeeded) => {
                    if let Ok(tablet_value) = tablet_value {
                        self.cache_entry_state =
                            TabletCacheEntryState::Cache(TabletData::<T>::create(tablet_value));
                    } else {
                        self.cache_entry_state = TabletCacheEntryState::Error;
                    }
                }
                Some(TabletDataStorageStatus::Failed) => {
                    self.cache_entry_state = TabletCacheEntryState::Error;
                }
                _ => {
                    panic!("Unexpected load tablet status");
                }
            }
        } else {
            panic!("Tablet cache entry doesn't expect load response");
        }
    }

    fn process_store_response(&mut self, store_tablet_response: StoreTabletResponse) {
        if let TabletCacheEntryState::Store(tablet_value) = &self.cache_entry_state {
            match TabletDataStorageStatus::from_i32(store_tablet_response.status) {
                Some(TabletDataStorageStatus::Succeeded) => {
                    self.cache_entry_state = TabletCacheEntryState::Cache(tablet_value.clone());
                }
                Some(TabletDataStorageStatus::Failed) => {
                    self.cache_entry_state = TabletCacheEntryState::Error;
                }
                _ => {
                    panic!("Unexpected store tablet status");
                }
            }
        } else {
            panic!("Tablet cache entry doesn't expect store response");
        }
    }
}

// Represents the state of the tablet batch. Both loading and storing of individual
// tablets happens independently (separate requests are issued to the Tablet Data Storage),
// however the result must be presented in one shot (e.g. as a batch). Specifically,
// while loading tablets it is important for the caller to get access to all requested
// tablets at once such that they can be processed together. Likewise, storing tablets
// together is a result of several tablets processed together.
// Type parameter T represents a variant type for the deserialized tablet data.
enum TabletBatchState<T> {
    Load(
        Vec<(TabletMetadata, TabletData<T>)>,
        ResultSource<Vec<(TabletMetadata, TabletData<T>)>, TabletDataStorageStatus>,
    ),
    Store(ResultSource<(), TabletDataStorageStatus>),
    Error,
    Completed,
}

// Tablet batch that represents a group of tablet cache entries that are being loaded or
// stored together. After all cache entries become ready and result for the batch processing
// is resolved, the tablet batch is destroyed.
// Type parameter T represents a variant type for the deserialized tablet data.
struct TabletBatch<T> {
    batch_id: u64,
    batch_state: TabletBatchState<T>,
    remaining_cache_entries: usize,
}

impl<T> TabletBatch<T> {
    fn with_load_state(
        batch_id: u64,
    ) -> (
        Self,
        ResultHandle<Vec<(TabletMetadata, TabletData<T>)>, TabletDataStorageStatus>,
    ) {
        let (op_handle, op_source) = create_eventual_result::<
            Vec<(TabletMetadata, TabletData<T>)>,
            TabletDataStorageStatus,
        >();
        (
            Self {
                batch_id,
                batch_state: TabletBatchState::Load(Vec::new(), op_source),
                remaining_cache_entries: 0,
            },
            op_handle,
        )
    }

    fn with_store_state(batch_id: u64) -> (Self, ResultHandle<(), TabletDataStorageStatus>) {
        let (op_handle, op_source) = create_eventual_result::<(), TabletDataStorageStatus>();
        (
            Self {
                batch_id,
                batch_state: TabletBatchState::Store(op_source),
                remaining_cache_entries: 0,
            },
            op_handle,
        )
    }

    fn is_ready(&self) -> bool {
        self.remaining_cache_entries == 0
    }

    fn add_pending_cache_entry(&mut self, tablet_cache_entry: &mut TabletCacheEntry<T>) {
        self.remaining_cache_entries += 1;
        match tablet_cache_entry.get_state() {
            TabletCacheEntryState::Load | TabletCacheEntryState::Store(_) => {
                tablet_cache_entry.register_waiting_batch(self.batch_id);
            }
            TabletCacheEntryState::Cache(_) | TabletCacheEntryState::Error => {
                self.resolve_pending_cache_entry(tablet_cache_entry);
            }
        }
    }

    fn resolve_pending_cache_entry(&mut self, tablet_cache_entry: &TabletCacheEntry<T>) {
        self.remaining_cache_entries -= 1;
        let has_completed = self.remaining_cache_entries == 0;

        let updated_batch_operation = match (tablet_cache_entry.get_state(), &mut self.batch_state)
        {
            (
                TabletCacheEntryState::Cache(tablet_value),
                TabletBatchState::Load(loaded_tablets, loaded_tablets_source),
            ) => {
                loaded_tablets.push((
                    tablet_cache_entry.get_metadata().clone(),
                    tablet_value.clone(),
                ));
                if has_completed {
                    loaded_tablets_source.set_result(mem::take(loaded_tablets));
                    Some(TabletBatchState::Completed)
                } else {
                    None
                }
            }
            (TabletCacheEntryState::Error, TabletBatchState::Load(_, loaded_tablets_source)) => {
                loaded_tablets_source.set_error(TabletDataStorageStatus::Failed);
                Some(TabletBatchState::Error)
            }
            (TabletCacheEntryState::Cache(_), TabletBatchState::Store(stored_tablets_source)) => {
                if has_completed {
                    stored_tablets_source.set_result(());
                    Some(TabletBatchState::Completed)
                } else {
                    None
                }
            }
            (TabletCacheEntryState::Error, TabletBatchState::Store(stored_tablets_source)) => {
                stored_tablets_source.set_error(TabletDataStorageStatus::Failed);
                Some(TabletBatchState::Error)
            }
            _ => None,
        };

        if updated_batch_operation.is_some() {
            self.batch_state = updated_batch_operation.unwrap();
        }
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use tcp_proto::runtime::endpoint::out_message;

    use super::*;
    use crate::mock::*;

    const DATA_CACHE_CAPACITY: u64 = 1024;
    const TABLET_ID_1: u32 = 1;
    const TABLET_VERSION_1: u32 = 5;
    const TABLET_VERSION_2: u32 = 6;
    const TABLET_DATA_VERSION_1: &'static str = "t1 v1";
    const TABLET_DATA_VERSION_2: &'static str = "t1 v2";
    const CORRELATION_ID_1: u64 = 1;
    const CORRELATION_ID_2: u64 = 2;
    const TABLET_BLOB_URI_1: &'static str = "blob 1";
    const TABLET_BLOB_URI_2: &'static str = "blob 2";

    fn create_tablet_data_cache() -> DefaultTabletDataCache<Bytes> {
        DefaultTabletDataCache::create(
            0,
            DATA_CACHE_CAPACITY,
            Box::new(BytesTabletDataSerializer {}),
            Box::new(DefaultTabletDataCachePolicy::new()),
        )
    }

    fn create_tablet_metadata(
        tablet_id: u32,
        tablet_version: u32,
        blob_uri: String,
    ) -> TabletMetadata {
        TabletMetadata {
            tablet_id,
            tablet_version,
            blob_uri,
            ..Default::default()
        }
    }

    fn create_load_tablet_request(blob_uri: String) -> LoadTabletRequest {
        LoadTabletRequest { blob_uri }
    }

    fn create_store_tablet_request(blob_uri: String) -> StoreTabletRequest {
        StoreTabletRequest { blob_uri }
    }

    fn create_load_tablet_response(status: TabletDataStorageStatus) -> LoadTabletResponse {
        LoadTabletResponse {
            status: status.into(),
        }
    }

    fn create_store_tablet_response(status: TabletDataStorageStatus) -> StoreTabletResponse {
        StoreTabletResponse {
            status: status.into(),
        }
    }

    struct TabletDataCacheLoop {
        tablet_data_cache: DefaultTabletDataCache<Bytes>,
    }

    impl TabletDataCacheLoop {
        fn create(tablet_data_cache: DefaultTabletDataCache<Bytes>) -> Self {
            Self { tablet_data_cache }
        }

        fn get_mut(&mut self) -> &mut DefaultTabletDataCache<Bytes> {
            &mut self.tablet_data_cache
        }

        fn execute_step(
            &mut self,
            instant: u64,
            in_message: Option<TabletDataCacheInMessage>,
        ) -> Vec<TabletDataCacheOutMessage> {
            self.tablet_data_cache.make_progress(instant);

            let out_messages = self.tablet_data_cache.take_out_messages();

            if in_message.is_some() {
                self.tablet_data_cache
                    .process_in_message(in_message.unwrap());
            }

            out_messages
        }
    }

    #[test]
    fn test_load_tablets_success() {
        let tablet_data_cache = create_tablet_data_cache();
        let mut tablet_data_cache_loop = TabletDataCacheLoop::create(tablet_data_cache);

        let tablet_metadata_1_v_1 =
            create_tablet_metadata(TABLET_ID_1, TABLET_VERSION_1, TABLET_BLOB_URI_1.to_string());
        let tablet_data_1_v_1 = Bytes::from(TABLET_DATA_VERSION_1);

        let load_tablets_result = tablet_data_cache_loop
            .get_mut()
            .load_tablets(&vec![tablet_metadata_1_v_1.clone()]);

        assert!(load_tablets_result.check_result().is_none());

        assert_eq!(
            vec![TabletDataCacheOutMessage::LoadRequest(
                CORRELATION_ID_1,
                create_load_tablet_request(TABLET_BLOB_URI_1.to_string())
            )],
            tablet_data_cache_loop.execute_step(
                1,
                Some(TabletDataCacheInMessage::LoadResponse(
                    CORRELATION_ID_1,
                    create_load_tablet_response(TabletDataStorageStatus::Succeeded),
                    tablet_data_1_v_1.clone()
                ))
            )
        );

        assert!(tablet_data_cache_loop.execute_step(2, None).is_empty());

        assert_eq!(
            Some(Ok(vec![(
                tablet_metadata_1_v_1.clone(),
                TabletData::create(tablet_data_1_v_1.clone())
            ),])),
            load_tablets_result.check_result()
        );

        let load_tablets_result = tablet_data_cache_loop
            .get_mut()
            .load_tablets(&vec![tablet_metadata_1_v_1.clone()]);

        assert_eq!(
            Some(Ok(vec![(
                tablet_metadata_1_v_1.clone(),
                TabletData::create(tablet_data_1_v_1.clone())
            ),])),
            load_tablets_result.check_result()
        );
    }

    #[test]
    fn test_store_tablets_success() {
        let tablet_data_cache = create_tablet_data_cache();
        let mut tablet_data_cache_loop = TabletDataCacheLoop::create(tablet_data_cache);

        let tablet_metadata_1_v_1 =
            create_tablet_metadata(TABLET_ID_1, TABLET_VERSION_1, TABLET_BLOB_URI_1.to_string());
        let mut tablet_metadata_1_v_1_to_v_2 = tablet_metadata_1_v_1.clone();
        let tablet_data_1_v_2 = Bytes::from(TABLET_DATA_VERSION_2);

        let store_tablets_result = tablet_data_cache_loop.get_mut().store_tablets(vec![(
            &mut tablet_metadata_1_v_1_to_v_2,
            tablet_data_1_v_2.clone(),
        )]);

        assert!(store_tablets_result.check_result().is_none());

        assert_eq!(
            vec![TabletDataCacheOutMessage::StoreRequest(
                CORRELATION_ID_1,
                create_store_tablet_request(tablet_metadata_1_v_1_to_v_2.blob_uri.clone()),
                tablet_data_1_v_2.clone()
            )],
            tablet_data_cache_loop.execute_step(
                1,
                Some(TabletDataCacheInMessage::StoreResponse(
                    CORRELATION_ID_1,
                    create_store_tablet_response(TabletDataStorageStatus::Succeeded)
                ))
            )
        );

        assert!(tablet_data_cache_loop.execute_step(2, None).is_empty());

        assert_eq!(Some(Ok(())), store_tablets_result.check_result());

        let load_tablets_result = tablet_data_cache_loop
            .get_mut()
            .load_tablets(&vec![tablet_metadata_1_v_1_to_v_2.clone()]);

        assert_eq!(
            Some(Ok(vec![(
                tablet_metadata_1_v_1_to_v_2.clone(),
                TabletData::create(tablet_data_1_v_2.clone())
            ),])),
            load_tablets_result.check_result()
        );
    }
}
