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

#![no_std]
#![no_main]
#![feature(alloc_error_handler)]

extern crate alloc;
extern crate tcp_proto;
extern crate tcp_runtime;

use alloc::{boxed::Box, string::ToString};
use oak_restricted_kernel_sdk::{
    channel::{start_blocking_server, FileDescriptorChannel},
    entrypoint,
    utils::{log, samplestore::StaticSampleStore},
};
use tcp_proto::runtime::endpoint::EndpointServiceServer;
use tcp_runtime::service::ApplicationService;
use tcp_tablet_cache_service::{
    actor::TabletCacheActor,
    store::SimpleKeyValueStore,
    transaction::{
        coordinator::DefaultTabletTransactionCoordinator, data::DefaultTabletDataCache,
        manager::DefaultTabletTransactionManager, metadata::DefaultTabletMetadataCache,
    },
};

const TRANSACTION_COORDINATOR_CORRELATION_COUNTER: u64 = 1 << 56;

#[entrypoint]
fn run_server() -> ! {
    // Only log warnings and errors to reduce the risk of accidentally leaking execution
    // information through debug logs.
    log::set_max_level(log::LevelFilter::Warn);

    let mut invocation_stats = StaticSampleStore::<1000>::new().unwrap();
    let service: ApplicationService<
        TabletCacheActor<DefaultTabletTransactionManager, SimpleKeyValueStore>,
    > = ApplicationService::new(TabletCacheActor::new(
        DefaultTabletTransactionManager::create(
            Box::new(DefaultTabletTransactionCoordinator::create(
                TRANSACTION_COORDINATOR_CORRELATION_COUNTER,
            )),
            Box::new(DefaultTabletMetadataCache::create()),
            Box::new(DefaultTabletDataCache::create(1024 * 1024 * 1024 * 16)),
        ),
        SimpleKeyValueStore::create("map".to_string(), 100, 100),
    ));
    let server = EndpointServiceServer::new(service);
    start_blocking_server(
        Box::<FileDescriptorChannel>::default(),
        server,
        &mut invocation_stats,
    )
    .expect("Server encountered an unrecoverable error");
}
