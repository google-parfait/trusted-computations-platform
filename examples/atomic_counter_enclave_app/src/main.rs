// Copyright 2023 The Trusted Computations Platform Authors.
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

use alloc::boxed::Box;
use core::panic::PanicInfo;
use oak_channel::server;
use oak_core::samplestore::StaticSampleStore;
use oak_restricted_kernel_api::{syscall, FileDescriptorChannel, StderrLogger};
use tcp_proto::runtime::endpoint::EndpointServiceServer;
use tcp_runtime::{examples::CounterActor, service::ApplicationService};

static LOGGER: StderrLogger = StderrLogger {};

#[no_mangle]
fn _start() -> ! {
    log::set_logger(&LOGGER).unwrap();
    log::set_max_level(log::LevelFilter::Debug);
    oak_enclave_runtime_support::init();
    main();
}

fn main() -> ! {
    log::info!("In main!");
    // Only log warnings and errors to reduce the risk of accidentally leaking execution
    // information through debug logs.
    log::set_max_level(log::LevelFilter::Warn);

    let mut invocation_stats = StaticSampleStore::<1000>::new().unwrap();
    let service: ApplicationService<CounterActor> = ApplicationService::new(CounterActor::new());
    let server = EndpointServiceServer::new(service);
    server::start_blocking_server(
        Box::<FileDescriptorChannel>::default(),
        server,
        &mut invocation_stats,
    )
    .expect("Server encountered an unrecoverable error");
}

#[alloc_error_handler]
fn out_of_memory(layout: ::core::alloc::Layout) -> ! {
    panic!("Error allocating memory: {:#?}", layout);
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    log::error!("PANIC: {}", info);
    syscall::exit(-1);
}
