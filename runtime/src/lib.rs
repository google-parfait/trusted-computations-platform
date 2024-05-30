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

#![feature(trait_upcasting)]
#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(not(feature = "std"), feature(error_in_core))]

extern crate alloc;
#[cfg(feature = "std")]
extern crate core;
extern crate hashbrown;
extern crate oak_attestation;
extern crate oak_attestation_verification;
extern crate oak_proto_rust;
extern crate oak_restricted_kernel_sdk;
extern crate oak_session;
extern crate prost;
extern crate raft;
extern crate slog;
extern crate tcp_proto;

pub mod communication;
pub mod consensus;
pub mod driver;
pub mod handshake;
pub mod logger;
#[cfg(feature = "std")]
pub mod mock;
pub mod model;
pub mod platform;
pub mod service;
pub mod snapshot;
pub mod storage;
pub mod util;

#[cfg(not(feature = "std"))]
use core::error::Error as StdError;
#[cfg(feature = "std")]
use std::error::Error as StdError;
