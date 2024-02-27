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

#![cfg_attr(not(feature = "std"), no_std)]
#![feature(never_type)]

extern crate alloc;
extern crate prost;
extern crate slog;
extern crate tcp_runtime;

pub mod fcp {
    pub mod confidentialcompute {
        include!(concat!(env!("OUT_DIR"), "/fcp.confidentialcompute.rs"));
    }
}

pub mod micro_rpc {
    include!(concat!(env!("OUT_DIR"), "/micro_rpc.rs"));
}

pub mod actor;
pub mod ledger;

mod attestation;
mod budget;
mod test_util;
