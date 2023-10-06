#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(not(feature = "std"), feature(error_in_core))]

extern crate alloc;
#[cfg(feature = "std")]
extern crate core;
extern crate hashbrown;
extern crate prost;
extern crate raft;
extern crate slog;

pub mod endpoint {
    #![allow(non_snake_case)]
    include!(concat!(env!("OUT_DIR"), "/endpoint.rs"));
}

pub mod consensus;
pub mod driver;
pub mod logger;
#[cfg(all(test, feature = "std"))]
pub mod mock;
pub mod model;
pub mod platform;
pub mod storage;
pub mod util;

#[cfg(not(feature = "std"))]
use core::error::Error as StdError;
#[cfg(feature = "std")]
use std::error::Error as StdError;
