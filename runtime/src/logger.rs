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

use alloc::boxed::Box;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::result::Result;
use slog::{o, Drain, Logger, Serializer, KV};
use tcp_proto::runtime::endpoint::{LogMessage, LogSeverity};

pub trait DrainOutput {
    fn take_entries(&mut self) -> Vec<LogMessage>;
}

pub struct EmptyDrainOutput {}
impl DrainOutput for EmptyDrainOutput {
    fn take_entries(&mut self) -> Vec<LogMessage> {
        Vec::with_capacity(0)
    }
}

struct ValueSerializer {
    output: String,
}

impl Serializer for ValueSerializer {
    fn emit_arguments(&mut self, key: slog::Key, val: &core::fmt::Arguments) -> slog::Result {
        self.output.push_str(format!("{}: {}, ", key, val).as_str());

        Ok(())
    }
}

fn create_log_message(record: &slog::Record, values: &slog::OwnedKVList) -> LogMessage {
    let severity = match record.level() {
        slog::Level::Critical => LogSeverity::Critical,
        slog::Level::Error => LogSeverity::Error,
        slog::Level::Warning => LogSeverity::Warning,
        slog::Level::Info => LogSeverity::Info,
        slog::Level::Debug => LogSeverity::Debug,
        slog::Level::Trace => LogSeverity::Trace,
    };

    let mut value_serializer = ValueSerializer {
        output: String::new(),
    };
    record
        .kv()
        .serialize(record, &mut value_serializer)
        .unwrap();
    values.serialize(record, &mut value_serializer).unwrap();

    let file = match record.file().rfind('/') {
        Some(pos) => &record.file()[pos + 1..],
        None => record.file(),
    };

    let message = format!(
        "{:?} {} @ {} : {} / {} // {}",
        record.level(),
        file,
        record.line(),
        record.column(),
        record.msg(),
        value_serializer.output
    );

    LogMessage {
        severity: severity.into(),
        message,
    }
}

#[cfg(feature = "std")]
pub mod log {
    extern crate slog_term;
    use super::*;
    use slog::Duplicate;
    use std::sync::{Arc, Mutex};

    #[derive(Clone)]
    pub struct RemoteDrainCore {
        entries: Arc<Mutex<Vec<LogMessage>>>,
    }

    impl RemoteDrainCore {
        fn new() -> RemoteDrainCore {
            RemoteDrainCore {
                entries: Arc::new(Mutex::new(Vec::new())),
            }
        }

        fn append_entry(&self, entry: LogMessage) {
            let mut entries = self.entries.lock().unwrap();
            entries.push(entry)
        }
    }

    impl DrainOutput for RemoteDrainCore {
        fn take_entries(&mut self) -> Vec<LogMessage> {
            let mut entries = self.entries.lock().unwrap();
            entries.drain(..).collect()
        }
    }

    struct RemoteDrain {
        core: RemoteDrainCore,
    }

    impl RemoteDrain {
        fn new(core: RemoteDrainCore) -> Self {
            RemoteDrain { core }
        }
    }

    impl Drain for RemoteDrain {
        type Ok = ();
        type Err = ();

        fn log(
            &self,
            record: &slog::Record,
            values: &slog::OwnedKVList,
        ) -> Result<Self::Ok, Self::Err> {
            self.core.append_entry(create_log_message(record, values));

            Ok(())
        }
    }

    pub fn create_remote_logger() -> (Logger, Box<dyn DrainOutput>) {
        let term_drain =
            slog_term::FullFormat::new(slog_term::TermDecorator::new().build()).build();

        let remote_drain_core = RemoteDrainCore::new();
        let remote_drain = RemoteDrain::new(remote_drain_core.clone());

        let drain = Duplicate::new(remote_drain, term_drain).fuse();
        (
            Logger::root(Mutex::new(drain).fuse(), o!()),
            Box::new(remote_drain_core),
        )
    }

    pub fn create_logger() -> Logger {
        let plain = slog_term::PlainSyncDecorator::new(std::io::stdout());
        Logger::root(slog_term::FullFormat::new(plain).build().fuse(), o!())
    }
}

#[cfg(not(feature = "std"))]
pub mod log {
    extern crate spin;
    use self::spin::Mutex;
    use super::*;
    use alloc::sync::Arc;
    use core::panic::AssertUnwindSafe;
    use slog::{Discard, Fuse};

    #[derive(Clone)]
    pub struct RemoteDrainCore {
        entries: Arc<Mutex<Vec<LogMessage>>>,
    }

    impl RemoteDrainCore {
        fn new() -> RemoteDrainCore {
            RemoteDrainCore {
                entries: Arc::new(Mutex::new(Vec::new())),
            }
        }

        fn append_entry(&self, entry: LogMessage) {
            let mut entries = self.entries.lock();
            entries.push(entry)
        }
    }

    impl DrainOutput for RemoteDrainCore {
        fn take_entries(&mut self) -> Vec<LogMessage> {
            let mut entries = self.entries.lock();
            entries.drain(..).collect()
        }
    }

    struct RemoteDrain {
        core: AssertUnwindSafe<RemoteDrainCore>,
    }

    impl RemoteDrain {
        fn new(core: RemoteDrainCore) -> Self {
            RemoteDrain {
                core: AssertUnwindSafe(core),
            }
        }
    }

    impl Drain for RemoteDrain {
        type Ok = ();
        type Err = ();

        fn log(
            &self,
            record: &slog::Record,
            values: &slog::OwnedKVList,
        ) -> Result<Self::Ok, Self::Err> {
            self.core.append_entry(create_log_message(record, values));

            Ok(())
        }
    }

    pub fn create_remote_logger() -> (Logger, Box<dyn DrainOutput>) {
        let remote_drain_core = RemoteDrainCore::new();
        let remote_drain = RemoteDrain::new(remote_drain_core.clone());

        (
            Logger::root(Fuse(remote_drain), o!()),
            Box::new(remote_drain_core),
        )
    }

    pub fn create_logger() -> Logger {
        Logger::root(Discard, o!())
    }
}
