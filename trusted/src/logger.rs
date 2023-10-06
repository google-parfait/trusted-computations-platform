use alloc::boxed::Box;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::result::Result;
use endpoint::{LogMessage, LogSeverity};
use slog::{o, Drain, Logger, Serializer, KV};

pub trait DrainOutput {
    fn take_entries(&mut self) -> Vec<LogMessage>;
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

    let message = format!(
        "{:?} {} @ {} : {} / {} / {}",
        record.level(),
        record.file(),
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

    pub fn create_remote_logger(node_id: u64) -> (Logger, Box<dyn DrainOutput>) {
        let term_drain =
            slog_term::FullFormat::new(slog_term::PlainDecorator::new(std::io::stdout())).build();

        let remote_drain_core = RemoteDrainCore::new();
        let remote_drain = RemoteDrain::new(remote_drain_core.clone());

        let drain = Duplicate::new(remote_drain, term_drain).fuse();
        (
            Logger::root(
                Mutex::new(drain).fuse(),
                o!("type" => format!("raft #{}", node_id)),
            ),
            Box::new(remote_drain_core),
        )
    }

    pub fn create_logger(node_id: u64) -> Logger {
        let plain = slog_term::PlainSyncDecorator::new(std::io::stdout());
        Logger::root(
            slog_term::FullFormat::new(plain).build().fuse(),
            o!("raft_id" => format!("{}", node_id)),
        )
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

    pub fn create_remote_logger(node_id: u64) -> (Logger, Box<dyn DrainOutput>) {
        let remote_drain_core = RemoteDrainCore::new();
        let remote_drain = RemoteDrain::new(remote_drain_core.clone());

        (
            Logger::root(
                Fuse(remote_drain),
                o!("type" => format!("raft #{}", node_id)),
            ),
            Box::new(remote_drain_core),
        )
    }

    pub fn create_logger(_node_id: u64) -> Logger {
        Logger::root(Discard, o!())
    }
}
