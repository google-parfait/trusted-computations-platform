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

use std::io::Result;

fn main() -> Result<()> {
    micro_rpc_build::compile(
        &["proto/tablet_cache.proto"],
        &["proto", "../../tablet_store/service/proto"],
        micro_rpc_build::CompileOptions {
            extern_paths: vec![micro_rpc_build::ExternPath::new(
                ".apps.tablet_store.service",
                "::tcp_tablet_store_service::apps::tablet_store::service",
            )],
            ..Default::default()
        },
    );
    Ok(())
}
