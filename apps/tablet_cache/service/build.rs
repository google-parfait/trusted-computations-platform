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
        &["proto"],
        micro_rpc_build::CompileOptions {
            bytes: vec![
                ".apps.tablet_cache.service.PutKeyRequest".to_string(),
                ".apps.tablet_cache.service.PutKeyResponse".to_string(),
                ".apps.tablet_cache.service.GetKeyRequest".to_string(),
                ".apps.tablet_cache.service.GetKeyResponse".to_string(),
                ".apps.tablet_cache.service.TabletContents".to_string(),
            ],
            extern_paths: vec![],
            ..Default::default()
        },
    );
    oak_proto_build_utils::fix_prost_derives().unwrap();
    Ok(())
}
