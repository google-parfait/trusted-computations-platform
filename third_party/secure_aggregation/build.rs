// Copyright 2025 The Trusted Computations Platform Authors.
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

fn main() {
    let proto_dir: std::path::PathBuf = std::env::var("DECRYPTOR_PROTO")
        .unwrap()
        .strip_suffix("/willow/proto/willow/decryptor.proto")
        .unwrap()
        .into();
    let shell_encryption_proto_dir: std::path::PathBuf = std::env::var("SHELL_ENCRYPTION_PROTO")
        .unwrap()
        .strip_suffix("/shell_encryption/serialization.proto")
        .unwrap()
        .into();
    micro_rpc_build::compile(
        &[
            shell_encryption_proto_dir.join("shell_encryption/serialization.proto"),
            shell_encryption_proto_dir.join("shell_encryption/rns/rns_serialization.proto"),
            proto_dir.join("willow/proto/shell/ciphertexts.proto"),
            proto_dir.join("willow/proto/willow/decryptor.proto"),
            proto_dir.join("willow/proto/willow/key.proto"),
            proto_dir.join("willow/proto/willow/messages.proto"),
            proto_dir.join("willow/proto/zk/proofs.proto"),
        ],
        &[
            shell_encryption_proto_dir
                .into_os_string()
                .to_str()
                .unwrap(),
            proto_dir.into_os_string().to_str().unwrap(),
        ],
        micro_rpc_build::CompileOptions {
            ..Default::default()
        },
    );
}
