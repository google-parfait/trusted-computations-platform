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

fn main() -> anyhow::Result<()> {
    let protos = ["src/endpoint.proto"];
    let includes = [
        "src".to_string(),
        std::env::var("DESCRIPTOR_PROTO")
            .unwrap()
            .strip_suffix("/google/protobuf/descriptor.proto")
            .unwrap()
            .to_string(),
        std::env::var("DIGEST_PROTO")
            .unwrap()
            .strip_suffix("/proto/digest.proto")
            .unwrap()
            .to_string(),
    ];

    micro_rpc_build::compile(
        &protos,
        &includes,
        micro_rpc_build::CompileOptions {
            bytes: vec![
                ".trustedcompute.runtime.endpoint.StartReplicaRequest".to_string(),
                ".trustedcompute.runtime.endpoint.DeliverSystemMessage".to_string(),
                ".trustedcompute.runtime.endpoint.DeliverSnapshotRequest".to_string(),
                ".trustedcompute.runtime.endpoint.DeliverSnapshotResponse".to_string(),
                ".trustedcompute.runtime.endpoint.ExecuteProposalRequest".to_string(),
                ".trustedcompute.runtime.endpoint.ExecuteProposalResponse".to_string(),
                ".trustedcompute.runtime.endpoint.DeliverAppMessage".to_string(),
                ".trustedcompute.runtime.endpoint.Entry".to_string(),
                ".trustedcompute.runtime.endpoint.Payload".to_string(),
            ],
            extern_paths: vec![micro_rpc_build::ExternPath::new(
                ".oak",
                "::oak_proto_rust::oak",
            )],
            ..Default::default()
        },
    );
    oak_proto_build_utils::fix_prost_derives().unwrap();

    let tonic_dir = std::path::Path::new(&std::env::var("OUT_DIR")?).join("tonic");
    std::fs::create_dir(&tonic_dir)?;
    tonic_build::configure()
        .build_client(false)
        .server_mod_attribute(".", "#[cfg(feature = \"tonic\")]")
        .out_dir(tonic_dir)
        .extern_path(".oak", "::oak_proto_rust::oak")
        // Reuse the protos produced by `micro_rpc_build::compile`.
        .extern_path(".trustedcompute", "crate")
        .compile(&protos, &includes)?;

    Ok(())
}
