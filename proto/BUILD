# Copyright 2024 The Trusted Computations Platform Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

load("@rules_rust//cargo:defs.bzl", "cargo_build_script")
load("@rules_rust//rust:defs.bzl", "rust_library")

cargo_build_script(
    name = "build",
    srcs = ["build.rs"],
    build_script_env = {
        "PROTOC": "$(execpath @com_google_protobuf//:protoc)",
        "DESCRIPTOR_PROTO": "$(location @com_google_protobuf//:descriptor_proto_srcs)",
        "DIGEST_PROTO": "$(location @oak//proto:digest.proto)",
    },
    data = glob(["src/*.proto"]) + [
        "@com_google_protobuf//:descriptor_proto_srcs",
        "@com_google_protobuf//:well_known_type_protos",
        "@oak//proto:digest.proto",
        "@oak//proto:validity.proto",
        "@oak//proto:variant.proto",
        "@oak//proto/attestation:assertion.proto",
        "@oak//proto/attestation:endorsement.proto",
        "@oak//proto/attestation:eventlog.proto",
        "@oak//proto/attestation:evidence.proto",
        "@oak//proto/attestation:reference_value.proto",
        "@oak//proto/attestation:tcb_version.proto",
        "@oak//proto/crypto:certificate.proto",
        "@oak//proto/crypto:crypto.proto",
        "@oak//proto/session:messages.proto",
        "@oak//proto/session:session.proto",
    ],
    tools = ["@com_google_protobuf//:protoc"],
    deps = [
        "@oak//micro_rpc_build",
        "@oak_crates_index//:anyhow",
        "@oak_crates_index//:tonic-build",
    ],
)

rust_library(
    name = "tcp_proto",
    srcs = glob(["src/*.rs"]),
    crate_features = select({
        "@platforms//os:linux": [
            "std",
            "tonic",
        ],
        "//conditions:default": [],
    }),
    proc_macro_deps = ["@oak_crates_index//:prost-derive"],
    visibility = ["//visibility:public"],
    deps = [
        ":build",
        "@oak//micro_rpc",
        "@oak//oak_proto_rust",
        "@oak_crates_index//:prost",
    ] + select({
        "@platforms//os:linux": ["@oak_crates_index//:tonic"],
        "//conditions:default": [],
    }),
)
