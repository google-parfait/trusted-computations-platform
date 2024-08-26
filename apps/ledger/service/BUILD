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
load("@rules_rust//rust:defs.bzl", "rust_library", "rust_test")

cargo_build_script(
    name = "build",
    srcs = ["build.rs"],
    build_script_env = {
        "PROTOC": "$(execpath @com_google_protobuf//:protoc)",
        "DESCRIPTOR_PROTO": "$(location @com_google_protobuf//:descriptor_proto_srcs)",
        "EVIDENCE_PROTO": "$(location @oak//proto/attestation:evidence.proto)",
    },
    data = glob(["proto/**"]) + [
        "//apps/ledger/federated_compute:proto/access_policy.proto",
        "//apps/ledger/federated_compute:proto/blob_header.proto",
        "//apps/ledger/federated_compute:proto/ledger.proto",
        "@com_google_protobuf//:descriptor_proto_srcs",
        "@com_google_protobuf//:well_known_type_protos",
        "@oak//proto:digest.proto",
        "@oak//proto/attestation:endorsement.proto",
        "@oak//proto/attestation:eventlog.proto",
        "@oak//proto/attestation:evidence.proto",
        "@oak//proto/attestation:reference_value.proto",
        "@oak//proto/micro_rpc:options.proto",
    ],
    tools = ["@com_google_protobuf//:protoc"],
    deps = [
        "@oak//micro_rpc_build",
        "@oak//oak_proto_build_utils",
    ],
)

rust_library(
    name = "tcp_ledger_service",
    srcs = glob([
        "src/*.rs",
    ]),
    crate_features = select({
        "@platforms//os:linux": [
            "testing",
            "std",
        ],
        "//conditions:default": [],
    }),
    proc_macro_deps = ["@oak_crates_index//:prost-derive"],
    visibility = [
        "//apps/ledger/app:__pkg__",
    ],
    deps = [
        ":build",
        "//apps/ledger/cfc_crypto",
        "//apps/ledger/federated_compute",
        "//proto:tcp_proto",
        "//runtime:tcp_runtime",
        "@oak//micro_rpc",
        "@oak//oak_attestation",
        "@oak//oak_attestation_verification",
        "@oak//oak_proto_rust",
        "@oak//oak_restricted_kernel_sdk",
        "@oak_crates_index//:anyhow",
        "@oak_crates_index//:coset",
        "@oak_crates_index//:hpke",
        "@oak_crates_index//:p256",
        "@oak_crates_index//:prost",
        "@oak_crates_index//:prost-types",
        "@oak_crates_index//:rand",
        "@oak_crates_index//:sha2",
        "@oak_crates_index//:slog",
    ] + select({
        "@platforms//os:linux": [
            "@oak_crates_index//:slog-term",
        ],
        "//conditions:default": [],
    }),
)

rust_test(
    name = "tcp_ledger_service_test",
    crate = ":tcp_ledger_service",
    crate_features = [
        "testing",
        "std",
    ],
    deps = [
        "@oak_crates_index//:googletest",
        "@oak_crates_index//:mockall",
    ],
)

rust_test(
    name = "tcp_ledger_service_integration_test",
    srcs = glob(["tests/*.rs"]),
    crate_features = [
        "testing",
        "std",
    ],
    deps = [
        ":tcp_ledger_service",
        "//apps/ledger/cfc_crypto",
        "//apps/ledger/federated_compute",
        "//integration:tcp_integration",
        "//proto:tcp_proto",
        "//runtime:tcp_runtime",
        "@oak//micro_rpc",
        "@oak//oak_attestation_verification",
        "@oak//oak_proto_rust",
        "@oak//oak_restricted_kernel_sdk",
        "@oak_crates_index//:anyhow",
        "@oak_crates_index//:coset",
        "@oak_crates_index//:googletest",
        "@oak_crates_index//:hpke",
        "@oak_crates_index//:p256",
        "@oak_crates_index//:prost",
        "@oak_crates_index//:prost-types",
        "@oak_crates_index//:rand",
        "@oak_crates_index//:sha2",
        "@oak_crates_index//:slog",
    ],
)
