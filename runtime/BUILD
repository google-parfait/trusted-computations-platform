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

load("@rules_rust//rust:defs.bzl", "rust_library", "rust_test")

rust_library(
    name = "tcp_runtime",
    srcs = glob(["src/**"]),
    crate_features = select({
        "@platforms//os:linux": [
            "std",
            "testing",
            "tonic",
        ],
        "//conditions:default": [],
    }),
    visibility = ["//visibility:public"],
    deps = [
        "//proto:tcp_proto",
        "@oak//micro_rpc",
        "@oak//oak_attestation",
        "@oak//oak_attestation_types",
        "@oak//oak_attestation_verification",
        "@oak//oak_attestation_verification/dice_attestation_verification:oak_dice_attestation_verifier",
        "@oak//oak_attestation_verification_types",
        "@oak//oak_crypto",
        "@oak//oak_proto_rust",
        "@oak//oak_restricted_kernel_sdk",
        "@oak//oak_session",
        "@oak_crates_index//:anyhow",
        "@oak_crates_index//:hashbrown",
        "@oak_crates_index//:prost",
        "@oak_crates_index//:slog",
        "@oak_crates_index//:spin",
        "@raft_rs//:raft",
    ] + select({
        "@platforms//os:linux": [
            "@oak//oak_sdk/common:oak_sdk_common",
            "@oak//oak_sdk/containers:oak_sdk_containers",
            "@oak_crates_index//:mockall",
            "@oak_crates_index//:slog-term",
            "@oak_crates_index//:tokio",
            "@oak_crates_index//:tonic",
        ],
        "//conditions:default": [],
    }),
)

rust_test(
    name = "tcp_runtime_test",
    crate = ":tcp_runtime",
    crate_features = [
        "testing",
        "std",
    ],
    env = {
        "RUST_TEST_THREADS": "1",
    },
    deps = [
        "@oak_crates_index//:googletest",
        "@oak_crates_index//:mockall",
    ],
)
