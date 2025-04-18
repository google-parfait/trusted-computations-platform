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

load("@rules_rust//rust:defs.bzl", "rust_library")

rust_library(
    name = "tcp_integration",
    srcs = glob(["src/*.rs"]),
    crate_features = select({
        "@platforms//os:linux": [
            "testing",
            "std",
        ],
        "//conditions:default": [],
    }),
    proc_macro_deps = ["@oak_crates_index//:prost-derive"],
    visibility = [
        "//visibility:public",
    ],
    deps = [
        "//proto:tcp_proto",
        "//runtime:tcp_runtime",
        "@oak//micro_rpc",
        "@oak//oak_attestation_types",
        "@oak//oak_proto_rust",
        "@oak//oak_restricted_kernel_sdk",
        "@oak//oak_session",
        "@oak_crates_index//:anyhow",
        "@oak_crates_index//:hashbrown",
        "@oak_crates_index//:prost",
        "@oak_crates_index//:prost-types",
        "@oak_crates_index//:slog",
        "@raft_rs//:raft",
    ] + select({
        "@platforms//os:linux": ["@oak_crates_index//:slog-term"],
        "//conditions:default": [],
    }),
)
