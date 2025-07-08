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
    },
    data = glob(["proto/**"]) + [
        "@com_google_protobuf//:descriptor_proto_srcs",
        "@com_google_protobuf//:well_known_type_protos",
    ],
    tools = ["@com_google_protobuf//:protoc"],
    deps = ["@oak//micro_rpc_build"],
)

rust_library(
    name = "tcp_tablet_cache_service",
    srcs = glob(["src/**/*.rs"]),
    crate_features = select({
        "@platforms//os:linux": [
            "testing",
            "std",
        ],
        "//conditions:default": [],
    }),
    proc_macro_deps = ["@oak_crates_index//:prost-derive"],
    visibility = [
        "//apps/tablet_cache/app:__pkg__",
    ],
    deps = [
        ":build",
        "//apps/tablet_store/service:tcp_tablet_store_service",
        "//proto:tcp_proto",
        "//runtime:tcp_runtime",
        "@oak//micro_rpc",
        "@oak//oak_attestation_verification",
        "@oak//oak_proto_rust",
        "@oak//oak_restricted_kernel_sdk",
        "@oak_crates_index//:ahash",
        "@oak_crates_index//:base64",
        "@oak_crates_index//:hashbrown",
        "@oak_crates_index//:prost",
        "@oak_crates_index//:prost-types",
        "@oak_crates_index//:rand",
        "@oak_crates_index//:sha2",
        "@oak_crates_index//:slog",
    ] + select({
        "@platforms//os:linux": [
            "@oak_crates_index//:mockall",
            "@oak_crates_index//:slog-term",
        ],
        "//conditions:default": [],
    }),
)

rust_test(
    name = "tcp_tablet_cache_service_test",
    crate = ":tcp_tablet_cache_service",
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
