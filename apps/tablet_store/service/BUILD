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
    crate_features = ["bazel"],
    data = glob(["proto/**"]) + [
        "@com_google_protobuf//:descriptor_proto_srcs",
        "@com_google_protobuf//:well_known_type_protos",
    ],
    tools = ["@com_google_protobuf//:protoc"],
    deps = [
        "@oak//micro_rpc_build",
        "@oak//oak_proto_build_utils",
    ],
)

rust_library(
    name = "tcp_tablet_store_service",
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
        "//apps/tablet_cache/service:__pkg__",
        "//apps/tablet_store/app:__pkg__",
    ],
    deps = [
        ":build",
        "//proto:tcp_proto",
        "//runtime:tcp_runtime",
        "@crates_index//:hashbrown",
        "@crates_index//:prost",
        "@crates_index//:prost-types",
        "@crates_index//:rand",
        "@crates_index//:slog",
        "@oak//micro_rpc",
        "@oak//oak_attestation_verification",
        "@oak//oak_proto_rust",
        "@oak//oak_restricted_kernel_sdk",
    ] + select({
        "@platforms//os:linux": ["@crates_index//:slog-term"],
        "//conditions:default": [],
    }),
)

rust_test(
    name = "tcp_tablet_store_service_test",
    crate = ":tcp_tablet_store_service",
    crate_features = [
        "testing",
        "std",
    ],
    deps = [
        "@crates_index//:googletest",
        "@crates_index//:mockall",
    ],
)

rust_test(
    name = "tcp_tablet_store_service_integration_test",
    srcs = glob(["tests/*.rs"]),
    crate_features = [
        "testing",
        "std",
    ],
    deps = [
        ":tcp_tablet_store_service",
        "//integration:tcp_integration",
        "//proto:tcp_proto",
        "@crates_index//:googletest",
        "@crates_index//:mockall",
        "@crates_index//:prost",
    ],
)
