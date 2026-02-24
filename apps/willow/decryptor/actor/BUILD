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
    name = "willow_decryptor_service",
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
        "//apps/willow/decryptor:__subpackages__",
    ],
    deps = [
        ":build",
        "//proto:tcp_proto",
        "//runtime:tcp_runtime",
        "//third_party/secure_aggregation",
        "@com_google_protobuf//rust:protobuf",
        "@oak//micro_rpc",
        "@oak//oak_attestation_verification",
        "@oak//oak_proto_rust",
        "@oak//oak_restricted_kernel_sdk",
        "@oak_crates_index//:hashbrown",
        "@oak_crates_index//:prost",
        "@oak_crates_index//:prost-types",
        "@oak_crates_index//:slog",
        "@secure_aggregation//willow/api:aggregation_config",
        "@secure_aggregation//willow/api:proto_serialization_traits",
        "@secure_aggregation//willow/crypto:ahe_traits",
        "@secure_aggregation//willow/crypto:kahe_traits",
        "@secure_aggregation//willow/crypto:shell_ahe",
        "@secure_aggregation//willow/crypto:shell_kahe",
        "@secure_aggregation//willow/crypto:shell_parameters",
        "@secure_aggregation//willow/crypto:shell_vahe",
        "@secure_aggregation//willow/crypto:vahe_traits",
        "@secure_aggregation//willow/proto/willow:key_rust_proto",
        "@secure_aggregation//willow/proto/willow:messages_rust_proto",
        "@secure_aggregation//willow/protocol:decryptor_traits",
        "@secure_aggregation//willow/protocol:messages",
        "@secure_aggregation//willow/protocol:willow_v1_decryptor",
    ] + select({
        "@platforms//os:linux": ["@oak_crates_index//:slog-term"],
        "//conditions:default": [],
    }),
)

rust_test(
    name = "willow_decryptor_service_integration_test",
    srcs = glob(["tests/*.rs"]),
    crate_features = [
        "testing",
        "std",
    ],
    env = {
        "RUST_TEST_THREADS": "1",
    },
    deps = [
        ":willow_decryptor_service",
        "//integration:tcp_integration",
        "//proto:tcp_proto",
        "//third_party/secure_aggregation",
        "@com_google_protobuf//rust:protobuf",
        "@oak_crates_index//:googletest",
        "@oak_crates_index//:mockall",
        "@oak_crates_index//:prost",
        "@secure_aggregation//willow/api:aggregation_config",
        "@secure_aggregation//willow/api:proto_serialization_traits",
        "@secure_aggregation//willow/crypto:ahe_traits",
        "@secure_aggregation//willow/crypto:kahe_traits",
        "@secure_aggregation//willow/crypto:shell_kahe",
        "@secure_aggregation//willow/crypto:shell_parameters",
        "@secure_aggregation//willow/crypto:shell_vahe",
        "@secure_aggregation//willow/proto/shell:shell_ciphertexts_rust_proto",
        "@secure_aggregation//willow/proto/willow:key_rust_proto",
        "@secure_aggregation//willow/proto/willow:messages_rust_proto",
        "@secure_aggregation//willow/protocol:client_traits",
        "@secure_aggregation//willow/protocol:messages",
        "@secure_aggregation//willow/protocol:server_traits",
        "@secure_aggregation//willow/protocol:verifier_traits",
        "@secure_aggregation//willow/protocol:willow_v1_client",
        "@secure_aggregation//willow/protocol:willow_v1_decryptor",
        "@secure_aggregation//willow/protocol:willow_v1_server",
        "@secure_aggregation//willow/protocol:willow_v1_verifier",
    ],
)
