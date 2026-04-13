# Copyright 2025 The Trusted Computations Platform Authors.
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

load("@oak//oak_containers/app_base:defs.bzl", "app_bundle")
load("@rules_rust//rust:defs.bzl", "rust_binary")

rust_binary(
    name = "main",
    srcs = glob(["src/*.rs"]),
    rustc_flags = ["-Cpanic=abort"],
    deps = [
        "//apps/willow/decryptor/actor:willow_decryptor_service",
        "//proto:tcp_proto",
        "//runtime:tcp_runtime",
        "@oak//oak_proto_rust",
        "@oak//oak_sdk/containers:oak_sdk_containers",
        "@oak_crates_index//:anyhow",
        "@oak_crates_index//:log",
        "@oak_crates_index//:tokio",
        "@oak_crates_index//:tonic",
        "@secure_aggregation//willow/protocol:willow_v1_decryptor",
    ],
)

app_bundle(
    name = "bundle",
    binary = ":main",
    visibility = ["//:__pkg__"],
)
