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

load("@rules_rust//rust:defs.bzl", "rust_binary")

rust_binary(
    name = "tcp_atomic_counter_enclave_app",
    srcs = glob(["src/*.rs"]),
    platform = "@oak//:x86_64-unknown-none",
    visibility = ["//:__pkg__"],
    deps = [
        "//apps/atomic_counter/service:tcp_atomic_counter_service",
        "//proto:tcp_proto",
        "//runtime:tcp_runtime",
        "@oak//micro_rpc",
        "@oak//oak_restricted_kernel_interface",
        "@oak//oak_restricted_kernel_sdk",
    ],
)
