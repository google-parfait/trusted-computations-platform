# Copyright 2024 The Trusted Computations Platform Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http:#www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

load("@rules_pkg//pkg:install.bzl", "pkg_install")
load("@rules_pkg//pkg:mappings.bzl", "pkg_files")

# All artifacts that will be built for release, along with their names in the
# destination directory.
_ALL_BINARIES = {
    "//apps/atomic_counter/app:tcp_atomic_counter_enclave_app": "tcp_atomic_counter_enclave_app/binary",
    "//apps/ledger/app:tcp_ledger_enclave_app": "tcp_ledger_enclave_app/binary",
    "//apps/tablet_cache/app:tcp_tablet_cache_enclave_app": "tcp_tablet_cache_enclave_app/binary",
    "//apps/tablet_store/app:tcp_tablet_store_enclave_app": "tcp_tablet_store_enclave_app/binary",
}

pkg_files(
    name = "all_binaries",
    srcs = _ALL_BINARIES.keys(),
    renames = _ALL_BINARIES,
)

pkg_install(
    name = "install_binaries",
    srcs = [":all_binaries"],
)
