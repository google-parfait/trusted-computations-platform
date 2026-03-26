# Copyright 2026 The Trusted Computations Platform Authors.
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

"""Loads dependencies for Trusted Computations Platform."""

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

def _tcp_deps_impl(ctx):
    # If a dependency supports bzlmod, add it in MODULE.bazel instead.
    # go/keep-sorted start block=yes newline_separated=yes
    http_archive(
        name = "raft_rs",
        patches = ["//third_party/raft_rs:bazel.patch"],
        sha256 = "e755de7613e7105c3bf90fb7742887cce7c7276723f16a9d1fe7c6053bd91973",
        strip_prefix = "raft-rs-10968a112dcc4143ad19a1b35b6dca6e30d2e439",
        url = "https://github.com/google-parfait/raft-rs/archive/10968a112dcc4143ad19a1b35b6dca6e30d2e439.tar.gz",
    )
    # go/keep-sorted end

    return ctx.extension_metadata(reproducible = True)

tcp_deps = module_extension(
    doc = """\
Non-bzlmod enabled, non-dev dependencies for Trusted Computations Platform.

These dependencies are loaded using a module extension instead of
`http_archive = use_repo_rule("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")`
in MODULE.bazel so that modules depending on TCP can reuse this extension to
avoid duplicate dependencies -- and possible linker errors.

The list of dependencies specified here is not guaranteed to be stable, with
the goal of all dependencies moving to MODULE.bazel when they support bzlmod.
    """,
    implementation = _tcp_deps_impl,
)

def _tcp_dev_deps_impl(ctx):
    # If a dependency supports bzlmod, add it in MODULE.bazel instead.
    # go/keep-sorted start block=yes newline_separated=yes
    http_archive(
        name = "bazel_toolchains",
        sha256 = "02e4f3744f1ce3f6e711e261fd322916ddd18cccd38026352f7a4c0351dbda19",
        strip_prefix = "bazel-toolchains-5.1.2",
        url = "https://github.com/bazelbuild/bazel-toolchains/archive/refs/tags/v5.1.2.tar.gz",
    )
    # go/keep-sorted end

    return ctx.extension_metadata(reproducible = True)

tcp_dev_deps = module_extension(
    doc = """\
Non-bzlmod enabled, dev dependencies for Trusted Computations Platform.

These dependencies are loaded using a module extension instead of
`http_archive = use_repo_rule("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")`
so that the dependencies can be loaded with `dev_dependency = True`.

The list of dependencies specified here is not guaranteed to be stable, with
the goal of all dependencies moving to MODULE.bazel when they support bzlmod.
    """,
    implementation = _tcp_dev_deps_impl,
)
