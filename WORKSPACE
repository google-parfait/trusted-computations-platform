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

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

http_archive(
    name = "bazel_skylib",
    sha256 = "bc283cdfcd526a52c3201279cda4bc298652efa898b10b4db0837dc51652756f",
    urls = [
        "https://mirror.bazel.build/github.com/bazelbuild/bazel-skylib/releases/download/1.7.1/bazel-skylib-1.7.1.tar.gz",
        "https://github.com/bazelbuild/bazel-skylib/releases/download/1.7.1/bazel-skylib-1.7.1.tar.gz",
    ],
)

load("@bazel_skylib//:workspace.bzl", "bazel_skylib_workspace")

bazel_skylib_workspace()

http_archive(
    name = "bazel_toolchains",
    sha256 = "02e4f3744f1ce3f6e711e261fd322916ddd18cccd38026352f7a4c0351dbda19",
    strip_prefix = "bazel-toolchains-5.1.2",
    url = "https://github.com/bazelbuild/bazel-toolchains/archive/refs/tags/v5.1.2.tar.gz",
)

http_archive(
    name = "rules_python",
    sha256 = "dc6e2756130fafb90273587003659cadd1a2dfef3f6464c227794cdc01ebf70e",
    strip_prefix = "rules_python-0.33.0",
    url = "https://github.com/bazelbuild/rules_python/releases/download/0.33.0/rules_python-0.33.0.tar.gz",
)

http_archive(
    name = "com_google_protobuf",
    sha256 = "1535151efbc7893f38b0578e83cac584f2819974f065698976989ec71c1af84a",
    strip_prefix = "protobuf-27.3",
    urls = ["https://github.com/protocolbuffers/protobuf/releases/download/v27.3/protobuf-27.3.tar.gz"],
)

load("@com_google_protobuf//:protobuf_deps.bzl", "protobuf_deps")

protobuf_deps()

http_archive(
    name = "rules_pkg",
    sha256 = "d20c951960ed77cb7b341c2a59488534e494d5ad1d30c4818c736d57772a9fef",
    urls = [
        "https://mirror.bazel.build/github.com/bazelbuild/rules_pkg/releases/download/1.0.1/rules_pkg-1.0.1.tar.gz",
        "https://github.com/bazelbuild/rules_pkg/releases/download/1.0.1/rules_pkg-1.0.1.tar.gz",
    ],
)

http_archive(
    name = "aspect_bazel_lib",
    sha256 = "b59781939f40c8bf148f4a71bd06e3027e15e40e98143ea5688b83531ec8528f",
    strip_prefix = "bazel-lib-2.7.6",
    url = "https://github.com/aspect-build/bazel-lib/releases/download/v2.7.6/bazel-lib-v2.7.6.tar.gz",
)

load("@aspect_bazel_lib//lib:repositories.bzl", "register_yq_toolchains")

register_yq_toolchains()

http_archive(
    name = "rules_proto",
    sha256 = "602e7161d9195e50246177e7c55b2f39950a9cf7366f74ed5f22fd45750cd208",
    strip_prefix = "rules_proto-97d8af4dc474595af3900dd85cb3a29ad28cc313",
    urls = [
        "https://mirror.bazel.build/github.com/bazelbuild/rules_proto/archive/97d8af4dc474595af3900dd85cb3a29ad28cc313.tar.gz",
        "https://github.com/bazelbuild/rules_proto/archive/97d8af4dc474595af3900dd85cb3a29ad28cc313.tar.gz",
    ],
)

load("@rules_proto//proto:repositories.bzl", "rules_proto_dependencies", "rules_proto_toolchains")

rules_proto_dependencies()

rules_proto_toolchains()

http_archive(
    name = "oak",
    sha256 = "5bb692898705ae3dcdb2e7a385e7afc681e3f18866120aee6b06d1615f5a4cf9",
    strip_prefix = "oak-d889956d9503c0459b96579e75ba34583d0809ae",
    url = "https://github.com/project-oak/oak/archive/d889956d9503c0459b96579e75ba34583d0809ae.tar.gz",
)

load("@oak//bazel:repositories.bzl", "oak_toolchain_repositories")

oak_toolchain_repositories()

load("@oak//bazel/rust:deps.bzl", "load_rust_repositories")

load_rust_repositories()

load("@oak//bazel/rust:defs.bzl", "setup_rust_dependencies")

setup_rust_dependencies()

load("@oak//bazel/crates:repositories.bzl", "create_oak_crate_repositories")
load("//bazel:crates.bzl", "TCP_NO_STD_PACKAGES", "TCP_PACKAGES")

create_oak_crate_repositories(
    extra_no_std_packages = TCP_NO_STD_PACKAGES,
    extra_packages = TCP_PACKAGES,
)

load("@oak//bazel/crates:crates.bzl", "load_oak_crate_repositories")

load_oak_crate_repositories()

http_archive(
    name = "aspect_gcc_toolchain",
    sha256 = "3341394b1376fb96a87ac3ca01c582f7f18e7dc5e16e8cf40880a31dd7ac0e1e",
    strip_prefix = "gcc-toolchain-0.4.2",
    url = "https://github.com/aspect-build/gcc-toolchain/archive/refs/tags/0.4.2.tar.gz",
)

load("@aspect_gcc_toolchain//toolchain:repositories.bzl", "gcc_toolchain_dependencies")

gcc_toolchain_dependencies()

load("@aspect_gcc_toolchain//toolchain:defs.bzl", "ARCHS", "gcc_register_toolchain")

gcc_register_toolchain(
    name = "gcc_toolchain_x86_64",
    target_arch = ARCHS.x86_64,
)

gcc_register_toolchain(
    name = "gcc_toolchain_x86_64_unknown_none",
    extra_ldflags = ["-nostdlib"],
    target_arch = ARCHS.x86_64,
    target_compatible_with = [
        "@platforms//cpu:x86_64",
        "@platforms//os:none",
    ],
)

load("@rules_python//python:repositories.bzl", "py_repositories", "python_register_toolchains")

py_repositories()

python_register_toolchains(
    name = "python",
    ignore_root_user_error = True,
    python_version = "3.10",
)

http_archive(
    name = "raft_rs",
    patches = ["//third_party/raft_rs:bazel.patch"],
    sha256 = "e755de7613e7105c3bf90fb7742887cce7c7276723f16a9d1fe7c6053bd91973",
    strip_prefix = "raft-rs-10968a112dcc4143ad19a1b35b6dca6e30d2e439",
    url = "https://github.com/google-parfait/raft-rs/archive/10968a112dcc4143ad19a1b35b6dca6e30d2e439.tar.gz",
)

# Bazel rules for building OCI images and runtime bundles.
http_archive(
    name = "rules_oci",
    sha256 = "1bd16e455278d523f01326e0c3964cd64d7840a7e99cdd6e2617e59f698f3504",
    strip_prefix = "rules_oci-2.2.0",
    url = "https://github.com/bazel-contrib/rules_oci/releases/download/v2.2.0/rules_oci-v2.2.0.tar.gz",
)

load("@rules_oci//oci:dependencies.bzl", "rules_oci_dependencies")

rules_oci_dependencies()

load("@rules_oci//oci:repositories.bzl", "oci_register_toolchains")

oci_register_toolchains(name = "oci")

load("@rules_oci//oci:pull.bzl", "oci_pull")

oci_pull(
    name = "distroless_cc_debian12",
    digest = "sha256:6714977f9f02632c31377650c15d89a7efaebf43bab0f37c712c30fc01edb973",
    image = "gcr.io/distroless/cc-debian12",
    platforms = ["linux/amd64"],
)

# Hacks

# Stub out unneeded Java proto library rules used by various dependencies. This
# avoids needing to depend on a Java toolchain.
load("//bazel:stub_repo.bzl", "stub_repo")

stub_repo(
    name = "io_grpc_grpc_java",
    rules = {":java_grpc_library.bzl": ["java_grpc_library"]},
)

stub_repo(
    name = "com_github_grpc_grpc",
    rules = {"bazel:cc_grpc_library.bzl": ["cc_grpc_library"]},
)
