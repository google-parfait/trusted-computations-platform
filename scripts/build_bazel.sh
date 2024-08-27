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
#
# A script that runs the build process for the entire repository.
# This script can be run locally or in CI.
#
# If `release` or `debug` is passed, this indicates that the script should build the
# artifacts for release or dev. In other words, it will build binaries in the form in
# which they can be executed in an enclave and export them to
# BINARY_OUTPUTS_DIR.

#!/usr/bin/env bash

set -e
set -x

# If bazelisk isn't in user's path, the BAZELISK environment variable may be set
# instead. This may also be used to pass startup options like --nosystem_rc to
# bazel; this usage requires us to not quote ${BAZELISK} when used later.
readonly BAZELISK="${BAZELISK:-bazelisk}"

if [ "$1" == "release" ] || [ "$1" == "debug" ]; then
  mode=$([ "$1" == "release" ] && echo "opt" || echo "dbg")
  # BINARY_OUTPUTS_DIR may be unset if this script is run manually; it'll
  # always be set during CI builds.
  if [[ -n "${BINARY_OUTPUTS_DIR}" ]]; then
    ${BAZELISK} run -c $mode //:install_binaries -- --destdir "${BINARY_OUTPUTS_DIR}"
  else
    # If unset, verify the binaries can be built.
    ${BAZELISK} build -c $mode //:install_binaries
  fi
else
  # Verify the runtime can be built with no_std support
  ${BAZELISK} build //runtime:tcp_runtime --platforms=@oak//:x86_64-unknown-none
  # Verify the binaries can be built.
  ${BAZELISK} build -c opt //:install_binaries
fi

# Run all tests
${BAZELISK} test //...
