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

#!/usr/bin/env bash

# Exit when any command fails
set -e

# Switch to the root of repository by stepping one level up
# from current script
cd $(dirname "$0")/..

readonly DOCKER_IMAGE_ID='europe-west2-docker.pkg.dev/oak-ci/oak-development/oak-development@sha256:a1ab2e25aa11e3e36900a0131f7430aa8cb11a38d0827c5e8c8c4d08470db6d0'
# Instuct the docker to mount cargo cache and root of this repo as volumes
declare -ar DOCKER_RUN_FLAGS=(
  "--rm"
  "--volume=$PWD/.cargo-cache:/root/.cargo"
  "--volume=$PWD:/workspace"
  "--workdir=/workspace"
)

# Run test suite using docker image
docker run "${DOCKER_RUN_FLAGS[@]}" "${DOCKER_IMAGE_ID}" nix develop --command bash -c './scripts/tests.sh'

if [ "$1" == "release" ] || [ "$1" == "debug" ]; then
  mode=$([ "$1" == "release" ] && echo "--$1" || echo "")
  docker run "${DOCKER_RUN_FLAGS[@]}" "${DOCKER_IMAGE_ID}" \
      nix develop --command env cargo build $mode \
          -p tcp_atomic_counter_enclave_app -p tcp_ledger_enclave_app -p tcp_tablet_cache_enclave_app -p tcp_tablet_store_enclave_app

  # KOKORO_ARTIFACTS_DIR may be unset if this script is run manually; it'll
  # always be set during CI builds.
  if [[ ! -z "${KOKORO_ARTIFACTS_DIR}" ]]; then
    mkdir -p "${KOKORO_ARTIFACTS_DIR}/binaries"
    cp --preserve=timestamps -v -f \
        target/x86_64-unknown-none/$1/tcp_atomic_counter_enclave_app \
        "${KOKORO_ARTIFACTS_DIR}/binaries/"
    cp --preserve=timestamps -v -f \
        target/x86_64-unknown-none/$1/tcp_ledger_enclave_app \
        "${KOKORO_ARTIFACTS_DIR}/binaries/"
  fi

  # Store the git commit hash in the name of an empty file, so that it can be efficiently found via a glob.
  touch "$KOKORO_ARTIFACTS_DIR/binaries/git_commit_${KOKORO_GOB_COMMIT_trusted_computations_platform:?}"
fi