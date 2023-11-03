#!/bin/bash

# Exit when any command fails
set -e

# Switch to the root of repository by stepping one level up
# from current script
cd $(dirname "$0")/..

readonly DOCKER_IMAGE_ID='europe-west2-docker.pkg.dev/oak-ci/oak-development/oak-development@sha256:7b6e401df8e90fec2597806a8c912649b9802de83abe9f6724c3dffe7772f07d'
# Instuct the docker to mount cargo cache and root of this repo as volumes
declare -ar DOCKER_RUN_FLAGS=(
  "--rm"
  "--volume=$PWD/.cargo-cache:/root/.cargo"
  "--volume=$PWD:/workspace"
  "--workdir=/workspace"
)

# Run test suite using docker image
docker run "${DOCKER_RUN_FLAGS[@]}" "${DOCKER_IMAGE_ID}" sh -c './scripts/tests.sh'

if [ "$1" == "release" ] || [ "$1" == "debug" ]; then
  mode=$([ "$1" == "release" ] && echo "--$1" || echo "")
  docker run "${DOCKER_RUN_FLAGS[@]}" "${DOCKER_IMAGE_ID}" \
      cargo build $mode \
          -p tcp_atomic_counter_enclave_app

  # KOKORO_ARTIFACTS_DIR may be unset if this script is run manually; it'll
  # always be set during CI builds.
  if [[ ! -z "${KOKORO_ARTIFACTS_DIR}" ]]; then
    mkdir -p "${KOKORO_ARTIFACTS_DIR}/binaries"
    cp --preserve=timestamps -v -f \
        target/x86_64-unknown-none/$1/tcp_atomic_counter_enclave_app \
        "${KOKORO_ARTIFACTS_DIR}/binaries/"
  fi

  # Store the git commit hash in the name of an empty file, so that it can be efficiently found via a glob.
  touch "$KOKORO_ARTIFACTS_DIR/binaries/git_commit_${KOKORO_GOB_COMMIT_trusted_computations_platform:?}"
fi