load("@rules_rust//cargo:defs.bzl", "cargo_build_script")
load("@rules_rust//rust:defs.bzl", "rust_library")

cargo_build_script(
    name = "build",
    srcs = ["build.rs"],
    build_script_env = {
        "PROTOC": "$(execpath @com_google_protobuf//:protoc)",
        "DECRYPTOR_PROTO": "$(location @secure_aggregation//willow/proto/willow:decryptor.proto)",
        "SHELL_ENCRYPTION_PROTO": "$(location @shell-encryption//shell_encryption:serialization.proto)",
    },
    data = [
        "@secure_aggregation//willow/proto/shell:ciphertexts.proto",
        "@secure_aggregation//willow/proto/willow:decryptor.proto",
        "@secure_aggregation//willow/proto/willow:key.proto",
        "@secure_aggregation//willow/proto/willow:messages.proto",
        "@secure_aggregation//willow/proto/zk:proofs.proto",
        "@shell-encryption//shell_encryption:serialization.proto",
        "@shell-encryption//shell_encryption/rns:rns_serialization.proto",
    ],
    tools = ["@com_google_protobuf//:protoc"],
    deps = ["@oak//micro_rpc_build"],
)

rust_library(
    name = "secure_aggregation",
    srcs = glob(["src/**"]),
    proc_macro_deps = ["@oak_crates_index//:prost-derive"],
    tags = ["no-clippy"],
    visibility = ["//visibility:public"],
    deps = [
        ":build",
        "@oak//micro_rpc",
        "@oak//oak_proto_rust",
        "@oak_crates_index//:prost",
        "@oak_crates_index//:prost-types",
    ],
)
