// Copyright 2024 The Trusted Computations Platform Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use alloc::vec::Vec;
use oak_proto_rust::oak::crypto::v1::SessionKeys;

// Encryptor trait responsible for encrypting/decrypting messages between TCP
// replicas after handshake has successfully completed.
pub trait Encryptor {
    fn encrypt(&self, plaintext: &[u8]) -> anyhow::Result<Vec<u8>>;

    fn decrypt(&self, ciphertext: &[u8]) -> anyhow::Result<Vec<u8>>;
}

// Default implementation for Encryptor trait.
// TODO: Use Oak's default noise encryptor implementation once it is ready.
pub struct DefaultEncryptor {
    _session_keys: SessionKeys,
}

impl DefaultEncryptor {
    pub fn new(session_keys: SessionKeys) -> Self {
        Self {
            _session_keys: session_keys,
        }
    }
}

impl Encryptor for DefaultEncryptor {
    fn encrypt(&self, plaintext: &[u8]) -> anyhow::Result<Vec<u8>> {
        Ok(plaintext.to_vec())
    }

    fn decrypt(&self, ciphertext: &[u8]) -> anyhow::Result<Vec<u8>> {
        Ok(ciphertext.to_vec())
    }
}
