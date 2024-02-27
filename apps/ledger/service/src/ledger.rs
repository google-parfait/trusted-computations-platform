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

use alloc::{collections::BTreeMap, format, vec::Vec};
use anyhow::anyhow;
use core::time::Duration;

use cfc_crypto::PrivateKey;
use hpke::{Deserializable, Serializable};
use prost::Message;
use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256};

use crate::attestation::{self, Application};
use crate::budget::{self, BudgetTracker};

use crate::fcp::confidentialcompute::*;

pub trait Ledger {
    fn create_key(
        &mut self,
        request: CreateKeyRequest,
    ) -> Result<CreateKeyResponse, micro_rpc::Status>;

    fn delete_key(
        &mut self,
        request: DeleteKeyRequest,
    ) -> Result<DeleteKeyResponse, micro_rpc::Status>;

    fn authorize_access(
        &mut self,
        request: AuthorizeAccessRequest,
    ) -> Result<AuthorizeAccessResponse, micro_rpc::Status>;

    fn revoke_access(
        &mut self,
        request: RevokeAccessRequest,
    ) -> Result<RevokeAccessResponse, micro_rpc::Status>;
}

struct PerKeyLedger {
    private_key: cfc_crypto::PrivateKey,
    public_key: Vec<u8>,
    expiration: Duration,
    budget_tracker: budget::BudgetTracker,
}

#[derive(Default)]
pub struct LedgerService {
    current_time: Duration,
    per_key_ledgers: BTreeMap<u32, PerKeyLedger>,
}

impl LedgerService {
    pub fn new() -> Self {
        Self::default()
    }

    /// Updates `self.current_time` and removes expired keys.
    fn update_current_time(&mut self, now: &Option<prost_types::Timestamp>) -> anyhow::Result<()> {
        let now = Self::parse_timestamp(now).map_err(|err| anyhow!("{:?}", err))?;
        if now < self.current_time {
            return Err(anyhow!("time must be monotonic"));
        }
        self.current_time = now;
        self.per_key_ledgers.retain(|_, v| v.expiration > now);
        Ok(())
    }

    /// Parses a proto Timestamp as a Duration since the Unix epoch.
    fn parse_timestamp(
        timestamp: &Option<prost_types::Timestamp>,
    ) -> Result<Duration, core::num::TryFromIntError> {
        timestamp.as_ref().map_or(Ok(Duration::ZERO), |ts| {
            Ok(Duration::new(ts.seconds.try_into()?, ts.nanos.try_into()?))
        })
    }

    fn format_timestamp(timestamp: &Duration) -> Result<prost_types::Timestamp, micro_rpc::Status> {
        Ok(prost_types::Timestamp {
            seconds: timestamp.as_secs().try_into().map_err(|_| {
                micro_rpc::Status::new_with_message(
                    micro_rpc::StatusCode::InvalidArgument,
                    "`timestamp` overflowed",
                )
            })?,
            nanos: timestamp.subsec_nanos().try_into().unwrap(),
        })
    }

    /// Parses a proto Duration as a Rust Duration.
    fn parse_duration(
        duration: &Option<prost_types::Duration>,
    ) -> Result<Duration, prost_types::DurationError> {
        duration
            .clone()
            .map_or(Ok(Duration::ZERO), <Duration>::try_from)
    }

    pub fn verify_attestation<'a>(
        request: &'a AuthorizeAccessRequest,
    ) -> Result<Application<'a>, micro_rpc::Status> {
        attestation::verify_attestation(
            &request.recipient_public_key,
            &request.recipient_attestation,
            &request.recipient_tag,
        )
    }

    pub fn produce_create_key_event(
        &self,
        request: CreateKeyRequest,
    ) -> Result<CreateKeyEvent, micro_rpc::Status> {
        let now = Self::parse_timestamp(&request.now).map_err(|err| {
            micro_rpc::Status::new_with_message(
                micro_rpc::StatusCode::InvalidArgument,
                format!("`now` is invalid: {:?}", err),
            )
        })?;

        let ttl = Self::parse_duration(&request.ttl).map_err(|err| {
            micro_rpc::Status::new_with_message(
                micro_rpc::StatusCode::InvalidArgument,
                format!("`ttl` is invalid: {:?}", err),
            )
        })?;

        // The expiration time cannot overflow because proto Timestamps and Durations are signed
        // but Rust's Durations are unsigned.
        let expiration = now + ttl;

        // Find an available key id. The number of keys is expected to remain small, so this is
        // unlikely to require more than 1 or 2 attempts.
        // This relies on the state at the time when the event is produced, so there is
        // an extremely tiny chance of key_id collision by the time when the event is applied.
        // The code that applies the event must ensure that there is no collision.
        let mut key_id: u32;
        while {
            key_id = OsRng.next_u32();
            self.per_key_ledgers.contains_key(&key_id)
        } {}

        // Construct a new keypair.
        let (private_key, public_key) = cfc_crypto::gen_keypair();

        // Construct the details for the new key.
        let public_key_details = PublicKeyDetails {
            public_key_id: key_id,
            issued: Some(Self::format_timestamp(&now)?),
            expiration: Some(Self::format_timestamp(&expiration)?),
        };

        // Construct the event
        Ok(CreateKeyEvent {
            public_key,
            private_key: private_key.to_bytes().to_vec(),
            public_key_details: Some(public_key_details),
        })
    }

    pub fn apply_create_key_event(
        &mut self,
        event: CreateKeyEvent,
    ) -> Result<CreateKeyResponse, micro_rpc::Status> {
        let public_key_details = event.public_key_details.ok_or_else(|| {
            micro_rpc::Status::new_with_message(
                micro_rpc::StatusCode::InvalidArgument,
                "`public_key_details` is missing",
            )
        })?;

        self.update_current_time(&public_key_details.issued)
            .map_err(|err| {
                micro_rpc::Status::new_with_message(
                    micro_rpc::StatusCode::InvalidArgument,
                    format!("`public_key_details.issued` is invalid: {:?}", err),
                )
            })?;

        let expiration = Self::parse_timestamp(&public_key_details.expiration).map_err(|err| {
            micro_rpc::Status::new_with_message(
                micro_rpc::StatusCode::InvalidArgument,
                format!("`public_key_details.expiration` is invalid: {:?}", err),
            )
        })?;

        let key_id = public_key_details.public_key_id;

        // Verify that there is no key_id collision
        if self.per_key_ledgers.contains_key(&key_id) {
            return Err(micro_rpc::Status::new_with_message(
                micro_rpc::StatusCode::InvalidArgument,
                "Cannot commit changes for already used key_id",
            ));
        }

        let public_key = event.public_key;
        let private_key = PrivateKey::from_bytes(&event.private_key).map_err(|err| {
            micro_rpc::Status::new_with_message(
                micro_rpc::StatusCode::InvalidArgument,
                format!("failed to parse `private_key`: {:?}", err),
            )
        })?;

        // Insert keys
        self.per_key_ledgers.insert(
            key_id,
            PerKeyLedger {
                private_key,
                public_key: public_key.clone(),
                expiration,
                budget_tracker: budget::BudgetTracker::new(),
            },
        );

        Ok(CreateKeyResponse {
            public_key,
            public_key_details: public_key_details.encode_to_vec(),
            ..Default::default()
        })
    }

    pub fn save_snapshot(&self) -> Result<LedgerSnapshot, micro_rpc::Status> {
        let mut snapshot = LedgerSnapshot::default();

        snapshot.current_time = Some(Self::format_timestamp(&self.current_time)?);

        for (key_id, per_key_ledger) in &self.per_key_ledgers {
            snapshot.per_key_snapshots.push(PerKeySnapshot {
                public_key_id: *key_id,
                public_key: per_key_ledger.public_key.clone(),
                private_key: per_key_ledger.private_key.to_bytes().to_vec(),
                expiration: Some(Self::format_timestamp(&per_key_ledger.expiration)?),
                budgets: Some(per_key_ledger.budget_tracker.save_snapshot()),
            });
        }
        Ok(snapshot)
    }

    pub fn load_snapshot(&mut self, snapshot: LedgerSnapshot) -> Result<(), micro_rpc::Status> {
        self.current_time = Self::parse_timestamp(&snapshot.current_time).map_err(|err| {
            micro_rpc::Status::new_with_message(
                micro_rpc::StatusCode::InvalidArgument,
                format!("`current_time` is invalid: {:?}", err),
            )
        })?;
        self.per_key_ledgers.clear();

        for per_key_snapshot in snapshot.per_key_snapshots {
            let mut per_key_ledger = PerKeyLedger {
                private_key: PrivateKey::from_bytes(&per_key_snapshot.private_key).map_err(
                    |err| {
                        micro_rpc::Status::new_with_message(
                            micro_rpc::StatusCode::InvalidArgument,
                            format!("failed to parse `private_key`: {:?}", err),
                        )
                    },
                )?,
                public_key: per_key_snapshot.public_key,
                expiration: Self::parse_timestamp(&per_key_snapshot.expiration).map_err(|err| {
                    micro_rpc::Status::new_with_message(
                        micro_rpc::StatusCode::InvalidArgument,
                        format!("`expiration` is invalid: {:?}", err),
                    )
                })?,
                budget_tracker: BudgetTracker::new(),
            };
            if per_key_snapshot.budgets.is_some() {
                per_key_ledger
                    .budget_tracker
                    .load_snapshot(per_key_snapshot.budgets.unwrap())?;
            }
            if self
                .per_key_ledgers
                .insert(per_key_snapshot.public_key_id, per_key_ledger)
                .is_some()
            {
                return Err(micro_rpc::Status::new_with_message(
                    micro_rpc::StatusCode::InvalidArgument,
                    "Duplicated `public_key_id` in the snapshot",
                ));
            }
        }

        Ok(())
    }
}

impl Ledger for LedgerService {
    fn create_key(
        &mut self,
        request: CreateKeyRequest,
    ) -> Result<CreateKeyResponse, micro_rpc::Status> {
        let create_key_event = self.produce_create_key_event(request)?;
        self.apply_create_key_event(create_key_event)
    }

    fn delete_key(
        &mut self,
        request: DeleteKeyRequest,
    ) -> Result<DeleteKeyResponse, micro_rpc::Status> {
        match self.per_key_ledgers.remove(&request.public_key_id) {
            Some(_) => Ok(DeleteKeyResponse::default()),
            None => Err(micro_rpc::Status::new_with_message(
                micro_rpc::StatusCode::NotFound,
                "public key not found",
            )),
        }
    }

    fn authorize_access(
        &mut self,
        request: AuthorizeAccessRequest,
    ) -> Result<AuthorizeAccessResponse, micro_rpc::Status> {
        self.update_current_time(&request.now).map_err(|err| {
            micro_rpc::Status::new_with_message(
                micro_rpc::StatusCode::InvalidArgument,
                format!("`now` is invalid: {:?}", err),
            )
        })?;

        // TODO(b/288331695): Attestation validation must be done before calling this method.
        // Here the implementation assumes that the attestation has already been done.
        let recipient_app = Application {
            tag: &request.recipient_tag,
        };

        // Decode the blob header and access policy. Since the access policy was provided by an
        // untrusted source, we need to verify it by checking the hash in the header. The header is
        // also unverified at this point, but will be authenticated later when it's used as the
        // associated data for re-wrapping the symmetric key. This ensures that any request that
        // uses a different header or access policy than what was approved by the client will fail.
        let header = BlobHeader::decode(request.blob_header.as_ref()).map_err(|err| {
            micro_rpc::Status::new_with_message(
                micro_rpc::StatusCode::InvalidArgument,
                format!("failed to parse blob header: {:?}", err),
            )
        })?;
        if Sha256::digest(&request.access_policy).as_slice() != header.access_policy_sha256 {
            return Err(micro_rpc::Status::new_with_message(
                micro_rpc::StatusCode::InvalidArgument,
                "access policy does not match blob header",
            ));
        }
        let access_policy =
            DataAccessPolicy::decode(request.access_policy.as_ref()).map_err(|err| {
                micro_rpc::Status::new_with_message(
                    micro_rpc::StatusCode::InvalidArgument,
                    format!("failed to parse access policy: {:?}", err),
                )
            })?;

        // Find the right per-key ledger.
        let per_key_ledger = self
            .per_key_ledgers
            .get_mut(&header.public_key_id)
            .ok_or_else(|| {
                micro_rpc::Status::new_with_message(
                    micro_rpc::StatusCode::NotFound,
                    "public key not found",
                )
            })?;

        // Verify that the access is authorized and that there is still budget remaining.
        let transform_index = per_key_ledger.budget_tracker.find_matching_transform(
            &header.blob_id,
            header.access_policy_node_id,
            &access_policy,
            &header.access_policy_sha256,
            &recipient_app,
        )?;

        // Re-wrap the blob's symmetric key. This should be done before budgets are updated in case
        // there are decryption errors (e.g., due to invalid associated data).
        let wrap_associated_data =
            [&per_key_ledger.public_key[..], &request.recipient_nonce[..]].concat();
        let (encapsulated_key, encrypted_symmetric_key) = cfc_crypto::rewrap_symmetric_key(
            &request.encrypted_symmetric_key,
            &request.encapsulated_key,
            &per_key_ledger.private_key,
            /* unwrap_associated_data= */ &request.blob_header,
            &request.recipient_public_key,
            &wrap_associated_data,
        )
        .map_err(|err| {
            micro_rpc::Status::new_with_message(
                micro_rpc::StatusCode::InvalidArgument,
                format!("failed to re-wrap symmetric key: {:?}", err),
            )
        })?;

        // Update the budget. This shouldn't fail since there was sufficient budget earlier.
        per_key_ledger.budget_tracker.update_budget(
            &header.blob_id,
            transform_index,
            &access_policy,
            &header.access_policy_sha256,
        )?;

        // TODO(b/288282266): Include the selected transform's destination node id in the response.
        Ok(AuthorizeAccessResponse {
            encapsulated_key,
            encrypted_symmetric_key,
            reencryption_public_key: per_key_ledger.public_key.clone(),
        })
    }

    fn revoke_access(
        &mut self,
        request: RevokeAccessRequest,
    ) -> Result<RevokeAccessResponse, micro_rpc::Status> {
        let per_key_ledger = self
            .per_key_ledgers
            .get_mut(&request.public_key_id)
            .ok_or_else(|| {
                micro_rpc::Status::new_with_message(
                    micro_rpc::StatusCode::NotFound,
                    "public key not found",
                )
            })?;

        per_key_ledger
            .budget_tracker
            .consume_budget(&request.blob_id);
        Ok(RevokeAccessResponse {})
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::assert_err;
    use crate::fcp::confidentialcompute::{
        access_budget::Kind as AccessBudgetKind, data_access_policy::Transform, AccessBudget,
        ApplicationMatcher,
    };
    use alloc::{borrow::ToOwned, vec};

    /// Helper function to create a LedgerService with one key.
    fn create_ledger_service() -> (LedgerService, Vec<u8>, u32) {
        let mut ledger = LedgerService::default();
        let response = ledger
            .create_key(CreateKeyRequest {
                ttl: Some(prost_types::Duration {
                    seconds: 3600,
                    ..Default::default()
                }),
                ..Default::default()
            })
            .unwrap();
        let details = PublicKeyDetails::decode(response.public_key_details.as_ref()).unwrap();
        (ledger, response.public_key, details.public_key_id)
    }

    #[test]
    fn test_create_key() {
        let mut ledger = LedgerService::default();

        let response1 = ledger
            .create_key(CreateKeyRequest {
                now: Some(prost_types::Timestamp {
                    seconds: 1000,
                    ..Default::default()
                }),
                ttl: Some(prost_types::Duration {
                    seconds: 100,
                    ..Default::default()
                }),
            })
            .unwrap();
        let details1 = PublicKeyDetails::decode(response1.public_key_details.as_ref()).unwrap();

        assert_eq!(response1.attestation, &[]);
        assert_eq!(
            details1.issued,
            Some(prost_types::Timestamp {
                seconds: 1000,
                ..Default::default()
            })
        );
        assert_eq!(
            details1.expiration,
            Some(prost_types::Timestamp {
                seconds: 1100,
                ..Default::default()
            })
        );

        // Since the response contains many random fields, we can't check them directly. Instead,
        // we create a second key and verify that those fields are different.
        let response2 = ledger
            .create_key(CreateKeyRequest {
                now: Some(prost_types::Timestamp {
                    seconds: 1000,
                    ..Default::default()
                }),
                ttl: Some(prost_types::Duration {
                    seconds: 100,
                    ..Default::default()
                }),
            })
            .unwrap();
        let details2 = PublicKeyDetails::decode(response2.public_key_details.as_ref()).unwrap();

        assert_ne!(response1.public_key, response2.public_key);
        assert_ne!(details1.public_key_id, details2.public_key_id);
    }

    #[test]
    fn test_delete_key() {
        let (mut ledger, _, public_key_id) = create_ledger_service();
        assert_eq!(
            ledger.delete_key(DeleteKeyRequest { public_key_id }),
            Ok(DeleteKeyResponse::default())
        );

        // To verify that the key was actually deleted, we check that attempting to delete it again
        // produces an error.
        assert_err!(
            ledger.delete_key(DeleteKeyRequest { public_key_id }),
            micro_rpc::StatusCode::NotFound,
            "public key not found"
        );
    }

    #[test]
    fn test_delete_key_not_found() {
        let (mut ledger, _, public_key_id) = create_ledger_service();
        assert_err!(
            ledger.delete_key(DeleteKeyRequest {
                public_key_id: public_key_id.wrapping_add(1)
            }),
            micro_rpc::StatusCode::NotFound,
            "public key not found"
        );
    }

    #[test]
    fn test_authorize_access() {
        let (mut ledger, public_key, public_key_id) = create_ledger_service();

        // Define an access policy that grants access.
        let recipient_tag = "tag";
        let access_policy = DataAccessPolicy {
            transforms: vec![Transform {
                application: Some(ApplicationMatcher {
                    tag: Some(recipient_tag.to_owned()),
                }),
                ..Default::default()
            }],
            ..Default::default()
        }
        .encode_to_vec();

        // Construct a client message.
        let plaintext = b"plaintext";
        let blob_header = BlobHeader {
            blob_id: "blob-id".into(),
            public_key_id,
            access_policy_sha256: Sha256::digest(&access_policy).to_vec(),
            ..Default::default()
        }
        .encode_to_vec();
        let (ciphertext, encapsulated_key, encrypted_symmetric_key) =
            cfc_crypto::encrypt_message(plaintext, &public_key, &blob_header).unwrap();

        // Request access.
        let (recipient_private_key, recipient_public_key) = cfc_crypto::gen_keypair();
        let recipient_nonce: &[u8] = b"nonce";
        let response = ledger
            .authorize_access(AuthorizeAccessRequest {
                access_policy,
                blob_header: blob_header.clone(),
                encapsulated_key,
                encrypted_symmetric_key,
                recipient_public_key,
                recipient_tag: recipient_tag.to_owned(),
                recipient_nonce: recipient_nonce.to_owned(),
                ..Default::default()
            })
            .unwrap();

        // Verify that the response contains the right public key and allows the message to be read.
        assert_eq!(response.reencryption_public_key, public_key);
        assert_eq!(
            cfc_crypto::decrypt_message(
                &ciphertext,
                &blob_header,
                &response.encrypted_symmetric_key,
                &[&response.reencryption_public_key, recipient_nonce].concat(),
                &response.encapsulated_key,
                &recipient_private_key
            )
            .unwrap(),
            plaintext
        );
    }

    // TODO(b/288331695): Test authorize_access with an attestation failure.

    #[test]
    fn test_authorize_access_invalid_header() {
        let (mut ledger, public_key, public_key_id) = create_ledger_service();

        // Define an access policy that grants access.
        let recipient_tag = "tag";
        let access_policy = DataAccessPolicy {
            transforms: vec![Transform {
                application: Some(ApplicationMatcher {
                    tag: Some(recipient_tag.to_owned()),
                }),
                ..Default::default()
            }],
            ..Default::default()
        }
        .encode_to_vec();

        // Construct a client message.
        let blob_header = BlobHeader {
            blob_id: "blob-id".into(),
            public_key_id,
            access_policy_sha256: Sha256::digest(&access_policy).to_vec(),
            ..Default::default()
        }
        .encode_to_vec();
        let (_, encapsulated_key, encrypted_symmetric_key) =
            cfc_crypto::encrypt_message(b"plaintext", &public_key, &blob_header).unwrap();

        // Request access.
        assert_err!(
            ledger.authorize_access(AuthorizeAccessRequest {
                access_policy,
                blob_header: "invalid".into(),
                encapsulated_key,
                encrypted_symmetric_key,
                recipient_public_key: cfc_crypto::gen_keypair().1,
                recipient_tag: recipient_tag.to_owned(),
                recipient_nonce: "nonce".into(),
                ..Default::default()
            }),
            micro_rpc::StatusCode::InvalidArgument,
            "failed to parse blob header"
        );
    }

    #[test]
    fn test_authorize_access_invalid_access_policy_sha256() {
        let (mut ledger, public_key, public_key_id) = create_ledger_service();

        // Define an access policy that grants access.
        let recipient_tag = "tag";
        let access_policy = DataAccessPolicy {
            transforms: vec![Transform {
                application: Some(ApplicationMatcher {
                    tag: Some(recipient_tag.to_owned()),
                }),
                ..Default::default()
            }],
            ..Default::default()
        }
        .encode_to_vec();

        // Construct a client message.
        let blob_header = BlobHeader {
            blob_id: "blob-id".into(),
            public_key_id,
            access_policy_sha256: "invalid".into(),
            ..Default::default()
        }
        .encode_to_vec();
        let (_, encapsulated_key, encrypted_symmetric_key) =
            cfc_crypto::encrypt_message(b"plaintext", &public_key, &blob_header).unwrap();

        // Request access.
        assert_err!(
            ledger.authorize_access(AuthorizeAccessRequest {
                access_policy,
                blob_header: blob_header,
                encapsulated_key,
                encrypted_symmetric_key,
                recipient_public_key: cfc_crypto::gen_keypair().1,
                recipient_tag: recipient_tag.to_owned(),
                recipient_nonce: "nonce".into(),
                ..Default::default()
            }),
            micro_rpc::StatusCode::InvalidArgument,
            "access policy does not match blob header"
        );
    }

    #[test]
    fn test_authorize_access_invalid_access_policy() {
        let (mut ledger, public_key, public_key_id) = create_ledger_service();

        // Define an access policy that can't be decoded.
        let access_policy = b"invalid";

        // Construct a client message.
        let blob_header = BlobHeader {
            blob_id: "blob-id".into(),
            public_key_id,
            access_policy_sha256: Sha256::digest(access_policy).to_vec(),
            ..Default::default()
        }
        .encode_to_vec();
        let (_, encapsulated_key, encrypted_symmetric_key) =
            cfc_crypto::encrypt_message(b"plaintext", &public_key, &blob_header).unwrap();

        // Request access.
        assert_err!(
            ledger.authorize_access(AuthorizeAccessRequest {
                access_policy: access_policy.to_vec(),
                blob_header: blob_header,
                encapsulated_key,
                encrypted_symmetric_key,
                recipient_public_key: cfc_crypto::gen_keypair().1,
                recipient_tag: "tag".into(),
                recipient_nonce: "nonce".into(),
                ..Default::default()
            }),
            micro_rpc::StatusCode::InvalidArgument,
            "failed to parse access policy"
        );
    }

    #[test]
    fn test_authorize_access_application_mismatch() {
        let (mut ledger, public_key, public_key_id) = create_ledger_service();

        // Define an access policy that does not grant access.
        let access_policy = DataAccessPolicy::default().encode_to_vec();

        // Construct a client message.
        let blob_header = BlobHeader {
            blob_id: "blob-id".into(),
            public_key_id,
            access_policy_sha256: Sha256::digest(&access_policy).to_vec(),
            ..Default::default()
        }
        .encode_to_vec();
        let (_, encapsulated_key, encrypted_symmetric_key) =
            cfc_crypto::encrypt_message(b"plaintext", &public_key, &blob_header).unwrap();

        // Request access.
        assert_err!(
            ledger.authorize_access(AuthorizeAccessRequest {
                access_policy,
                blob_header,
                encapsulated_key,
                encrypted_symmetric_key,
                recipient_public_key: cfc_crypto::gen_keypair().1,
                recipient_tag: "non-matching-tag".into(),
                recipient_nonce: "nonce".into(),
                ..Default::default()
            }),
            micro_rpc::StatusCode::FailedPrecondition,
            ""
        );
    }

    #[test]
    fn test_authorize_access_decryption_error() {
        let (mut ledger, public_key, public_key_id) = create_ledger_service();

        // Define an access policy that grants access.
        let recipient_tag = "tag";
        let access_policy = DataAccessPolicy {
            transforms: vec![Transform {
                application: Some(ApplicationMatcher {
                    tag: Some(recipient_tag.to_owned()),
                }),
                ..Default::default()
            }],
            ..Default::default()
        }
        .encode_to_vec();

        // Construct a client message that was encrypted with different associated data.
        let blob_header = BlobHeader {
            blob_id: "blob-id".into(),
            public_key_id,
            access_policy_sha256: Sha256::digest(&access_policy).to_vec(),
            ..Default::default()
        }
        .encode_to_vec();
        let (_, encapsulated_key, encrypted_symmetric_key) =
            cfc_crypto::encrypt_message(b"plaintext", &public_key, b"other aad").unwrap();

        // Request access.
        assert_err!(
            ledger.authorize_access(AuthorizeAccessRequest {
                access_policy,
                blob_header: blob_header,
                encapsulated_key,
                encrypted_symmetric_key,
                recipient_public_key: cfc_crypto::gen_keypair().1,
                recipient_tag: recipient_tag.to_owned(),
                recipient_nonce: "nonce".into(),
                ..Default::default()
            }),
            micro_rpc::StatusCode::InvalidArgument,
            "failed to re-wrap symmetric key"
        );
    }

    #[test]
    fn test_authorize_access_missing_key_id() {
        let (mut ledger, public_key, public_key_id) = create_ledger_service();

        // Define an access policy that grants access.
        let recipient_tag = "tag";
        let access_policy = DataAccessPolicy {
            transforms: vec![Transform {
                application: Some(ApplicationMatcher {
                    tag: Some(recipient_tag.to_owned()),
                }),
                ..Default::default()
            }],
            ..Default::default()
        }
        .encode_to_vec();

        // Construct a client message using a public key id that doesn't exist.
        let blob_header = BlobHeader {
            blob_id: "blob-id".into(),
            public_key_id: public_key_id.wrapping_add(1),
            access_policy_sha256: Sha256::digest(&access_policy).to_vec(),
            ..Default::default()
        }
        .encode_to_vec();
        let (_, encapsulated_key, encrypted_symmetric_key) =
            cfc_crypto::encrypt_message(b"plaintext", &public_key, &blob_header).unwrap();

        // Request access.
        assert_err!(
            ledger.authorize_access(AuthorizeAccessRequest {
                access_policy,
                blob_header: blob_header,
                encapsulated_key,
                encrypted_symmetric_key,
                recipient_public_key: cfc_crypto::gen_keypair().1,
                recipient_tag: recipient_tag.to_owned(),
                recipient_nonce: "nonce".into(),
                ..Default::default()
            }),
            micro_rpc::StatusCode::NotFound,
            "public key not found"
        );
    }

    #[test]
    fn test_authorize_access_expired_key() {
        let (mut ledger, public_key, public_key_id) = create_ledger_service();

        // Define an access policy that grants access.
        let recipient_tag = "tag";
        let access_policy = DataAccessPolicy {
            transforms: vec![Transform {
                application: Some(ApplicationMatcher {
                    tag: Some(recipient_tag.to_owned()),
                }),
                ..Default::default()
            }],
            ..Default::default()
        }
        .encode_to_vec();

        // Construct a client message.
        let blob_header = BlobHeader {
            blob_id: "blob-id".into(),
            public_key_id,
            access_policy_sha256: Sha256::digest(&access_policy).to_vec(),
            ..Default::default()
        }
        .encode_to_vec();
        let (_, encapsulated_key, encrypted_symmetric_key) =
            cfc_crypto::encrypt_message(b"plaintext", &public_key, &blob_header).unwrap();

        // Request access. Since `now` is after the key's expiration time, access should be denied.
        assert_err!(
            ledger.authorize_access(AuthorizeAccessRequest {
                now: Some(prost_types::Timestamp {
                    seconds: 1_000_000_000,
                    ..Default::default()
                }),
                access_policy,
                blob_header: blob_header,
                encapsulated_key,
                encrypted_symmetric_key,
                recipient_public_key: cfc_crypto::gen_keypair().1,
                recipient_tag: recipient_tag.to_owned(),
                recipient_nonce: "nonce".into(),
                ..Default::default()
            }),
            micro_rpc::StatusCode::NotFound,
            "public key not found"
        );
    }

    #[test]
    fn test_authorize_access_updates_budget() {
        let (mut ledger, public_key, public_key_id) = create_ledger_service();
        let access_policy = DataAccessPolicy {
            transforms: vec![Transform {
                access_budget: Some(AccessBudget {
                    kind: Some(AccessBudgetKind::Times(1)),
                }),
                ..Default::default()
            }],
            ..Default::default()
        }
        .encode_to_vec();
        let plaintext = b"plaintext";
        let blob_header = BlobHeader {
            blob_id: b"blob-id".to_vec(),
            public_key_id,
            access_policy_sha256: Sha256::digest(&access_policy).to_vec(),
            ..Default::default()
        }
        .encode_to_vec();
        let (_, encapsulated_key, encrypted_symmetric_key) =
            cfc_crypto::encrypt_message(plaintext, &public_key, &blob_header).unwrap();

        // The first access should succeed.
        assert!(ledger
            .authorize_access(AuthorizeAccessRequest {
                access_policy: access_policy.clone(),
                blob_header: blob_header.clone(),
                encapsulated_key: encapsulated_key.clone(),
                encrypted_symmetric_key: encrypted_symmetric_key.clone(),
                recipient_public_key: cfc_crypto::gen_keypair().1,
                recipient_tag: "tag".to_owned(),
                recipient_nonce: b"nonce1".to_vec(),
                ..Default::default()
            })
            .is_ok());

        // But the second should fail because the budget has been exhausted.
        assert_err!(
            ledger.authorize_access(AuthorizeAccessRequest {
                access_policy,
                blob_header: blob_header.clone(),
                encapsulated_key,
                encrypted_symmetric_key,
                recipient_public_key: cfc_crypto::gen_keypair().1,
                recipient_tag: "tag".to_owned(),
                recipient_nonce: b"nonce2".to_vec(),
                ..Default::default()
            }),
            micro_rpc::StatusCode::ResourceExhausted,
            ""
        );
    }

    #[test]
    fn test_revoke_access() {
        let (mut ledger, public_key, public_key_id) = create_ledger_service();
        let blob_id = b"blob-id";
        assert_eq!(
            ledger.revoke_access(RevokeAccessRequest {
                public_key_id,
                blob_id: blob_id.to_vec(),
            }),
            Ok(RevokeAccessResponse::default())
        );

        // Subsequent access should not be granted.
        let access_policy = DataAccessPolicy {
            transforms: vec![Transform::default()],
            ..Default::default()
        }
        .encode_to_vec();
        let plaintext = b"plaintext";
        let blob_header = BlobHeader {
            blob_id: blob_id.to_vec(),
            public_key_id,
            access_policy_sha256: Sha256::digest(&access_policy).to_vec(),
            ..Default::default()
        }
        .encode_to_vec();
        let (_, encapsulated_key, encrypted_symmetric_key) =
            cfc_crypto::encrypt_message(plaintext, &public_key, &blob_header).unwrap();

        assert_err!(
            ledger.authorize_access(AuthorizeAccessRequest {
                access_policy,
                blob_header: blob_header.clone(),
                encapsulated_key,
                encrypted_symmetric_key,
                recipient_public_key: cfc_crypto::gen_keypair().1,
                recipient_tag: "tag".to_owned(),
                recipient_nonce: b"nonce".to_vec(),
                ..Default::default()
            }),
            micro_rpc::StatusCode::ResourceExhausted,
            ""
        );
    }

    #[test]
    fn test_revoke_access_key_not_found() {
        let (mut ledger, _, public_key_id) = create_ledger_service();
        assert_err!(
            ledger.revoke_access(RevokeAccessRequest {
                public_key_id: public_key_id.wrapping_add(1),
                blob_id: "blob-id".into(),
            }),
            micro_rpc::StatusCode::NotFound,
            "public key not found"
        );
    }

    #[test]
    fn test_monotonic_time() {
        let mut ledger = LedgerService::default();
        ledger
            .create_key(CreateKeyRequest {
                now: Some(prost_types::Timestamp {
                    seconds: 1000,
                    ..Default::default()
                }),
                ..Default::default()
            })
            .unwrap();

        // Timestamps passed to the LedgerService must be non-decreasing.
        assert_err!(
            ledger.create_key(CreateKeyRequest {
                now: Some(prost_types::Timestamp {
                    seconds: 500,
                    ..Default::default()
                }),
                ..Default::default()
            }),
            micro_rpc::StatusCode::InvalidArgument,
            "time must be monotonic"
        );
        assert_err!(
            ledger.authorize_access(AuthorizeAccessRequest {
                now: Some(prost_types::Timestamp {
                    seconds: 500,
                    ..Default::default()
                }),
                ..Default::default()
            }),
            micro_rpc::StatusCode::InvalidArgument,
            "time must be monotonic"
        );
    }

    #[test]
    fn test_save_snapshot() {
        let (mut ledger, public_key, public_key_id) = create_ledger_service();

        // Define an access policy that grants access.
        let recipient_tag = "tag";
        let access_policy = DataAccessPolicy {
            transforms: vec![Transform {
                application: Some(ApplicationMatcher {
                    tag: Some(recipient_tag.to_owned()),
                }),
                ..Default::default()
            }],
            ..Default::default()
        }
        .encode_to_vec();

        // Construct a client message.
        let now = prost_types::Timestamp {
            seconds: 1000,
            ..Default::default()
        };
        let plaintext = b"plaintext";
        let blob_header = BlobHeader {
            blob_id: "blob-id".into(),
            public_key_id,
            access_policy_sha256: Sha256::digest(&access_policy).to_vec(),
            ..Default::default()
        }
        .encode_to_vec();
        let (_, encapsulated_key, encrypted_symmetric_key) =
            cfc_crypto::encrypt_message(plaintext, &public_key, &blob_header).unwrap();

        // Request access.
        let (_, recipient_public_key) = cfc_crypto::gen_keypair();
        let recipient_nonce: &[u8] = b"nonce";
        let _ = ledger
            .authorize_access(AuthorizeAccessRequest {
                now: Some(now.clone()),
                access_policy: access_policy.clone(),
                blob_header: blob_header.clone(),
                encapsulated_key,
                encrypted_symmetric_key,
                recipient_public_key,
                recipient_tag: recipient_tag.to_owned(),
                recipient_nonce: recipient_nonce.to_owned(),
                ..Default::default()
            })
            .unwrap();

        // Produce the snapshot.
        let snapshot = ledger.save_snapshot().unwrap();
        assert_eq!(snapshot.per_key_snapshots.len(), 1);
        // Since the private key isn't exposed we have to assume that the one
        // in the snapshot is the right one.
        let private_key = &snapshot.per_key_snapshots[0].private_key;
        assert_eq!(
            snapshot,
            LedgerSnapshot {
                current_time: Some(now),
                per_key_snapshots: vec![PerKeySnapshot {
                    public_key_id,
                    public_key,
                    private_key: private_key.clone(),
                    expiration: Some(prost_types::Timestamp {
                        seconds: 3600,
                        ..Default::default()
                    }),
                    budgets: Some(BudgetSnapshot {
                        per_policy_snapshots: vec![PerPolicyBudgetSnapshot {
                            access_policy_sha256: Sha256::digest(&access_policy).to_vec(),
                            budgets: vec![BlobBudgetSnapshot {
                                blob_id: "blob-id".into(),
                                transform_access_budgets: vec![0],
                                shared_access_budgets: vec![],
                            }]
                        }],
                        consumed_budgets: vec![],
                    }),
                }],
            }
        );
    }

    #[test]
    fn test_load_snapshot() {
        let mut ledger = LedgerService::default();
        let (private_key, public_key) = cfc_crypto::gen_keypair();
        let snapshot = LedgerSnapshot {
            current_time: Some(prost_types::Timestamp {
                seconds: 1000,
                ..Default::default()
            }),
            per_key_snapshots: vec![
                PerKeySnapshot {
                    public_key_id: 1,
                    public_key: public_key.clone(),
                    private_key: private_key.to_bytes().to_vec(),
                    expiration: Some(prost_types::Timestamp {
                        seconds: 2000,
                        ..Default::default()
                    }),
                    budgets: Some(BudgetSnapshot {
                        per_policy_snapshots: vec![PerPolicyBudgetSnapshot {
                            access_policy_sha256: b"hash1".to_vec(),
                            budgets: vec![BlobBudgetSnapshot {
                                blob_id: b"blob1".to_vec(),
                                ..Default::default()
                            }],
                        }],
                        consumed_budgets: vec![],
                    }),
                },
                PerKeySnapshot {
                    public_key_id: 2,
                    public_key: public_key.clone(),
                    private_key: private_key.to_bytes().to_vec(),
                    expiration: Some(prost_types::Timestamp {
                        seconds: 2500,
                        ..Default::default()
                    }),
                    budgets: Some(BudgetSnapshot {
                        per_policy_snapshots: vec![],
                        consumed_budgets: vec![b"blob2".to_vec()],
                    }),
                },
            ],
        };
        // Load the snapshot then save a new one and verify that the same
        // snapshot is produced.
        assert_eq!(ledger.load_snapshot(snapshot.clone()), Ok(()));
        assert_eq!(ledger.save_snapshot(), Ok(snapshot));
    }

    #[test]
    fn test_load_snapshot_replaces_state() {
        let (mut ledger, _, _) = create_ledger_service();
        let snapshot = LedgerSnapshot {
            current_time: Some(prost_types::Timestamp::default()),
            ..Default::default()
        };
        assert_ne!(ledger.save_snapshot(), Ok(snapshot.clone()));
        assert_eq!(ledger.load_snapshot(snapshot.clone()), Ok(()));
        assert_eq!(ledger.save_snapshot(), Ok(snapshot));
    }

    #[test]
    fn test_load_snapshot_duplicating_public_key_id() {
        let mut ledger = LedgerService::default();
        let (private_key, public_key) = cfc_crypto::gen_keypair();
        assert_err!(
            ledger.load_snapshot(LedgerSnapshot {
                current_time: Some(prost_types::Timestamp::default()),
                per_key_snapshots: vec![
                    PerKeySnapshot {
                        public_key_id: 1,
                        public_key: public_key.clone(),
                        private_key: private_key.to_bytes().to_vec(),
                        ..Default::default()
                    },
                    PerKeySnapshot {
                        public_key_id: 1,
                        public_key: public_key.clone(),
                        private_key: private_key.to_bytes().to_vec(),
                        ..Default::default()
                    }
                ],
            }),
            micro_rpc::StatusCode::InvalidArgument,
            "Duplicated `public_key_id` in the snapshot"
        );
    }
}
