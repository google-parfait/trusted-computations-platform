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

use crate::platform::PalError;
use alloc::boxed::Box;
use oak_attestation::dice::evidence_to_proto;
use oak_attestation_verification::verifier::verify;
use oak_proto_rust::oak::attestation::v1::{
    Endorsements, Evidence, ExtractedEvidence, ReferenceValues,
};
use oak_restricted_kernel_sdk::attestation::EvidenceProvider;
use slog::error;
use slog::Logger;
use tcp_proto::runtime::endpoint::AttestationConfig;

pub trait Attestor {
    // Initialize the attestor with a config containing Oak ReferenceValues and Endorsements
    // and verify that the extracted evidence from this TEE matches the supplied config.
    fn init(
        &mut self,
        now_utc_millis: i64,
        attestation_config: AttestationConfig,
    ) -> Result<(), PalError>;

    // Get the attestation evidence for this replica.
    fn get_evidence(&self) -> &Evidence;

    // Get the endorsements for this replica.
    fn get_endorsements(&self) -> Result<&Endorsements, PalError>;

    // Verify the attestation report from other raft peers and return the ExtractedEvidence.
    // The ExtractedEvidence contains public signing and encryption keys which will be used
    // for E2E encryption.
    fn verify(
        &self,
        now_utc_millis: i64,
        evidence: Evidence,
        endorsements: Endorsements,
    ) -> Result<ExtractedEvidence, PalError>;
}

pub struct DefaultAttestor {
    logger: Logger,
    evidence: Evidence,
    endorsements: Option<Endorsements>,
    reference_values: Option<ReferenceValues>,
}

impl DefaultAttestor {
    // Creates a default attestor and generates attestation evidence once which can be retrieved
    // later to send it to other raft peers as part of the handshake protocol.
    fn create(
        logger: Logger,
        evidence_provider: Box<dyn EvidenceProvider>,
    ) -> Result<Self, PalError> {
        let evidence =
            evidence_to_proto(evidence_provider.get_evidence().clone()).map_err(|e| {
                error!(logger, "Failed to get evidence {}", e);
                PalError::Internal
            })?;
        Ok(Self {
            logger,
            evidence,
            endorsements: None,
            reference_values: None,
        })
    }
}

impl Attestor for DefaultAttestor {
    fn init(
        &mut self,
        now_utc_millis: i64,
        attestation_config: AttestationConfig,
    ) -> Result<(), PalError> {
        if attestation_config.endorsements.is_none()
            || attestation_config.reference_values.is_none()
        {
            error!(
                self.logger,
                "Endorsements and ReferenceValues must be specified."
            );
            return Err(PalError::InvalidArgument);
        }

        let endorsements = attestation_config.endorsements.unwrap();
        let reference_values = attestation_config.reference_values.unwrap();

        // Verify that the config containing endorsements and reference values is compatible
        // with the evidence for this TEE.
        verify(
            now_utc_millis,
            &self.evidence,
            &endorsements,
            &reference_values,
        )
        .map_err(|e| {
            error!(self.logger, "Self verification failed : {}", e);
            PalError::Internal
        })?;

        self.endorsements = Some(endorsements);
        self.reference_values = Some(reference_values);
        Ok({})
    }

    fn get_evidence(&self) -> &Evidence {
        &self.evidence
    }

    fn get_endorsements(&self) -> Result<&Endorsements, PalError> {
        self.endorsements.as_ref().ok_or_else(|| {
            error!(self.logger, "Endorsements have not been initialized.");
            PalError::InvalidOperation
        })
    }

    fn verify(
        &self,
        now_utc_millis: i64,
        evidence: Evidence,
        endorsements: Endorsements,
    ) -> Result<ExtractedEvidence, PalError> {
        match &self.reference_values {
            Some(rv) => {
                let extracted_evidence = verify(now_utc_millis, &evidence, &endorsements, rv)
                    .map_err(|e| {
                        error!(self.logger, "Attestation verification failed {}", e);
                        PalError::Internal
                    })?;
                Ok(extracted_evidence)
            }
            None => {
                error!(self.logger, "ReferenceValues have not been initialized.");
                Err(PalError::InvalidOperation)
            }
        }
    }
}

#[cfg(all(test, feature = "std"))]
mod test {
    use crate::attestation::{Attestor, DefaultAttestor};
    use crate::logger::log::create_logger;
    use alloc::boxed::Box;
    use core::convert::TryInto;
    use core::time::Duration;
    use oak_attestation::dice::evidence_to_proto;
    use oak_proto_rust::oak::attestation::v1::{
        binary_reference_value, endorsements, kernel_binary_reference_value, reference_values,
        text_reference_value, ApplicationLayerReferenceValues, BinaryReferenceValue, Endorsements,
        Evidence, InsecureReferenceValues, KernelBinaryReferenceValue, KernelLayerReferenceValues,
        OakRestrictedKernelEndorsements, OakRestrictedKernelReferenceValues, ReferenceValues,
        RootLayerEndorsements, RootLayerReferenceValues, SkipVerification, TextReferenceValue,
    };
    use oak_restricted_kernel_sdk::{attestation::EvidenceProvider, testing::MockEvidenceProvider};
    use platform::PalError;
    use prost::bytes::Bytes;
    use tcp_proto::runtime::endpoint::AttestationConfig;

    pub fn get_test_evidence() -> Evidence {
        evidence_to_proto(
            MockEvidenceProvider::create()
                .unwrap()
                .get_evidence()
                .clone(),
        )
        .unwrap()
    }

    pub fn get_test_endorsements() -> Endorsements {
        Endorsements {
            r#type: Some(endorsements::Type::OakRestrictedKernel(
                OakRestrictedKernelEndorsements {
                    root_layer: Some(RootLayerEndorsements::default()),
                    ..Default::default()
                },
            )),
        }
    }

    pub fn get_test_reference_values() -> ReferenceValues {
        let skip = BinaryReferenceValue {
            r#type: Some(binary_reference_value::Type::Skip(
                SkipVerification::default(),
            )),
        };
        let text_skip = TextReferenceValue {
            r#type: Some(text_reference_value::Type::Skip(SkipVerification::default())),
        };
        ReferenceValues {
            r#type: Some(reference_values::Type::OakRestrictedKernel(
                OakRestrictedKernelReferenceValues {
                    root_layer: Some(RootLayerReferenceValues {
                        insecure: Some(InsecureReferenceValues::default()),
                        ..Default::default()
                    }),
                    kernel_layer: Some(KernelLayerReferenceValues {
                        kernel: Some(KernelBinaryReferenceValue {
                            r#type: Some(kernel_binary_reference_value::Type::Skip(
                                SkipVerification::default(),
                            )),
                        }),
                        init_ram_fs: Some(skip.clone()),
                        memory_map: Some(skip.clone()),
                        acpi: Some(skip.clone()),
                        kernel_cmd_line_text: Some(text_skip.clone()),
                        ..Default::default()
                    }),
                    application_layer: Some(ApplicationLayerReferenceValues {
                        binary: Some(skip.clone()),
                        configuration: Some(skip.clone()),
                    }),
                },
            )),
        }
    }

    pub fn get_test_attestation_config() -> AttestationConfig {
        AttestationConfig {
            endorsements: Some(get_test_endorsements()),
            reference_values: Some(get_test_reference_values()),
        }
    }

    #[test]
    fn test_create_and_init() {
        let mut attestor = DefaultAttestor::create(
            create_logger(),
            Box::new(MockEvidenceProvider::create().unwrap()),
        )
        .unwrap();
        let instant = Duration::default().as_millis();

        assert_eq!(
            Ok(()),
            attestor.init(instant.try_into().unwrap(), get_test_attestation_config())
        );
        assert_eq!(get_test_evidence(), attestor.get_evidence().clone());
        assert_eq!(
            get_test_endorsements(),
            attestor.get_endorsements().unwrap().clone()
        );
    }

    #[test]
    fn test_empty_attestation_config() {
        let mut attestor = DefaultAttestor::create(
            create_logger(),
            Box::new(MockEvidenceProvider::create().unwrap()),
        )
        .unwrap();
        let instant = Duration::default().as_millis();
        let config = AttestationConfig::default();

        assert_eq!(
            Err(PalError::InvalidArgument),
            attestor.init(instant.try_into().unwrap(), config)
        );
        assert_eq!(Err(PalError::InvalidOperation), attestor.get_endorsements());
    }

    #[test]
    fn test_invalid_attestation_config() {
        let mut attestor = DefaultAttestor::create(
            create_logger(),
            Box::new(MockEvidenceProvider::create().unwrap()),
        )
        .unwrap();
        let instant = Duration::default().as_millis();
        let config = AttestationConfig {
            endorsements: Some(Endorsements::default()),
            reference_values: Some(ReferenceValues::default()),
        };

        assert_eq!(
            Err(PalError::Internal),
            attestor.init(instant.try_into().unwrap(), config)
        );
        assert_eq!(Err(PalError::InvalidOperation), attestor.get_endorsements());
    }

    #[test]
    fn test_verify_success() {
        let mut attestor = DefaultAttestor::create(
            create_logger(),
            Box::new(MockEvidenceProvider::create().unwrap()),
        )
        .unwrap();
        let instant = Duration::default().as_millis();

        assert_eq!(
            Ok(()),
            attestor.init(instant.try_into().unwrap(), get_test_attestation_config())
        );
        assert!(attestor
            .verify(
                instant.try_into().unwrap(),
                get_test_evidence(),
                get_test_endorsements(),
            )
            .is_ok());
    }

    #[test]
    fn test_verify_invalid_attestation_report_fails() {
        let mut attestor = DefaultAttestor::create(
            create_logger(),
            Box::new(MockEvidenceProvider::create().unwrap()),
        )
        .unwrap();
        let instant = Duration::default().as_millis();

        assert_eq!(
            Ok(()),
            attestor.init(instant.try_into().unwrap(), get_test_attestation_config())
        );
        assert_eq!(
            Err(PalError::Internal),
            attestor.verify(
                instant.try_into().unwrap(),
                Evidence::default(),
                Endorsements::default()
            )
        );
    }

    #[test]
    fn test_verify_before_init_fails() {
        let mut attestor = DefaultAttestor::create(
            create_logger(),
            Box::new(MockEvidenceProvider::create().unwrap()),
        )
        .unwrap();
        let instant = Duration::default().as_millis();

        assert_eq!(
            Err(PalError::InvalidOperation),
            attestor.verify(
                instant.try_into().unwrap(),
                get_test_evidence(),
                get_test_endorsements()
            )
        );
    }
}
