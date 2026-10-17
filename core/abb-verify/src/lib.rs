//! Verifier result model: dimensions, per-profile requirements, overall result.
//!
//! This crate holds no cryptography. It is the decision table of
//! `PROTOCOL.md` 16.1 and 16.2 (D-05, D-19) on its own, so that the rules can
//! be tested exhaustively without building a receipt, and so the UI, the CLI
//! and a later WASM build cannot drift apart on what `PARTIAL` means.
//!
//! Three things it refuses to do, on purpose:
//!
//! * it never collapses the dimensions into one boolean (`R-REC-02`);
//! * a missing dimension is [`Status::Unknown`], never a pass (`R-COV-05`);
//! * an informational `FAIL` is a finding, not a broken receipt, and an
//!   optional dimension that is present but does not verify **is** a failure.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;

/// The result of one dimension.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Status {
    /// Checked and correct.
    Pass,
    /// Checked and wrong.
    Fail,
    /// Could not be checked: evidence missing, or a hidden field is needed.
    Unknown,
    /// Does not apply to this receipt, for example no mandate is present.
    NotApplicable,
    /// Present, but the parties share a failure domain (D-15). Never green.
    NotIndependent,
}

impl Status {
    /// The wire form.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "PASS",
            Self::Fail => "FAIL",
            Self::Unknown => "UNKNOWN",
            Self::NotApplicable => "NOT_APPLICABLE",
            Self::NotIndependent => "NOT_INDEPENDENT",
        }
    }
}

impl std::fmt::Display for Status {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The sixteen dimensions: fourteen from v9 §16 plus `global_log_inclusion`
/// (D-10) and `mandate_compliance` (D-16).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Dimension {
    /// Events match their leaf hashes and inclusion proofs.
    EvidenceIntegrity,
    /// Every checkpoint signature verifies under a trusted key.
    CheckpointSignatures,
    /// The checkpoint chain and its consistency proofs hold.
    Consistency,
    /// Artifact bytes are present to check.
    ArtifactAvailability,
    /// Enough independent witness signatures.
    WitnessQuorum,
    /// A published anchor matches the chain.
    AnchorMatch,
    /// Declared coverage is supported by the evidence.
    ObservationCoverage,
    /// Deterministic policy decisions and approvals.
    PolicyAssessment,
    /// Semantic invariants.
    SemanticAssessment,
    /// Prompt-injection guard output.
    PromptSecurityAssessment,
    /// Behaviour anomaly output.
    BehaviorAnomalyAssessment,
    /// The artifact manifest chain and its head in the checkpoint.
    ArtifactManifestIntegrity,
    /// Display-only aggregate of the advisory channels.
    MlAssessment,
    /// What the run reported as its outcome.
    ExecutionOutcome,
    /// The run's inclusion in the global log (D-10).
    GlobalLogInclusion,
    /// Compliance with a signed mandate (D-16).
    MandateCompliance,
}

impl Dimension {
    /// Every dimension, in report order.
    pub const ALL: [Self; 16] = [
        Self::EvidenceIntegrity,
        Self::CheckpointSignatures,
        Self::Consistency,
        Self::GlobalLogInclusion,
        Self::ObservationCoverage,
        Self::PolicyAssessment,
        Self::ArtifactManifestIntegrity,
        Self::MandateCompliance,
        Self::WitnessQuorum,
        Self::AnchorMatch,
        Self::ArtifactAvailability,
        Self::SemanticAssessment,
        Self::PromptSecurityAssessment,
        Self::BehaviorAnomalyAssessment,
        Self::MlAssessment,
        Self::ExecutionOutcome,
    ];

    /// The wire form, as receipts and the CLI spell it.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::EvidenceIntegrity => "evidence_integrity",
            Self::CheckpointSignatures => "checkpoint_signatures",
            Self::Consistency => "consistency",
            Self::ArtifactAvailability => "artifact_availability",
            Self::WitnessQuorum => "witness_quorum",
            Self::AnchorMatch => "anchor_match",
            Self::ObservationCoverage => "observation_coverage",
            Self::PolicyAssessment => "policy_assessment",
            Self::SemanticAssessment => "semantic_assessment",
            Self::PromptSecurityAssessment => "prompt_security_assessment",
            Self::BehaviorAnomalyAssessment => "behavior_anomaly_assessment",
            Self::ArtifactManifestIntegrity => "artifact_manifest_integrity",
            Self::MlAssessment => "ml_assessment",
            Self::ExecutionOutcome => "execution_outcome",
            Self::GlobalLogInclusion => "global_log_inclusion",
            Self::MandateCompliance => "mandate_compliance",
        }
    }

    /// Only these two may ever report [`Status::NotIndependent`] (D-15).
    #[must_use]
    pub const fn may_be_not_independent(self) -> bool {
        matches!(self, Self::WitnessQuorum | Self::AnchorMatch)
    }
}

impl std::fmt::Display for Dimension {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Which profile the receipt was produced under.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Profile {
    /// Default. Works offline; makes no external anti-rollback claim.
    LocalOnly,
    /// Opt-in. Adds witnesses, anchors and remote adapters.
    ConnectedEvidence,
}

impl Profile {
    /// Parse the wire form.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "LOCAL_ONLY" => Some(Self::LocalOnly),
            "CONNECTED_EVIDENCE" => Some(Self::ConnectedEvidence),
            _ => None,
        }
    }

    /// The wire form.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::LocalOnly => "LOCAL_ONLY",
            Self::ConnectedEvidence => "CONNECTED_EVIDENCE",
        }
    }
}

/// How much a dimension counts towards the overall result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Requirement {
    /// Must pass. `UNKNOWN` here makes the receipt `INCOMPLETE`.
    Required,
    /// `UNKNOWN` or `NOT_INDEPENDENT` here makes the receipt `PARTIAL`.
    Optional,
    /// Always shown, never changes the overall result by itself.
    Informational,
}

/// What the receipt contains, for the two conditional rows of the table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ReceiptShape {
    /// True when the run captured at least one artifact.
    pub artifacts_present: bool,
    /// True when `RUN_STARTED` carried a mandate.
    pub mandate_present: bool,
}

/// The required-dimension table of `PROTOCOL.md` 16.1 (D-19).
#[must_use]
pub fn requirement(dim: Dimension, profile: Profile, shape: ReceiptShape) -> Requirement {
    use Dimension as D;
    match dim {
        D::EvidenceIntegrity
        | D::CheckpointSignatures
        | D::Consistency
        | D::GlobalLogInclusion
        | D::ObservationCoverage
        | D::PolicyAssessment => Requirement::Required,
        D::ArtifactManifestIntegrity => {
            if shape.artifacts_present {
                Requirement::Required
            } else {
                Requirement::Optional
            }
        }
        D::MandateCompliance => {
            if shape.mandate_present {
                Requirement::Required
            } else {
                Requirement::Optional
            }
        }
        D::WitnessQuorum | D::AnchorMatch => match profile {
            Profile::LocalOnly => Requirement::Optional,
            Profile::ConnectedEvidence => Requirement::Required,
        },
        D::ArtifactAvailability => Requirement::Optional,
        D::SemanticAssessment
        | D::PromptSecurityAssessment
        | D::BehaviorAnomalyAssessment
        | D::MlAssessment
        | D::ExecutionOutcome => Requirement::Informational,
    }
}

/// The overall result (`PROTOCOL.md` 16.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Overall {
    /// Unknown protocol, schema or critical field.
    Unsupported,
    /// A required dimension failed, or a present optional one did not verify.
    Invalid,
    /// Something the profile requires is missing.
    Incomplete,
    /// Everything required is fine; something optional is missing.
    Partial,
    /// Everything required passes and nothing optional is missing.
    Valid,
}

impl Overall {
    /// The wire form.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unsupported => "UNSUPPORTED",
            Self::Invalid => "INVALID",
            Self::Incomplete => "INCOMPLETE",
            Self::Partial => "PARTIAL",
            Self::Valid => "VALID",
        }
    }

    /// The CLI exit code (`ERROR_HANDLING.md` section 9).
    #[must_use]
    pub const fn exit_code(self) -> i32 {
        match self {
            Self::Valid => 0,
            Self::Invalid => 1,
            Self::Incomplete => 2,
            Self::Partial => 3,
            Self::Unsupported => 4,
        }
    }
}

impl std::fmt::Display for Overall {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One line of explanation attached to a dimension.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Detail {
    /// Which dimension this is about.
    pub dimension: Dimension,
    /// The event, checkpoint or artifact at fault, when there is one.
    pub locator: Option<String>,
    /// Plain words for a person. Never a stack trace, path or secret.
    pub message: String,
}

/// A full verifier report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    /// Which profile the receipt claims.
    pub profile: Profile,
    /// What the receipt contains.
    pub shape: ReceiptShape,
    /// Set when the protocol or schema version is not supported.
    pub unsupported: bool,
    /// Every dimension's status. A dimension never left out: absent evidence
    /// is recorded as [`Status::Unknown`].
    pub dimensions: BTreeMap<Dimension, Status>,
    /// Findings, in the order they were produced.
    pub details: Vec<Detail>,
}

impl Report {
    /// A report with every dimension `UNKNOWN`: the honest starting point.
    #[must_use]
    pub fn new(profile: Profile, shape: ReceiptShape) -> Self {
        let mut dimensions = BTreeMap::new();
        for dim in Dimension::ALL {
            dimensions.insert(dim, Status::Unknown);
        }
        Self {
            profile,
            shape,
            unsupported: false,
            dimensions,
            details: Vec::new(),
        }
    }

    /// Record a status.
    ///
    /// `NOT_INDEPENDENT` is only meaningful for two dimensions; anywhere else
    /// it is downgraded to `UNKNOWN` rather than silently treated as a pass.
    pub fn set(&mut self, dim: Dimension, status: Status) {
        let status = if status == Status::NotIndependent && !dim.may_be_not_independent() {
            Status::Unknown
        } else {
            status
        };
        self.dimensions.insert(dim, status);
    }

    /// Record a status together with an explanation.
    pub fn fail(&mut self, dim: Dimension, locator: Option<String>, message: impl Into<String>) {
        self.set(dim, Status::Fail);
        self.details.push(Detail {
            dimension: dim,
            locator,
            message: message.into(),
        });
    }

    /// Add an explanation without changing a status.
    pub fn note(&mut self, dim: Dimension, locator: Option<String>, message: impl Into<String>) {
        self.details.push(Detail {
            dimension: dim,
            locator,
            message: message.into(),
        });
    }

    /// The status of one dimension, `UNKNOWN` if it was never set.
    #[must_use]
    pub fn status(&self, dim: Dimension) -> Status {
        self.dimensions
            .get(&dim)
            .copied()
            .unwrap_or(Status::Unknown)
    }

    /// How much a dimension counts in this report.
    #[must_use]
    pub fn requirement(&self, dim: Dimension) -> Requirement {
        requirement(dim, self.profile, self.shape)
    }

    /// The overall result, by the first-match-wins order of 16.2.
    #[must_use]
    pub fn overall(&self) -> Overall {
        if self.unsupported {
            return Overall::Unsupported;
        }
        let mut required_unknown = false;
        let mut optional_missing = false;

        for dim in Dimension::ALL {
            let status = self.status(dim);
            let requirement = self.requirement(dim);
            match requirement {
                Requirement::Informational => {
                    // A finding, not a broken receipt.
                }
                Requirement::Required | Requirement::Optional => {
                    if status == Status::Fail {
                        // A present signature that does not verify is an
                        // integrity failure even when the dimension is
                        // optional (D-19).
                        return Overall::Invalid;
                    }
                }
            }
            match (requirement, status) {
                (Requirement::Required, Status::Unknown) => required_unknown = true,
                // The protocol defines INCOMPLETE and PARTIAL over UNKNOWN
                // only. A *required* dimension that is NOT_INDEPENDENT is
                // neither PASS nor NOT_APPLICABLE, so it cannot be VALID or
                // PARTIAL; the independence evidence is missing, which is what
                // INCOMPLETE means. Flagged as an open question for the
                // protocol owner rather than decided silently.
                (Requirement::Required, Status::NotIndependent) => required_unknown = true,
                (Requirement::Optional, Status::Unknown | Status::NotIndependent) => {
                    optional_missing = true;
                }
                _ => {}
            }
        }

        if required_unknown {
            Overall::Incomplete
        } else if optional_missing {
            Overall::Partial
        } else {
            Overall::Valid
        }
    }

    /// A stable one-line-per-dimension rendering for the CLI.
    #[must_use]
    pub fn to_lines(&self) -> Vec<String> {
        Dimension::ALL
            .iter()
            .map(|dim| {
                let requirement = match self.requirement(*dim) {
                    Requirement::Required => "required",
                    Requirement::Optional => "optional",
                    Requirement::Informational => "informational",
                };
                format!(
                    "{:<28} {:<16} {requirement}",
                    dim.as_str(),
                    self.status(*dim).as_str()
                )
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn all(status: Status, profile: Profile, shape: ReceiptShape) -> Report {
        let mut report = Report::new(profile, shape);
        for dim in Dimension::ALL {
            report.set(dim, status);
        }
        report
    }

    #[test]
    fn dimension_names_are_unique_and_complete() {
        let mut names: Vec<&str> = Dimension::ALL.iter().map(|d| d.as_str()).collect();
        assert_eq!(names.len(), 16);
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), 16);
        // The two added by the review are present (R-REC-05).
        assert!(names.contains(&"global_log_inclusion"));
        assert!(names.contains(&"mandate_compliance"));
    }

    #[test]
    fn a_new_report_is_all_unknown_not_all_pass() {
        let report = Report::new(Profile::LocalOnly, ReceiptShape::default());
        for dim in Dimension::ALL {
            assert_eq!(report.status(dim), Status::Unknown, "{dim}");
        }
        assert_eq!(report.overall(), Overall::Incomplete);
    }

    #[test]
    fn local_only_requires_the_six_core_dimensions() {
        let shape = ReceiptShape::default();
        let required: Vec<&str> = Dimension::ALL
            .iter()
            .filter(|d| requirement(**d, Profile::LocalOnly, shape) == Requirement::Required)
            .map(|d| d.as_str())
            .collect();
        assert_eq!(
            required,
            vec![
                "evidence_integrity",
                "checkpoint_signatures",
                "consistency",
                "global_log_inclusion",
                "observation_coverage",
                "policy_assessment",
            ]
        );
    }

    #[test]
    fn connected_evidence_also_requires_witnesses_and_anchors() {
        let shape = ReceiptShape::default();
        for dim in [Dimension::WitnessQuorum, Dimension::AnchorMatch] {
            assert_eq!(
                requirement(dim, Profile::LocalOnly, shape),
                Requirement::Optional
            );
            assert_eq!(
                requirement(dim, Profile::ConnectedEvidence, shape),
                Requirement::Required
            );
        }
    }

    #[test]
    fn artifacts_and_mandates_switch_two_rows_to_required() {
        let without = ReceiptShape::default();
        let with = ReceiptShape {
            artifacts_present: true,
            mandate_present: true,
        };
        assert_eq!(
            requirement(
                Dimension::ArtifactManifestIntegrity,
                Profile::LocalOnly,
                without
            ),
            Requirement::Optional
        );
        assert_eq!(
            requirement(
                Dimension::ArtifactManifestIntegrity,
                Profile::LocalOnly,
                with
            ),
            Requirement::Required
        );
        assert_eq!(
            requirement(Dimension::MandateCompliance, Profile::LocalOnly, without),
            Requirement::Optional
        );
        assert_eq!(
            requirement(Dimension::MandateCompliance, Profile::LocalOnly, with),
            Requirement::Required
        );
    }

    #[test]
    fn the_five_advisory_channels_stay_informational() {
        for dim in [
            Dimension::SemanticAssessment,
            Dimension::PromptSecurityAssessment,
            Dimension::BehaviorAnomalyAssessment,
            Dimension::MlAssessment,
            Dimension::ExecutionOutcome,
        ] {
            for profile in [Profile::LocalOnly, Profile::ConnectedEvidence] {
                assert_eq!(
                    requirement(
                        dim,
                        profile,
                        ReceiptShape {
                            artifacts_present: true,
                            mandate_present: true
                        }
                    ),
                    Requirement::Informational,
                    "{dim}"
                );
            }
        }
    }

    #[test]
    fn everything_passing_is_valid() {
        let report = all(Status::Pass, Profile::LocalOnly, ReceiptShape::default());
        assert_eq!(report.overall(), Overall::Valid);
    }

    #[test]
    fn unsupported_wins_over_everything() {
        let mut report = all(Status::Fail, Profile::LocalOnly, ReceiptShape::default());
        report.unsupported = true;
        assert_eq!(report.overall(), Overall::Unsupported);
    }

    #[test]
    fn a_required_failure_is_invalid() {
        let mut report = all(Status::Pass, Profile::LocalOnly, ReceiptShape::default());
        report.fail(
            Dimension::EvidenceIntegrity,
            Some("event 3".to_owned()),
            "leaf hash differs",
        );
        assert_eq!(report.overall(), Overall::Invalid);
        assert_eq!(report.details.len(), 1);
    }

    #[test]
    fn an_optional_failure_is_also_invalid() {
        // A witness signature that is present but does not verify (D-19).
        let mut report = all(Status::Pass, Profile::LocalOnly, ReceiptShape::default());
        report.set(Dimension::WitnessQuorum, Status::Fail);
        assert_eq!(
            report.requirement(Dimension::WitnessQuorum),
            Requirement::Optional
        );
        assert_eq!(report.overall(), Overall::Invalid);
    }

    #[test]
    fn an_informational_failure_is_only_a_finding() {
        let mut report = all(Status::Pass, Profile::LocalOnly, ReceiptShape::default());
        report.fail(
            Dimension::SemanticAssessment,
            None,
            "invariant SEM-2 failed",
        );
        assert_eq!(report.overall(), Overall::Valid);
    }

    #[test]
    fn a_required_unknown_is_incomplete() {
        let mut report = all(Status::Pass, Profile::LocalOnly, ReceiptShape::default());
        report.set(Dimension::GlobalLogInclusion, Status::Unknown);
        assert_eq!(report.overall(), Overall::Incomplete);
    }

    #[test]
    fn an_optional_unknown_is_partial() {
        let mut report = all(Status::Pass, Profile::LocalOnly, ReceiptShape::default());
        report.set(Dimension::WitnessQuorum, Status::Unknown);
        assert_eq!(report.overall(), Overall::Partial);
    }

    #[test]
    fn not_independent_is_partial_when_optional_and_never_valid() {
        let mut report = all(Status::Pass, Profile::LocalOnly, ReceiptShape::default());
        report.set(Dimension::WitnessQuorum, Status::NotIndependent);
        assert_eq!(report.overall(), Overall::Partial);
        assert_ne!(report.overall(), Overall::Valid);
    }

    #[test]
    fn not_independent_on_a_required_dimension_is_incomplete() {
        // Open question for the protocol owner: 16.2 defines INCOMPLETE over
        // UNKNOWN only, so this case is undecided in the document.
        let mut report = all(
            Status::Pass,
            Profile::ConnectedEvidence,
            ReceiptShape::default(),
        );
        report.set(Dimension::AnchorMatch, Status::NotIndependent);
        assert_eq!(report.overall(), Overall::Incomplete);
    }

    #[test]
    fn not_independent_is_refused_on_dimensions_that_cannot_hold_it() {
        let mut report = all(Status::Pass, Profile::LocalOnly, ReceiptShape::default());
        report.set(Dimension::EvidenceIntegrity, Status::NotIndependent);
        assert_eq!(report.status(Dimension::EvidenceIntegrity), Status::Unknown);
    }

    #[test]
    fn not_applicable_counts_as_satisfied() {
        let mut report = all(Status::Pass, Profile::LocalOnly, ReceiptShape::default());
        report.set(Dimension::MandateCompliance, Status::NotApplicable);
        report.set(Dimension::ArtifactManifestIntegrity, Status::NotApplicable);
        assert_eq!(report.overall(), Overall::Valid);
    }

    #[test]
    fn exit_codes_match_error_handling_section_9() {
        assert_eq!(Overall::Valid.exit_code(), 0);
        assert_eq!(Overall::Invalid.exit_code(), 1);
        assert_eq!(Overall::Incomplete.exit_code(), 2);
        assert_eq!(Overall::Partial.exit_code(), 3);
        assert_eq!(Overall::Unsupported.exit_code(), 4);
    }

    #[test]
    fn profile_round_trips_and_rejects_unknown_values() {
        for profile in [Profile::LocalOnly, Profile::ConnectedEvidence] {
            assert_eq!(Profile::parse(profile.as_str()), Some(profile));
        }
        assert_eq!(Profile::parse("LOCAL"), None);
    }

    #[test]
    fn every_dimension_appears_in_the_rendering() {
        let report = Report::new(Profile::LocalOnly, ReceiptShape::default());
        let lines = report.to_lines();
        assert_eq!(lines.len(), 16);
        for dim in Dimension::ALL {
            assert!(lines.iter().any(|l| l.starts_with(dim.as_str())), "{dim}");
        }
    }
}
