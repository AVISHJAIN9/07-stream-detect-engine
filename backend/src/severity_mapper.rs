/// Feature 68 – Dynamic Alert Severity Mapping & Risk Scoring Engine
///
/// Computes contextual risk scores using the formula:
///   RiskScore = min(100, S_base × W_asset × W_user × W_ti)
///
/// Base severity weights:
///   Informational = 10, Low = 25, Medium = 50, High = 75, Critical = 90
///
/// Environmental multiplier ranges:
///   W_asset (Asset Criticality)   ∈ [1.0, 3.0]
///   W_user  (User Privilege)      ∈ [1.0, 2.5]
///   W_ti    (TI Confidence)       ∈ [1.0, 2.0]
///
/// KPI: Risk score computation ≤ 15 ns.

use crate::detection_match::Severity;

// ---------------------------------------------------------------------------
// Severity level with Informational variant
// ---------------------------------------------------------------------------

/// Extended severity level used by the scoring engine.
/// Adds `Informational` below `Low` to cover the full 0-100 dynamic range.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SeverityLevel {
    /// Score range  0–14.
    Informational,
    /// Score range 15–39.
    Low,
    /// Score range 40–59.
    Medium,
    /// Score range 60–84.
    High,
    /// Score range 85–100.
    Critical,
}

impl SeverityLevel {
    /// Maps a `Severity` (from detection_match) to a `SeverityLevel`.
    pub fn from_severity(s: Severity) -> Self {
        match s {
            Severity::Low => Self::Low,
            Severity::Medium => Self::Medium,
            Severity::High => Self::High,
            Severity::Critical => Self::Critical,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Informational => "informational",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }

    /// Numeric S_base used in the risk formula.
    #[inline]
    pub fn base_score(&self) -> f64 {
        match self {
            Self::Informational => 10.0,
            Self::Low => 25.0,
            Self::Medium => 50.0,
            Self::High => 75.0,
            Self::Critical => 90.0,
        }
    }
}

impl std::fmt::Display for SeverityLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// Environmental Multiplier Weights
// ---------------------------------------------------------------------------

/// Environmental multiplier weights for the risk scoring formula.
///
/// All weights are clamped to their documented valid ranges.
#[derive(Debug, Clone, Copy)]
pub struct RiskMultipliers {
    /// W_asset: Asset criticality weight ∈ [1.0, 3.0].
    /// 1.0 = non-critical workstation, 3.0 = crown-jewel domain controller.
    pub asset_criticality: f64,
    /// W_user: User privilege level ∈ [1.0, 2.5].
    /// 1.0 = standard user, 2.5 = domain admin / service account.
    pub user_privilege: f64,
    /// W_ti: Threat intelligence confidence ∈ [1.0, 2.0].
    /// 1.0 = no TI match, 2.0 = confirmed IOC from premium feed.
    pub threat_intel_confidence: f64,
}

impl RiskMultipliers {
    /// Constructs multipliers, clamping each weight to its valid range.
    pub fn new(asset_criticality: f64, user_privilege: f64, threat_intel_confidence: f64) -> Self {
        Self {
            asset_criticality: asset_criticality.clamp(1.0, 3.0),
            user_privilege: user_privilege.clamp(1.0, 2.5),
            threat_intel_confidence: threat_intel_confidence.clamp(1.0, 2.0),
        }
    }

    /// Constructs multipliers with all weights set to 1.0 (neutral).
    pub fn neutral() -> Self {
        Self { asset_criticality: 1.0, user_privilege: 1.0, threat_intel_confidence: 1.0 }
    }
}

impl Default for RiskMultipliers {
    fn default() -> Self {
        Self::neutral()
    }
}

// ---------------------------------------------------------------------------
// Scoring result
// ---------------------------------------------------------------------------

/// Result of a risk score computation.
#[derive(Debug, Clone, Copy)]
pub struct RiskScoringResult {
    /// Final clamped integer risk score in range [0, 100].
    pub risk_score: u8,
    /// Contextual severity level after applying environmental multipliers.
    pub contextual_severity: SeverityLevel,
    /// Pre-clamp floating-point score for debugging/audit.
    pub raw_score: f64,
}

// ---------------------------------------------------------------------------
// Severity Scorer
// ---------------------------------------------------------------------------

/// Computes dynamic risk scores and derives contextual severity levels.
///
/// # Algorithm
/// ```text
/// raw_score = S_base × W_asset × W_user × W_ti
/// risk_score = min(100, raw_score) as u8
/// contextual_severity = map_score_to_severity(risk_score)
/// ```
///
/// # Score → Severity Mapping
/// | Score  | Severity      |
/// |--------|---------------|
/// |  0–14  | Informational |
/// | 15–39  | Low           |
/// | 40–59  | Medium        |
/// | 60–84  | High          |
/// | 85–100 | Critical      |
pub struct SeverityScorer;

impl SeverityScorer {
    pub fn new() -> Self {
        Self
    }

    /// Computes risk score from a base `SeverityLevel` and environmental multipliers.
    ///
    /// # Arguments
    /// * `base` – Base severity from the rule definition.
    /// * `multipliers` – Environmental weight multipliers.
    ///
    /// # Returns
    /// A `RiskScoringResult` containing the integer risk score and derived severity.
    #[inline]
    pub fn compute_risk_score(
        &self,
        base: SeverityLevel,
        multipliers: RiskMultipliers,
    ) -> RiskScoringResult {
        let raw_score = base.base_score()
            * multipliers.asset_criticality
            * multipliers.user_privilege
            * multipliers.threat_intel_confidence;

        let clamped = raw_score.min(100.0);
        let risk_score = clamped as u8;
        let contextual_severity = Self::score_to_severity(risk_score);

        RiskScoringResult { risk_score, contextual_severity, raw_score }
    }

    /// Computes risk score from individual multiplier parameters directly.
    ///
    /// Convenience wrapper that constructs `RiskMultipliers` internally.
    #[inline]
    pub fn compute(
        &self,
        base: SeverityLevel,
        asset_criticality: f64,
        user_privilege: f64,
        threat_intel_confidence: f64,
    ) -> RiskScoringResult {
        let multipliers = RiskMultipliers::new(asset_criticality, user_privilege, threat_intel_confidence);
        self.compute_risk_score(base, multipliers)
    }

    /// Applies a risk score to a `NormalizedAlert` in-place, updating both
    /// `risk_score` and `severity`.
    pub fn apply_to_alert(
        &self,
        alert: &mut crate::alert_normalizer::NormalizedAlert,
        multipliers: RiskMultipliers,
    ) {
        let base = SeverityLevel::from_severity(alert.severity);
        let result = self.compute_risk_score(base, multipliers);
        alert.risk_score = result.risk_score;
        // Map contextual severity back to Severity enum for the alert
        alert.severity = match result.contextual_severity {
            SeverityLevel::Informational | SeverityLevel::Low => crate::detection_match::Severity::Low,
            SeverityLevel::Medium => crate::detection_match::Severity::Medium,
            SeverityLevel::High => crate::detection_match::Severity::High,
            SeverityLevel::Critical => crate::detection_match::Severity::Critical,
        };
    }

    /// Maps an integer risk score to a `SeverityLevel`.
    #[inline]
    pub fn score_to_severity(score: u8) -> SeverityLevel {
        match score {
            0..=14  => SeverityLevel::Informational,
            15..=39 => SeverityLevel::Low,
            40..=59 => SeverityLevel::Medium,
            60..=84 => SeverityLevel::High,
            _       => SeverityLevel::Critical,
        }
    }
}

impl Default for SeverityScorer {
    fn default() -> Self {
        Self::new()
    }
}
