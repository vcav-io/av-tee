use serde::Deserialize;

/// What an allowlisted measurement covers.
#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum MeasurementPlatform {
    /// Not stated (entries written before this field existed).
    #[default]
    Unspecified,
    /// GCP Confidential VM (SEV-SNP): the launch measurement of Google's
    /// endorsed OVMF firmware for a given vCPU count. It does not cover the
    /// kernel, the container or the relay. Populate from Google's firmware
    /// endorsements (`gcetcbendorsement`); see docs/deployment.md.
    GcpSnpOvmf,
    /// SEV-SNP direct boot with kernel, initrd and command line hashes in the
    /// launch measurement (self-hosted). This covers the relay code only if
    /// the measured command line carries a dm-verity root hash for a root
    /// filesystem that contains the relay; use this platform only for such
    /// images.
    SnpDirectBoot,
    /// The simulated runtime (development and tests only).
    Simulated,
}

impl MeasurementPlatform {
    /// Whether a match shows which relay code ran. For `SnpDirectBoot` this
    /// relies on the entry describing an image whose measured command line
    /// pins a dm-verity root filesystem containing the relay.
    pub fn covers_relay_code(&self) -> bool {
        matches!(self, MeasurementPlatform::SnpDirectBoot)
    }

    /// The claim a match supports.
    pub fn claim(&self) -> &'static str {
        match self {
            MeasurementPlatform::GcpSnpOvmf => {
                "genuine GCP SNP VM running Google-endorsed firmware; relay code not measured"
            }
            MeasurementPlatform::SnpDirectBoot => {
                "SNP VM launched with the allowlisted kernel, initrd and command line \
                 (relay code covered via the dm-verity root hash on the command line)"
            }
            MeasurementPlatform::Simulated => "simulated runtime; no hardware isolation",
            MeasurementPlatform::Unspecified => "allowlisted measurement; coverage not stated",
        }
    }
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MeasurementEntry {
    pub measurement: String,
    /// What the measurement covers.
    #[serde(default)]
    pub platform: MeasurementPlatform,
    #[serde(default)]
    pub build_id: String,
    #[serde(default)]
    pub git_rev: String,
    /// Free-text provenance (e.g. the endorsement file and vCPU count).
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub oci_digest: Option<String>,
    #[serde(default)]
    pub artifact_hash: Option<String>,
    #[serde(default)]
    pub toolchain: Option<String>,
    #[serde(default)]
    pub timestamp: Option<String>,
}

pub trait TransparencySource {
    fn is_allowed(&self, measurement: &str) -> Option<MeasurementEntry>;
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct AllowlistFile {
    entries: Vec<MeasurementEntry>,
}

/// Errors loading an allowlist.
#[derive(Debug, thiserror::Error)]
pub enum AllowlistError {
    #[error("allowlist TOML: {0}")]
    Toml(#[from] toml::de::Error),
    #[error("allowlist entry {index}: {reason}")]
    InvalidEntry { index: usize, reason: String },
}

/// SEV-SNP measurements are 48 bytes: 96 lowercase hex characters.
fn is_snp_measurement(m: &str) -> bool {
    m.len() == 96
        && m.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

#[derive(Debug, Clone)]
pub struct StaticAllowlist {
    entries: Vec<MeasurementEntry>,
}

impl StaticAllowlist {
    /// Parse a TOML allowlist. Unknown fields are rejected, and SEV-SNP
    /// entries must hold a 48-byte measurement in lowercase hex.
    pub fn from_toml(toml_str: &str) -> Result<Self, AllowlistError> {
        let file: AllowlistFile = toml::from_str(toml_str)?;
        for (index, entry) in file.entries.iter().enumerate() {
            let snp = matches!(
                entry.platform,
                MeasurementPlatform::GcpSnpOvmf | MeasurementPlatform::SnpDirectBoot
            );
            if snp && !is_snp_measurement(&entry.measurement) {
                return Err(AllowlistError::InvalidEntry {
                    index,
                    reason: "SEV-SNP measurement must be 96 lowercase hex characters".into(),
                });
            }
            if entry.measurement.is_empty() {
                return Err(AllowlistError::InvalidEntry {
                    index,
                    reason: "measurement is empty".into(),
                });
            }
        }
        Ok(Self {
            entries: file.entries,
        })
    }

    pub fn from_entries(entries: Vec<MeasurementEntry>) -> Self {
        Self { entries }
    }
}

impl TransparencySource for StaticAllowlist {
    fn is_allowed(&self, measurement: &str) -> Option<MeasurementEntry> {
        self.entries
            .iter()
            .find(|e| e.measurement == measurement)
            .cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_TOML: &str = r#"
[[entries]]
measurement = "abc123"
build_id = "v1.0.0"
git_rev = "deadbeef"
oci_digest = "sha256:0123456789abcdef"
artifact_hash = "fedcba9876543210"

[[entries]]
measurement = "def456"
build_id = "v1.1.0"
git_rev = "cafebabe"
"#;

    #[test]
    fn parse_toml_allowlist() {
        let allowlist = StaticAllowlist::from_toml(SAMPLE_TOML).unwrap();
        assert_eq!(allowlist.entries.len(), 2);
        assert_eq!(allowlist.entries[0].measurement, "abc123");
        assert_eq!(allowlist.entries[1].build_id, "v1.1.0");
    }

    #[test]
    fn exact_match_returns_entry() {
        let allowlist = StaticAllowlist::from_toml(SAMPLE_TOML).unwrap();
        let result = allowlist.is_allowed("abc123");
        assert!(result.is_some());
        assert_eq!(result.unwrap().build_id, "v1.0.0");
    }

    #[test]
    fn prefix_no_match() {
        let allowlist = StaticAllowlist::from_toml(SAMPLE_TOML).unwrap();
        assert!(allowlist.is_allowed("abc").is_none());
    }

    #[test]
    fn unknown_measurement_returns_none() {
        let allowlist = StaticAllowlist::from_toml(SAMPLE_TOML).unwrap();
        assert!(allowlist.is_allowed("unknown").is_none());
    }

    #[test]
    fn empty_allowlist() {
        let allowlist = StaticAllowlist::from_entries(vec![]);
        assert!(allowlist.is_allowed("anything").is_none());
    }

    const GCP_TOML: &str = include_str!("../../../tests/fixtures/gcp_ovmf_allowlist.example.toml");

    #[test]
    fn gcp_ovmf_example_parses_and_states_its_claim() {
        let allowlist = StaticAllowlist::from_toml(GCP_TOML).unwrap();
        assert!(!allowlist.entries.is_empty());
        for entry in &allowlist.entries {
            assert_eq!(entry.platform, MeasurementPlatform::GcpSnpOvmf);
            assert!(!entry.platform.covers_relay_code());
            assert!(entry.platform.claim().contains("relay code not measured"));
        }
        let first = &allowlist.entries[0];
        assert_eq!(
            allowlist.is_allowed(&first.measurement).unwrap().platform,
            MeasurementPlatform::GcpSnpOvmf
        );
    }

    #[test]
    fn entries_without_platform_are_unspecified() {
        let allowlist = StaticAllowlist::from_toml(SAMPLE_TOML).unwrap();
        assert_eq!(
            allowlist.entries[0].platform,
            MeasurementPlatform::Unspecified
        );
    }

    #[test]
    fn snp_entries_require_a_48_byte_measurement() {
        for bad in ["abc123", &"A".repeat(96), &"a".repeat(95)] {
            let toml =
                format!("[[entries]]\nmeasurement = \"{bad}\"\nplatform = \"gcp-snp-ovmf\"\n");
            assert!(
                matches!(
                    StaticAllowlist::from_toml(&toml),
                    Err(AllowlistError::InvalidEntry { .. })
                ),
                "{bad}"
            );
        }
    }

    #[test]
    fn unknown_fields_and_platforms_are_rejected() {
        let typo = format!(
            "[[entries]]\nmeasurement = \"{}\"\nplatfrom = \"gcp-snp-ovmf\"\n",
            "a".repeat(96)
        );
        assert!(StaticAllowlist::from_toml(&typo).is_err());
        let unknown = format!(
            "[[entries]]\nmeasurement = \"{}\"\nplatform = \"other\"\n",
            "a".repeat(96)
        );
        assert!(StaticAllowlist::from_toml(&unknown).is_err());
    }

    #[test]
    fn optional_fields_default_to_none() {
        let allowlist = StaticAllowlist::from_toml(SAMPLE_TOML).unwrap();
        let entry = &allowlist.entries[1];
        assert!(entry.oci_digest.is_none());
        assert!(entry.artifact_hash.is_none());
        assert!(entry.toolchain.is_none());
        assert!(entry.timestamp.is_none());
    }
}
