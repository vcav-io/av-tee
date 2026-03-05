use serde::Deserialize;

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct MeasurementEntry {
    pub measurement: String,
    pub build_id: String,
    pub git_rev: String,
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
struct AllowlistFile {
    entries: Vec<MeasurementEntry>,
}

#[derive(Debug, Clone)]
pub struct StaticAllowlist {
    entries: Vec<MeasurementEntry>,
}

impl StaticAllowlist {
    pub fn from_toml(toml_str: &str) -> Result<Self, toml::de::Error> {
        let file: AllowlistFile = toml::from_str(toml_str)?;
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
