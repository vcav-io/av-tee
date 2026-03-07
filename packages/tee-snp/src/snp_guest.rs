//! Narrow adapter wrapping all `sev` crate usage.
//!
//! No `sev` types escape this module — callers see only `tee-core` types
//! and the internal result structs defined here.
//!
//! The `sev` guest firmware API is only available on Linux. All functions
//! that touch the device are gated behind `#[cfg(target_os = "linux")]`.
//! Report parsing is platform-independent.

#[cfg(any(target_os = "linux", test))]
use tee_core::attestation::CvmError;

#[cfg(target_os = "linux")]
use sev::firmware::guest::{DerivedKey, Firmware, GuestFieldSelect};
#[cfg(target_os = "linux")]
use zeroize::Zeroizing;

/// Parsed fields from a raw SEV-SNP attestation report.
#[cfg(any(target_os = "linux", test))]
pub(crate) struct ParsedReport {
    pub report_bytes: Vec<u8>,
    pub measurement_hex: String,
    pub user_data: [u8; 64],
}

// Report layout constants (AMD SEV-SNP ABI spec).
#[cfg(any(target_os = "linux", test))]
const SNP_REPORT_DATA_OFFSET: usize = 80;
#[cfg(any(target_os = "linux", test))]
const SNP_MEASUREMENT_OFFSET: usize = 144;
#[cfg(any(target_os = "linux", test))]
const SNP_MEASUREMENT_LEN: usize = 48;
#[cfg(any(target_os = "linux", test))]
const SNP_MIN_REPORT_SIZE: usize = 192; // minimum for fields we read

/// Open the SEV-SNP guest firmware device.
#[cfg(target_os = "linux")]
pub(crate) fn open_device() -> Result<Firmware, CvmError> {
    Firmware::open().map_err(|e| {
        CvmError::AttestationUnavailable(format!("device not found: /dev/sev-guest: {e}"))
    })
}

/// Request an extended attestation report with optional certificate chain.
#[cfg(target_os = "linux")]
pub(crate) fn get_ext_report(
    fw: &mut Firmware,
    user_data: &[u8; 64],
) -> Result<ParsedReport, CvmError> {
    let (report_bytes, _certs) = fw
        .get_ext_report(None, Some(*user_data), Some(0))
        .map_err(|e| {
            CvmError::AttestationUnavailable(format!("SNP_GET_EXT_REPORT failed: {e}"))
        })?;

    parse_report_bytes(&report_bytes)
}

/// Parse raw report bytes to extract measurement and user_data.
/// Does not verify the report cryptographically — that's the verifier's job.
#[cfg(any(target_os = "linux", test))]
pub(crate) fn parse_report_bytes(report_bytes: &[u8]) -> Result<ParsedReport, CvmError> {
    if report_bytes.len() < SNP_MIN_REPORT_SIZE {
        return Err(CvmError::AttestationUnavailable(format!(
            "report too short: {} bytes, need at least {SNP_MIN_REPORT_SIZE}",
            report_bytes.len()
        )));
    }

    let version = u32::from_le_bytes(
        report_bytes[0..4]
            .try_into()
            .expect("4-byte slice"),
    );
    if version != 2 {
        return Err(CvmError::AttestationUnavailable(format!(
            "unsupported report version {version}, expected 2"
        )));
    }

    let mut user_data = [0u8; 64];
    user_data.copy_from_slice(&report_bytes[SNP_REPORT_DATA_OFFSET..SNP_REPORT_DATA_OFFSET + 64]);

    let measurement_hex = hex::encode(
        &report_bytes[SNP_MEASUREMENT_OFFSET..SNP_MEASUREMENT_OFFSET + SNP_MEASUREMENT_LEN],
    );

    Ok(ParsedReport {
        report_bytes: report_bytes.to_vec(),
        measurement_hex,
        user_data,
    })
}

/// Derive a 32-byte sealing key from the AMD Secure Processor.
///
/// Policy: VCEK root key, VMPL 0, measurement-only field selection.
#[cfg(target_os = "linux")]
pub(crate) fn derive_seal_key(fw: &mut Firmware) -> Result<Zeroizing<[u8; 32]>, CvmError> {
    let mut gfs = GuestFieldSelect::default();
    gfs.set_measurement(true);

    let request = DerivedKey::new(
        false, // root_key_select: false = VCEK
        gfs,
        0,    // vmpl
        0,    // guest_svn
        0,    // tcb_version
        None, // launch_mit_vector
    );

    let key = fw
        .get_derived_key(None, request)
        .map_err(|e| CvmError::SealError(format!("SNP_GET_DERIVED_KEY failed: {e}")))?;

    Ok(Zeroizing::new(key))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_report_extracts_measurement_and_user_data() {
        let mut report = vec![0u8; 1184];
        report[0..4].copy_from_slice(&2u32.to_le_bytes());
        let user_data = [0xAAu8; 64];
        report[80..144].copy_from_slice(&user_data);
        let measurement_bytes = [0xBBu8; 48];
        report[144..192].copy_from_slice(&measurement_bytes);

        let result = parse_report_bytes(&report).unwrap();
        assert_eq!(result.user_data, user_data);
        assert_eq!(result.measurement_hex, hex::encode(measurement_bytes));
        assert_eq!(result.report_bytes.len(), 1184);
    }

    #[test]
    fn parse_report_rejects_wrong_version() {
        let mut report = vec![0u8; 1184];
        report[0..4].copy_from_slice(&99u32.to_le_bytes());
        assert!(parse_report_bytes(&report).is_err());
    }

    #[test]
    fn parse_report_rejects_short_input() {
        let report = vec![0u8; 100];
        assert!(parse_report_bytes(&report).is_err());
    }
}
