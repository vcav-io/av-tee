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
    // Read only on Linux, where the device returns certificates.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub vcek_cert_der: Option<Vec<u8>>,
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
    let (report_bytes, certs) = fw
        .get_ext_report(None, Some(*user_data), Some(0))
        .map_err(|e| CvmError::AttestationUnavailable(format!("SNP_GET_EXT_REPORT failed: {e}")))?;

    let vcek_cert_der = certs
        .as_ref()
        .and_then(|entries| {
            entries
                .iter()
                .find(|e| e.cert_type == sev::firmware::host::CertType::VCEK)
        })
        .map(|e| e.data.clone());

    let mut parsed = parse_report_bytes(&report_bytes)?;
    parsed.vcek_cert_der = vcek_cert_der;
    Ok(parsed)
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

    let version = u32::from_le_bytes(report_bytes[0..4].try_into().expect("4-byte slice"));
    if version < 2 {
        return Err(CvmError::AttestationUnavailable(format!(
            "unsupported report version {version}, expected >= 2"
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
        vcek_cert_der: None,
    })
}

// GUEST_FIELD_SELECT bits (SNP ABI, MSG_KEY_REQ).
#[cfg(any(target_os = "linux", test))]
pub(crate) const FIELD_GUEST_POLICY: u64 = 1 << 0;
#[cfg(any(target_os = "linux", test))]
pub(crate) const FIELD_MEASUREMENT: u64 = 1 << 3;
#[cfg(any(target_os = "linux", test))]
pub(crate) const FIELD_TCB_VERSION: u64 = 1 << 5;

/// Offset of COMMITTED_TCB (8 bytes) in the attestation report.
#[cfg(any(target_os = "linux", test))]
const SNP_COMMITTED_TCB_OFFSET: usize = 0x1E0;

/// Parameters of the sealing key derivation request.
#[cfg(any(target_os = "linux", test))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SealKeyRequest {
    /// Root key: `false` selects the VCEK (chip-unique).
    pub root_key_vmrk: bool,
    /// GUEST_FIELD_SELECT bits mixed into the key.
    pub field_select: u64,
    pub vmpl: u32,
    pub guest_svn: u32,
    /// TCB version mixed into the key (the TCB floor). The firmware refuses
    /// a value above the platform's committed TCB.
    pub tcb_version: u64,
}

/// Sealing key policy 0x02: VCEK root, VMPL 0, and the guest policy, the
/// launch measurement and the TCB floor mixed into the key.
///
/// A key sealed under one guest policy (e.g. with DEBUG or MIGRATE_MA
/// allowed) cannot be derived under another, and the key cannot be derived
/// on a platform whose committed TCB is below the floor.
#[cfg(any(target_os = "linux", test))]
pub(crate) fn seal_key_request(tcb_floor: u64) -> SealKeyRequest {
    SealKeyRequest {
        root_key_vmrk: false,
        field_select: FIELD_GUEST_POLICY | FIELD_MEASUREMENT | FIELD_TCB_VERSION,
        vmpl: 0,
        guest_svn: 0,
        tcb_version: tcb_floor,
    }
}

/// COMMITTED_TCB from a raw attestation report (little-endian u64).
#[cfg(any(target_os = "linux", test))]
pub(crate) fn parse_committed_tcb(report_bytes: &[u8]) -> Result<u64, CvmError> {
    let bytes = report_bytes
        .get(SNP_COMMITTED_TCB_OFFSET..SNP_COMMITTED_TCB_OFFSET + 8)
        .ok_or_else(|| {
            CvmError::AttestationUnavailable("report too short for COMMITTED_TCB".into())
        })?;
    Ok(u64::from_le_bytes(bytes.try_into().expect("8-byte slice")))
}

/// Read the platform's committed TCB from a fresh attestation report.
#[cfg(target_os = "linux")]
pub(crate) fn committed_tcb(fw: &mut Firmware) -> Result<u64, CvmError> {
    let report = fw
        .get_report(None, Some([0u8; 64]), Some(0))
        .map_err(|e| CvmError::AttestationUnavailable(format!("SNP_GET_REPORT failed: {e}")))?;
    parse_committed_tcb(&report)
}

/// Derive a 32-byte sealing key from the AMD Secure Processor.
#[cfg(target_os = "linux")]
pub(crate) fn derive_seal_key(
    fw: &mut Firmware,
    request: SealKeyRequest,
) -> Result<Zeroizing<[u8; 32]>, CvmError> {
    let mut gfs = GuestFieldSelect::default();
    // Only the fields named in `field_select` are mixed in (image id, family
    // id and guest SVN are not used).
    gfs.set_guest_policy(request.field_select & FIELD_GUEST_POLICY != 0);
    gfs.set_measurement(request.field_select & FIELD_MEASUREMENT != 0);
    gfs.set_tcb_version(request.field_select & FIELD_TCB_VERSION != 0);

    let derived = DerivedKey::new(
        request.root_key_vmrk,
        gfs,
        request.vmpl,
        request.guest_svn,
        request.tcb_version,
        None, // launch_mit_vector
    );

    let key = fw
        .get_derived_key(Some(1), derived)
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
    fn parse_report_rejects_old_version() {
        let mut report = vec![0u8; 1184];
        report[0..4].copy_from_slice(&1u32.to_le_bytes());
        assert!(parse_report_bytes(&report).is_err());
    }

    #[test]
    fn seal_key_request_binds_policy_measurement_and_tcb_floor() {
        let floor = 0x1700_0000_0000_0304;
        let req = seal_key_request(floor);
        assert!(!req.root_key_vmrk, "VCEK root key");
        assert_eq!(req.vmpl, 0);
        assert_ne!(req.field_select & FIELD_GUEST_POLICY, 0, "guest policy");
        assert_ne!(req.field_select & FIELD_MEASUREMENT, 0, "measurement");
        assert_ne!(req.field_select & FIELD_TCB_VERSION, 0, "TCB version");
        assert_eq!(req.tcb_version, floor);
    }

    #[test]
    fn parse_committed_tcb_reads_offset_0x1e0() {
        let mut report = vec![0u8; 1184];
        report[0x1E0..0x1E8].copy_from_slice(&0x1122_3344_5566_7788u64.to_le_bytes());
        assert_eq!(parse_committed_tcb(&report).unwrap(), 0x1122_3344_5566_7788);
        assert!(parse_committed_tcb(&report[..0x1E4]).is_err());
    }

    #[test]
    fn parse_report_rejects_short_input() {
        let report = vec![0u8; 100];
        assert!(parse_report_bytes(&report).is_err());
    }
}
