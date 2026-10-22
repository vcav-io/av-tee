//! SEV-SNP attestation report fields used by the verifier.
//!
//! Offsets follow the AMD SEV-SNP ABI specification (ATTESTATION_REPORT,
//! report versions 2 to 5). The fields read here have the same offsets in
//! all of these versions.
//!
//! Only Milan and Genoa are supported (the bundled AMD roots). Turin uses a
//! different TCB_VERSION layout (FMC byte first) and an 8-byte hwID, and is
//! rejected by the chain check (no bundled Turin roots).

use crate::quote::QuoteVerifyError;

pub const SNP_REPORT_SIZE: usize = 1184;
pub const SNP_MIN_REPORT_VERSION: u32 = 2;
pub const SNP_MAX_REPORT_VERSION: u32 = 5;

const VERSION_OFFSET: usize = 0x00;
const POLICY_OFFSET: usize = 0x08;
const VMPL_OFFSET: usize = 0x30;
const CURRENT_TCB_OFFSET: usize = 0x38;
const PLATFORM_INFO_OFFSET: usize = 0x40;
const KEY_INFO_OFFSET: usize = 0x48;
const REPORTED_TCB_OFFSET: usize = 0x180;
const CHIP_ID_OFFSET: usize = 0x1A0;
const CHIP_ID_LEN: usize = 64;
const COMMITTED_TCB_OFFSET: usize = 0x1E0;

/// Guest POLICY bits.
pub const POLICY_SMT_ALLOWED: u64 = 1 << 16;
pub const POLICY_MIGRATE_MA: u64 = 1 << 18;
pub const POLICY_DEBUG: u64 = 1 << 19;

/// PLATFORM_INFO bit 0: SMT is enabled on the platform.
pub const PLATFORM_INFO_SMT_EN: u64 = 1 << 0;

/// TCB_VERSION components (Milan and Genoa layout: boot loader byte 0,
/// TEE byte 1, SNP byte 6, microcode byte 7; bytes 2 to 5 reserved).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcbVersion {
    pub boot_loader: u8,
    pub tee: u8,
    pub snp: u8,
    pub microcode: u8,
}

impl TcbVersion {
    pub fn from_raw(raw: u64) -> Self {
        let b = raw.to_le_bytes();
        Self {
            boot_loader: b[0],
            tee: b[1],
            snp: b[6],
            microcode: b[7],
        }
    }

    pub fn to_raw(self) -> u64 {
        u64::from_le_bytes([
            self.boot_loader,
            self.tee,
            0,
            0,
            0,
            0,
            self.snp,
            self.microcode,
        ])
    }
}

/// Fields of a raw SEV-SNP report that the verifier checks.
#[derive(Debug, Clone)]
pub struct SnpReportFields {
    pub version: u32,
    pub policy: u64,
    pub vmpl: u32,
    pub current_tcb: TcbVersion,
    pub platform_info: u64,
    pub key_info: u32,
    pub reported_tcb: TcbVersion,
    pub chip_id: [u8; CHIP_ID_LEN],
    pub committed_tcb: TcbVersion,
}

impl SnpReportFields {
    /// SIGNING_KEY (KEY_INFO bits 4:2): 0 = VCEK, 1 = VLEK, 7 = none.
    pub fn signing_key(&self) -> u32 {
        (self.key_info >> 2) & 0b111
    }

    /// MASK_CHIP_KEY (KEY_INFO bit 1).
    pub fn mask_chip_key(&self) -> bool {
        self.key_info & 0b10 != 0
    }
}

fn u32_at(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().expect("4-byte slice"))
}

fn u64_at(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().expect("8-byte slice"))
}

/// Parse the checked fields. The report must be exactly 1184 bytes with a
/// version from 2 to 5.
pub fn parse_report_fields(report: &[u8]) -> Result<SnpReportFields, QuoteVerifyError> {
    if report.len() != SNP_REPORT_SIZE {
        return Err(QuoteVerifyError::WrongLength {
            got: report.len(),
            expected: SNP_REPORT_SIZE,
        });
    }
    let version = u32_at(report, VERSION_OFFSET);
    if !(SNP_MIN_REPORT_VERSION..=SNP_MAX_REPORT_VERSION).contains(&version) {
        return Err(QuoteVerifyError::SnpParseFailed(format!(
            "version {version}, expected {SNP_MIN_REPORT_VERSION} to {SNP_MAX_REPORT_VERSION}"
        )));
    }
    let mut chip_id = [0u8; CHIP_ID_LEN];
    chip_id.copy_from_slice(&report[CHIP_ID_OFFSET..CHIP_ID_OFFSET + CHIP_ID_LEN]);
    Ok(SnpReportFields {
        version,
        policy: u64_at(report, POLICY_OFFSET),
        vmpl: u32_at(report, VMPL_OFFSET),
        current_tcb: TcbVersion::from_raw(u64_at(report, CURRENT_TCB_OFFSET)),
        platform_info: u64_at(report, PLATFORM_INFO_OFFSET),
        key_info: u32_at(report, KEY_INFO_OFFSET),
        reported_tcb: TcbVersion::from_raw(u64_at(report, REPORTED_TCB_OFFSET)),
        chip_id,
        committed_tcb: TcbVersion::from_raw(u64_at(report, COMMITTED_TCB_OFFSET)),
    })
}

/// Test helpers for building synthetic reports.
#[cfg(test)]
pub(crate) mod build {
    use super::*;

    pub fn set_u32(report: &mut [u8], offset: usize, v: u32) {
        report[offset..offset + 4].copy_from_slice(&v.to_le_bytes());
    }

    pub fn set_u64(report: &mut [u8], offset: usize, v: u64) {
        report[offset..offset + 8].copy_from_slice(&v.to_le_bytes());
    }

    pub const OFF_POLICY: usize = POLICY_OFFSET;
    pub const OFF_VMPL: usize = VMPL_OFFSET;
    pub const OFF_PLATFORM_INFO: usize = PLATFORM_INFO_OFFSET;
    pub const OFF_KEY_INFO: usize = KEY_INFO_OFFSET;
    pub const OFF_REPORTED_TCB: usize = REPORTED_TCB_OFFSET;
    pub const OFF_CHIP_ID: usize = CHIP_ID_OFFSET;
    pub const OFF_CURRENT_TCB: usize = CURRENT_TCB_OFFSET;
    pub const OFF_COMMITTED_TCB: usize = COMMITTED_TCB_OFFSET;
}

#[cfg(test)]
mod tests {
    use super::build::*;
    use super::*;

    #[test]
    fn tcb_layout_reads_snp_and_microcode_from_bytes_6_and_7() {
        let raw = u64::from_le_bytes([3, 0, 0xEE, 0xEE, 0xEE, 0xEE, 22, 213]);
        let tcb = TcbVersion::from_raw(raw);
        assert_eq!(
            tcb,
            TcbVersion {
                boot_loader: 3,
                tee: 0,
                snp: 22,
                microcode: 213
            }
        );
    }

    #[test]
    fn parses_fields_at_abi_offsets() {
        let mut r = vec![0u8; SNP_REPORT_SIZE];
        set_u32(&mut r, 0, 3);
        set_u64(&mut r, OFF_POLICY, 0x3_0000);
        set_u32(&mut r, OFF_VMPL, 1);
        set_u64(&mut r, OFF_PLATFORM_INFO, 1);
        set_u32(&mut r, OFF_KEY_INFO, 1 << 2);
        set_u64(
            &mut r,
            OFF_REPORTED_TCB,
            u64::from_le_bytes([4, 0, 0, 0, 0, 0, 22, 213]),
        );
        set_u64(
            &mut r,
            OFF_CURRENT_TCB,
            u64::from_le_bytes([5, 0, 0, 0, 0, 0, 23, 214]),
        );
        set_u64(
            &mut r,
            OFF_COMMITTED_TCB,
            u64::from_le_bytes([4, 0, 0, 0, 0, 0, 22, 214]),
        );
        r[OFF_CHIP_ID..OFF_CHIP_ID + 64].copy_from_slice(&[0x5A; 64]);

        let f = parse_report_fields(&r).unwrap();
        assert_eq!(f.version, 3);
        assert_eq!(f.policy, 0x3_0000);
        assert_eq!(f.vmpl, 1);
        assert_eq!(f.platform_info & PLATFORM_INFO_SMT_EN, 1);
        assert_eq!(f.signing_key(), 1);
        assert!(!f.mask_chip_key());
        assert_eq!(f.reported_tcb.snp, 22);
        assert_eq!(f.reported_tcb.microcode, 213);
        assert_eq!(f.current_tcb.boot_loader, 5);
        assert_eq!(f.committed_tcb.microcode, 214);
        assert_eq!(f.chip_id, [0x5A; 64]);
    }

    #[test]
    fn accepts_report_versions_2_to_5_only() {
        for (v, ok) in [(1, false), (2, true), (3, true), (5, true), (6, false)] {
            let mut r = vec![0u8; SNP_REPORT_SIZE];
            set_u32(&mut r, 0, v);
            assert_eq!(parse_report_fields(&r).is_ok(), ok, "version {v}");
        }
    }

    #[test]
    fn rejects_wrong_size() {
        assert!(parse_report_fields(&[0u8; 1000]).is_err());
    }
}
