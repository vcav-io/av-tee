//! Startup decisions: which CVM runtime to use and where to listen.
//!
//! Kept free of process exits and environment reads so the rules can be
//! tested; `main` reads the environment and exits on error.

use std::net::{IpAddr, Ipv4Addr};

/// Environment variable that permits the simulated CVM runtime.
pub const ALLOW_SIMULATED_ENV: &str = "SELKEY_ALLOW_SIMULATED";

/// Default listen address: loopback only. Set `SELKEY_BIND_ADDR` (e.g.
/// `0.0.0.0` inside a container) to listen on other interfaces.
pub const DEFAULT_BIND_ADDR: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

/// Whether `SELKEY_ALLOW_SIMULATED` permits the simulated runtime
/// (`1` or `true`).
pub fn allow_simulated(value: Option<&str>) -> bool {
    matches!(value.map(str::trim), Some("1") | Some("true"))
}

/// Which CVM runtime the relay runs on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeChoice {
    /// The SEV-SNP hardware runtime.
    SevSnp,
    /// The simulated runtime (no hardware isolation).
    Simulated,
}

/// Outcome of trying to open the hardware runtime.
#[derive(Debug)]
pub enum HardwareRuntime {
    /// The binary was built without the `snp` feature.
    NotBuilt,
    /// SEV-SNP initialisation succeeded.
    Available,
    /// SEV-SNP initialisation failed (reason, without secrets).
    Failed(String),
}

/// Decide which runtime to use.
///
/// The hardware runtime is used whenever it initialises. Otherwise the relay
/// refuses to start, unless the simulated runtime is explicitly allowed with
/// `SELKEY_ALLOW_SIMULATED=1`. There is no silent fallback.
pub fn choose_runtime(
    hardware: HardwareRuntime,
    allow_simulated: bool,
) -> Result<RuntimeChoice, String> {
    match hardware {
        HardwareRuntime::Available => Ok(RuntimeChoice::SevSnp),
        HardwareRuntime::NotBuilt if allow_simulated => Ok(RuntimeChoice::Simulated),
        HardwareRuntime::NotBuilt => Err(format!(
            "this tee-relay binary was built without SEV-SNP support (feature `snp`); \
             set {ALLOW_SIMULATED_ENV}=1 to run the simulated runtime (no hardware isolation)"
        )),
        // The caller logs the failure reason; the choice is still explicit.
        HardwareRuntime::Failed(_) if allow_simulated => Ok(RuntimeChoice::Simulated),
        HardwareRuntime::Failed(reason) => Err(format!(
            "SEV-SNP initialisation failed ({reason}); refusing to start. Pass /dev/sev-guest \
             to the container, or set {ALLOW_SIMULATED_ENV}=1 to run the simulated runtime \
             (no hardware isolation)"
        )),
    }
}

/// Resolve the listen address from `SELKEY_BIND_ADDR`.
///
/// Unset or empty uses [`DEFAULT_BIND_ADDR`]. An unparseable value is an
/// error: the relay refuses to start rather than guess its exposure.
pub fn resolve_bind_addr(value: Option<&str>) -> Result<IpAddr, String> {
    match value.map(str::trim).filter(|v| !v.is_empty()) {
        None => Ok(DEFAULT_BIND_ADDR),
        Some(v) => v
            .parse()
            .map_err(|_| "SELKEY_BIND_ADDR is not a valid IP address".to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hardware_runtime_is_used_when_available() {
        for allow in [false, true] {
            assert_eq!(
                choose_runtime(HardwareRuntime::Available, allow),
                Ok(RuntimeChoice::SevSnp)
            );
        }
    }

    #[test]
    fn failed_snp_initialisation_refuses_to_start_by_default() {
        let err = choose_runtime(HardwareRuntime::Failed("no device".into()), false).unwrap_err();
        assert!(err.contains("refusing to start"));
        assert!(err.contains(ALLOW_SIMULATED_ENV));
    }

    #[test]
    fn build_without_snp_refuses_to_start_by_default() {
        let err = choose_runtime(HardwareRuntime::NotBuilt, false).unwrap_err();
        assert!(err.contains(ALLOW_SIMULATED_ENV));
    }

    #[test]
    fn simulated_runtime_requires_explicit_opt_in() {
        assert_eq!(
            choose_runtime(HardwareRuntime::NotBuilt, true),
            Ok(RuntimeChoice::Simulated)
        );
        assert_eq!(
            choose_runtime(HardwareRuntime::Failed("no device".into()), true),
            Ok(RuntimeChoice::Simulated)
        );
    }

    #[test]
    fn allow_simulated_accepts_only_explicit_values() {
        assert!(allow_simulated(Some("1")));
        assert!(allow_simulated(Some("true")));
        assert!(!allow_simulated(None));
        assert!(!allow_simulated(Some("")));
        assert!(!allow_simulated(Some("0")));
        assert!(!allow_simulated(Some("yes")));
    }

    #[test]
    fn bind_addr_defaults_to_loopback() {
        assert_eq!(resolve_bind_addr(None), Ok(DEFAULT_BIND_ADDR));
        assert_eq!(resolve_bind_addr(Some("")), Ok(DEFAULT_BIND_ADDR));
        assert!(DEFAULT_BIND_ADDR.is_loopback());
    }

    #[test]
    fn bind_addr_accepts_explicit_addresses() {
        assert_eq!(
            resolve_bind_addr(Some("0.0.0.0")),
            Ok(IpAddr::V4(Ipv4Addr::UNSPECIFIED))
        );
        assert_eq!(
            resolve_bind_addr(Some(" ::1 ")),
            Ok("::1".parse::<IpAddr>().unwrap())
        );
    }

    #[test]
    fn bind_addr_rejects_invalid_values() {
        assert!(resolve_bind_addr(Some("localhost:3100")).is_err());
        assert!(resolve_bind_addr(Some("not-an-ip")).is_err());
    }
}
