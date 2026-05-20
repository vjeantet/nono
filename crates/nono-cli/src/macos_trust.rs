//! macOS system trust store integration for nono's proxy CA.
//!
//! Persists the CA private key in macOS Keychain and the public cert in the
//! user trust store via Security.framework. Regenerates when expired (24h).
//!
//! This enables Go CLI tools (`gh`, `terraform`, etc.) that ignore
//! `SSL_CERT_FILE` and only use `com.apple.trustd` for TLS verification.

use nono::{NonoError, Result};
use nono_proxy::config::PreloadedCa;
use security_framework::certificate::SecCertificate;
use security_framework::os::macos::keychain::SecKeychain;
use security_framework::passwords;
use security_framework::trust_settings::{Domain, TrustSettings, TrustSettingsForCertificate};
use std::time::SystemTime;
use tracing::{debug, info, warn};
use x509_parser::pem::parse_x509_pem;
use zeroize::Zeroizing;

// Service name for Keychain items. Sufficiently specific to avoid collision
// with other apps. set_generic_password overwrites on conflict (desired).
const KEYCHAIN_SERVICE: &str = "nono-proxy-ca";
const KEYCHAIN_ACCOUNT_KEY: &str = "private-key";
const KEYCHAIN_ACCOUNT_CERT: &str = "certificate-pem";

/// Load or generate a shared CA and ensure it's trusted in the macOS user
/// trust store. Returns `Some(PreloadedCa)` on success, `None` if the user
/// cancelled the auth prompt or setup failed (fallback to ephemeral CA).
///
/// All logging happens internally — the caller just checks the Option.
pub(crate) fn load_or_generate_proxy_ca() -> Option<PreloadedCa> {
    match try_ensure_trusted_ca() {
        Ok(Some(ca)) => Some(ca),
        Ok(None) => None,
        Err(e) => {
            warn!("Shared CA setup failed: {e}. Falling back to ephemeral CA.");
            None
        }
    }
}

fn try_ensure_trusted_ca() -> Result<Option<PreloadedCa>> {
    match load_existing_ca()? {
        Some((key_der, cert_pem)) => {
            if !cert_pem_is_valid(&cert_pem)? {
                debug!("stored proxy CA has expired; regenerating");
                remove_cert_from_keychain(&cert_pem);
                delete_existing_ca();
                return generate_and_trust_new_ca();
            }

            let cert_der = pem_to_der(&cert_pem)?;
            let cert = SecCertificate::from_der(&cert_der).map_err(|e| {
                NonoError::SandboxInit(format!("failed to parse stored CA cert: {e}"))
            })?;

            if !is_cert_trusted(&cert) {
                info!("Re-trusting proxy CA (you may be prompted for authentication)...");
                if let Err(e) = trust_cert(&cert) {
                    if is_user_cancelled_error(&e) {
                        warn!(
                            "Trust store auth cancelled. Falling back to ephemeral CA. \
                             Go CLI tools won't validate proxy certs; other tools still work."
                        );
                        return Ok(None);
                    }
                    return Err(e);
                }
                info!("Proxy CA re-trusted successfully");
            } else {
                info!("Reusing proxy CA from Keychain (already trusted)");
            }

            Ok(Some(PreloadedCa {
                key_der: Zeroizing::new(key_der),
                cert_pem,
            }))
        }
        None => {
            debug!("no existing proxy CA in Keychain; generating new one");
            generate_and_trust_new_ca()
        }
    }
}

fn load_existing_ca() -> Result<Option<(Vec<u8>, String)>> {
    let key = match passwords::get_generic_password(KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT_KEY) {
        Ok(data) => data,
        Err(_) => return Ok(None),
    };
    let cert_bytes = match passwords::get_generic_password(KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT_CERT)
    {
        Ok(data) => data,
        Err(_) => return Ok(None),
    };
    let cert_pem = String::from_utf8(cert_bytes).map_err(|e| {
        NonoError::SandboxInit(format!("stored CA cert PEM is not valid UTF-8: {e}"))
    })?;

    // Verify key and cert are a valid pair. The proxy will call from_existing()
    // again at startup — this intentional double-check catches corruption before
    // we attempt trust store operations.
    if let Err(e) = nono_proxy::tls_intercept::ca::EphemeralCa::from_existing(&key, &cert_pem) {
        warn!("Stored CA key/cert pair is invalid ({e}); regenerating");
        return Ok(None);
    }

    Ok(Some((key, cert_pem)))
}

fn generate_and_trust_new_ca() -> Result<Option<PreloadedCa>> {
    let (key_der, cert_pem) = generate_ca_material()?;

    // Note: concurrent nono processes may race here — second writer wins.
    // This is benign: the losing process already has its material in memory,
    // and next session's load_existing_ca validates the pair before use.
    passwords::set_generic_password(KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT_KEY, &key_der)
        .map_err(|e| NonoError::SandboxInit(format!("failed to store CA key in Keychain: {e}")))?;
    passwords::set_generic_password(KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT_CERT, cert_pem.as_bytes())
        .map_err(|e| NonoError::SandboxInit(format!("failed to store CA cert in Keychain: {e}")))?;

    let cert_der = pem_to_der(&cert_pem)?;
    let sec_cert = SecCertificate::from_der(&cert_der)
        .map_err(|e| NonoError::SandboxInit(format!("failed to create SecCertificate: {e}")))?;

    info!("Adding proxy CA to macOS trust store (you may be prompted for authentication)...");
    if let Err(e) = trust_cert(&sec_cert) {
        if is_user_cancelled_error(&e) {
            warn!(
                "Trust store auth cancelled. Falling back to ephemeral CA. \
                 Go CLI tools won't validate proxy certs; other tools still work."
            );
            return Ok(None);
        }
        return Err(e);
    }

    info!("Proxy CA added to macOS trust store");
    Ok(Some(PreloadedCa { key_der, cert_pem }))
}

fn ensure_cert_in_keychain(cert: &SecCertificate) -> Result<()> {
    let keychain = SecKeychain::default()
        .map_err(|e| NonoError::SandboxInit(format!("failed to open default keychain: {e}")))?;
    if let Err(e) = cert.add_to_keychain(Some(keychain)) {
        // errSecDuplicateItem (-25299) — cert already imported from a prior run.
        if e.code() != -25299 {
            return Err(NonoError::SandboxInit(format!(
                "failed to add CA cert to keychain: {e}"
            )));
        }
    }
    Ok(())
}

fn trust_cert(cert: &SecCertificate) -> Result<()> {
    ensure_cert_in_keychain(cert)?;
    TrustSettings::new(Domain::User)
        .set_trust_settings_always(cert)
        .map_err(|e| NonoError::SandboxInit(format!("failed to set trust settings: {e}")))
}

fn is_cert_trusted(cert: &SecCertificate) -> bool {
    let ts = TrustSettings::new(Domain::User);
    match ts.tls_trust_settings_for_certificate(cert) {
        Ok(Some(r)) => {
            let trusted = matches!(
                r,
                TrustSettingsForCertificate::TrustRoot | TrustSettingsForCertificate::TrustAsRoot
            );
            debug!("trust store lookup: {:?}, trusted={}", r, trusted);
            trusted
        }
        Ok(None) => {
            // NULL/empty trust settings means "always trust for all purposes"
            // per Apple docs. SecTrustSettingsCopyTrustSettings returns
            // errSecItemNotFound (Err) when the cert isn't present, so Ok(None)
            // confirms presence + unconditional trust.
            debug!("trust store lookup: unconditionally trusted (empty settings)");
            true
        }
        Err(e) => {
            debug!("trust store lookup: {e} (cert not in trust store)");
            false
        }
    }
}

fn remove_cert_from_keychain(cert_pem: &str) {
    if let Ok(der) = pem_to_der(cert_pem)
        && let Ok(cert) = SecCertificate::from_der(&der)
        && let Err(e) = cert.delete()
    {
        warn!(
            "Failed to remove expired CA cert from keychain: {e}. \
             Run: security delete-certificate -c \"nono-proxy-ca\""
        );
    }
}

fn delete_existing_ca() {
    let _ = passwords::delete_generic_password(KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT_KEY);
    let _ = passwords::delete_generic_password(KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT_CERT);
}

fn cert_pem_is_valid(cert_pem: &str) -> Result<bool> {
    let (_, pem) = parse_x509_pem(cert_pem.as_bytes())
        .map_err(|e| NonoError::SandboxInit(format!("failed to parse stored CA cert PEM: {e}")))?;
    let cert = pem.parse_x509().map_err(|e| {
        NonoError::SandboxInit(format!("failed to parse X.509 from stored PEM: {e}"))
    })?;
    let not_after = cert.validity().not_after.timestamp();
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_err(|e| NonoError::SandboxInit(format!("system clock before UNIX epoch: {e}")))?
        .as_secs() as i64;
    Ok(now < not_after)
}

fn pem_to_der(cert_pem: &str) -> Result<Vec<u8>> {
    let (_, pem) = parse_x509_pem(cert_pem.as_bytes())
        .map_err(|e| NonoError::SandboxInit(format!("failed to parse CA cert PEM: {e}")))?;
    Ok(pem.contents.to_vec())
}

fn generate_ca_material() -> Result<(Zeroizing<Vec<u8>>, String)> {
    let ca = nono_proxy::tls_intercept::ca::EphemeralCa::generate_with_cn("nono-proxy-ca")
        .map_err(|e| NonoError::SandboxInit(format!("failed to generate CA: {e}")))?;
    Ok((
        Zeroizing::new(ca.key_der().to_vec()),
        ca.cert_pem().to_string(),
    ))
}

fn is_user_cancelled_error(err: &NonoError) -> bool {
    let msg = err.to_string();
    msg.contains("cancelled")
        || msg.contains("canceled")
        || msg.contains("errSecAuthFailed")
        || msg.contains("User interaction is not allowed")
        || msg.contains("errSecInternalComponent")
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn generate_ca_material_produces_valid_output() {
        let (key_der, cert_pem) = generate_ca_material().unwrap();

        assert!(!key_der.is_empty());
        assert!(cert_pem.contains("BEGIN CERTIFICATE"));

        let ca =
            nono_proxy::tls_intercept::ca::EphemeralCa::from_existing(&key_der, &cert_pem).unwrap();
        assert_eq!(ca.cert_pem(), cert_pem);
    }

    #[test]
    fn cert_pem_is_valid_returns_true_for_fresh_cert() {
        let (_, cert_pem) = generate_ca_material().unwrap();
        assert!(cert_pem_is_valid(&cert_pem).unwrap());
    }

    #[test]
    fn cert_pem_is_valid_rejects_garbage() {
        assert!(cert_pem_is_valid("not a cert").is_err());
    }

    #[test]
    fn pem_to_der_roundtrips() {
        use x509_parser::prelude::FromDer;

        let (_, cert_pem) = generate_ca_material().unwrap();
        let der = pem_to_der(&cert_pem).unwrap();
        assert!(!der.is_empty());
        let (_, cert) = x509_parser::prelude::X509Certificate::from_der(&der).unwrap();
        assert_eq!(
            cert.subject()
                .iter_common_name()
                .next()
                .unwrap()
                .as_str()
                .unwrap(),
            "nono-proxy-ca"
        );
    }

    #[test]
    fn is_user_cancelled_detects_cancel_messages() {
        let err = NonoError::SandboxInit("failed to set trust settings: cancelled".to_string());
        assert!(is_user_cancelled_error(&err));

        let err = NonoError::SandboxInit("some other error".to_string());
        assert!(!is_user_cancelled_error(&err));
    }
}
