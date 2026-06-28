//! Registry client for package hosting.

use crate::package::{
    PackageRef, PackageSearchResponse, PackageSearchResult, PackageStatusResponse, PullResponse,
    YankedErrorResponse,
};
use nono::{NonoError, Result};
use serde::de::DeserializeOwned;
use sha2::Digest;
use std::fs;
use std::io::{Read, Write};
use std::path::Path;
use std::time::Duration;

pub const DEFAULT_REGISTRY_URL: &str = "https://registry.nono.sh";
const REGISTRY_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const REGISTRY_RESPONSE_TIMEOUT: Duration = Duration::from_secs(30);
const REGISTRY_BODY_TIMEOUT: Duration = Duration::from_secs(300);
const REGISTRY_CALL_TIMEOUT: Duration = Duration::from_secs(300);
const REGISTRY_JSON_LIMIT_BYTES: u64 = 2 * 1024 * 1024;
const REGISTRY_BUNDLE_LIMIT_BYTES: u64 = 8 * 1024 * 1024;
const REGISTRY_ARTIFACT_LIMIT_BYTES: u64 = 64 * 1024 * 1024;

pub struct RegistryClient {
    base_url: String,
    http: ureq::Agent,
}

impl RegistryClient {
    /// Build a registry client whose TLS verifier delegates to the OS-native
    /// trust store at handshake time (SecTrust on macOS, system CA stores on
    /// Linux). This picks up corporate or MDM-installed root CAs — including
    /// the kind injected by VPN-based TLS-inspecting proxies — that the bundled
    /// webpki roots wouldn't recognize, without any startup-time enumeration of
    /// the keychain (which can spuriously fail in restricted environments).
    #[must_use]
    pub fn new(base_url: String) -> Self {
        let tls_config = ureq::tls::TlsConfig::builder()
            .root_certs(ureq::tls::RootCerts::PlatformVerifier)
            .build();
        let http = ureq::Agent::config_builder()
            .timeout_global(Some(REGISTRY_CALL_TIMEOUT))
            .timeout_resolve(Some(REGISTRY_CONNECT_TIMEOUT))
            .timeout_connect(Some(REGISTRY_CONNECT_TIMEOUT))
            .timeout_recv_response(Some(REGISTRY_RESPONSE_TIMEOUT))
            .timeout_recv_body(Some(REGISTRY_BODY_TIMEOUT))
            .tls_config(tls_config)
            .build()
            .new_agent();
        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            http,
        }
    }

    pub fn fetch_pull_response(
        &self,
        package_ref: &PackageRef,
        version: &str,
    ) -> Result<PullResponse> {
        let url = format!(
            "{}/api/v1/packages/{}/{}/versions/{version}/pull",
            self.base_url, package_ref.namespace, package_ref.name
        );
        let mut response = self
            .http
            .get(&url)
            .config()
            .http_status_as_error(false)
            .build()
            .call()
            .map_err(map_ureq_error)?;

        if response.status().as_u16() == 410 {
            enforce_content_length(
                response.body().content_length(),
                REGISTRY_JSON_LIMIT_BYTES,
                &url,
            )?;
            let body = response
                .body_mut()
                .with_config()
                .limit(REGISTRY_JSON_LIMIT_BYTES)
                .read_to_string()
                .map_err(|e| {
                    NonoError::RegistryError(format!(
                        "failed to read registry response from {}: {}",
                        url, e
                    ))
                })?;
            let yanked: YankedErrorResponse =
                serde_json::from_str(&body).unwrap_or(YankedErrorResponse {
                    error: None,
                    yanked: true,
                    yank_reason: None,
                    advisory: None,
                });
            let mut msg = format!(
                "{}/{}@{} has been yanked",
                package_ref.namespace, package_ref.name, version
            );
            if let Some(reason) = &yanked.yank_reason {
                msg.push_str(&format!(" (reason: {reason})"));
            }
            if let Some(advisory) = &yanked.advisory {
                let severity = advisory.severity.as_deref().unwrap_or("unknown");
                let summary = advisory.summary.as_deref().unwrap_or("");
                if !summary.is_empty() {
                    msg.push_str(&format!("\nadvisory: {severity} — {summary}"));
                } else {
                    msg.push_str(&format!("\nadvisory severity: {severity}"));
                }
            }
            msg.push_str(&format!(
                "\ninstall the latest safe release: nono pull {}/{}",
                package_ref.namespace, package_ref.name
            ));
            return Err(NonoError::RegistryError(msg));
        }

        if !response.status().is_success() {
            return Err(NonoError::RegistryError(format!(
                "registry returned HTTP {} for {}/{}@{}",
                response.status().as_u16(),
                package_ref.namespace,
                package_ref.name,
                version
            )));
        }

        enforce_content_length(
            response.body().content_length(),
            REGISTRY_JSON_LIMIT_BYTES,
            &url,
        )?;
        let body = response
            .body_mut()
            .with_config()
            .limit(REGISTRY_JSON_LIMIT_BYTES)
            .read_to_string()
            .map_err(|e| {
                NonoError::RegistryError(format!(
                    "failed to read registry response from {}: {}",
                    url, e
                ))
            })?;
        serde_json::from_str(&body).map_err(|e| {
            NonoError::RegistryError(format!("failed to decode registry response: {e}"))
        })
    }

    pub fn search_packages(&self, query: &str) -> Result<Vec<PackageSearchResult>> {
        let response: PackageSearchResponse =
            self.get_json(&format!("/api/v1/packages?q={query}"))?;
        Ok(response.packages)
    }

    pub fn fetch_package_status(
        &self,
        package_ref: &PackageRef,
        installed: Option<&str>,
    ) -> Result<PackageStatusResponse> {
        let mut path = format!(
            "/api/v1/packages/{}/{}/status",
            package_ref.namespace, package_ref.name
        );
        if let Some(installed) = installed {
            let encoded: String =
                url::form_urlencoded::byte_serialize(installed.as_bytes()).collect();
            path.push_str("?installed=");
            path.push_str(&encoded);
        }
        self.get_json(&path)
    }

    /// Look up which packs (if any) ship a profile with the given
    /// `install_as` name. Used by the migration prompt to discover
    /// which pack to offer when `--profile <name>` misses every local
    /// resolver. Returns `Ok(vec![])` if the registry has no providers
    /// for that name.
    pub fn fetch_profile_providers(
        &self,
        profile_name: &str,
    ) -> Result<Vec<crate::package::ProfileProvider>> {
        let response: crate::package::ProfileProvidersResponse =
            self.get_json(&format!("/api/v1/profiles/{profile_name}/providers"))?;
        Ok(response.providers)
    }

    pub fn download_bundle(&self, url: &str) -> Result<String> {
        let resolved_url = self.resolve_url(url);
        let mut response = self
            .http
            .get(&resolved_url)
            .call()
            .map_err(map_ureq_error)?;
        enforce_content_length(
            response.body().content_length(),
            REGISTRY_BUNDLE_LIMIT_BYTES,
            &resolved_url,
        )?;
        response
            .body_mut()
            .with_config()
            .limit(REGISTRY_BUNDLE_LIMIT_BYTES)
            .read_to_string()
            .map_err(|e| {
                NonoError::RegistryError(format!(
                    "failed to read registry response from {}: {}",
                    resolved_url, e
                ))
            })
    }

    pub fn download_artifact_to_path(&self, url: &str, dest: &Path) -> Result<String> {
        let resolved_url = self.resolve_url(url);
        let mut response = self
            .http
            .get(&resolved_url)
            .call()
            .map_err(map_ureq_error)?;
        enforce_content_length(
            response.body().content_length(),
            REGISTRY_ARTIFACT_LIMIT_BYTES,
            &resolved_url,
        )?;

        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent).map_err(NonoError::Io)?;
        }

        let mut reader = response
            .body_mut()
            .with_config()
            .limit(REGISTRY_ARTIFACT_LIMIT_BYTES)
            .reader();
        let mut file = fs::File::create(dest).map_err(NonoError::Io)?;
        let mut hasher = sha2::Sha256::new();
        let mut buffer = [0_u8; 8192];

        loop {
            let bytes_read = match reader.read(&mut buffer) {
                Ok(0) => break,
                Ok(bytes_read) => bytes_read,
                Err(error) => {
                    let _ = fs::remove_file(dest);
                    return Err(NonoError::RegistryError(format!(
                        "failed to read registry response from {}: {}",
                        resolved_url, error
                    )));
                }
            };
            file.write_all(&buffer[..bytes_read])
                .map_err(NonoError::Io)?;
            use sha2::Digest as _;
            hasher.update(&buffer[..bytes_read]);
        }

        let digest = hasher.finalize();
        Ok(digest.iter().map(|byte| format!("{byte:02x}")).collect())
    }

    fn get_json<T: DeserializeOwned>(&self, path: &str) -> Result<T> {
        let url = format!("{}{}", self.base_url, path);
        let mut response = self.http.get(&url).call().map_err(map_ureq_error)?;
        enforce_content_length(
            response.body().content_length(),
            REGISTRY_JSON_LIMIT_BYTES,
            &url,
        )?;
        let body = response
            .body_mut()
            .with_config()
            .limit(REGISTRY_JSON_LIMIT_BYTES)
            .read_to_string()
            .map_err(|e| {
                NonoError::RegistryError(format!(
                    "failed to read registry response from {}: {}",
                    url, e
                ))
            })?;
        serde_json::from_str(&body).map_err(|e| {
            NonoError::RegistryError(format!("failed to decode registry response: {e}"))
        })
    }

    fn resolve_url(&self, url: &str) -> String {
        if url.starts_with("http://") || url.starts_with("https://") {
            url.to_string()
        } else {
            format!("{}{}", self.base_url, url)
        }
    }
}

/// How pack signatures are verified for a resolved registry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrustMode {
    /// Sigstore/Fulcio keyless verification against the public trusted root.
    Keyless,
    /// Keyed verification against a self-managed ECDSA P-256 public key
    /// (`spki_der`), bound to its fingerprint (`fingerprint` = SHA-256 of the
    /// SPKI, hex). For air-gapped enterprise fleets.
    Keyed {
        spki_der: Vec<u8>,
        fingerprint: String,
    },
    /// No signature verification; SHA-256 integrity only.
    Unsigned,
}

/// Resolved registry endpoint plus the trust mode for pack verification.
#[derive(Debug, Clone)]
pub struct ResolvedRegistry {
    pub url: String,
    pub trust: TrustMode,
}

/// Resolve the registry URL alone. Kept for callers that do not need the
/// trust mode (migration prompt, update-hint helper). Precedence:
/// `--registry` flag → `NONO_REGISTRY` env → compiled-in default.
pub fn resolve_registry_url(override_url: Option<&str>) -> String {
    override_url
        .map(ToOwned::to_owned)
        .or_else(|| std::env::var("NONO_REGISTRY").ok())
        .unwrap_or_else(|| DEFAULT_REGISTRY_URL.to_string())
}

/// Resolve both the registry URL and the pack-verification trust mode.
///
/// URL precedence: `--registry` flag → `NONO_REGISTRY` env →
/// `[registry].url` in `config.toml` → compiled-in default.
///
/// Trust mode (fail-secure, defaults to `Keyless`):
/// - `[registry].trusted_key` / `trusted_key_file` set → `Keyed`. A configured
///   trusted key cannot be silently downgraded: combining it with
///   `verify = false` is a hard error, and `NONO_REGISTRY_INSECURE` is ignored
///   (warned). Only an explicit `--insecure` flag downgrades it to `Unsigned`,
///   loudly.
/// - otherwise, `--insecure` / `NONO_REGISTRY_INSECURE` / `verify = false`
///   → `Unsigned`; else `Keyless`.
///
/// Trust mode affects signature verification only; TLS host verification is
/// unaffected in every mode.
pub fn resolve_registry(
    override_url: Option<&str>,
    insecure_flag: bool,
    config: Option<&crate::config::user::UserConfig>,
) -> Result<ResolvedRegistry> {
    let url = override_url
        .map(ToOwned::to_owned)
        .or_else(|| std::env::var("NONO_REGISTRY").ok())
        .or_else(|| config.and_then(|c| c.registry.url.clone()))
        .unwrap_or_else(|| DEFAULT_REGISTRY_URL.to_string());

    let env_insecure = std::env::var("NONO_REGISTRY_INSECURE")
        .map(|v| !v.is_empty())
        .unwrap_or(false);
    let config_disables = config.map(|c| !c.registry.verify).unwrap_or(false);

    let inline = config.and_then(|c| c.registry.trusted_key.as_deref());
    let key_file = config.and_then(|c| c.registry.trusted_key_file.as_deref());

    if inline.is_some() || key_file.is_some() {
        // Keyed mode requested. Load and bind the trusted key.
        let (spki_der, fingerprint) = load_trusted_key(inline, key_file)?;

        // Fail-secure: a configured trusted key must not be silently overridden.
        if config_disables {
            return Err(NonoError::ConfigParse(
                "[registry] sets a trusted key together with verify = false: \
                 contradictory configuration. Remove one."
                    .to_string(),
            ));
        }
        if insecure_flag {
            eprintln!(
                "warning: --insecure overrides the configured [registry] trusted key; \
                 installing UNSIGNED (SHA-256 integrity only)"
            );
            return Ok(ResolvedRegistry {
                url,
                trust: TrustMode::Unsigned,
            });
        }
        if env_insecure {
            eprintln!(
                "warning: NONO_REGISTRY_INSECURE ignored because [registry] sets a trusted key; \
                 keeping keyed verification"
            );
        }
        return Ok(ResolvedRegistry {
            url,
            trust: TrustMode::Keyed {
                spki_der,
                fingerprint,
            },
        });
    }

    let trust = if insecure_flag || env_insecure || config_disables {
        TrustMode::Unsigned
    } else {
        TrustMode::Keyless
    };
    Ok(ResolvedRegistry { url, trust })
}

/// Load and fingerprint the configured keyed-signing trusted public key.
///
/// `inline` is base64 SPKI (DER); `key_file` is a path to a file holding either
/// the same base64 or a PEM public key. The two are mutually exclusive. Returns
/// the raw SPKI DER and its fingerprint (`public_key_id_hex`). SPKI validity is
/// checked at verification time (`verify_keyed_signature`).
fn load_trusted_key(inline: Option<&str>, key_file: Option<&str>) -> Result<(Vec<u8>, String)> {
    let der = match (inline, key_file) {
        (Some(_), Some(_)) => {
            return Err(NonoError::ConfigParse(
                "[registry] trusted_key and trusted_key_file are mutually exclusive".to_string(),
            ));
        }
        (Some(b64), None) => decode_spki_b64(b64)?,
        (None, Some(path)) => {
            let content = fs::read_to_string(path).map_err(|e| {
                NonoError::ConfigParse(format!(
                    "failed to read [registry].trusted_key_file '{path}': {e}"
                ))
            })?;
            decode_spki_maybe_pem(&content)?
        }
        (None, None) => unreachable!("load_trusted_key called without a key"),
    };
    if der.is_empty() {
        return Err(NonoError::ConfigParse(
            "[registry] trusted key decoded to empty bytes".to_string(),
        ));
    }
    let fingerprint = nono::trust::public_key_id_hex(&der);
    Ok((der, fingerprint))
}

/// Load the configured `[registry]` trusted key (if any) as `(SPKI DER,
/// fingerprint)`. Used at run time to resolve a keyed pack's verification key
/// offline. Returns `Ok(None)` when no trusted key is configured.
pub(crate) fn configured_trusted_key(
    config: Option<&crate::config::user::UserConfig>,
) -> Result<Option<(Vec<u8>, String)>> {
    let inline = config.and_then(|c| c.registry.trusted_key.as_deref());
    let key_file = config.and_then(|c| c.registry.trusted_key_file.as_deref());
    if inline.is_none() && key_file.is_none() {
        return Ok(None);
    }
    Ok(Some(load_trusted_key(inline, key_file)?))
}

fn decode_spki_b64(b64: &str) -> Result<Vec<u8>> {
    nono::trust::base64::base64_decode(b64.trim()).map_err(|e| {
        NonoError::ConfigParse(format!("invalid base64 in [registry] trusted key: {e}"))
    })
}

/// Decode a public key that may be raw base64 SPKI or PEM-armored.
pub(crate) fn decode_spki_maybe_pem(content: &str) -> Result<Vec<u8>> {
    if content.contains("-----BEGIN") {
        let body: String = content
            .lines()
            .filter(|line| !line.trim_start().starts_with("-----"))
            .collect::<Vec<_>>()
            .join("");
        decode_spki_b64(&body)
    } else {
        decode_spki_b64(content)
    }
}

fn map_ureq_error(error: ureq::Error) -> NonoError {
    NonoError::RegistryError(error.to_string())
}

fn enforce_content_length(content_length: Option<u64>, limit: u64, url: &str) -> Result<()> {
    if let Some(content_length) = content_length
        && content_length > limit
    {
        return Err(NonoError::RegistryError(format!(
            "registry response from {} exceeds {} bytes",
            url, limit
        )));
    }

    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn registry_client_normalizes_base_url() {
        // Trailing slash should be stripped. Construction is infallible because
        // TLS verification is delegated to the OS verifier at handshake time.
        let client = RegistryClient::new("https://example.invalid/".to_string());
        assert_eq!(client.base_url, "https://example.invalid");
    }

    fn config_with(url: Option<&str>, verify: bool) -> crate::config::user::UserConfig {
        let mut config = crate::config::user::UserConfig::default();
        config.registry.url = url.map(ToOwned::to_owned);
        config.registry.verify = verify;
        config
    }

    /// Generate a real ECDSA P-256 public key, returning its base64 SPKI and
    /// fingerprint so keyed-mode resolution can be exercised end to end.
    fn make_trusted_key() -> (String, String) {
        let key_pair = nono::trust::generate_signing_key().unwrap();
        let pub_key = nono::trust::export_public_key(&key_pair).unwrap();
        let der = pub_key.as_bytes();
        let b64 = nono::trust::base64::base64_encode(der);
        let fingerprint = nono::trust::public_key_id_hex(der);
        (b64, fingerprint)
    }

    #[test]
    fn resolve_registry_url_precedence() {
        let _lock = match crate::test_env::ENV_LOCK.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        let guard = crate::test_env::EnvVarGuard::set_all(&[
            ("NONO_REGISTRY", ""),
            ("NONO_REGISTRY_INSECURE", ""),
        ]);
        guard.remove("NONO_REGISTRY");
        guard.remove("NONO_REGISTRY_INSECURE");

        let config = config_with(Some("https://config.example"), true);

        // Flag beats env and config.
        let _env =
            crate::test_env::EnvVarGuard::set_all(&[("NONO_REGISTRY", "https://env.example")]);
        assert_eq!(
            resolve_registry(Some("https://flag.example"), false, Some(&config))
                .unwrap()
                .url,
            "https://flag.example"
        );
        // Env beats config.
        assert_eq!(
            resolve_registry(None, false, Some(&config)).unwrap().url,
            "https://env.example"
        );
        drop(_env);
        guard.remove("NONO_REGISTRY");
        // Config beats the compiled-in default.
        assert_eq!(
            resolve_registry(None, false, Some(&config)).unwrap().url,
            "https://config.example"
        );
        // Default when nothing is set.
        assert_eq!(
            resolve_registry(None, false, None).unwrap().url,
            DEFAULT_REGISTRY_URL
        );
    }

    #[test]
    fn resolve_registry_trust_is_fail_secure() {
        let _lock = match crate::test_env::ENV_LOCK.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        let guard = crate::test_env::EnvVarGuard::set_all(&[("NONO_REGISTRY_INSECURE", "")]);
        guard.remove("NONO_REGISTRY_INSECURE");

        // Defaults to keyless verification.
        assert_eq!(
            resolve_registry(None, false, None).unwrap().trust,
            TrustMode::Keyless
        );
        assert_eq!(
            resolve_registry(None, false, Some(&config_with(None, true)))
                .unwrap()
                .trust,
            TrustMode::Keyless
        );

        // Disabled by the flag.
        assert_eq!(
            resolve_registry(None, true, None).unwrap().trust,
            TrustMode::Unsigned
        );
        // Disabled by config.
        assert_eq!(
            resolve_registry(None, false, Some(&config_with(None, false)))
                .unwrap()
                .trust,
            TrustMode::Unsigned
        );
        // Disabled by env (any non-empty value).
        let _env = crate::test_env::EnvVarGuard::set_all(&[("NONO_REGISTRY_INSECURE", "1")]);
        assert_eq!(
            resolve_registry(None, false, None).unwrap().trust,
            TrustMode::Unsigned
        );
    }

    #[test]
    fn resolve_registry_keyed_from_inline_key() {
        let _lock = match crate::test_env::ENV_LOCK.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        let guard = crate::test_env::EnvVarGuard::set_all(&[("NONO_REGISTRY_INSECURE", "")]);
        guard.remove("NONO_REGISTRY_INSECURE");

        let (b64, fingerprint) = make_trusted_key();
        let mut config = config_with(None, true);
        config.registry.trusted_key = Some(b64);

        match resolve_registry(None, false, Some(&config)).unwrap().trust {
            TrustMode::Keyed {
                fingerprint: fp, ..
            } => assert_eq!(fp, fingerprint),
            other => panic!("expected keyed, got {other:?}"),
        }
    }

    #[test]
    fn resolve_registry_keyed_plus_verify_false_is_error() {
        let _lock = match crate::test_env::ENV_LOCK.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        let guard = crate::test_env::EnvVarGuard::set_all(&[("NONO_REGISTRY_INSECURE", "")]);
        guard.remove("NONO_REGISTRY_INSECURE");

        let (b64, _) = make_trusted_key();
        let mut config = config_with(None, false);
        config.registry.trusted_key = Some(b64);

        // Contradictory: a trusted key cannot coexist with verify = false.
        assert!(resolve_registry(None, false, Some(&config)).is_err());
    }

    #[test]
    fn resolve_registry_keyed_insecure_flag_downgrades_to_unsigned() {
        let _lock = match crate::test_env::ENV_LOCK.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        let guard = crate::test_env::EnvVarGuard::set_all(&[("NONO_REGISTRY_INSECURE", "")]);
        guard.remove("NONO_REGISTRY_INSECURE");

        let (b64, _) = make_trusted_key();
        let mut config = config_with(None, true);
        config.registry.trusted_key = Some(b64);

        // Explicit --insecure deliberately downgrades to unsigned.
        assert_eq!(
            resolve_registry(None, true, Some(&config)).unwrap().trust,
            TrustMode::Unsigned
        );
    }

    #[test]
    fn resolve_registry_keyed_ignores_env_insecure() {
        let _lock = match crate::test_env::ENV_LOCK.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        let guard = crate::test_env::EnvVarGuard::set_all(&[("NONO_REGISTRY_INSECURE", "")]);
        guard.remove("NONO_REGISTRY_INSECURE");

        let (b64, fingerprint) = make_trusted_key();
        let mut config = config_with(None, true);
        config.registry.trusted_key = Some(b64);

        // NONO_REGISTRY_INSECURE must not silently downgrade a keyed registry.
        let _env = crate::test_env::EnvVarGuard::set_all(&[("NONO_REGISTRY_INSECURE", "1")]);
        match resolve_registry(None, false, Some(&config)).unwrap().trust {
            TrustMode::Keyed {
                fingerprint: fp, ..
            } => assert_eq!(fp, fingerprint),
            other => panic!("expected keyed (env ignored), got {other:?}"),
        }
    }

    #[test]
    fn trusted_key_and_file_are_mutually_exclusive() {
        let (b64, _) = make_trusted_key();
        let mut config = crate::config::user::UserConfig::default();
        config.registry.trusted_key = Some(b64);
        config.registry.trusted_key_file = Some("/some/path.pem".to_string());
        assert!(resolve_registry(None, false, Some(&config)).is_err());
    }
}
