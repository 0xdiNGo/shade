//! Self-signed CA + node-certificate generation for the mesh.
//!
//! Two operator commands live here:
//!
//! * [`init_ca`] generates a fresh self-signed root CA — written to
//!   `botnet-ca.pem` + `botnet-ca.key` plus a JSON metadata sidecar.
//! * [`issue_cert`] reads that CA and signs a node cert keyed to a
//!   stable `node_id` — written to `node.pem` + `node.key`.
//!
//! Both write into `--out-dir`. File names are fixed so the
//! `deploy/shade.example.toml` defaults work without extra plumbing.
//!
//! Cryptographic choices:
//!
//! * **Ed25519** for both CA and node keys. Small, fast, no parameter
//!   confusion. rcgen uses `ring` under the hood.
//! * **5-year validity** on the CA, **2-year validity** on node certs.
//!   These are placeholders until M6 rollover tooling lands; rotation
//!   is going to be a documented operator runbook.
//! * **Subject CN = node_id, single SAN = node_id** on node certs. The
//!   handshake validates `PeerHello.node_id == cert SAN` to bind the
//!   transport identity to the application identity.

use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Context, Result};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, KeyIdMethod, KeyPair,
    KeyUsagePurpose, SanType,
};

const CA_CERT_FILE: &str = "botnet-ca.pem";
const CA_KEY_FILE: &str = "botnet-ca.key";
const CA_META_FILE: &str = "ca-meta.json";
const NODE_CERT_FILE: &str = "node.pem";
const NODE_KEY_FILE: &str = "node.key";

const CA_VALIDITY_DAYS: u64 = 365 * 5;
const NODE_VALIDITY_DAYS: u64 = 365 * 2;
const ADMIN_VALIDITY_DAYS: u64 = 365;

/// Generate a self-signed root CA and write it to `out_dir`.
///
/// Files written:
/// * `botnet-ca.pem` — PEM-encoded root cert (chmod 0644)
/// * `botnet-ca.key` — PEM-encoded private key (chmod 0600)
/// * `ca-meta.json` — JSON metadata (subject, generated_at, validity)
pub fn init_ca(out_dir: &Path) -> Result<()> {
    fs::create_dir_all(out_dir).with_context(|| format!("creating {}", out_dir.display()))?;

    let key_pair =
        KeyPair::generate_for(&rcgen::PKCS_ED25519).context("generating CA Ed25519 key pair")?;
    let mut params = CertificateParams::new(Vec::<String>::new()).context("init CA cert params")?;
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "Shade Botnet CA");
    dn.push(DnType::OrganizationName, "Shade");
    params.distinguished_name = dn;
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
    ];
    params.use_authority_key_identifier_extension = true;
    params.key_identifier_method = KeyIdMethod::Sha256;
    let now = std::time::SystemTime::now();
    params.not_before = (now - std::time::Duration::from_secs(60)).into();
    params.not_after = (now + std::time::Duration::from_secs(CA_VALIDITY_DAYS * 86_400)).into();

    let cert = params
        .self_signed(&key_pair)
        .context("self-signing the CA")?;

    write_secure(
        out_dir.join(CA_CERT_FILE).as_path(),
        cert.pem().as_bytes(),
        0o644,
    )?;
    write_secure(
        out_dir.join(CA_KEY_FILE).as_path(),
        key_pair.serialize_pem().as_bytes(),
        0o600,
    )?;

    let meta = serde_json::json!({
        "subject": "Shade Botnet CA",
        "generated_at_ms": now_ms(),
        "validity_days": CA_VALIDITY_DAYS,
        "algorithm": "Ed25519",
    });
    write_secure(
        out_dir.join(CA_META_FILE).as_path(),
        serde_json::to_string_pretty(&meta)
            .context("encoding ca-meta.json")?
            .as_bytes(),
        0o644,
    )?;

    println!(
        "wrote {}, {}, and {} to {}",
        CA_CERT_FILE,
        CA_KEY_FILE,
        CA_META_FILE,
        out_dir.display()
    );
    Ok(())
}

/// Issue a node certificate signed by the CA at `ca_dir`.
///
/// Subject CN = `node_id`; single SAN entry = `node_id` (so the mesh
/// handshake's "cert SAN must equal claimed node_id" check passes).
pub fn issue_cert(node_id: &str, ca_dir: &Path, out_dir: &Path) -> Result<()> {
    if node_id.trim().is_empty() {
        return Err(anyhow!("--node-id must not be empty"));
    }
    fs::create_dir_all(out_dir).with_context(|| format!("creating {}", out_dir.display()))?;

    let ca_pem = fs::read_to_string(ca_dir.join(CA_CERT_FILE))
        .with_context(|| format!("reading {}", ca_dir.join(CA_CERT_FILE).display()))?;
    let ca_key_pem = fs::read_to_string(ca_dir.join(CA_KEY_FILE))
        .with_context(|| format!("reading {}", ca_dir.join(CA_KEY_FILE).display()))?;

    let ca_kp = KeyPair::from_pem(&ca_key_pem).context("parsing CA private key")?;
    let ca_params = CertificateParams::from_ca_cert_pem(&ca_pem)
        .context("parsing CA certificate (enable rcgen 'x509-parser' feature)")?;
    let ca_cert = ca_params
        .self_signed(&ca_kp)
        .context("re-binding CA cert to its key pair")?;

    let node_kp =
        KeyPair::generate_for(&rcgen::PKCS_ED25519).context("generating node Ed25519 key pair")?;
    let mut node_params =
        CertificateParams::new(vec![node_id.to_owned()]).context("init node cert params")?;
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, node_id);
    dn.push(DnType::OrganizationName, "Shade");
    node_params.distinguished_name = dn;
    node_params.subject_alt_names = vec![SanType::DnsName(
        node_id
            .to_owned()
            .try_into()
            .with_context(|| format!("node_id `{node_id}` is not a valid DNS-name SAN"))?,
    )];
    node_params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyEncipherment,
    ];
    node_params.extended_key_usages = vec![
        rcgen::ExtendedKeyUsagePurpose::ServerAuth,
        rcgen::ExtendedKeyUsagePurpose::ClientAuth,
    ];
    node_params.use_authority_key_identifier_extension = true;
    node_params.key_identifier_method = KeyIdMethod::Sha256;
    let now = std::time::SystemTime::now();
    node_params.not_before = (now - std::time::Duration::from_secs(60)).into();
    node_params.not_after =
        (now + std::time::Duration::from_secs(NODE_VALIDITY_DAYS * 86_400)).into();

    let signed = node_params
        .signed_by(&node_kp, &ca_cert, &ca_kp)
        .context("signing node cert with CA")?;

    write_secure(
        out_dir.join(NODE_CERT_FILE).as_path(),
        signed.pem().as_bytes(),
        0o644,
    )?;
    write_secure(
        out_dir.join(NODE_KEY_FILE).as_path(),
        node_kp.serialize_pem().as_bytes(),
        0o600,
    )?;

    println!(
        "wrote {} and {} (CN={node_id}) to {}",
        NODE_CERT_FILE,
        NODE_KEY_FILE,
        out_dir.display()
    );
    Ok(())
}

/// Issue an **admin client** certificate signed by the CA at `ca_dir`.
///
/// Subject CN = `handle`; **no SAN**. EKU = clientAuth only — these
/// certs are presented by operators (or `shadectl`) to authenticate to
/// the admin listener and must never be honored as a server identity.
///
/// The handle becomes the audit `actor` for every request from this
/// cert holder. It must match an existing `User.handle` (case-
/// insensitive); operators bootstrap the user record via `shadectl users
/// upsert` before issuing the cert.
///
/// Files written to `out_dir`:
/// * `<handle>.pem` — PEM-encoded client cert (chmod 0644)
/// * `<handle>.key` — PEM-encoded private key (chmod 0600)
pub fn issue_admin_cert(handle: &str, ca_dir: &Path, out_dir: &Path) -> Result<()> {
    let trimmed = handle.trim();
    if trimmed.is_empty() {
        return Err(anyhow!("--handle must not be empty"));
    }
    if trimmed.contains('/') || trimmed.contains('\0') {
        return Err(anyhow!(
            "--handle `{trimmed}` contains characters not allowed in a filename"
        ));
    }
    fs::create_dir_all(out_dir).with_context(|| format!("creating {}", out_dir.display()))?;

    let ca_pem = fs::read_to_string(ca_dir.join(CA_CERT_FILE))
        .with_context(|| format!("reading {}", ca_dir.join(CA_CERT_FILE).display()))?;
    let ca_key_pem = fs::read_to_string(ca_dir.join(CA_KEY_FILE))
        .with_context(|| format!("reading {}", ca_dir.join(CA_KEY_FILE).display()))?;

    let ca_kp = KeyPair::from_pem(&ca_key_pem).context("parsing CA private key")?;
    let ca_params = CertificateParams::from_ca_cert_pem(&ca_pem)
        .context("parsing CA certificate (enable rcgen 'x509-parser' feature)")?;
    let ca_cert = ca_params
        .self_signed(&ca_kp)
        .context("re-binding CA cert to its key pair")?;

    let kp =
        KeyPair::generate_for(&rcgen::PKCS_ED25519).context("generating admin Ed25519 key pair")?;
    let mut params =
        CertificateParams::new(Vec::<String>::new()).context("init admin client cert params")?;
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, trimmed);
    dn.push(DnType::OrganizationName, "Shade Admin");
    params.distinguished_name = dn;
    // Deliberately no SAN — admin certs are not server identities.
    params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyEncipherment,
    ];
    params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth];
    params.use_authority_key_identifier_extension = true;
    params.key_identifier_method = KeyIdMethod::Sha256;
    let now = std::time::SystemTime::now();
    params.not_before = (now - std::time::Duration::from_secs(60)).into();
    params.not_after = (now + std::time::Duration::from_secs(ADMIN_VALIDITY_DAYS * 86_400)).into();

    let signed = params
        .signed_by(&kp, &ca_cert, &ca_kp)
        .context("signing admin client cert with CA")?;

    let cert_path = out_dir.join(format!("{trimmed}.pem"));
    let key_path = out_dir.join(format!("{trimmed}.key"));
    write_secure(&cert_path, signed.pem().as_bytes(), 0o644)?;
    write_secure(&key_path, kp.serialize_pem().as_bytes(), 0o600)?;

    println!(
        "wrote {} and {} (CN={trimmed}, EKU=clientAuth, no SAN) to {}",
        cert_path.file_name().unwrap_or_default().to_string_lossy(),
        key_path.file_name().unwrap_or_default().to_string_lossy(),
        out_dir.display()
    );
    Ok(())
}

#[allow(unused_variables)] // mode is consumed only on Unix.
fn write_secure(path: &Path, contents: &[u8], mode: u32) -> Result<()> {
    fs::write(path, contents).with_context(|| format!("writing {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = fs::Permissions::from_mode(mode);
        fs::set_permissions(path, perms)
            .with_context(|| format!("chmod {} {:o}", path.display(), mode))?;
    }
    Ok(())
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn init_ca_writes_three_files_with_expected_perms() {
        let tmp = tempfile::tempdir().unwrap();
        init_ca(tmp.path()).unwrap();

        for f in [CA_CERT_FILE, CA_KEY_FILE, CA_META_FILE] {
            let p = tmp.path().join(f);
            assert!(p.exists(), "{f} should exist");
        }

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let key_mode = fs::metadata(tmp.path().join(CA_KEY_FILE))
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(key_mode, 0o600, "CA private key must be 0600");
        }

        let pem = fs::read_to_string(tmp.path().join(CA_CERT_FILE)).unwrap();
        assert!(pem.contains("BEGIN CERTIFICATE"));
        let key = fs::read_to_string(tmp.path().join(CA_KEY_FILE)).unwrap();
        assert!(key.contains("BEGIN PRIVATE KEY"));
    }

    #[test]
    fn issue_cert_signed_by_init_ca_validates() {
        let ca_dir = tempfile::tempdir().unwrap();
        init_ca(ca_dir.path()).unwrap();

        let out = tempfile::tempdir().unwrap();
        issue_cert("shade-iad-01", ca_dir.path(), out.path()).unwrap();

        let cert_pem = fs::read_to_string(out.path().join(NODE_CERT_FILE)).unwrap();
        assert!(cert_pem.contains("BEGIN CERTIFICATE"));

        let cert_der = pem::parse(cert_pem.as_bytes()).unwrap();
        let (_, parsed) = x509_parser::parse_x509_certificate(cert_der.contents()).unwrap();
        let cn = parsed
            .subject()
            .iter_common_name()
            .next()
            .unwrap()
            .as_str()
            .unwrap();
        assert_eq!(cn, "shade-iad-01");
        // SAN entry should match node_id.
        let san = parsed.subject_alternative_name().unwrap().unwrap();
        let dns_names: Vec<&str> = san
            .value
            .general_names
            .iter()
            .filter_map(|n| match n {
                x509_parser::extensions::GeneralName::DNSName(s) => Some(*s),
                _ => None,
            })
            .collect();
        assert_eq!(dns_names, vec!["shade-iad-01"]);
    }

    #[test]
    fn issue_cert_with_empty_node_id_errors() {
        let ca_dir = tempfile::tempdir().unwrap();
        init_ca(ca_dir.path()).unwrap();
        let out = tempfile::tempdir().unwrap();
        let err = issue_cert("", ca_dir.path(), out.path()).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("node-id"), "got: {msg}");
    }
}
