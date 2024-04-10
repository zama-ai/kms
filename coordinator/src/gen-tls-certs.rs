use anyhow::anyhow;
use clap::Parser;
use kms_lib::file_handling::write_bytes;
use rcgen::{
    BasicConstraints::Constrained, Certificate, CertificateParams, DistinguishedName, DnType,
    ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose, PKCS_ECDSA_P256_SHA256,
};
use std::collections::HashMap;

#[derive(Parser, Debug)]
#[clap(name = "KMS TLS Certificate Generator")]
#[clap(about = "A CLI tool for generating TLS certificates for the KMS coordinator and cores")]
pub struct Cli {
    #[clap(short, long)]
    coordinator_name: String,

    // TODO: this should be a PathBuf once the file handling works on paths instead of strings
    #[clap(short, long, default_value = "tls/")]
    dir: String,

    #[clap(short, long, default_value = "1")]
    num_cores: usize,
}

/// Validates if a user-specified coordinator name is valid.
/// By valid we mean if it is alphanumeric plus '-' and '.'.
/// This should be changed to check coordinator names, that we actually want to allow.
fn validate_coordinator_name(input: &str) -> bool {
    for cur_char in input.chars() {
        if !cur_char.is_ascii_alphanumeric() && cur_char != '-' && cur_char != '.' {
            return false;
        }
    }
    true
}

/// create the keypair and self-signed certificate for the coordinator identified by the given name
fn create_coordinator_cert(coordinator_name: &str) -> anyhow::Result<(KeyPair, Certificate)> {
    if !validate_coordinator_name(coordinator_name) {
        return Err(anyhow!(
            "Error: invalid coordinator name: {}",
            coordinator_name
        ));
    }
    let keypair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
    let mut cp = CertificateParams::new(vec![coordinator_name.to_string()])?;

    // set distinguished name of coordinator cert
    let mut distinguished_name = DistinguishedName::new();
    distinguished_name.push(DnType::CommonName, coordinator_name);
    cp.distinguished_name = distinguished_name;

    // set coordinator cert CA flag to true (only allow to sign core certs directly, without intermediate CAs)
    cp.is_ca = IsCa::Ca(Constrained(1));

    // set coordinator cert Key Usage Purposes
    cp.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::KeyEncipherment,
        KeyUsagePurpose::KeyAgreement,
    ];

    // set coordinator cert Extended Key Usage Purposes
    cp.extended_key_usages = vec![
        ExtendedKeyUsagePurpose::ServerAuth,
        ExtendedKeyUsagePurpose::ClientAuth,
    ];

    // self-sign cert with coordinator key
    let cert = cp.self_signed(&keypair)?;
    Ok((keypair, cert))
}

/// create a keypair and certificate for each of the `num_cores`, signed by the given coordinator
fn create_core_certs(
    coordinator_name: &str,
    num_cores: usize,
    coordinator_keypair: &KeyPair,
    coordinator_cert: &Certificate,
) -> anyhow::Result<HashMap<usize, (KeyPair, Certificate)>> {
    let core_cert_bundle: HashMap<usize, (KeyPair, Certificate)> = (0..num_cores)
        .map(|i: usize| {
            let core_name = format!("core-{}.{}", i, coordinator_name);
            let core_keypair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
            let mut cp = CertificateParams::new(vec![core_name.clone()]).unwrap();

            // set distinguished name of core cert
            let mut distinguished_name = DistinguishedName::new();
            distinguished_name.push(DnType::CommonName, core_name);
            cp.distinguished_name = distinguished_name;

            // set core cert Key Usage Purposes
            cp.key_usages = vec![
                KeyUsagePurpose::DigitalSignature,
                KeyUsagePurpose::KeyEncipherment,
                KeyUsagePurpose::KeyAgreement,
            ];

            // set core cert Extended Key Usage Purposes
            cp.extended_key_usages = vec![
                ExtendedKeyUsagePurpose::ServerAuth,
                ExtendedKeyUsagePurpose::ClientAuth,
            ];

            let core_cert = cp
                .signed_by(&core_keypair, coordinator_cert, coordinator_keypair)
                .unwrap();
            (i, (core_keypair, core_cert))
        })
        .collect();

    Ok(core_cert_bundle)
}

/// write the given certificate and keypair to the given path under the given name
fn write_certs_and_keys(
    path: &str,
    name: &str,
    cert: &Certificate,
    keypair: &KeyPair,
) -> anyhow::Result<()> {
    tracing::info!(
        "Generating keys and cert for {:?}",
        cert.params().subject_alt_names[0]
    );
    tracing::info!("{}", cert.pem());
    tracing::info!("{}", keypair.serialize_pem());

    // ensure that path ends with a '/' to avoid problems with file handling in the rest of this fn
    let mut path_string = path.to_string();
    if !path_string.ends_with('/') {
        path_string.push('/');
    }

    // write cert and key as both DER (binary) and PEM (text) file
    write_bytes(format!("{path_string}cert_{name}.der"), cert.der())?;
    write_bytes(format!("{path_string}cert_{name}.pem"), cert.pem())?;

    write_bytes(
        format!("{path_string}keys_{name}.der"),
        keypair.serialized_der(),
    )?;
    write_bytes(
        format!("{path_string}keys_{name}.pem"),
        keypair.serialize_pem(),
    )?;

    Ok(())
}

fn main() -> anyhow::Result<()> {
    // initialize tracing subscriber, so we get tracing logs to stdout
    tracing_subscriber::fmt::init();

    let args = Cli::parse();
    let coordinator_name = args.coordinator_name.as_str();
    let (coordinator_keypair, coordinator_cert) = create_coordinator_cert(coordinator_name)?;

    write_certs_and_keys(
        args.dir.as_str(),
        coordinator_name,
        &coordinator_cert,
        &coordinator_keypair,
    )?;

    let core_certs = create_core_certs(
        coordinator_name,
        args.num_cores,
        &coordinator_keypair,
        &coordinator_cert,
    )?;

    // write all core keypairs and certificates to disk
    for (core_id, (core_keypair, core_cert)) in core_certs.iter() {
        write_certs_and_keys(
            args.dir.as_str(),
            format!("{}-core-{}", coordinator_name, core_id).as_str(),
            core_cert,
            core_keypair,
        )?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::{create_coordinator_cert, create_core_certs, validate_coordinator_name};
    use rcgen::Certificate;
    use webpki::{EndEntityCert, ErrorExt, TlsClientTrustAnchors, TrustAnchor};

    fn inner_verify(
        core_cert: &Certificate,
        coordinator_cert: &Certificate,
    ) -> Result<(), ErrorExt> {
        let ee = EndEntityCert::try_from(core_cert.der().as_ref()).unwrap();
        let ta = [TrustAnchor::try_from_cert_der(coordinator_cert.der().as_ref()).unwrap()];
        let tcta = TlsClientTrustAnchors(&ta);
        let wt = webpki::Time::try_from(std::time::SystemTime::now()).unwrap();

        ee.verify_is_valid_tls_client_cert_ext(&[&webpki::ECDSA_P256_SHA256], &tcta, &[], wt)
    }

    #[test]
    fn test_cert_chain() {
        let coordinator_name = "coordinator.kms.zama.ai";
        let (coordinator_keypair, coordinator_cert) =
            create_coordinator_cert(coordinator_name).unwrap();

        let core_certs =
            create_core_certs(coordinator_name, 2, &coordinator_keypair, &coordinator_cert)
                .unwrap();

        // check that we can import the coordinator cert into the trust store
        let mut root_store = rustls::RootCertStore::empty();
        let cc = (*coordinator_cert.der()).clone();
        root_store.add(cc).unwrap();

        // create another coordinator cert, that did not sign the core certs for negative testing
        let (_coordinator_keypair_wrong, coordinator_cert_wrong) =
            create_coordinator_cert(coordinator_name).unwrap();

        // check all core certs
        for c in core_certs {
            let verif = inner_verify(&c.1 .1, &coordinator_cert);
            // check that verification works for each core cert
            assert!(verif.is_ok(), "certificate validation failed!");

            // check that verification does not work for wrong coordinator cert
            let verif = inner_verify(&c.1 .1, &coordinator_cert_wrong);
            assert!(
                verif.is_err(),
                "certificate validation succeeded, but was expected to fail!"
            );
        }
    }

    #[test]
    fn test_coordinator_name_validation() {
        assert!(
            validate_coordinator_name("coordinator"),
            "this should have been a valid coordinator name."
        );
        assert!(
            !validate_coordinator_name("coordinator/is#bad!"),
            "this should have been an invalid coordinator name."
        );
    }
}
