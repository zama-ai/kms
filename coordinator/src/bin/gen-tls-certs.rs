use anyhow::anyhow;
use clap::Parser;
use kms_lib::util::file_handling::write_bytes;
use rcgen::BasicConstraints::Constrained;
use rcgen::{
    Certificate, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose, PKCS_ECDSA_P256_SHA256,
};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;

#[derive(clap::ValueEnum, Debug, Clone, Copy)]
enum CertFileType {
    Der,
    Pem,
}

#[derive(Debug, clap::Args)]
#[group(required = true, multiple = false)]
struct Group {
    #[clap(short, long, value_parser, num_args = 1.., value_delimiter = ' ', help = "cannot be used with coordinator_prefix")]
    coordinator_names: Vec<String>,

    #[clap(
        long,
        default_value = "coordinator",
        help = "cannot be used with coordinator_names"
    )]
    coordinator_prefix: String,
}

#[derive(Parser, Debug)]
#[clap(name = "KMS TLS Certificate Generator")]
#[clap(
    about = "A CLI tool for generating TLS certificates for the KMS coordinator and cores. \
The user need to provide a set of coordinator names using either the \
--coordinator_names option, or the --coordinator_prefix and the \
--coordinator_count options. The tool also allows the user to set \
the number of cores, output directory and file format. Example usage:
kms-gen-tls-certs --help # for all available options
kms-gen-tls-certs --coordinator-prefix c --coordinator-count 4 -n 1 -o certs
kms-gen-tls-certs --coordinator-names alice bob charlie dave -n 1 -o certs 

Under the hood, the tool generates self-signed CA certificates for \
each coordinator and <num_cores> core certificates for each \
coordinator. The core certificates are signed by its corresponding coordinator.\
The private key associated to each certificate can also be found in the output.\
Finally, the combined coordinator certificate (cert_combined.{pem,der}) \
is also a part of the output."
)]
pub struct Cli {
    // this group is needed to ensure the user only suplies the exact names or a prefix
    #[clap(flatten)]
    group: Group,

    #[clap(
        long,
        default_value_t = 0,
        help = "only valid when coordinator_prefix is set"
    )]
    coordinator_count: u8,

    #[clap(
        short,
        long,
        default_value = "certs/",
        help = "the output directory for certificates and keys"
    )]
    output_dir: PathBuf,

    #[clap(
        short,
        long,
        default_value = "1",
        help = "the number of cores certificates to generate for each coordinator"
    )]
    num_cores: usize,

    #[clap(long, value_enum, default_value_t = CertFileType::Pem, help = "the output file type, select between pem and der")]
    output_file_type: CertFileType,
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
    let mut cp = CertificateParams::new(vec![
        coordinator_name.to_string(),
        "localhost".to_string(),
        "192.168.0.1".to_string(),
        "127.0.0.1".to_string(),
        "0:0:0:0:0:0:0:1".to_string(),
    ])?;

    // set distinguished name of coordinator cert
    let mut distinguished_name = DistinguishedName::new();
    distinguished_name.push(DnType::CommonName, coordinator_name);
    cp.distinguished_name = distinguished_name;

    // set coordinator cert CA flag to true (only allow to sign core certs directly, without
    // intermediate CAs)
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
    let core_cert_bundle: HashMap<usize, (KeyPair, Certificate)> = (1..=num_cores)
        .map(|i: usize| {
            let core_name = format!("core{}.{}", i, coordinator_name);
            let core_keypair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
            let mut cp = CertificateParams::new(vec![
                core_name.clone(),
                "localhost".to_string(),
                "192.168.0.1".to_string(),
                "127.0.0.1".to_string(),
                "0:0:0:0:0:0:0:1".to_string(),
            ])
            .unwrap();

            // set core cert CA flag to false
            cp.is_ca = IsCa::ExplicitNoCa;

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
    root_dir: &std::path::Path,
    name: &str,
    cert: &Certificate,
    keypair: &KeyPair,
    file_type: CertFileType,
) -> anyhow::Result<()> {
    tracing::info!(
        "Generating keys and cert for {:?}",
        cert.params().subject_alt_names[0]
    );
    tracing::info!("{}", cert.pem());
    tracing::info!("{}", keypair.serialize_pem());

    match file_type {
        CertFileType::Der => {
            let cert_dir = root_dir.join(format!("cert_{name}.der"));
            write_bytes(&cert_dir, cert.der())?;

            let key_dir = root_dir.join(format!("key_{name}.der"));
            write_bytes(&key_dir, keypair.serialized_der())?;
        }
        CertFileType::Pem => {
            let cert_dir = root_dir.join(format!("cert_{name}.pem"));
            write_bytes(&cert_dir, cert.pem())?;

            let key_dir = root_dir.join(format!("key_{name}.pem"));
            write_bytes(&key_dir, keypair.serialize_pem())?;
        }
    };
    Ok(())
}

fn main() -> anyhow::Result<()> {
    // initialize tracing subscriber, so we get tracing logs to stdout
    tracing_subscriber::fmt::init();

    let args = Cli::parse();

    let coordinator_set: HashSet<String> = if args.group.coordinator_names.is_empty() {
        HashSet::from_iter(
            (1..=args.coordinator_count).map(|i| format!("{}{i}", args.group.coordinator_prefix)),
        )
    } else {
        HashSet::from_iter(args.group.coordinator_names.iter().cloned())
    };

    let mut all_certs = vec![];
    for coordinator_name in coordinator_set {
        let (coordinator_keypair, coordinator_cert) = create_coordinator_cert(&coordinator_name)?;

        write_certs_and_keys(
            &args.output_dir,
            &coordinator_name,
            &coordinator_cert,
            &coordinator_keypair,
            args.output_file_type,
        )?;

        let core_certs = create_core_certs(
            &coordinator_name,
            args.num_cores,
            &coordinator_keypair,
            &coordinator_cert,
        )?;

        // write all core keypairs and certificates to disk
        for (core_id, (core_keypair, core_cert)) in core_certs.iter() {
            write_certs_and_keys(
                &args.output_dir,
                format!("{}-core{}", coordinator_name, core_id).as_str(),
                core_cert,
                core_keypair,
                args.output_file_type,
            )?;
        }

        all_certs.push(coordinator_cert);
    }

    // write the combined coordinator certificate
    match args.output_file_type {
        CertFileType::Der => {
            let cert_dir = args.output_dir.join("cert_combined.der");
            let buf: Vec<u8> = all_certs
                .into_iter()
                .flat_map(|cert| cert.der().to_vec())
                .collect();
            write_bytes(&cert_dir, buf)?;
        }
        CertFileType::Pem => {
            let cert_dir = args.output_dir.join("cert_combined.pem");
            let buf: Vec<u8> = all_certs
                .into_iter()
                .flat_map(|cert| cert.pem().as_bytes().to_vec())
                .collect();
            write_bytes(&cert_dir, buf)?;
        }
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
