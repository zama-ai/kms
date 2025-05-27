use anyhow::anyhow;
use clap::Parser;
use rcgen::BasicConstraints::Constrained;
use rcgen::{
    Certificate, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose, PKCS_ECDSA_P256_SHA256,
};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

#[derive(clap::ValueEnum, Debug, Clone, Copy)]
enum CertFileType {
    Der,
    Pem,
}

#[derive(Debug, clap::Args)]
#[group(required = true, multiple = false)]
struct Group {
    #[clap(short, long, value_parser, num_args = 1.., value_delimiter = ' ', help = "cannot be used with ca_prefix")]
    ca_names: Vec<String>,

    #[clap(long, default_value = "party", help = "cannot be used with ca_names")]
    ca_prefix: String,
}

#[derive(Parser, Debug)]
#[clap(name = "TLS Certificate Generator for MPC nodes")]
#[clap(
    about = "A CLI tool for generating separate TLS certificates for MPC nodes (cores). \
The user needs to provide a set of CA names using either the \
--ca_names option, or the --ca-prefix and the \
--ca-count options. The tool also allows the user to set \
the number of cores, output directory and file format. Example usage:\n
./kms-gen-tls-certs --help # for all available options \n
./kms-gen-tls-certs --ca-prefix c --ca-count 4 -n 1 -o certs \n
./kms-gen-tls-certs --ca-names alice bob charlie dave -n 1 -o certs \n

Under the hood, the tool generates self-signed CA certificates for \
each CA and <num_cores> core certificates for each core.\
The core certificates are signed by its corresponding CA. \
The private key associated to each certificate can also be found in the output. \
Finally, the combined CA certificate (cert_combined.{pem,der}) \
is also a part of the output. \n
Currently, the default is to use only a single CA certificate per logical party \
and no separate core certificates."
)]
pub struct Cli {
    // this group is needed to ensure the user only supplies the exact names or a prefix
    #[clap(flatten)]
    group: Group,

    #[clap(long, default_value_t = 0, help = "only valid when ca-prefix is set")]
    ca_count: u8,

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
        default_value = "0",
        help = "the number of core certificates to generate for each CA. Can be set to 0 to only generate the CA certificates."
    )]
    num_cores: usize,

    #[clap(long, value_enum, default_value_t = CertFileType::Pem, help = "the output file type, select between pem and der")]
    output_file_type: CertFileType,
}

/// Validates if a user-specified CA name is valid.
/// By valid we mean if it is alphanumeric plus '-' and '.'.
/// This should be changed to check CA names, that we actually want to allow.
fn validate_ca_name(input: &str) -> anyhow::Result<()> {
    for cur_char in input.chars() {
        if !cur_char.is_ascii_alphanumeric() && cur_char != '-' && cur_char != '.' {
            return Err(anyhow!("Error: invalid CA name: {}", input));
        }
    }
    Ok(())
}

/// Write bytes to a filepath.
/// The function will create the necessary directories in the path in order to write the [bytes].
/// If the file already exists then it will be COMPLETELY OVERWRITTEN without warning.
async fn write_bytes<S: AsRef<std::ffi::OsStr> + ?Sized, B: AsRef<[u8]>>(
    file_path: &S,
    bytes: B,
) -> anyhow::Result<()> {
    let path = Path::new(file_path);
    // Create the parent directories of the file path if they don't exist
    if let Some(p) = path.parent() {
        tokio::fs::create_dir_all(p).await?
    };
    tokio::fs::write(path, bytes).await?;
    Ok(())
}

/// create the keypair and self-signed certificate for the CA identified by the given name
fn create_ca_cert(
    ca_name: &str,
    is_ca: &IsCa,
) -> anyhow::Result<(KeyPair, Certificate, CertificateParams)> {
    validate_ca_name(ca_name)?;
    let keypair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
    let mut cp = CertificateParams::new(vec![
        ca_name.to_string(),
        "127.0.0.1".to_string(),
        "localhost".to_string(),
        "192.168.0.1".to_string(),
        "0:0:0:0:0:0:0:1".to_string(),
        "::1".to_string(),
    ])?;

    // set distinguished name of CA cert
    let mut distinguished_name = DistinguishedName::new();
    distinguished_name.push(DnType::CommonName, ca_name); // this might be the one for docker deployment
                                                          // distinguished_name.push(DnType::CommonName, "127.0.0.1".to_string()); // this seems to be needed for local deployment
    cp.distinguished_name = distinguished_name;

    // set CA cert CA flag
    cp.is_ca = *is_ca;

    // set CA cert Key Usage Purposes
    cp.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::KeyEncipherment,
        KeyUsagePurpose::KeyAgreement,
    ];

    // set CA cert Extended Key Usage Purposes
    cp.extended_key_usages = vec![
        ExtendedKeyUsagePurpose::ServerAuth,
        ExtendedKeyUsagePurpose::ClientAuth,
    ];

    // self-sign cert with CA key
    tracing::info!("Generating keys and cert for {:?}", cp.subject_alt_names[0]);
    let cert = cp.self_signed(&keypair)?;
    Ok((keypair, cert, cp))
}

/// create a keypair and certificate for each of the `num_cores`, signed by the given CA
fn create_core_certs(
    ca_name: &str,
    num_cores: usize,
    ca_keypair: &KeyPair,
    ca_cert_params: &CertificateParams,
) -> anyhow::Result<HashMap<usize, (KeyPair, Certificate)>> {
    let core_cert_bundle: HashMap<usize, (KeyPair, Certificate)> = (1..=num_cores)
        .map(|i: usize| {
            let core_name = format!("core{}.{}", i, ca_name);
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

            tracing::info!("Generating keys and cert for {:?}", cp.subject_alt_names[0]);
            let core_cert = cp
                .signed_by(&core_keypair, ca_cert_params, ca_keypair)
                .unwrap();
            (i, (core_keypair, core_cert))
        })
        .collect();

    Ok(core_cert_bundle)
}

/// write the given certificate and keypair to the given path under the given name
async fn write_certs_and_keys(
    root_dir: &std::path::Path,
    name: &str,
    cert: &Certificate,
    keypair: &KeyPair,
    file_type: CertFileType,
) -> anyhow::Result<()> {
    tracing::info!("{}", cert.pem());
    tracing::info!("{}", keypair.serialize_pem());

    match file_type {
        CertFileType::Der => {
            let cert_dir = root_dir.join(format!("cert_{name}.der"));
            write_bytes(&cert_dir, cert.der()).await?;

            let key_dir = root_dir.join(format!("key_{name}.der"));
            write_bytes(&key_dir, keypair.serialized_der()).await?;
        }
        CertFileType::Pem => {
            let cert_dir = root_dir.join(format!("cert_{name}.pem"));
            write_bytes(&cert_dir, cert.pem()).await?;

            let key_dir = root_dir.join(format!("key_{name}.pem"));
            write_bytes(&key_dir, keypair.serialize_pem()).await?;
        }
    };
    Ok(())
}

/// Execute TLS certificate generation.
pub async fn entry_point() -> anyhow::Result<()> {
    let args = Cli::parse();

    let ca_set: HashSet<String> = if args.group.ca_names.is_empty() {
        HashSet::from_iter((1..=args.ca_count).map(|i| format!("{}{i}", args.group.ca_prefix)))
    } else {
        HashSet::from_iter(args.group.ca_names.iter().cloned())
    };

    // As default, we only use self-signed player certificates, so we must not set the CA flag.
    // This is due to `webpki` that only exposes an `EndEntityCert` for verification, which cannot be a CA.
    // This limitation can be worked around by using some other method for verifying a certs validity.
    let mut is_ca = IsCa::NoCa;

    // if we want to generate core certs, we need to set the CA flag to true
    // we only allow to sign core certs directly, without intermediate CAs
    if args.num_cores > 0 {
        is_ca = IsCa::Ca(Constrained(1));
    }

    let mut all_certs = vec![];
    for ca_name in ca_set {
        let (ca_keypair, ca_cert, ca_cert_params) = create_ca_cert(&ca_name, &is_ca)?;

        write_certs_and_keys(
            &args.output_dir,
            &ca_name,
            &ca_cert,
            &ca_keypair,
            args.output_file_type,
        )
        .await?;

        // only generate core certs, if specifically desired (currently not the default)
        if args.num_cores > 0 {
            let core_certs =
                create_core_certs(&ca_name, args.num_cores, &ca_keypair, &ca_cert_params)?;

            // write all core keypairs and certificates to disk
            for (core_id, (core_keypair, core_cert)) in core_certs.iter() {
                write_certs_and_keys(
                    &args.output_dir,
                    format!("{}-core{}", ca_name, core_id).as_str(),
                    core_cert,
                    core_keypair,
                    args.output_file_type,
                )
                .await?;
            }
        }

        all_certs.push(ca_cert);
    }

    // write the combined CA certificate
    match args.output_file_type {
        CertFileType::Der => {
            let cert_dir = args.output_dir.join("cert_combined.der");
            let buf: Vec<u8> = all_certs
                .into_iter()
                .flat_map(|cert| cert.der().to_vec())
                .collect();
            write_bytes(&cert_dir, buf).await?;
        }
        CertFileType::Pem => {
            let cert_dir = args.output_dir.join("cert_combined.pem");
            let buf: Vec<u8> = all_certs
                .into_iter()
                .flat_map(|cert| cert.pem().as_bytes().to_vec())
                .collect();
            write_bytes(&cert_dir, buf).await?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{create_ca_cert, create_core_certs, validate_ca_name};
    use rcgen::{BasicConstraints::Constrained, Certificate, IsCa};
    use webpki::{EndEntityCert, ErrorExt, TlsClientTrustAnchors, TrustAnchor};

    fn signed_verify(leaf_cert: &Certificate, ca_cert: &Certificate) -> Result<(), ErrorExt> {
        let ee = EndEntityCert::try_from(leaf_cert.der().as_ref()).unwrap();
        let ta = [TrustAnchor::try_from_cert_der(ca_cert.der().as_ref()).unwrap()];
        let tcta = TlsClientTrustAnchors(&ta);
        let wt = webpki::Time::try_from(std::time::SystemTime::now()).unwrap();

        ee.verify_is_valid_tls_client_cert_ext(&[&webpki::ECDSA_P256_SHA256], &tcta, &[], wt)
    }

    #[test]
    fn test_cert_chain() {
        let ca_name = "party.kms.zama.ai";
        let is_ca = IsCa::Ca(Constrained(1));
        let (ca_keypair, ca_cert, ca_cert_params) = create_ca_cert(ca_name, &is_ca).unwrap();

        let core_certs = create_core_certs(ca_name, 2, &ca_keypair, &ca_cert_params).unwrap();

        // check that we can import the CA cert into the trust store
        let mut root_store = tokio_rustls::rustls::RootCertStore::empty();
        let cc = (*ca_cert.der()).clone();
        root_store.add(cc).unwrap();

        // create another CA cert, that did not sign the core certs for negative testing
        let (_ca_keypair_wrong, ca_cert_wrong, _ca_cert_params_wrong) =
            create_ca_cert(ca_name, &is_ca).unwrap();

        // check all core certs
        for c in core_certs {
            let verif = signed_verify(&c.1 .1, &ca_cert);
            // check that verification works for each core cert
            assert!(verif.is_ok(), "certificate validation failed!");

            // check that verification does not work for wrong CA cert
            let verif = signed_verify(&c.1 .1, &ca_cert_wrong);
            assert!(
                verif.is_err(),
                "certificate validation succeeded, but was expected to fail!"
            );
        }
    }

    #[test]
    fn test_ca_cert_selfsigned_verify() {
        let ca_name = "p1.kms.zama.ai";
        let is_ca = IsCa::NoCa;

        let (_ca_keypair, ca_cert, _ca_cert_params) = create_ca_cert(ca_name, &is_ca).unwrap();

        // check that we can import the CA cert into the trust store
        let mut root_store = tokio_rustls::rustls::RootCertStore::empty();
        let cc = (*ca_cert.der()).clone();
        root_store.add(cc).unwrap();

        // create another CA cert, that did not sign the core certs for negative testing
        let (_ca_keypair_wrong, ca_cert_wrong, _ca_cert_params_wrong) =
            create_ca_cert(ca_name, &is_ca).unwrap();

        let verif = signed_verify(&ca_cert, &ca_cert);

        // check that verification works for self-signed each cert
        assert!(verif.is_ok(), "certificate validation failed!");

        // check that verification does not work for wrong CA cert
        let verif = signed_verify(&ca_cert, &ca_cert_wrong);
        assert!(
            verif.is_err(),
            "certificate validation succeeded, but was expected to fail!"
        );
    }

    #[test]
    fn test_ca_name_validation() {
        assert!(
            validate_ca_name("party").is_ok(),
            "this should have been a valid CA name."
        );
        assert!(
            validate_ca_name("party/is#bad!").is_err(),
            "this should have been an invalid CA name."
        );
    }
}
