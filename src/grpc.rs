pub(crate) fn extract_sender<T>(request: &tonic::Request<T>) -> Result<Option<String>, String> {
    match request.peer_certs() {
        None => Ok(None),
        Some(certs) => {
            if certs.len() != 1 {
                return Err(format!(
                    "cannot extract identity from certificate chain of length {:?}",
                    certs.len()
                ));
            }

            let (_rem, cert) =
                x509_parser::parse_x509_certificate(certs[0].as_ref()).map_err(|err| {
                    format!("failed to parse X509 certificate: {:?}", err.to_string())
                })?;

            let cns: Vec<_> = cert
                .subject()
                .iter_common_name()
                .map(|attr| attr.as_str().map_err(|err| err.to_string()))
                .collect::<Result<_, _>>()?;

            if let Some(cn) = cns.first() {
                Ok(Some(cn.to_string()))
            } else {
                Err("certificate common name was empty".to_string())
            }
        }
    }
}
