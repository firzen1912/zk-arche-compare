use anyhow::{Context, Result};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls_pemfile::{certs, pkcs8_private_keys, rsa_private_keys};
use std::fs::File;
use std::io::BufReader;

pub fn load_certs(path: &str) -> Result<Vec<CertificateDer<'static>>> {
    let file = File::open(path).with_context(|| format!("open cert file: {path}"))?;
    let mut reader = BufReader::new(file);
    let certs = certs(&mut reader).collect::<std::result::Result<Vec<_>, _>>()?;
    Ok(certs)
}

pub fn load_private_key(path: &str) -> Result<PrivateKeyDer<'static>> {
    let file = File::open(path).with_context(|| format!("open key file: {path}"))?;
    let mut reader = BufReader::new(file);

    let pkcs8 = pkcs8_private_keys(&mut reader).collect::<std::result::Result<Vec<_>, _>>()?;
    if let Some(k) = pkcs8.into_iter().next() {
        return Ok(PrivateKeyDer::Pkcs8(k));
    }

    let file = File::open(path).with_context(|| format!("re-open key file: {path}"))?;
    let mut reader = BufReader::new(file);
    let rsa = rsa_private_keys(&mut reader).collect::<std::result::Result<Vec<_>, _>>()?;
    if let Some(k) = rsa.into_iter().next() {
        return Ok(PrivateKeyDer::Pkcs1(k));
    }

    anyhow::bail!("no usable private key found in {path}");
}
