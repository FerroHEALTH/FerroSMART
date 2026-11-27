// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! `ferrosmart key generate`: a fresh ML-DSA private key (FIPS 204) as the
//! PKCS#8 PEM FerroSMART's key settings read (RFC 9881 §6), so no
//! deployment needs an OpenSSL that generates ML-DSA keys.

use std::io::Write as _;
use std::path::Path;

use aws_lc_rs::signature::{
    ML_DSA_44_SIGNING, ML_DSA_65_SIGNING, ML_DSA_87_SIGNING, PqdsaKeyPair, PqdsaSigningAlgorithm,
};
use base64::Engine as _;
use secrecy::{ExposeSecret as _, SecretString};

/// Why no key was written.
#[derive(Debug, thiserror::Error)]
pub enum KeyGenError {
    /// The algorithm names no ML-DSA parameter set.
    #[error("`--algorithm` is `ML-DSA-44`, `ML-DSA-65` or `ML-DSA-87`, not {0:?}")]
    Algorithm(String),
    /// The key could not be generated or encoded.
    #[error("the key could not be generated")]
    Generate,
    /// The file exists already or cannot be written.
    #[error("the key cannot be written to the file")]
    Write(#[source] std::io::Error),
}

/// Returns a fresh private key of the ML-DSA parameter set `algorithm`
/// names, PKCS#8 PEM.
///
/// # Errors
///
/// Returns [`KeyGenError::Algorithm`] for another name and
/// [`KeyGenError::Generate`] when the random source or the encoder fails.
pub fn generate(algorithm: &str) -> Result<SecretString, KeyGenError> {
    let parameters: &'static PqdsaSigningAlgorithm = match algorithm {
        "ML-DSA-44" => &ML_DSA_44_SIGNING,
        "ML-DSA-65" => &ML_DSA_65_SIGNING,
        "ML-DSA-87" => &ML_DSA_87_SIGNING,
        _ => return Err(KeyGenError::Algorithm(algorithm.to_owned())),
    };
    let pair = PqdsaKeyPair::generate(parameters).map_err(|_unspecified| KeyGenError::Generate)?;
    let der = pair
        .to_pkcs8v1()
        .map_err(|_unspecified| KeyGenError::Generate)?;
    let body = base64::engine::general_purpose::STANDARD.encode(der.as_ref());
    let mut pem = String::from("-----BEGIN PRIVATE KEY-----\n");
    for line in body.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(line).map_err(|_never| KeyGenError::Generate)?);
        pem.push('\n');
    }
    pem.push_str("-----END PRIVATE KEY-----\n");
    Ok(SecretString::from(pem))
}

/// Writes a fresh key of `algorithm` to `out`, a file that must not exist,
/// readable by its owner alone.
///
/// # Errors
///
/// Returns the [`KeyGenError`] of [`generate`], and [`KeyGenError::Write`]
/// when `out` exists or cannot be written.
pub fn write(algorithm: &str, out: &Path) -> Result<(), KeyGenError> {
    let pem = generate(algorithm)?;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let mut file = options.open(out).map_err(KeyGenError::Write)?;
    file.write_all(pem.expose_secret().as_bytes())
        .map_err(KeyGenError::Write)
}

#[cfg(test)]
mod tests {
    use secrecy::ExposeSecret as _;

    use super::{KeyGenError, generate, write};

    #[test]
    fn each_parameter_set_reads_back_as_its_algorithm() {
        use ferrohealth_smart::jws::algorithm::Algorithm;
        for (name, algorithm) in [
            ("ML-DSA-44", Algorithm::MlDsa44),
            ("ML-DSA-65", Algorithm::MlDsa65),
            ("ML-DSA-87", Algorithm::MlDsa87),
        ] {
            let pem = generate(name).expect("a key");
            let key =
                ferrohealth_smart::jws::key::PrivateKey::from_pem(pem.expose_secret().as_bytes())
                    .expect("the key reads");
            assert_eq!(Some(algorithm), key.algorithm(), "{name}");
        }
        assert!(matches!(generate("ES384"), Err(KeyGenError::Algorithm(_))));
    }

    #[test]
    fn a_key_is_written_once_and_for_its_owner_alone() {
        let dir = tempfile::tempdir().expect("a directory");
        let out = dir.path().join("backend.pem");
        write("ML-DSA-65", &out).expect("written");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&out)
                .expect("metadata")
                .permissions()
                .mode();
            assert_eq!(0o600, mode & 0o777);
        }
        assert!(matches!(
            write("ML-DSA-65", &out),
            Err(KeyGenError::Write(_))
        ));
    }
}
