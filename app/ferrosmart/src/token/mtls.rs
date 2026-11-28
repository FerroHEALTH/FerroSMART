// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! Mutual-TLS client authentication (RFC 8705 §2).
//!
//! A `tls_client_auth` client authenticates by the subject its certificate
//! holds (§2.1), a `self_signed_tls_client_auth` client by the certificate
//! its JWK Set registers (§2.2).

use base64::Engine as _;
use serde_json::Value;
use x509_parser::certificate::X509Certificate;
use x509_parser::extensions::GeneralName;
use x509_parser::x509::X509Name;

use crate::clients::{AuthMethod, Client, TlsSubject};
use crate::server::AppState;

use super::Refusal;

/// Authenticates `client`, a mutual-TLS client, by `leaf`, the DER of the
/// connection's certificate, which the listener verified against its client
/// CAs (RFC 8705 §2.1, "The TLS handshake is utilized to validate the
/// client's possession of the private key").
///
/// # Errors
/// Returns `invalid_client` when the connection presented no certificate,
/// the certificate does not parse, or it is not the client's.
pub(crate) async fn authenticate(
    state: &AppState,
    client: &Client,
    leaf: Option<&[u8]>,
) -> Result<(), Refusal> {
    let leaf = leaf.ok_or(Refusal::client(
        "the connection presented no client certificate",
    ))?;
    let held = match client.auth_method {
        AuthMethod::TlsClientAuth => {
            let subject = client.tls_subject.as_ref().ok_or(Refusal::client(
                "the client registers no certificate subject",
            ))?;
            let (_, certificate) = x509_parser::parse_x509_certificate(leaf)
                .map_err(|_unparsed| Refusal::client("the client certificate does not parse"))?;
            holds(&certificate, subject)
        }
        AuthMethod::SelfSignedTlsClientAuth => registered(state, client, leaf).await?,
        _ => false,
    };
    if held {
        Ok(())
    } else {
        Err(Refusal::client(
            "the client certificate is not the client's",
        ))
    }
}

/// Returns whether `certificate` holds `subject` (RFC 8705 §2.1.2).
fn holds(certificate: &X509Certificate<'_>, subject: &TlsSubject) -> bool {
    if let TlsSubject::SubjectDn(expected) = subject {
        return rfc4514(certificate.subject())
            .is_some_and(|dn| normalized(&dn) == normalized(expected));
    }
    let Ok(Some(names)) = certificate.subject_alternative_name() else {
        return false;
    };
    names
        .value
        .general_names
        .iter()
        .any(|name| match (subject, name) {
            // NOTE: RFC 8705 §2.1.2 names no dNSName comparison; one without case is our own design.
            (TlsSubject::SanDns(expected), GeneralName::DNSName(dns)) => {
                dns.eq_ignore_ascii_case(expected)
            }
            (TlsSubject::SanUri(expected), GeneralName::URI(uri)) => uri == expected,
            (TlsSubject::SanEmail(expected), GeneralName::RFC822Name(email)) => email == expected,
            // NOTE: RFC 8705 §2.1.2, the IP address is compared in binary form.
            (TlsSubject::SanIp(expected), GeneralName::IPAddress(octets)) => match *expected {
                std::net::IpAddr::V4(address) => *octets == address.octets(),
                std::net::IpAddr::V6(address) => *octets == address.octets(),
            },
            _ => false,
        })
}

/// Returns the RFC 4514 string of `name`: its RDNs from the last to the
/// first (§2.1), each attribute by its §3 short name or dotted OID (§2.3),
/// its value escaped as §2.4 says; `None` for a value that is no string.
fn rfc4514(name: &X509Name<'_>) -> Option<String> {
    let mut rdns = Vec::new();
    for rdn in name.iter() {
        let mut attributes = Vec::new();
        for attribute in rdn.iter() {
            let oid = attribute.attr_type().to_id_string();
            let short = match oid.as_str() {
                "2.5.4.3" => "CN".to_owned(),
                "2.5.4.7" => "L".to_owned(),
                "2.5.4.8" => "ST".to_owned(),
                "2.5.4.10" => "O".to_owned(),
                "2.5.4.11" => "OU".to_owned(),
                "2.5.4.6" => "C".to_owned(),
                "2.5.4.9" => "STREET".to_owned(),
                "0.9.2342.19200300.100.1.25" => "DC".to_owned(),
                "0.9.2342.19200300.100.1.1" => "UID".to_owned(),
                _ => oid,
            };
            attributes.push(format!("{short}={}", escaped(attribute.as_str().ok()?)));
        }
        rdns.push(attributes.join("+"));
    }
    rdns.reverse();
    Some(rdns.join(","))
}

/// Returns `value` escaped as RFC 4514 §2.4 says.
fn escaped(value: &str) -> String {
    let last = value.chars().count().saturating_sub(1);
    value
        .chars()
        .enumerate()
        .fold(String::new(), |mut out, (index, character)| {
            let special = matches!(character, '"' | '+' | ',' | ';' | '<' | '>' | '\\')
                || (index == 0 && matches!(character, ' ' | '#'))
                || (index == last && character == ' ');
            if special {
                out.push('\\');
            }
            out.push(character);
            out
        })
}

/// Returns the RFC 4514 string `dn` with the attribute types in upper case
/// and the spaces around its separators taken out, so that two spellings of
/// one name compare equal.
// NOTE: RFC 8705 §2.1 asks for "a predictable treatment of DN values"; this one is our design.
fn normalized(dn: &str) -> String {
    let mut out = String::new();
    let mut escape = false;
    let mut in_type = true;
    for character in dn.trim().chars() {
        if escape {
            out.push(character);
            escape = false;
            continue;
        }
        match character {
            '\\' => {
                out.push(character);
                escape = true;
            }
            ',' | '+' => {
                while out.ends_with(' ') {
                    out.pop();
                }
                out.push(character);
                in_type = true;
            }
            '=' if in_type => {
                while out.ends_with(' ') {
                    out.pop();
                }
                out.push(character);
                in_type = false;
            }
            ' ' if out.ends_with(',') || out.ends_with('+') || out.ends_with('=') => {}
            _ if in_type => out.push(character.to_ascii_uppercase()),
            _ => out.push(character),
        }
    }
    out
}

/// Returns whether the client's JWK Set registers `leaf` as the first
/// certificate of a key's `x5c` (RFC 8705 §2.2; RFC 7517 §4.7).
async fn registered(state: &AppState, client: &Client, leaf: &[u8]) -> Result<bool, Refusal> {
    for refresh in [false, true] {
        let set = state
            .client_keys()
            .get(client, refresh)
            .await
            .map_err(|_unread| Refusal::client("the client's JWK Set cannot be read"))?;
        // NOTE: RFC 7517 §4.7, each x5c member is base64 (not base64url) DER.
        let found = set
            .get("keys")
            .and_then(Value::as_array)
            .is_some_and(|keys| {
                keys.iter().any(|key| {
                    key.get("x5c")
                        .and_then(Value::as_array)
                        .and_then(|chain| chain.first())
                        .and_then(Value::as_str)
                        .and_then(|der| base64::engine::general_purpose::STANDARD.decode(der).ok())
                        .is_some_and(|der| der == leaf)
                })
            });
        if found {
            return Ok(true);
        }
    }
    Ok(false)
}
