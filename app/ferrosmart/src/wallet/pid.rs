// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The PID's attributes as the person a SMART token names
//! (`docs/architecture.md` §13.32).
//!
//! The attributes and their names in each format are the PID Rulebook 1.7
//! §2.2 to §2.6, §3.1.2 and §4.1.1 (Implementing Regulation (EU) 2024/2977
//! Annex, as amended by 2026/1731). No specification says how a PID becomes
//! the claims of an ID Token or the identifier a patient index resolves:
//! that mapping is FerroSMART's own design.

use std::collections::BTreeMap;

use serde_json::{Map, Value};

use super::Format;

/// What FerroSMART does with a PID attribute.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Target {
    /// The ID Token claim of this name, under `profile` or `email`.
    Claim(&'static str),
    /// The identifier the patient index resolves to the patient.
    Identifier,
    /// The Member State whose identifier system names the identifier, and
    /// in whose name the person's `sub` is derived.
    IdentifierCountry,
    /// Never asked for, and dropped on receipt: FerroSMART identifies the
    /// person without it, so it does not retain it (Implementing Regulation
    /// (EU) 2024/2977 Art 3a(3), inserted by 2026/1731; Regulation (EU)
    /// 2016/679 Art 5(1)(c)).
    NotRetained,
    /// Never asked for by default and mapped to nothing, for the reason
    /// given: FerroSMART uses it for no claim and no identifier, so it
    /// collects it not (Regulation (EU) 2016/679 Art 5(1)(c)).
    NotAsked(&'static str),
}

impl Target {
    /// Returns the handling as `conformance/pid-attributes.tsv` names it.
    #[must_use]
    pub fn handling(self) -> String {
        match self {
            Self::Claim(name) => name.to_owned(),
            Self::Identifier => String::from("identifier"),
            Self::IdentifierCountry => String::from("identifier country"),
            Self::NotRetained => String::from("not retained (CIR 2024/2977 Art 3a(3))"),
            Self::NotAsked(reason) => format!("not asked ({reason})"),
        }
    }
}

/// One data identifier of the PID Rulebook.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Attribute {
    /// The data identifier (PID Rulebook §2, §4.1.1).
    pub data_identifier: &'static str,
    /// Whether Implementing Regulation (EU) 2024/2977 makes it mandatory
    /// (PID Rulebook §2.2, §2.4).
    pub mandatory: bool,
    /// Its claim name in an SD-JWT VC (PID Rulebook §4.1.1).
    pub sd_jwt_vc: &'static str,
    /// Its attribute identifier in an mdoc (PID Rulebook §3.1.2); none for
    /// the one the Rulebook encodes only in an SD-JWT VC.
    pub mdoc: Option<&'static str>,
    /// What FerroSMART does with it.
    pub target: Target,
}

impl Attribute {
    /// Returns its name in `format`, when that format encodes it.
    #[must_use]
    pub const fn name(&self, format: Format) -> Option<&'static str> {
        match format {
            Format::SdJwtVc => Some(self.sd_jwt_vc),
            Format::Mdoc => self.mdoc,
        }
    }
}

/// The reason no address attribute is asked for.
const NO_ADDRESS: &str = "no address claim: GDPR Art 5(1)(c)";

/// Returns the attribute of `data_identifier`, mandatory or not, under the
/// same name in both formats, handled by `target`.
const fn same(data_identifier: &'static str, mandatory: bool, target: Target) -> Attribute {
    Attribute {
        data_identifier,
        mandatory,
        sd_jwt_vc: data_identifier,
        mdoc: Some(data_identifier),
        target,
    }
}

/// Returns the optional attribute `data_identifier`, under `sd_jwt_vc` in
/// an SD-JWT VC and its own name in an mdoc, handled by `target`.
const fn renamed(
    data_identifier: &'static str,
    sd_jwt_vc: &'static str,
    target: Target,
) -> Attribute {
    Attribute {
        data_identifier,
        mandatory: false,
        sd_jwt_vc,
        mdoc: Some(data_identifier),
        target,
    }
}

/// Every data identifier of the PID Rulebook, in its order.
///
/// The mandatory attributes (§2.2), the optional ones (§2.3), the mandatory
/// and optional metadata (§2.4, §2.5), the Rulebook's own attributes
/// (§2.6), and `resident_house_number`, which §4.1.1 adds to an SD-JWT VC
/// alone.
pub const ATTRIBUTES: [Attribute; 27] = [
    same("family_name", true, Target::Claim("family_name")),
    same("given_name", true, Target::Claim("given_name")),
    Attribute {
        data_identifier: "birth_date",
        mandatory: true,
        sd_jwt_vc: "birthdate",
        mdoc: Some("birth_date"),
        target: Target::Claim("birthdate"),
    },
    Attribute {
        data_identifier: "birth_place",
        mandatory: true,
        sd_jwt_vc: "place_of_birth",
        mdoc: Some("place_of_birth"),
        target: Target::Claim("place_of_birth"),
    },
    Attribute {
        data_identifier: "nationality",
        mandatory: true,
        sd_jwt_vc: "nationalities",
        mdoc: Some("nationality"),
        target: Target::Claim("nationalities"),
    },
    Attribute {
        data_identifier: "portrait",
        mandatory: true,
        sd_jwt_vc: "picture",
        mdoc: Some("portrait"),
        target: Target::NotRetained,
    },
    renamed(
        "resident_address",
        "address.formatted",
        Target::NotAsked(NO_ADDRESS),
    ),
    renamed(
        "resident_country",
        "address.country",
        Target::NotAsked(NO_ADDRESS),
    ),
    renamed(
        "resident_state",
        "address.region",
        Target::NotAsked(NO_ADDRESS),
    ),
    renamed(
        "resident_city",
        "address.locality",
        Target::NotAsked(NO_ADDRESS),
    ),
    renamed(
        "resident_postal_code",
        "address.postal_code",
        Target::NotAsked(NO_ADDRESS),
    ),
    renamed(
        "resident_street",
        "address.street_address",
        Target::NotAsked(NO_ADDRESS),
    ),
    same("personal_administrative_number", false, Target::Identifier),
    renamed(
        "family_name_birth",
        "birth_family_name",
        Target::NotAsked("no birth-name claim: GDPR Art 5(1)(c)"),
    ),
    renamed(
        "given_name_birth",
        "birth_given_name",
        Target::NotAsked("no birth-name claim: GDPR Art 5(1)(c)"),
    ),
    same(
        "sex",
        false,
        Target::NotAsked("no claim: OIDC gender has another value range, Rulebook §4.1.1"),
    ),
    renamed("email_address", "email", Target::Claim("email")),
    renamed(
        "mobile_phone_number",
        "phone_number",
        Target::NotAsked("no phone claim: GDPR Art 5(1)(c)"),
    ),
    same(
        "issuing_authority",
        true,
        Target::NotAsked(
            "the provider's certificate under the PID providers list names it, Rulebook §6",
        ),
    ),
    same("issuing_country", true, Target::IdentifierCountry),
    renamed(
        "expiry_date",
        "date_of_expiry",
        Target::NotAsked("the technical validity and the status list decide, Rulebook §2.5, §7"),
    ),
    same(
        "document_number",
        false,
        Target::NotAsked("names the PID, not the person: GDPR Art 5(1)(c)"),
    ),
    same(
        "issuing_jurisdiction",
        false,
        Target::NotAsked("issuing_country names the identifier's system"),
    ),
    renamed(
        "issuance_date",
        "date_of_issuance",
        Target::NotAsked("the technical validity and the status list decide, Rulebook §2.5, §7"),
    ),
    same(
        "trust_anchor",
        false,
        Target::NotAsked("the anchors come from the PID providers list, never a PID, Rulebook §6"),
    ),
    same(
        "attestation_legal_category",
        false,
        Target::NotAsked("the credential type and the PID providers list say it is a PID"),
    ),
    Attribute {
        data_identifier: "resident_house_number",
        mandatory: false,
        sd_jwt_vc: "address.house_number",
        mdoc: None,
        target: Target::NotAsked(NO_ADDRESS),
    },
];

/// Whether `name`, in either format, names an attribute that is
/// [`Target::NotRetained`].
#[must_use]
pub fn not_retained(name: &str) -> bool {
    ATTRIBUTES.iter().any(|attribute| {
        attribute.target == Target::NotRetained
            && (attribute.sd_jwt_vc == name || attribute.mdoc == Some(name))
    })
}

/// Returns the verified `claims` of `format` as a login keeps them: every
/// attribute that is [`Target::NotRetained`] dropped, and the attributes
/// [`person_claims`] maps added under their ID Token names.
#[must_use]
pub fn received(mut claims: Map<String, Value>, format: Format) -> Map<String, Value> {
    claims.retain(|name, _| !not_retained(name));
    let person = person_claims(&claims, format);
    claims.extend(person);
    claims
}

/// Returns the ID Token claims the presented `claims` of `format` map to,
/// each under its [`Target::Claim`] name and only in the shape the PID
/// Rulebook gives it.
#[must_use]
pub fn person_claims(claims: &Map<String, Value>, format: Format) -> Map<String, Value> {
    ATTRIBUTES
        .iter()
        .filter_map(|attribute| {
            let Target::Claim(name) = attribute.target else {
                return None;
            };
            let value = claims.get(attribute.name(format)?)?;
            shaped(name, value).then(|| (name.to_owned(), value.clone()))
        })
        .collect()
}

/// Whether `value` has the shape the PID Rulebook gives the claim `name`.
///
/// Text, `birthdate` a full date `YYYY-MM-DD` (§3.1.2, §4.1.1),
/// `place_of_birth` an object of text members (§3.1.4, §4.1.1),
/// `nationalities` an array of alpha-2 codes (§3.1.3).
#[must_use]
pub fn shaped(name: &str, value: &Value) -> bool {
    match name {
        "birthdate" => value.as_str().is_some_and(full_date),
        "place_of_birth" => value.as_object().is_some_and(|place| {
            !place.is_empty()
                && place.iter().all(|(member, text)| {
                    matches!(member.as_str(), "country" | "region" | "locality")
                        && text.as_str().is_some_and(|text| !text.trim().is_empty())
                })
        }),
        "nationalities" => value.as_array().is_some_and(|codes| {
            !codes.is_empty() && codes.iter().all(|code| code.as_str().is_some_and(alpha_2))
        }),
        _ => value.as_str().is_some_and(|text| !text.trim().is_empty()),
    }
}

/// Whether `text` has the form of an RFC 3339 `full-date`, `YYYY-MM-DD`.
fn full_date(text: &str) -> bool {
    text.len() == 10
        && text.bytes().enumerate().all(|(at, byte)| match at {
            4 | 7 => byte == b'-',
            _ => byte.is_ascii_digit(),
        })
}

/// Whether `code` is an ISO 3166-1 alpha-2 code's form: two capital letters.
#[must_use]
pub fn alpha_2(code: &str) -> bool {
    code.len() == 2 && code.bytes().all(|byte| byte.is_ascii_uppercase())
}

/// The coding system of HL7 v2 table 0203, the identifier types FHIR R4
/// `Identifier.type` is bound to.
pub const IDENTIFIER_TYPES: &str = "http://terminology.hl7.org/CodeSystem/v2-0203";

/// The system of ISO 3166-1 country codes in FHIR R4.
pub const COUNTRIES: &str = "urn:iso:std:iso:3166";

/// The person's identifier, as the patient index is asked for it: the
/// administrative number in the identifier system of the Member State that
/// issued it.
#[derive(Clone, PartialEq, Eq)]
pub struct PidIdentifier {
    /// The identifier system of the issuing Member State's numbers.
    pub system: String,
    /// The number.
    pub value: String,
    /// The HL7 v2 table 0203 code of the identifier's type.
    pub kind: String,
    /// The issuing Member State, an ISO 3166-1 alpha-2 code.
    pub country: String,
}

impl std::fmt::Debug for PidIdentifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PidIdentifier")
            .field("system", &self.system)
            .finish_non_exhaustive()
    }
}

impl PidIdentifier {
    /// Returns the FHIR R4 token `system|value` a search or `$ihe-pix`
    /// names it by (FHIR R4 search, token parameters).
    #[must_use]
    pub fn token(&self) -> String {
        format!("{}|{}", self.system, self.value)
    }

    /// Returns it as a FHIR R4 `Identifier`: its type, system and value, and
    /// the issuing Member State as the assigning authority.
    #[must_use]
    pub fn fhir(&self) -> Value {
        serde_json::json!({
            "type": {"coding": [{"system": IDENTIFIER_TYPES, "code": self.kind}]},
            "system": self.system,
            "value": self.value,
            "assigner": {"identifier": {"system": COUNTRIES, "value": self.country}},
        })
    }
}

/// Why no identifier is drawn from a PID.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum IdentifierError {
    /// The PID discloses no administrative number or no issuing country.
    #[error("the PID names no administrative number and issuing country")]
    Undisclosed,
    /// No identifier system is configured for the issuing country.
    #[error("no identifier system is configured for the issuing country")]
    UnknownCountry,
}

/// Returns the identifier the `claims` of a verified PID name: the
/// `identifier_claim`'s value in the system `systems` names for its
/// `issuing_country`, typed `kind`.
///
/// # Errors
/// Returns [`IdentifierError`] when the PID discloses either value not, or
/// no system is configured for the country.
pub fn identifier(
    claims: &Map<String, Value>,
    identifier_claim: &str,
    systems: &BTreeMap<String, String>,
    kind: &str,
) -> Result<PidIdentifier, IdentifierError> {
    let text = |name: &str| {
        claims
            .get(name)
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|text| !text.is_empty())
    };
    let (Some(value), Some(country)) = (text(identifier_claim), text("issuing_country")) else {
        return Err(IdentifierError::Undisclosed);
    };
    let system = systems
        .get(country)
        .ok_or(IdentifierError::UnknownCountry)?;
    Ok(PidIdentifier {
        system: system.clone(),
        value: value.to_owned(),
        kind: kind.to_owned(),
        country: country.to_owned(),
    })
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    const BSN: &str = "http://fhir.nl/fhir/NamingSystem/bsn";

    fn object(value: Value) -> Map<String, Value> {
        match value {
            Value::Object(object) => object,
            _ => Map::new(),
        }
    }

    fn sd_jwt_pid() -> Map<String, Value> {
        object(json!({
            "family_name": "Jansen",
            "given_name": "Eva",
            "birthdate": "1980-02-12",
            "place_of_birth": {"country": "NL", "locality": "Leiden"},
            "nationalities": ["NL"],
            "picture": "data:image/jpeg;base64,AA",
            "personal_administrative_number": "999990019",
            "issuing_country": "NL",
        }))
    }

    fn mdoc_pid() -> Map<String, Value> {
        object(json!({
            "family_name": "Jansen",
            "given_name": "Eva",
            "birth_date": "1980-02-12",
            "place_of_birth": {"locality": "Leiden"},
            "nationality": ["NL", "BE"],
            "portrait": "AA",
            "personal_administrative_number": "999990019",
            "issuing_country": "NL",
        }))
    }

    #[test]
    fn the_table_holds_every_data_identifier_of_the_rulebook_in_its_order() {
        let identifiers: Vec<&str> = ATTRIBUTES
            .iter()
            .map(|attribute| attribute.data_identifier)
            .collect();
        // NOTE: PID Rulebook 1.7 §2.2 to §2.6, and §4.1.1's resident_house_number.
        assert_eq!(
            vec![
                "family_name",
                "given_name",
                "birth_date",
                "birth_place",
                "nationality",
                "portrait",
                "resident_address",
                "resident_country",
                "resident_state",
                "resident_city",
                "resident_postal_code",
                "resident_street",
                "personal_administrative_number",
                "family_name_birth",
                "given_name_birth",
                "sex",
                "email_address",
                "mobile_phone_number",
                "issuing_authority",
                "issuing_country",
                "expiry_date",
                "document_number",
                "issuing_jurisdiction",
                "issuance_date",
                "trust_anchor",
                "attestation_legal_category",
                "resident_house_number",
            ],
            identifiers
        );
        let mandatory: Vec<&str> = ATTRIBUTES
            .iter()
            .filter(|attribute| attribute.mandatory)
            .map(|attribute| attribute.data_identifier)
            .collect();
        // NOTE: PID Rulebook 1.7 §2.2 and §2.4, the mandatory attributes and metadata.
        assert_eq!(
            vec![
                "family_name",
                "given_name",
                "birth_date",
                "birth_place",
                "nationality",
                "portrait",
                "issuing_authority",
                "issuing_country"
            ],
            mandatory
        );
        let identifiers: Vec<&str> = ATTRIBUTES
            .iter()
            .filter(|attribute| attribute.target == Target::Identifier)
            .map(|attribute| attribute.data_identifier)
            .collect();
        assert_eq!(vec!["personal_administrative_number"], identifiers);
    }

    /// Returns the presented claims of `format` holding every attribute
    /// FerroSMART does not ask for, each with a well-formed text value.
    fn unused(format: Format) -> Map<String, Value> {
        ATTRIBUTES
            .iter()
            .filter(|attribute| matches!(attribute.target, Target::NotAsked(_)))
            .filter_map(|attribute| attribute.name(format))
            .map(|name| (name.to_owned(), json!("synthetic")))
            .collect()
    }

    // NOTE: Regulation (EU) 2016/679 Art 5(1)(c), what no claim or identifier uses is
    // not asked for, and maps to nothing when a wallet sends it.
    #[test]
    fn an_attribute_it_does_not_use_is_neither_asked_nor_mapped() {
        for format in [Format::SdJwtVc, Format::Mdoc] {
            assert!(
                person_claims(&unused(format), format).is_empty(),
                "{format:?}"
            );
        }
        let section = crate::upstream::wallet::WalletSection::default();
        for (format, asked) in [
            (Format::SdJwtVc, &section.claims),
            (Format::Mdoc, &section.mdoc_claims),
        ] {
            for name in asked {
                let target = ATTRIBUTES
                    .iter()
                    .find(|attribute| attribute.name(format) == Some(name.as_str()))
                    .map(|attribute| attribute.target);
                assert!(
                    matches!(
                        target,
                        Some(Target::Claim(_) | Target::Identifier | Target::IdentifierCountry)
                    ),
                    "the default request asks {name} of an {format:?}, which it uses for nothing"
                );
            }
        }
    }

    // NOTE: PID Rulebook 1.7 §4.1.1, email_address is OpenID Connect Core 1.0 §5.1's
    // email in an SD-JWT VC; an mdoc names it email_address (§3.1.2).
    #[test]
    fn the_email_address_reaches_the_email_claim_from_either_format() {
        let sd_jwt = object(json!({"email": "eva@example.org"}));
        let mdoc = object(json!({"email_address": "eva@example.org"}));
        let expected = object(json!({"email": "eva@example.org"}));
        assert_eq!(expected, person_claims(&sd_jwt, Format::SdJwtVc));
        assert_eq!(expected, person_claims(&mdoc, Format::Mdoc));
        assert!(person_claims(&mdoc, Format::SdJwtVc).is_empty());
    }

    #[test]
    fn every_mapped_attribute_reaches_its_claim_from_an_sd_jwt_vc() {
        let mapped = person_claims(&sd_jwt_pid(), Format::SdJwtVc);
        assert_eq!(
            object(json!({
                "family_name": "Jansen",
                "given_name": "Eva",
                "birthdate": "1980-02-12",
                "place_of_birth": {"country": "NL", "locality": "Leiden"},
                "nationalities": ["NL"],
            })),
            mapped
        );
    }

    #[test]
    fn every_mapped_attribute_reaches_its_claim_from_an_mdoc() {
        let mapped = person_claims(&mdoc_pid(), Format::Mdoc);
        assert_eq!(
            object(json!({
                "family_name": "Jansen",
                "given_name": "Eva",
                "birthdate": "1980-02-12",
                "place_of_birth": {"locality": "Leiden"},
                "nationalities": ["NL", "BE"],
            })),
            mapped
        );
    }

    #[test]
    fn a_value_of_another_shape_maps_to_no_claim() {
        let claims = object(json!({
            "family_name": "",
            "given_name": 7,
            "birthdate": "12-02-1978",
            "place_of_birth": {"planet": "Earth"},
            "nationalities": ["nl"],
        }));
        assert!(person_claims(&claims, Format::SdJwtVc).is_empty());
        let empty_place = object(json!({"place_of_birth": {}, "nationalities": []}));
        assert!(person_claims(&empty_place, Format::SdJwtVc).is_empty());
    }

    #[test]
    fn the_administrative_number_is_named_in_its_member_state_system() {
        let systems = BTreeMap::from([(String::from("NL"), String::from(BSN))]);
        let found = identifier(
            &sd_jwt_pid(),
            "personal_administrative_number",
            &systems,
            "NI",
        )
        .expect("an identifier");
        assert_eq!(format!("{BSN}|999990019"), found.token());
        assert_eq!(
            json!({
                "type": {"coding": [{"system": IDENTIFIER_TYPES, "code": "NI"}]},
                "system": BSN,
                "value": "999990019",
                "assigner": {"identifier": {"system": COUNTRIES, "value": "NL"}},
            }),
            found.fhir()
        );
        assert!(
            !format!("{found:?}").contains("999990019"),
            "Debug shows no number"
        );
    }

    #[test]
    fn an_identifier_needs_its_number_country_and_system() {
        let systems = BTreeMap::from([(String::from("BE"), String::from(BSN))]);
        assert_eq!(
            Err(IdentifierError::UnknownCountry),
            identifier(
                &sd_jwt_pid(),
                "personal_administrative_number",
                &systems,
                "NI"
            )
        );
        let mut claims = sd_jwt_pid();
        claims.remove("issuing_country");
        assert_eq!(
            Err(IdentifierError::Undisclosed),
            identifier(&claims, "personal_administrative_number", &systems, "NI")
        );
    }

    #[test]
    fn the_conformance_table_is_the_mapping() {
        let table = include_str!("../../../../conformance/pid-attributes.tsv");
        let rows: Vec<Vec<String>> = table
            .lines()
            .filter(|line| !line.starts_with('#') && !line.is_empty())
            .map(|line| line.split('\t').take(5).map(str::to_owned).collect())
            .collect();
        let expected: Vec<Vec<String>> = ATTRIBUTES
            .iter()
            .map(|attribute| {
                vec![
                    attribute.data_identifier.to_owned(),
                    String::from(if attribute.mandatory { "yes" } else { "no" }),
                    attribute.sd_jwt_vc.to_owned(),
                    attribute.mdoc.unwrap_or("-").to_owned(),
                    attribute.target.handling(),
                ]
            })
            .collect();
        assert_eq!(
            expected, rows,
            "conformance/pid-attributes.tsv lists the table row for row"
        );
    }

    #[test]
    fn a_login_keeps_no_portrait_from_either_format() {
        let sd_jwt = received(sd_jwt_pid(), Format::SdJwtVc);
        assert!(!sd_jwt.contains_key("picture"), "{sd_jwt:?}");
        assert_eq!(
            Some(&json!("999990019")),
            sd_jwt.get("personal_administrative_number")
        );
        assert_eq!(Some(&json!("Jansen")), sd_jwt.get("family_name"));
        let mdoc = received(mdoc_pid(), Format::Mdoc);
        assert!(!mdoc.contains_key("portrait"), "{mdoc:?}");
        assert_eq!(Some(&json!("1980-02-12")), mdoc.get("birthdate"));
        assert!(not_retained("picture") && not_retained("portrait"));
        assert!(!not_retained("family_name"));
    }

    #[test]
    fn alpha_2_is_two_capital_letters() {
        assert!(alpha_2("NL"));
        assert!(!alpha_2("nl"));
        assert!(!alpha_2("NLD"));
    }
}
