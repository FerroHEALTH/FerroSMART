// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The PID's attributes as the person a SMART token names
//! (`docs/architecture.md` §13.32).
//!
//! The attributes and their names in each format are the PID Rulebook 1.6
//! §2.2, §2.3, §3.1.2 and §4.1.1 (Implementing Regulation (EU) 2024/2977
//! Annex, as amended by 2026/1731). No specification says how a PID becomes
//! the claims of an ID Token or the identifier a patient index resolves:
//! that mapping is FerroSMART's own design.

use std::collections::BTreeMap;

use serde_json::{Map, Value};

use super::Format;

/// Where a PID attribute goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Target {
    /// The ID Token claim of this name, under `profile`.
    Claim(&'static str),
    /// The identifier the patient index resolves to the patient.
    Identifier,
    /// Never asked for, and dropped on receipt: FerroSMART identifies the
    /// person without it, so it does not retain it (Implementing Regulation
    /// (EU) 2024/2977 Art 3a(3), inserted by 2026/1731; Regulation (EU)
    /// 2016/679 Art 5(1)(c)).
    NotRetained,
}

/// One attribute of the PID Rulebook.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Attribute {
    /// The data identifier (PID Rulebook §2).
    pub data_identifier: &'static str,
    /// Whether Implementing Regulation (EU) 2024/2977 makes it mandatory
    /// (PID Rulebook §2.2).
    pub mandatory: bool,
    /// Its claim name in an SD-JWT VC (PID Rulebook §4.1.1).
    pub sd_jwt_vc: &'static str,
    /// Its attribute identifier in an mdoc (PID Rulebook §3.1.2).
    pub mdoc: &'static str,
    /// Where FerroSMART maps it.
    pub target: Target,
}

impl Attribute {
    /// Returns its name in `format`.
    #[must_use]
    pub const fn name(&self, format: Format) -> &'static str {
        match format {
            Format::SdJwtVc => self.sd_jwt_vc,
            Format::Mdoc => self.mdoc,
        }
    }
}

/// The mandatory attributes of the PID Rulebook §2.2 and the optional
/// `personal_administrative_number` of §2.3, the attributes that name the
/// person.
pub const ATTRIBUTES: [Attribute; 7] = [
    Attribute {
        data_identifier: "family_name",
        mandatory: true,
        sd_jwt_vc: "family_name",
        mdoc: "family_name",
        target: Target::Claim("family_name"),
    },
    Attribute {
        data_identifier: "given_name",
        mandatory: true,
        sd_jwt_vc: "given_name",
        mdoc: "given_name",
        target: Target::Claim("given_name"),
    },
    Attribute {
        data_identifier: "birth_date",
        mandatory: true,
        sd_jwt_vc: "birthdate",
        mdoc: "birth_date",
        target: Target::Claim("birthdate"),
    },
    Attribute {
        data_identifier: "birth_place",
        mandatory: true,
        sd_jwt_vc: "place_of_birth",
        mdoc: "place_of_birth",
        target: Target::Claim("place_of_birth"),
    },
    Attribute {
        data_identifier: "nationality",
        mandatory: true,
        sd_jwt_vc: "nationalities",
        mdoc: "nationality",
        target: Target::Claim("nationalities"),
    },
    Attribute {
        data_identifier: "portrait",
        mandatory: true,
        sd_jwt_vc: "picture",
        mdoc: "portrait",
        target: Target::NotRetained,
    },
    Attribute {
        data_identifier: "personal_administrative_number",
        mandatory: false,
        sd_jwt_vc: "personal_administrative_number",
        mdoc: "personal_administrative_number",
        target: Target::Identifier,
    },
];

/// Whether `name`, in either format, names an attribute that is
/// [`Target::NotRetained`].
#[must_use]
pub fn not_retained(name: &str) -> bool {
    ATTRIBUTES.iter().any(|attribute| {
        attribute.target == Target::NotRetained
            && (attribute.sd_jwt_vc == name || attribute.mdoc == name)
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
            let value = claims.get(attribute.name(format))?;
            shaped(name, value).then(|| (name.to_owned(), value.clone()))
        })
        .collect()
}

/// Whether `value` has the shape the PID Rulebook gives the claim `name`:
/// text, `place_of_birth` an object of text members (§3.1.4, §4.1.1),
/// `nationalities` an array of alpha-2 codes (§3.1.3).
#[must_use]
pub fn shaped(name: &str, value: &Value) -> bool {
    match name {
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
    fn the_table_holds_the_rulebook_mandatory_attributes_and_the_administrative_number() {
        let mandatory: Vec<&str> = ATTRIBUTES
            .iter()
            .filter(|attribute| attribute.mandatory)
            .map(|attribute| attribute.data_identifier)
            .collect();
        // NOTE: PID Rulebook 1.6 §2.2, the mandatory attributes of CIR 2024/2977.
        assert_eq!(
            vec![
                "family_name",
                "given_name",
                "birth_date",
                "birth_place",
                "nationality",
                "portrait"
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
        let rows: Vec<Vec<&str>> = table
            .lines()
            .filter(|line| !line.starts_with('#') && !line.is_empty())
            .map(|line| line.split('\t').take(5).collect())
            .collect();
        let expected: Vec<Vec<&str>> = ATTRIBUTES
            .iter()
            .map(|attribute| {
                vec![
                    attribute.data_identifier,
                    if attribute.mandatory { "yes" } else { "no" },
                    attribute.sd_jwt_vc,
                    attribute.mdoc,
                    match attribute.target {
                        Target::Claim(name) => name,
                        Target::Identifier => "identifier",
                        Target::NotRetained => "not retained (CIR 2024/2977 Art 3a(3))",
                    },
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
