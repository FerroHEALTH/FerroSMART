// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The caller classification through the public API: a signed token in, a
//! `Caller` with its `CallerKind` out, every refusal a typed
//! `Rejection::Unclassified`. One suite of cases runs against the generic
//! standards-only issuer, then against the Entra ID, Keycloak, Okta and
//! FerroSMART profiles, each with tokens shaped as its vendored
//! documentation shows them; the preset-specific cases follow each vendor's
//! suite.

use std::error::Error as StdError;

use ferrohealth_smart::kind::Actor;
use ferrohealth_smart::kind::CallerKind;
use ferrohealth_smart::kind::IssuerKind;
use ferrohealth_smart::kind::Unclassified;
use ferrohealth_smart::profile::Marker;
use ferrohealth_smart::profile::Preset;
use ferrohealth_smart::profile::Profile;
use ferrohealth_smart::profile::ProfileError;
use ferrohealth_smart::profile::ProfileKeys;
use ferrohealth_smart::profile::Representation;
use ferrohealth_smart::profile::ScopeForm;
use ferrohealth_smart::resource::Caller;
use ferrohealth_smart::resource::Compartment;
use ferrohealth_smart::resource::Rejection;
use ferrohealth_smart::resource::ResourceError;
use ferrohealth_smart::resource::ResourceServer;
use ferrohealth_smart::resource::Settings;
use ferrohealth_smart::scope::Permission;
use jsonwebtoken::Algorithm;
use jsonwebtoken::Header;
use serde_json::Value;
use serde_json::json;

use crate::support::SigningKey;
use crate::support::ec_key;
use crate::support::mint_with;
use crate::support::now;
use crate::support::temp_file;

/// The issuer of every case; its key set is a file, so nothing is read.
const ISSUER: &str = "https://as.example.org/realms/ferro";
/// The audience of every case.
const AUDIENCE: &str = "https://ehr.example.org/openehr";
/// The deployment's own client, through which a person signs in.
const FIRST_PARTY: &str = "first-party-app";
/// A third-party client the person's token was issued to.
const THIRD_PARTY: &str = "third-party-app";
/// The client of the machine's client credentials grant.
const MACHINE: &str = "machine-client";

type Outcome = Result<(), Box<dyn StdError>>;

/// One authorization server's token shape, as its documentation shows it.
struct Vendor {
    /// The preset its issuer selects.
    preset: Preset,
    /// The `typ` header its tokens carry.
    typ: &'static str,
    /// Sets what a deployment of this issuer must set beside the preset.
    deploy: fn(&mut Profile),
    /// The claims of a person's token through [`FIRST_PARTY`].
    person: fn(&str) -> Value,
    /// The claims of the machine's app-only token.
    app: fn(&str) -> Value,
    /// The value of the profile's person key in [`Vendor::person`].
    person_key: &'static str,
}

/// The scope claim value of `scope` in `form`.
fn scopes(scope: &str, form: ScopeForm) -> Value {
    match form {
        ScopeForm::String => json!(scope),
        ScopeForm::Array => json!(scope.split(' ').collect::<Vec<_>>()),
    }
}

/// The generic issuer: RFC 9068 §2.2, every claim REQUIRED there, `sub`
/// the resource owner and `client_id` the client.
fn generic() -> Vendor {
    Vendor {
        preset: Preset::Rfc9068,
        typ: "at+jwt",
        deploy: |_| {},
        person: |scope| {
            json!({
                "iss": ISSUER, "aud": AUDIENCE, "sub": "user-5ba552d67",
                "client_id": FIRST_PARTY, "iat": now(), "exp": now() + 300,
                "jti": "jti-person", "scope": scope,
            })
        },
        // NOTE: RFC 9068 §2.2 and §5, a client credentials token's `sub`
        // identifies the client application.
        app: |scope| {
            json!({
                "iss": ISSUER, "aud": AUDIENCE, "sub": MACHINE, "client_id": MACHINE,
                "iat": now(), "exp": now() + 300, "jti": "jti-app", "scope": scope,
            })
        },
        person_key: "user-5ba552d67",
    }
}

/// Entra ID v2.0: Microsoft, "Access token claims reference" (header
/// `typ` "always `JWT`", `azp`, `oid`, `tid`, `uti`, `ver`, `scp` a space
/// separated list on user tokens, `roles` on app tokens) and "Optional claims
/// reference" (`idtyp` = `app`, `acct` 0 for a member).
fn entra() -> Vendor {
    Vendor {
        preset: Preset::Entra,
        typ: "JWT",
        deploy: |_| {},
        person: |scope| {
            json!({
                "iss": ISSUER, "aud": AUDIENCE, "sub": "pairwise-sub-of-this-app",
                "oid": "oid-of-the-person", "tid": "tenant-1", "azp": FIRST_PARTY,
                "uti": "uti-person", "ver": "2.0", "iat": now(), "exp": now() + 300,
                "scp": scope, "acct": 0,
            })
        },
        app: |scope| {
            json!({
                "iss": ISSUER, "aud": AUDIENCE, "sub": "sp-object-id", "oid": "sp-object-id",
                "tid": "tenant-1", "azp": MACHINE, "uti": "uti-app", "ver": "2.0",
                "iat": now(), "exp": now() + 300, "idtyp": "app",
                "roles": scope.split(' ').collect::<Vec<_>>(),
            })
        },
        person_key: "oid-of-the-person",
    }
}

/// Keycloak: `azp` and `scope` on every token (`con-protocol-mappers.adoc`),
/// and a service account a user whose `sub` the deployment lists
/// (`admin-cli.adoc`).
fn keycloak() -> Vendor {
    Vendor {
        preset: Preset::Keycloak,
        typ: "JWT",
        deploy: |profile| {
            profile.app_only = vec![Marker::Subjects(vec![String::from("service-account-uuid")])];
        },
        person: |scope| {
            json!({
                "iss": ISSUER, "aud": AUDIENCE, "sub": "user-uuid", "azp": FIRST_PARTY,
                "iat": now(), "exp": now() + 300, "jti": "jti-person", "scope": scope,
            })
        },
        app: |scope| {
            json!({
                "iss": ISSUER, "aud": AUDIENCE, "sub": "service-account-uuid", "azp": MACHINE,
                "iat": now(), "exp": now() + 300, "jti": "jti-app", "scope": scope,
            })
        },
        person_key: "user-uuid",
    }
}

/// Okta: `cid`, `uid` and `scp` as an array (Okta, "OpenID Connect & OAuth
/// 2.0 API", the reserved claims of the access token); the page states no
/// `typ`, so the deployment declares the one its server writes.
fn okta() -> Vendor {
    Vendor {
        preset: Preset::Okta,
        typ: "JWT",
        deploy: |profile| profile.token_types = vec![String::from("JWT")],
        person: |scope| {
            json!({
                "iss": ISSUER, "aud": AUDIENCE, "sub": "person@example.org", "uid": "okta-uid-1",
                "cid": FIRST_PARTY, "iat": now(), "exp": now() + 300, "jti": "jti-person",
                "scp": scope.split(' ').collect::<Vec<_>>(),
            })
        },
        app: |scope| {
            json!({
                "iss": ISSUER, "aud": AUDIENCE, "sub": MACHINE, "cid": MACHINE,
                "iat": now(), "exp": now() + 300, "jti": "jti-app",
                "scp": scope.split(' ').collect::<Vec<_>>(),
            })
        },
        person_key: "okta-uid-1",
    }
}

/// FerroSMART: plain RFC 9068 (`docs/architecture.md` §13.6 items 2 and 9),
/// `typ` `at+jwt`, a pairwise `sub`, `client_id` and `scope` on every
/// token, the launch context beside them.
fn ferrosmart() -> Vendor {
    Vendor {
        preset: Preset::Ferrosmart,
        typ: "at+jwt",
        deploy: |_| {},
        person: |scope| {
            json!({
                "iss": ISSUER, "aud": AUDIENCE, "sub": "pairwise-person-1",
                "client_id": FIRST_PARTY, "iat": now(), "exp": now() + 300,
                "jti": "jti-person", "scope": scope,
            })
        },
        app: |scope| {
            json!({
                "iss": ISSUER, "aud": AUDIENCE, "sub": MACHINE, "client_id": MACHINE,
                "iat": now(), "exp": now() + 300, "jti": "jti-app", "scope": scope,
            })
        },
        person_key: "pairwise-person-1",
    }
}

/// An issuer of one vendor, with its key and its resolved profile.
struct Harness {
    /// The vendor.
    vendor: Vendor,
    /// The signing key, published in the key set file.
    key: SigningKey,
    /// The profile the server reads under.
    profile: Profile,
}

impl Harness {
    /// Returns the harness of `vendor`.
    fn new(vendor: Vendor) -> Result<Self, Box<dyn StdError>> {
        let mut profile = Profile::resolve(vendor.preset, &ProfileKeys::default())?;
        (vendor.deploy)(&mut profile);
        Ok(Self {
            vendor,
            key: ec_key("k1", Algorithm::ES256),
            profile,
        })
    }

    /// Returns the settings of an issuer of `kind` under the profile as
    /// `tweak` leaves it.
    fn settings(&self, kind: IssuerKind, tweak: impl FnOnce(&mut Profile)) -> Settings {
        let set = json!({ "keys": [self.key.jwk.clone()] }).to_string();
        let mut settings = Settings::new(ISSUER, AUDIENCE, kind);
        settings.jwks_file = Some(temp_file("classify-jwks.json", set.as_bytes()));
        settings.profile = self.profile.clone();
        tweak(&mut settings.profile);
        settings
    }

    /// Returns the caller `claims` authenticate on an issuer of `kind`.
    async fn admit(
        &self,
        kind: IssuerKind,
        tweak: impl FnOnce(&mut Profile),
        claims: &Value,
    ) -> Result<Caller, Rejection> {
        let server = ResourceServer::discover(self.settings(kind, tweak))
            .await
            .expect("the key set file reads");
        let mut header = Header::new(Algorithm::ES256);
        header.kid = Some(String::from("k1"));
        header.typ = Some(String::from(self.vendor.typ));
        server
            .authenticate(&mint_with(&self.key, &header, claims))
            .await
    }

    /// Returns the claims of a person's token granting `scope`.
    #[expect(
        clippy::indexing_slicing,
        reason = "test support: the claims are an object the vendor built"
    )]
    fn person(&self, scope: &str) -> Value {
        let mut claims = (self.vendor.person)(scope);
        claims[&self.profile.scope_claim.claim] = scopes(scope, self.profile.scope_claim.form);
        claims
    }

    /// Returns the claims of the machine's app-only token granting `scope`.
    fn app(&self, scope: &str) -> Value {
        (self.vendor.app)(scope)
    }

    /// Returns the claim the profile reads the client from.
    fn client_claim(&self) -> String {
        self.profile
            .client_claims
            .first()
            .cloned()
            .unwrap_or_default()
    }
}

/// Returns the classification refusal of `outcome`.
fn refused(outcome: Result<Caller, Rejection>) -> Option<Unclassified> {
    match outcome {
        Err(Rejection::Unclassified { reason }) => Some(reason),
        _ => None,
    }
}

/// No change to the profile.
fn keep(_: &mut Profile) {}

/// The cases every vendor runs, in the order the classification decides.
#[expect(
    clippy::indexing_slicing,
    clippy::missing_assert_message,
    reason = "the case bodies are test code, run from each suite's test functions"
)]
mod cases {
    use super::*;

    // NOTE: SMART on openEHR `master08-scopes`: the `patient` context alone names
    // the record subject; on a `patients` issuer that is the `Patient` step.
    pub(super) async fn a_patient_token_on_a_patients_issuer(h: &Harness) -> Outcome {
        let mut claims = h.person("launch/patient patient/Observation.rs");
        claims["patient"] = json!("synthetic-patient");
        let caller = h.admit(IssuerKind::Patients, keep, &claims).await?;
        assert_eq!(&CallerKind::Patient, caller.kind());
        assert!(caller.is_the_person());
        assert_eq!(
            Some(FIRST_PARTY),
            caller.client_id(),
            "the client is recorded"
        );
        Ok(())
    }

    // NOTE: EHDS Art. 4(2) and Art. 5 give the representative the person's
    // rights; the subject and the ground are recorded as asserted (our own design).
    pub(super) async fn a_representative_on_a_declaring_persons_issuer(h: &Harness) -> Outcome {
        let declare = |profile: &mut Profile| {
            profile.representation = Some(Representation {
                claim: String::from("represents"),
                ground_claim: Some(String::from("ground")),
            });
        };
        let mut claims = h.person("user/Observation.rs");
        claims["represents"] = json!("represented-subject-9");
        claims["ground"] = json!("legal-guardian");
        let caller = h.admit(IssuerKind::Persons, declare, &claims).await?;
        assert_eq!(
            &CallerKind::Representative {
                represented: String::from("represented-subject-9"),
                ground: Some(String::from("legal-guardian")),
            },
            caller.kind()
        );
        assert!(!format!("{:?}", caller.kind()).contains("represented-subject-9"));
        claims["act"] = json!({ "sub": "actor-1" });
        assert_eq!(
            Some(Unclassified::RepresentationWithAct),
            refused(h.admit(IssuerKind::Persons, declare, &claims).await)
        );
        let refusal = ResourceServer::discover(h.settings(IssuerKind::Patients, declare)).await;
        assert!(
            matches!(refusal, Err(ResourceError::Profile(_))),
            "representation is declared on persons issuers only"
        );
        Ok(())
    }

    // NOTE: SMART App Launch 2.2.0, Scopes and Launch Context, §Patient-specific
    // scopes names what a `patient/` scope reaches, never who asks.
    pub(super) async fn a_persons_token_with_patient_scopes_is_never_patient_context(
        h: &Harness,
    ) -> Outcome {
        let mixed = h.person("user/Practitioner.r patient/Observation.rs");
        let caller = h.admit(IssuerKind::Persons, keep, &mixed).await?;
        assert_eq!(&CallerKind::Person, caller.kind());
        assert!(!caller.is_the_person());
        let mut confined = h.person("patient/Observation.rs");
        confined["patient"] = json!("synthetic-patient");
        let context = |profile: &mut Profile| profile.patient_context = true;
        let caller = h.admit(IssuerKind::Persons, context, &confined).await?;
        assert_eq!(&CallerKind::Person, caller.kind());
        assert!(!caller.is_the_person());
        assert_eq!(
            Some(Compartment::Patient(String::from("synthetic-patient"))),
            caller.reach(Permission::Read, "Observation"),
            "a Person confined to its launch context"
        );
        Ok(())
    }

    // NOTE: RFC 9068 §2.2: with a resource owner involved, as in the
    // authorization code grant, `sub` names the resource owner.
    pub(super) async fn an_authorization_code_token_is_a_person(h: &Harness) -> Outcome {
        let caller = h
            .admit(IssuerKind::Persons, keep, &h.person("user/Observation.rs"))
            .await?;
        assert_eq!(&CallerKind::Person, caller.kind());
        assert_eq!(Some(h.vendor.person_key), caller.person_key());
        assert_eq!(Some(FIRST_PARTY), caller.client_id());
        Ok(())
    }

    // NOTE: RFC 8693 §4.1: `act` identifies "the acting party to whom authority
    // has been delegated", by `iss` and `sub`; prior actors are informational only.
    pub(super) async fn an_rfc_8693_actor_is_delegated_as_asserted(h: &Harness) -> Outcome {
        let mut claims = h.person("user/Observation.rs");
        claims["act"] = json!({ "sub": "actor-1" });
        let caller = h.admit(IssuerKind::Persons, keep, &claims).await?;
        assert_eq!(
            &CallerKind::Delegated {
                actor: Actor {
                    issuer: String::from(ISSUER),
                    sub: String::from("actor-1"),
                },
            },
            caller.kind()
        );
        claims["act"] = json!({ "sub": "actor-1", "iss": "https://other.example.org" });
        let caller = h.admit(IssuerKind::Persons, keep, &claims).await?;
        assert_eq!(
            &CallerKind::Delegated {
                actor: Actor {
                    issuer: String::from("https://other.example.org"),
                    sub: String::from("actor-1"),
                },
            },
            caller.kind(),
            "the actor is its issuer and its sub together"
        );
        claims["act"] = json!({ "sub": "actor-1", "act": { "sub": "prior" } });
        assert_eq!(
            Some(Unclassified::ActorChain),
            refused(h.admit(IssuerKind::Persons, keep, &claims).await),
            "a chain deeper than one actor is refused unless declared"
        );
        let deeper = |profile: &mut Profile| profile.max_actor_chain = 2;
        assert!(h.admit(IssuerKind::Persons, deeper, &claims).await.is_ok());
        Ok(())
    }

    // NOTE: RFC 9068 §5 describes an issuer that "elects to use the client_id as
    // the sub value" for the client credentials grant; the profile marks it.
    pub(super) async fn a_client_credentials_token_is_a_system(h: &Harness) -> Outcome {
        for kind in [IssuerKind::Persons, IssuerKind::Machines] {
            let caller = h.admit(kind, keep, &h.app("system/Observation.rs")).await?;
            assert_eq!(&CallerKind::System, caller.kind(), "{kind}");
            assert_eq!(Some(MACHINE), caller.client_id());
            assert_eq!(
                Some(Compartment::Any),
                caller.reach(Permission::Read, "Observation")
            );
        }
        Ok(())
    }

    // NOTE: RFC 9068 §4 has the resource server check that `aud` names it, and RFC
    // 8707 lets the issuer issue a token only for the resources its client may reach.
    pub(super) async fn every_client_of_a_token_for_this_server_is_admitted(
        h: &Harness,
    ) -> Outcome {
        let mut claims = h.person("user/Observation.rs");
        claims[h.client_claim()] = json!(THIRD_PARTY);
        let caller = h.admit(IssuerKind::Persons, keep, &claims).await?;
        assert_eq!(&CallerKind::Person, caller.kind());
        assert_eq!(
            Some(THIRD_PARTY),
            caller.client_id(),
            "the client is recorded"
        );
        let mut clientless = h.person("user/Observation.rs");
        if let Some(object) = clientless.as_object_mut() {
            object.remove(&h.client_claim());
        }
        let outcome = h
            .admit(
                IssuerKind::Persons,
                |profile| {
                    profile
                        .required_claims
                        .retain(|claim| claim != "azp" && claim != "cid" && claim != "client_id");
                },
                &clientless,
            )
            .await;
        assert_eq!(Some(Unclassified::NoClient), refused(outcome));
        Ok(())
    }

    pub(super) async fn an_expect_claim_and_the_impersonation_marker_are_refused(
        h: &Harness,
    ) -> Outcome {
        let expecting = |profile: &mut Profile| {
            profile
                .expect
                .insert(String::from("token_format"), String::from("2"));
        };
        let claims = h.person("user/Observation.rs");
        assert_eq!(
            Some(Unclassified::Expected {
                claim: String::from("token_format")
            }),
            refused(h.admit(IssuerKind::Persons, expecting, &claims).await)
        );
        let marked = |profile: &mut Profile| {
            profile.impersonation_marker = Some(String::from("impersonator"));
        };
        let mut impersonated = claims.clone();
        impersonated["impersonator"] = json!({ "id": "admin-1" });
        assert_eq!(
            Some(Unclassified::Impersonation),
            refused(h.admit(IssuerKind::Persons, marked, &impersonated).await)
        );
        assert!(h.admit(IssuerKind::Persons, marked, &claims).await.is_ok());
        Ok(())
    }

    pub(super) async fn a_token_matching_no_step_is_refused_once_per_kind(h: &Harness) -> Outcome {
        assert_eq!(
            Some(Unclassified::NotPatientContext),
            refused(
                h.admit(IssuerKind::Patients, keep, &h.person("user/Observation.rs"))
                    .await
            )
        );
        assert_eq!(
            Some(Unclassified::NotAppOnly),
            refused(
                h.admit(
                    IssuerKind::Machines,
                    keep,
                    &h.person("system/Observation.rs")
                )
                .await
            )
        );
        // NOTE: a federation token is classified by its issuer's federation table
        // (tests/it/federation.rs); an issuer without one never loads.
        assert!(
            matches!(
                ResourceServer::discover(h.settings(IssuerKind::Federation, keep)).await,
                Err(ResourceError::Kind { .. })
            ),
            "a federation issuer without its table"
        );
        Ok(())
    }

    pub(super) async fn a_guest_marker_makes_a_guest(h: &Harness) -> Outcome {
        let guests = |profile: &mut Profile| {
            profile.guest = vec![Marker::Claim {
                claim: String::from("guest_of"),
                value: String::from("tenant-2"),
            }];
        };
        let mut claims = h.person("user/Observation.rs");
        claims["guest_of"] = json!("tenant-2");
        let caller = h.admit(IssuerKind::Persons, guests, &claims).await?;
        assert_eq!(
            &CallerKind::Guest(Box::new(CallerKind::Person)),
            caller.kind()
        );
        Ok(())
    }
}

/// Runs every case of [`cases`] against one vendor.
macro_rules! suite {
    ($vendor:ident) => {
        mod $vendor {
            use super::*;

            #[tokio::test]
            async fn a_patient_token_on_a_patients_issuer() -> Outcome {
                cases::a_patient_token_on_a_patients_issuer(&Harness::new(super::$vendor())?).await
            }

            #[tokio::test]
            async fn a_representative_on_a_declaring_persons_issuer() -> Outcome {
                cases::a_representative_on_a_declaring_persons_issuer(&Harness::new(
                    super::$vendor(),
                )?)
                .await
            }

            #[tokio::test]
            async fn a_persons_token_with_patient_scopes_is_never_patient_context() -> Outcome {
                cases::a_persons_token_with_patient_scopes_is_never_patient_context(&Harness::new(
                    super::$vendor(),
                )?)
                .await
            }

            #[tokio::test]
            async fn an_authorization_code_token_is_a_person() -> Outcome {
                cases::an_authorization_code_token_is_a_person(&Harness::new(super::$vendor())?)
                    .await
            }

            #[tokio::test]
            async fn an_rfc_8693_actor_is_delegated_as_asserted() -> Outcome {
                cases::an_rfc_8693_actor_is_delegated_as_asserted(&Harness::new(super::$vendor())?)
                    .await
            }

            #[tokio::test]
            async fn a_client_credentials_token_is_a_system() -> Outcome {
                cases::a_client_credentials_token_is_a_system(&Harness::new(super::$vendor())?)
                    .await
            }

            #[tokio::test]
            async fn every_client_of_a_token_for_this_server_is_admitted() -> Outcome {
                cases::every_client_of_a_token_for_this_server_is_admitted(&Harness::new(
                    super::$vendor(),
                )?)
                .await
            }

            #[tokio::test]
            async fn an_expect_claim_and_the_impersonation_marker_are_refused() -> Outcome {
                cases::an_expect_claim_and_the_impersonation_marker_are_refused(&Harness::new(
                    super::$vendor(),
                )?)
                .await
            }

            #[tokio::test]
            async fn a_token_matching_no_step_is_refused_once_per_kind() -> Outcome {
                cases::a_token_matching_no_step_is_refused_once_per_kind(&Harness::new(
                    super::$vendor(),
                )?)
                .await
            }

            #[tokio::test]
            async fn a_guest_marker_makes_a_guest() -> Outcome {
                cases::a_guest_marker_makes_a_guest(&Harness::new(super::$vendor())?).await
            }
        }
    };
}

suite!(generic);
suite!(entra);
suite!(keycloak);
suite!(okta);
suite!(ferrosmart);

// NOTE: owner ruling of 2026-11-05: a Basic credential is a person's; a machine
// uses the client credentials grant (RFC 6749 §4.4) and is classified by its token.
#[test]
fn a_basic_credential_is_a_person_and_never_a_system() {
    let caller = Caller::basic(String::from("etl"), "system/*.rs");
    assert_eq!(&CallerKind::Person, caller.kind());
    assert_ne!(&CallerKind::System, caller.kind());
}

/// The Entra ID cases of its profile's own claims.
mod entra_profile {
    use super::*;

    // NOTE: Microsoft, "Access token claims reference": `oid` is "The immutable
    // identifier for the requestor"; `sub` is pairwise per application.
    #[tokio::test]
    async fn oid_is_the_person_key_and_tid_the_tenant() -> Outcome {
        let h = Harness::new(entra())?;
        let caller = h
            .admit(IssuerKind::Persons, keep, &h.person("user/Observation.rs"))
            .await?;
        assert_eq!(Some("oid-of-the-person"), caller.person_key());
        assert_eq!(Some("tenant-1"), caller.tenant());
        assert_eq!("pairwise-sub-of-this-app", caller.subject());
        Ok(())
    }

    // NOTE: Microsoft, "Optional claims reference": `idtyp` is `app` for an
    // app-only token; "Access token claims reference": `roles` carries its permissions.
    #[tokio::test]
    async fn idtyp_marks_an_app_only_token_whose_permissions_are_its_roles() -> Outcome {
        let h = Harness::new(entra())?;
        let caller = h
            .admit(IssuerKind::Machines, keep, &h.app("system/Observation.rs"))
            .await?;
        assert_eq!(&CallerKind::System, caller.kind());
        assert!(caller.has_scope("system/Observation.rs"));
        let mut disagreeing = h.app("system/Observation.rs");
        disagreeing["scp"] = json!("user/Observation.rs");
        assert_eq!(
            Some(Unclassified::MarkersDisagree),
            refused(h.admit(IssuerKind::Machines, keep, &disagreeing).await),
            "an app-only idtyp beside a user token's scp"
        );
        Ok(())
    }

    // NOTE: Microsoft, "Optional claims reference": `acct` is `1` for a guest;
    // "Access token claims reference": `idp` differs from `iss` for a guest.
    #[tokio::test]
    async fn a_guest_by_acct_and_a_member_of_another_tenant_by_idp() -> Outcome {
        let h = Harness::new(entra())?;
        let mut by_acct = h.person("user/Observation.rs");
        by_acct["acct"] = json!(1);
        let caller = h.admit(IssuerKind::Persons, keep, &by_acct).await?;
        assert_eq!(
            &CallerKind::Guest(Box::new(CallerKind::Person)),
            caller.kind()
        );
        let mut by_idp = h.person("user/Observation.rs");
        by_idp["acct"] = json!(0);
        by_idp["idp"] = json!("https://sts.example.org/home-tenant/");
        let caller = h.admit(IssuerKind::Persons, keep, &by_idp).await?;
        assert_eq!(
            &CallerKind::Guest(Box::new(CallerKind::Person)),
            caller.kind()
        );
        let mut home = h.person("user/Observation.rs");
        home["idp"] = json!(ISSUER);
        let caller = h.admit(IssuerKind::Persons, keep, &home).await?;
        assert_eq!(&CallerKind::Person, caller.kind(), "idp equal to iss");
        Ok(())
    }

    // NOTE: Microsoft, "Optional claims reference": `acct` is an optional claim
    // the app registration must ask for, so its absence names the configuration.
    #[tokio::test]
    async fn a_user_token_without_acct_is_refused_naming_the_claim() -> Outcome {
        let h = Harness::new(entra())?;
        let mut claims = h.person("user/Observation.rs");
        claims.as_object_mut().ok_or("an object")?.remove("acct");
        assert_eq!(
            Some(Unclassified::UserClaim {
                claim: String::from("acct")
            }),
            refused(h.admit(IssuerKind::Persons, keep, &claims).await)
        );
        Ok(())
    }

    // NOTE: Microsoft, "Access token claims reference": `ver` is "either `1.0`
    // or `2.0`", and `azp` is "only present in v2.0 tokens".
    #[tokio::test]
    async fn a_v1_token_is_refused_by_expect() -> Outcome {
        let h = Harness::new(entra())?;
        let mut claims = h.person("user/Observation.rs");
        claims["ver"] = json!("1.0");
        assert_eq!(
            Some(Unclassified::Expected {
                claim: String::from("ver")
            }),
            refused(h.admit(IssuerKind::Persons, keep, &claims).await)
        );
        Ok(())
    }
}

/// The Keycloak cases of its profile's own claims.
mod keycloak_profile {
    use super::*;

    // NOTE: Keycloak 26.8.0 release notes: an impersonation session's tokens carry the RFC
    // 8693 `act` claim, which TokenManager.java fills with `sub` and `preferred_username`.
    #[tokio::test]
    async fn an_impersonation_is_an_actor_delegated() -> Outcome {
        let h = Harness::new(keycloak())?;
        let mut claims = h.person("user/Observation.rs");
        claims["act"] = json!({ "sub": "admin-user-uuid", "preferred_username": "admin" });
        let caller = h.admit(IssuerKind::Persons, keep, &claims).await?;
        assert_eq!(
            &CallerKind::Delegated {
                actor: Actor {
                    issuer: String::from(ISSUER),
                    sub: String::from("admin-user-uuid"),
                },
            },
            caller.kind(),
            "an act with no iss names an actor of the token's own issuer"
        );
        Ok(())
    }

    // NOTE: Keycloak 26.8.2 OIDCLoginProtocolFactory.java: the built-in IMPERSONATOR_ID and
    // IMPERSONATOR_USERNAME session note mappers write `impersonator.id` and `.username`.
    #[tokio::test]
    async fn the_built_in_impersonator_mappers_and_marker_refuse_every_impersonation() -> Outcome {
        let h = Harness::new(keycloak())?;
        assert_eq!(None, h.profile.impersonation_marker, "no default marker");
        let mut claims = h.person("user/Observation.rs");
        claims["impersonator"] = json!({ "id": "admin-user-uuid", "username": "admin" });
        let marked = |profile: &mut Profile| {
            profile.impersonation_marker = Some(String::from("impersonator"));
        };
        assert_eq!(
            Some(Unclassified::Impersonation),
            refused(h.admit(IssuerKind::Persons, marked, &claims).await)
        );
        Ok(())
    }

    // NOTE: Keycloak 26.8.2 `con-protocol-mappers.adoc`: a session note reaches a token only
    // through a mapper, so the preset marks nothing until the deployment names a claim.
    #[tokio::test]
    async fn a_token_carrying_the_configured_impersonation_claim_is_refused() -> Outcome {
        let h = Harness::new(keycloak())?;
        assert_eq!(None, h.profile.impersonation_marker, "no default marker");
        let mut claims = h.person("user/Observation.rs");
        claims["impersonator_id"] = json!("admin-user-uuid");
        assert!(
            h.admit(IssuerKind::Persons, keep, &claims).await.is_ok(),
            "an unmapped claim marks nothing"
        );
        let mapped = |profile: &mut Profile| {
            profile.impersonation_marker = Some(String::from("impersonator_id"));
        };
        assert_eq!(
            Some(Unclassified::Impersonation),
            refused(h.admit(IssuerKind::Persons, mapped, &claims).await)
        );
        Ok(())
    }

    // NOTE: Keycloak 26.8.2, `admin-cli.adoc`: "A client's service account is a
    // user account with username `service-account-CLIENT_ID`".
    #[tokio::test]
    async fn a_listed_service_account_is_a_system_and_the_preset_needs_the_list() -> Outcome {
        let h = Harness::new(keycloak())?;
        let caller = h
            .admit(IssuerKind::Machines, keep, &h.app("system/Observation.rs"))
            .await?;
        assert_eq!(&CallerKind::System, caller.kind());
        let unlisted = Harness::new(Vendor {
            deploy: |_| {},
            ..keycloak()
        })?;
        assert!(
            matches!(
                ResourceServer::discover(unlisted.settings(IssuerKind::Machines, keep)).await,
                Err(ResourceError::Profile(_))
            ),
            "the preset's empty subject list refuses the issuer until it is set"
        );
        Ok(())
    }
}

/// The Okta cases of its profile's own claims.
mod okta_profile {
    use super::*;

    // NOTE: Okta, "OpenID Connect & OAuth 2.0 API": `uid` is "A unique identifier
    // for the user", absent "if there is no user bound to it".
    #[tokio::test]
    async fn uid_is_the_person_key_and_its_absence_a_system() -> Outcome {
        let h = Harness::new(okta())?;
        let caller = h
            .admit(IssuerKind::Persons, keep, &h.person("user/Observation.rs"))
            .await?;
        assert_eq!(Some("okta-uid-1"), caller.person_key());
        let caller = h
            .admit(IssuerKind::Persons, keep, &h.app("system/Observation.rs"))
            .await?;
        assert_eq!(&CallerKind::System, caller.kind());
        Ok(())
    }

    // NOTE: the Okta page lists `alg` and `kid` as the header's only reserved
    // claims, so the preset declares no `typ` and the deployment must.
    #[tokio::test]
    async fn the_preset_needs_the_deployments_token_types() -> Outcome {
        let h = Harness::new(Vendor {
            deploy: |_| {},
            ..okta()
        })?;
        assert!(matches!(
            ResourceServer::discover(h.settings(IssuerKind::Persons, keep)).await,
            Err(ResourceError::Profile(_))
        ));
        Ok(())
    }
}

/// The FerroSMART cases of a patient's own token (#681).
#[expect(
    clippy::indexing_slicing,
    reason = "test code: the claims are objects the vendor built"
)]
mod ferrosmart_profile {
    use super::*;

    /// The patient of every case.
    const PATIENT: &str = "synthetic-patient";

    /// Returns a patient's own token through `client`: `fhirUser` the
    /// `Patient` the `patient` claim names, and `scope`.
    fn own(h: &Harness, client: &str, scope: &str) -> Value {
        let mut claims = h.person(scope);
        claims["client_id"] = json!(client);
        claims["patient"] = json!(PATIENT);
        claims["fhirUser"] = json!(format!("Patient/{PATIENT}"));
        claims
    }

    // NOTE: no specification governs who asks under a `patient/` scope (SMART App
    // Launch 2.2.0, Patient-specific scopes): the owner's decision on #681.
    #[tokio::test]
    async fn a_patients_own_token_through_any_client_is_the_person() -> Outcome {
        let h = Harness::new(ferrosmart())?;
        let claims = own(
            &h,
            FIRST_PARTY,
            "openid fhirUser launch/patient patient/Observation.rs",
        );
        let caller = h.admit(IssuerKind::Persons, keep, &claims).await?;
        assert_eq!(&CallerKind::Patient, caller.kind());
        assert!(caller.is_the_person());
        assert_eq!(
            Some(PATIENT),
            caller.person().and_then(|person| person.patient),
            "bound to its patient"
        );
        assert_eq!(
            Some(FIRST_PARTY),
            caller.client_id(),
            "the client is recorded"
        );
        let claims = own(&h, THIRD_PARTY, "patient/Observation.rs");
        let caller = h.admit(IssuerKind::Persons, keep, &claims).await?;
        assert_eq!(
            &CallerKind::Patient,
            caller.kind(),
            "through another client"
        );
        Ok(())
    }

    // NOTE: RFC 9068 §4 has the resource server check that `aud` names it.
    #[tokio::test]
    async fn a_token_for_another_server_is_refused_before_the_client_is_read() -> Outcome {
        let h = Harness::new(ferrosmart())?;
        let mut claims = h.person("openid user/Observation.rs");
        claims["client_id"] = json!(THIRD_PARTY);
        claims["aud"] = json!("https://elsewhere.example.org/fhir");
        assert!(
            matches!(
                h.admit(IssuerKind::Persons, keep, &claims).await,
                Err(Rejection::Invalid {
                    reason: ferrohealth_smart::refusal::Reason::Audience
                })
            ),
            "a token for another server is refused"
        );
        Ok(())
    }

    // NOTE: SMART App Launch 2.2.0, Scopes and Launch Context, `launch/patient`: the
    // authorization server's own picker acts for the signed-in person (#730).
    #[tokio::test]
    async fn the_pickers_token_is_the_person() -> Outcome {
        let h = Harness::new(ferrosmart())?;
        let mut claims = h.person("openid fhirUser user/Patient.rs");
        claims["client_id"] = json!(ISSUER);
        let caller = h.admit(IssuerKind::Persons, keep, &claims).await?;
        assert_eq!(&CallerKind::Person, caller.kind());
        assert_eq!(
            Some(ISSUER),
            caller.client_id(),
            "the access record names FerroSMART as the client"
        );
        Ok(())
    }

    // NOTE: SMART App Launch 2.2.0, Scopes and Launch Context, `launch/patient`: the
    // patient context is the authorization server's to set, read per issuer (#730).
    #[tokio::test]
    async fn only_an_issuer_with_patient_context_sets_the_patient() -> Outcome {
        let h = Harness::new(ferrosmart())?;
        let mut claims = h.person("launch/patient patient/Observation.rs");
        claims["patient"] = json!(PATIENT);
        let caller = h.admit(IssuerKind::Persons, keep, &claims).await?;
        assert_eq!(
            Some(PATIENT),
            caller.patient(),
            "on under the ferrosmart preset"
        );
        let generic = Harness::new(generic())?;
        let mut claims = generic.person("launch/patient patient/Observation.rs");
        claims["patient"] = json!(PATIENT);
        let caller = generic.admit(IssuerKind::Persons, keep, &claims).await?;
        assert_eq!(None, caller.patient(), "off under every other preset");
        let on = |profile: &mut Profile| profile.patient_context = true;
        let caller = generic.admit(IssuerKind::Persons, on, &claims).await?;
        assert_eq!(
            Some(PATIENT),
            caller.patient(),
            "an explicit key turns it on"
        );
        Ok(())
    }

    // NOTE: SMART App Launch 2.2.0, Scopes for requesting identity data: the
    // `fhirUser` URL MAY be absolute or relative to the FHIR base.
    #[tokio::test]
    async fn an_absolute_fhir_user_names_the_patient_too() -> Outcome {
        let h = Harness::new(ferrosmart())?;
        let mut claims = own(&h, FIRST_PARTY, "patient/Observation.rs");
        claims["fhirUser"] = json!(format!("https://fhir.example.org/r4/Patient/{PATIENT}"));
        let caller = h.admit(IssuerKind::Persons, keep, &claims).await?;
        assert_eq!(&CallerKind::Patient, caller.kind());
        for other in [
            format!("Group/Patient/{PATIENT}"),
            format!("XPatient/{PATIENT}"),
            format!("Patient/{PATIENT}/_history/1"),
            format!("https://fhir.example.org/r4/Practitioner/{PATIENT}"),
        ] {
            claims["fhirUser"] = json!(other);
            let caller = h.admit(IssuerKind::Persons, keep, &claims).await?;
            assert_eq!(
                &CallerKind::Person,
                caller.kind(),
                "{other} names no patient"
            );
        }
        Ok(())
    }

    #[tokio::test]
    async fn each_condition_alone_keeps_the_token_a_professionals() -> Outcome {
        let h = Harness::new(ferrosmart())?;
        let mut other_patient = own(&h, FIRST_PARTY, "patient/Observation.rs");
        other_patient["patient"] = json!("another-patient");
        let mut no_fhir_user = own(&h, FIRST_PARTY, "patient/Observation.rs");
        if let Some(object) = no_fhir_user.as_object_mut() {
            object.remove("fhirUser");
        }
        let mut no_patient = own(&h, FIRST_PARTY, "patient/Observation.rs");
        if let Some(object) = no_patient.as_object_mut() {
            object.remove("patient");
        }
        let mut practitioner = own(&h, FIRST_PARTY, "patient/Observation.rs");
        practitioner["fhirUser"] = json!(format!("Practitioner/{PATIENT}"));
        let cases = [
            ("a patient claim naming another patient", other_patient),
            ("no fhirUser", no_fhir_user),
            ("no patient claim", no_patient),
            ("a Practitioner fhirUser", practitioner),
            (
                "a user/ scope",
                own(
                    &h,
                    FIRST_PARTY,
                    "patient/Observation.rs user/Practitioner.r",
                ),
            ),
            (
                "a system/ scope",
                own(
                    &h,
                    FIRST_PARTY,
                    "patient/Observation.rs system/Observation.r",
                ),
            ),
            (
                "no patient/ scope",
                own(&h, FIRST_PARTY, "openid fhirUser launch/patient"),
            ),
        ];
        for (case, claims) in cases {
            let caller = h.admit(IssuerKind::Persons, keep, &claims).await?;
            assert_eq!(&CallerKind::Person, caller.kind(), "{case}");
            assert!(!caller.is_the_person(), "{case}");
        }
        Ok(())
    }

    // NOTE: RFC 8693 §4.1, an `act` names another acting party, so a token that
    // carries one is never the person's own.
    #[tokio::test]
    async fn an_actor_or_a_represented_subject_is_never_the_patients_own() -> Outcome {
        let h = Harness::new(ferrosmart())?;
        let mut acted = own(&h, FIRST_PARTY, "patient/Observation.rs");
        acted["act"] = json!({ "sub": "actor-1" });
        let caller = h.admit(IssuerKind::Persons, keep, &acted).await?;
        assert!(matches!(caller.kind(), CallerKind::Delegated { .. }));
        let mut represented = own(&h, FIRST_PARTY, "patient/Observation.rs");
        represented["represents"] = json!("represented-subject-9");
        let declare = |profile: &mut Profile| {
            profile.representation = Some(Representation {
                claim: String::from("represents"),
                ground_claim: None,
            });
        };
        let caller = h.admit(IssuerKind::Persons, declare, &represented).await?;
        assert!(matches!(caller.kind(), CallerKind::Representative { .. }));
        Ok(())
    }

    #[tokio::test]
    async fn the_reading_is_the_profile_keys_and_no_other_preset_sets_it() -> Outcome {
        let h = Harness::new(ferrosmart())?;
        let claims = own(&h, FIRST_PARTY, "patient/Observation.rs");
        let caller = h
            .admit(
                IssuerKind::Persons,
                |profile| profile.fhir_user_patient = false,
                &claims,
            )
            .await?;
        assert_eq!(&CallerKind::Person, caller.kind(), "the key off");
        for preset in [
            Preset::Rfc9068,
            Preset::Entra,
            Preset::Keycloak,
            Preset::Okta,
        ] {
            assert!(!Profile::resolve(preset, &ProfileKeys::default())?.fhir_user_patient);
        }
        Ok(())
    }
}

#[tokio::test]
async fn every_preset_key_is_overridable_on_the_issuer() -> Outcome {
    let h = Harness::new(entra())?;
    let caller = h
        .admit(
            IssuerKind::Persons,
            |profile| profile.person_key = String::from("sub"),
            &h.person("user/Observation.rs"),
        )
        .await?;
    assert_eq!(Some("pairwise-sub-of-this-app"), caller.person_key());
    Ok(())
}

// NOTE: no specification governs adapters: our own design, in which a profile naming an
// adapter whose feature this build leaves out fails to load.
#[cfg(not(feature = "idp-entra"))]
#[tokio::test]
async fn a_profile_naming_an_adapter_this_build_lacks_fails_to_load() -> Outcome {
    let h = Harness::new(entra())?;
    let settings = h.settings(IssuerKind::Persons, |profile| {
        profile.adapter = Some(String::from("idp-entra"));
    });
    assert!(matches!(
        ResourceServer::discover(settings).await,
        Err(ResourceError::Profile(_))
    ));
    Ok(())
}

#[test]
fn no_core_module_names_a_vendor() -> Outcome {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut stack = vec![root.clone()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir)? {
            let path = entry?.path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            // NOTE: the preset selector is data naming the shipped files, and `idp` holds the
            // adapters, the two places a vendor's name stands (no specification governs this).
            if path.ends_with("profile/mod.rs") || path.starts_with(root.join("idp")) {
                continue;
            }
            let text = std::fs::read_to_string(&path)?.to_lowercase();
            let words: Vec<&str> = text.split(|c: char| !c.is_ascii_alphanumeric()).collect();
            for vendor in ["entra", "keycloak", "okta", "azure", "microsoft"] {
                assert!(
                    !words.contains(&vendor),
                    "{} names {vendor}",
                    path.display()
                );
            }
        }
    }
    Ok(())
}

// NOTE: no specification governs adapters: our own design, in which a name no feature
// compiles in refuses the issuer in every build, and the error names it.
#[tokio::test]
async fn a_profile_naming_an_unknown_adapter_fails_to_load_naming_it() -> Outcome {
    let h = Harness::new(entra())?;
    let settings = h.settings(IssuerKind::Persons, |profile| {
        profile.adapter = Some(String::from("idp-unknown"));
    });
    let refused = ResourceServer::discover(settings).await;
    assert!(
        matches!(
            &refused,
            Err(ResourceError::Profile(ProfileError::Adapter { adapter })) if adapter == "idp-unknown"
        ),
        "{refused:?}"
    );
    Ok(())
}

// NOTE: no specification governs adapters: our own design, in which a profile may name an
// adapter this build compiles in.
#[cfg(feature = "idp-entra")]
#[tokio::test]
async fn a_profile_naming_the_compiled_adapter_loads() -> Outcome {
    let h = Harness::new(entra())?;
    let settings = h.settings(IssuerKind::Persons, |profile| {
        profile.adapter = Some(String::from(ferrohealth_smart::idp::entra::NAME));
    });
    assert!(ResourceServer::discover(settings).await.is_ok());
    Ok(())
}
