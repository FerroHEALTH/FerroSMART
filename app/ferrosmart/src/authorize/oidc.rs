// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The OpenID Connect parameters of an app's authorization request: what
//! OpenID Connect Core 1.0 §15.1 has every OpenID Provider support
//! (`prompt`, `display`, `ui_locales`, `claims_locales`, `max_age`,
//! `acr_values`), read beside SMART App Launch 2.2.0's own parameters,
//! which keep their rules (`docs/architecture.md` §13.25).

use url::Url;

use crate::assurance::Assurance;
use crate::form::Params;
use crate::store::{Asking, Prompt};

use super::Denial;

/// Reads what `params` ask of the person's login.
///
/// `prompt=none` is `login_required`: FerroSMART keeps no session of its
/// own, so every authorization request logs the person in upstream, and
/// "an error is returned if an End-User is not already authenticated"
/// (OpenID Connect Core 1.0 §3.1.2.1). `display` and `claims_locales` are
/// taken and do not change the flow, the minimum §15.1 sets for each.
/// `acr_values` naming an eIDAS level is a level the login must reach
/// (RFC 9470 §5); any other value is taken and ignored.
pub(super) fn read(params: &Params) -> Result<Asking, Denial> {
    let mut asking = Asking::default();
    if let Some(prompt) = params.get("prompt") {
        let values: Vec<&str> = prompt
            .split(' ')
            .filter(|value| !value.is_empty())
            .collect();
        // NOTE: OpenID Connect Core 1.0 §3.1.2.1: none with any other value is an error.
        if values.contains(&"none") {
            return Err(if values.len() == 1 {
                Denial {
                    error: "login_required",
                    description: "the person must log in, and prompt is none",
                }
            } else {
                Denial::request("prompt none is combined with another value")
            });
        }
        asking.prompt = Prompt::of(&values.join(" "));
    }
    if let Some(max_age) = params.get("max_age") {
        // NOTE: OpenID Connect Core 1.0 §3.1.2.1: max_age is a number of seconds.
        let seconds = max_age
            .parse::<i64>()
            .ok()
            .filter(|seconds| *seconds >= 0)
            .ok_or(Denial::request("the max_age is not a number of seconds"))?;
        // NOTE: OpenID Connect Core 1.0 §3.1.2.1: max_age=0 is equivalent to prompt=login.
        asking.prompt.login |= seconds == 0;
        asking.max_age = Some(seconds);
    }
    asking.ui_locales = params.get("ui_locales").map(str::to_owned);
    asking.acr = params
        .get("acr_values")
        .and_then(crate::assurance::requested);
    Ok(asking)
}

/// Returns the upstream authorization request `url` carrying what `asking`
/// passes on: `prompt` (`login`, `select_account`, beside any value the
/// request already carries), `max_age` and `ui_locales` (OpenID Connect
/// Core 1.0 §3.1.2.1), and as `acr_values` the provider's values that reach
/// both the level asked and the provider's minimum, by its `assurance`.
pub(super) fn upstream(mut url: Url, asking: &Asking, assurance: &Assurance) -> Url {
    let mut pairs: Vec<(String, String)> = url.query_pairs().into_owned().collect();
    let mut prompt: Vec<String> = pairs
        .iter()
        .filter(|(name, _)| name == "prompt")
        .flat_map(|(_, value)| value.split(' ').map(str::to_owned).collect::<Vec<_>>())
        .collect();
    for (asked, value) in [
        (asking.prompt.login, "login"),
        (asking.prompt.select_account, "select_account"),
    ] {
        if asked && !prompt.iter().any(|kept| kept == value) {
            prompt.push(value.to_owned());
        }
    }
    pairs.retain(|(name, _)| name != "prompt");
    if !prompt.is_empty() {
        pairs.push((String::from("prompt"), prompt.join(" ")));
    }
    if let Some(max_age) = asking.max_age {
        pairs.push((String::from("max_age"), max_age.to_string()));
    }
    if let Some(ui_locales) = &asking.ui_locales {
        pairs.push((String::from("ui_locales"), ui_locales.clone()));
    }
    if let Some(level) = asking.acr.max(assurance.minimum()) {
        let values = assurance.values_from(level);
        if !values.is_empty() {
            pairs.retain(|(name, _)| name != "acr_values");
            pairs.push((String::from("acr_values"), values.join(" ")));
        }
    }
    url.query_pairs_mut().clear().extend_pairs(pairs);
    url
}

#[cfg(test)]
mod tests {
    use super::*;

    fn read_query(query: &str) -> Result<Asking, Denial> {
        read(&Params::parse(query.as_bytes(), &[]).expect("parses"))
    }

    #[test]
    fn prompt_none_alone_is_login_required_and_beside_another_value_invalid_request() {
        assert_eq!(
            Some("login_required"),
            read_query("prompt=none").err().map(|denial| denial.error)
        );
        assert_eq!(
            Some("invalid_request"),
            read_query("prompt=none+login")
                .err()
                .map(|denial| denial.error)
        );
    }

    #[test]
    fn max_age_zero_is_prompt_login_and_a_negative_or_word_is_refused() {
        let asking = read_query("max_age=0").expect("taken");
        assert!(asking.prompt.login);
        assert_eq!(Some(0), asking.max_age);
        for bad in ["max_age=-1", "max_age=soon", "max_age=1.5"] {
            assert_eq!(
                Some("invalid_request"),
                read_query(bad).err().map(|denial| denial.error),
                "{bad}"
            );
        }
    }

    #[test]
    fn the_upstream_request_keeps_its_prompt_and_adds_the_app_s() {
        let asking = read_query("prompt=login+select_account+consent&max_age=60&ui_locales=nl+en")
            .expect("taken");
        assert!(asking.prompt.consent);
        let url = upstream(
            Url::parse("https://idp.example.org/authorize?tenant=a&prompt=consent").expect("a URL"),
            &asking,
            &Assurance::default(),
        );
        let pairs: Vec<(String, String)> = url.query_pairs().into_owned().collect();
        assert!(pairs.contains(&(String::from("tenant"), String::from("a"))));
        assert!(pairs.contains(&(
            String::from("prompt"),
            String::from("consent login select_account")
        )));
        assert!(pairs.contains(&(String::from("max_age"), String::from("60"))));
        assert!(pairs.contains(&(String::from("ui_locales"), String::from("nl en"))));
        assert_eq!(1, pairs.iter().filter(|(name, _)| name == "prompt").count());
        assert!(!pairs.iter().any(|(name, _)| name == "acr_values"));
    }

    #[test]
    fn the_upstream_request_asks_for_the_provider_s_values_at_the_level_needed() {
        use ferrohealth_smart::assurance::AssuranceLevel;
        let section = crate::assurance::AssuranceSection {
            levels: std::collections::BTreeMap::from([
                (String::from("urn:idp:password"), AssuranceLevel::Low),
                (String::from("urn:idp:app"), AssuranceLevel::Substantial),
                (String::from("urn:idp:wallet"), AssuranceLevel::High),
            ]),
            minimum: None,
        };
        let assurance =
            Assurance::resolve(&section, crate::assurance::Floor::Substantial).expect("resolves");
        let asked = |query: &str| {
            let asking = read_query(query).expect("taken");
            upstream(
                Url::parse("https://idp.example.org/authorize").expect("a URL"),
                &asking,
                &assurance,
            )
            .query_pairs()
            .find(|(name, _)| name == "acr_values")
            .map(|(_, value)| value.into_owned())
        };
        assert_eq!(Some(String::from("urn:idp:app urn:idp:wallet")), asked(""));
        assert_eq!(
            Some(String::from("urn:idp:wallet")),
            asked("acr_values=http%3A%2F%2Feidas.europa.eu%2FLoA%2Fhigh")
        );
        assert_eq!(
            Some(String::from("urn:idp:app urn:idp:wallet")),
            asked("acr_values=urn%3Aother")
        );
    }
}
