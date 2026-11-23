// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The groups a token asserts: the group claim and a claim the token
//! carries elsewhere, intersected with the party's memberships.

use super::*;

// NOTE: OpenID Connect Core 1.0 §5.6.2: `_claim_names` names a claim the token
// carries in another source, so its groups cannot be read from it.
#[tokio::test]
async fn a_group_claim_carried_elsewhere_is_groups_unavailable() -> Outcome2 {
    let source = FakeSource::answering(one_professional());
    let binding = binding(&source);
    let claims = json!({
        "_claim_names": { "groups": "src1" },
        "_claim_sources": { "src1": { "endpoint": "https://claims.invalid/groups" } }
    });
    let outcome = binding.resolve(&person(&claims)).await?;
    assert!(
        matches!(
            outcome,
            Some(Outcome::GroupsUnavailable(GroupsCause::Overage))
        ),
        "{outcome:?}"
    );
    assert_eq!(
        0,
        source.calls(),
        "the groups are decided before the lookup"
    );
    Ok(())
}

#[tokio::test]
async fn a_group_claim_that_is_no_set_of_strings_is_groups_unavailable() -> Outcome2 {
    let source = FakeSource::answering(one_professional());
    let binding = binding(&source);
    for groups in [json!("src1"), json!(["g", 1]), json!({ "g": true })] {
        let outcome = binding
            .resolve(&person(&json!({ "groups": groups })))
            .await?;
        assert!(
            matches!(
                outcome,
                Some(Outcome::GroupsUnavailable(GroupsCause::Malformed))
            ),
            "{groups}: {outcome:?}"
        );
    }
    Ok(())
}

// NOTE: no specification governs the groups: our own design, in which an absent group
// claim is the empty set and binds with no groups.
#[tokio::test]
async fn a_token_with_no_group_claim_binds_with_no_groups() -> Outcome2 {
    let source = FakeSource::answering(Lookup::Parties(vec![
        record("p-1", Markers::PROFESSIONAL)
            .with_memberships(vec![Membership::new(group_ref("g-1"), "group-1")]),
    ]));
    let party = bound(binding(&source).resolve(&person(&json!({}))).await?)?;
    assert!(party.groups.is_empty(), "{:?}", party.groups);
    assert_eq!(
        Some(String::from(GROUPS)),
        source
            .seen()
            .first()
            .and_then(|seen| seen.group_identifier_issuer.clone()),
        "the memberships are asked under the group identifier issuer"
    );
    Ok(())
}

// NOTE: no specification governs the groups: our own design, in which the memberships are
// intersected with the group claim on each request, so a person in two groups has two.
#[tokio::test]
async fn a_party_in_three_groups_whose_token_names_two_lists_exactly_those_two() -> Outcome2 {
    let source = FakeSource::answering(Lookup::Parties(vec![
        record("p-1", Markers::PROFESSIONAL).with_memberships(vec![
            Membership::new(group_ref("g-1"), "group-1"),
            Membership::new(group_ref("g-2"), "group-2"),
            Membership::new(group_ref("g-3"), "group-3"),
        ]),
    ]));
    let claims = json!({ "groups": ["group-3", "group-1", "group-not-held"] });
    let party = bound(binding(&source).resolve(&person(&claims)).await?)?;
    assert_eq!(vec![group_ref("g-1"), group_ref("g-3")], party.groups);
    Ok(())
}
