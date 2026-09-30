//! Vecteurs de tickets signés par une implémentation Node indépendante
//! (tests/vectors/generate.mjs) : garantit que ce que synco_api signe avec
//! `node:crypto` est exactement ce que le CDN accepte, et rien de plus.

use std::collections::HashMap;

use serde::Deserialize;
use synco_cdn::ticket::{Operation, TicketPolicy, TicketScope, TicketVerifier};

#[derive(Deserialize)]
struct Vectors {
    public_keys: HashMap<String, String>,
    policy: Policy,
    cases: Vec<Case>,
}

#[derive(Deserialize)]
struct Policy {
    clock_skew_secs: u64,
    max_lifetime_secs: u64,
    max_file_bytes: u64,
}

#[derive(Deserialize)]
struct Case {
    name: String,
    token: String,
    op: String,
    now: u64,
    expect: String,
    #[serde(default)]
    part_count: Option<u64>,
}

#[test]
fn node_signed_vectors() {
    let vectors: Vectors = serde_json::from_str(include_str!("vectors/tickets.json")).unwrap();
    let verifier = TicketVerifier::new(
        &vectors.public_keys,
        TicketPolicy {
            clock_skew_secs: vectors.policy.clock_skew_secs,
            max_lifetime_secs: vectors.policy.max_lifetime_secs,
            max_file_bytes: vectors.policy.max_file_bytes,
        },
    )
    .unwrap();

    assert!(vectors.cases.len() >= 15);
    for case in &vectors.cases {
        let op = if case.op == "up" { Operation::Upload } else { Operation::Download };
        let result = verifier.verify(&case.token, op, case.now);
        match (&result, case.expect.as_str()) {
            (Ok(ticket), "ok") => {
                assert_eq!(ticket.sub, "user-42", "{}", case.name);
                if let (TicketScope::Upload { part_count, .. }, Some(expected)) = (&ticket.scope, case.part_count) {
                    assert_eq!(*part_count, expected, "{}", case.name);
                }
                if let TicketScope::Download { mtime_ns, .. } = ticket.scope {
                    assert_eq!(mtime_ns, 1_759_229_000_123_456_789, "{}", case.name);
                }
            }
            (Err(error), expected) => assert_eq!(error.code(), expected, "{}", case.name),
            (Ok(_), expected) => panic!("{} : accepté, attendu {expected}", case.name),
        }
    }
}
