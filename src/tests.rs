use super::*;

#[test]
fn basic() {
    // The one from the example.
    let payload =
        r#"{"origin": "https://example.com:443", "feature": "Frobulate", "expiry": 1609459199}"#;
    let token = Token::from_payload(LATEST_VERSION, payload.as_bytes()).unwrap();
    assert_eq!(token.origin, "https://example.com:443");
    assert_eq!(token.feature, "Frobulate");
    assert_eq!(token.expiry, 1609459199);
    assert_eq!(token.is_subdomain, false);
    assert_eq!(token.is_third_party, false);
    assert!(token.usage.is_none());
}

#[test]
fn subdomain() {
    // The one from the example.
    let payload = r#"{"origin": "https://example.com:443", "isSubdomain": true, "feature": "Frobulate", "expiry": 1609459199}"#;
    let token = Token::from_payload(LATEST_VERSION, payload.as_bytes()).unwrap();
    assert_eq!(token.origin, "https://example.com:443");
    assert_eq!(token.feature, "Frobulate");
    assert_eq!(token.expiry, 1609459199);
    assert_eq!(token.is_subdomain, true);
    assert_eq!(token.is_third_party, false);
    assert!(token.usage.is_none());
}

#[test]
fn third_party() {
    let payload = r#"{"origin": "https://thirdparty.com:443", "feature": "Frobulate", "expiry": 1609459199, "isThirdParty": true}"#;
    let token = Token::from_payload(LATEST_VERSION, payload.as_bytes()).unwrap();
    assert_eq!(token.origin, "https://thirdparty.com:443");
    assert_eq!(token.feature, "Frobulate");
    assert_eq!(token.expiry, 1609459199);
    assert_eq!(token.is_subdomain, false);
    assert_eq!(token.is_third_party, true);
    assert!(token.usage.is_none());
}

#[test]
fn third_party_usage_restriction() {
    let payload = r#"{"origin": "https://thirdparty.com:443", "feature": "Frobulate", "expiry": 1609459199, "isThirdParty": true, "usage": "subset"}"#;
    let token = Token::from_payload(LATEST_VERSION, payload.as_bytes()).unwrap();
    assert_eq!(token.origin, "https://thirdparty.com:443");
    assert_eq!(token.feature, "Frobulate");
    assert_eq!(token.expiry, 1609459199);
    assert_eq!(token.is_subdomain, false);
    assert_eq!(token.is_third_party, true);
    assert_eq!(token.usage, Usage::Subset);
}
