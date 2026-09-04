//! Duplicate object keys are refused at any depth, as the reference does.
//!
//! serde_json's default keeps the last duplicate. Two verifiers that
//! disagree on hostile input are worse than one, so the parser fails on the
//! first repeated key. The boundary that has to be right is the last case:
//! the same key in two different objects is not a duplicate.

use verifyum::parse_json;

#[test]
fn plain_object_accepted() {
    assert!(parse_json(br#"{"a":1,"b":2}"#).is_ok());
}

#[test]
fn duplicate_at_top_level_rejected() {
    let err = parse_json(br#"{"a":1,"a":2}"#).unwrap_err();
    assert!(err.0.contains("duplicate object key"), "{}", err.0);
}

#[test]
fn duplicate_nested_rejected() {
    assert!(parse_json(br#"{"outer":{"x":1,"x":2}}"#).is_err());
}

#[test]
fn duplicate_inside_array_rejected() {
    assert!(parse_json(br#"{"list":[{"y":1,"y":2}]}"#).is_err());
}

#[test]
fn same_key_in_different_objects_accepted() {
    assert!(parse_json(br#"{"a":{"k":1},"b":{"k":2}}"#).is_ok());
}

#[test]
fn value_tree_unchanged_for_ordinary_input() {
    // The strict visitor must build exactly what serde_json built before.
    let bytes = br#"{"b":1,"a":"x","n":null,"t":true,"arr":[2,"s",{"z":0,"y":[]}]}"#;
    let strict = parse_json(bytes).unwrap();
    let plain: serde_json::Value = serde_json::from_slice(bytes).unwrap();
    assert_eq!(strict, plain);
}
