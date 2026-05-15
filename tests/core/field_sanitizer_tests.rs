/*******************************************************************************
 *
 *    Copyright (c) 2026 Haixing Hu.
 *
 *    SPDX-License-Identifier: Apache-2.0
 *
 *    Licensed under the Apache License, Version 2.0.
 *
 ******************************************************************************/
//! Tests for [`FieldSanitizer`](qubit_sanitize::FieldSanitizer).

use std::borrow::Cow;
use std::collections::BTreeMap;

use qubit_sanitize::{
    FieldSanitizePolicy, FieldSanitizer, MaskPolicies, MaskPolicy, SensitiveFields,
    SensitivityLevel,
};

#[test]
fn test_field_sanitizer_sanitize_value_masks_default_sensitive_field() {
    let sanitizer = FieldSanitizer::default();

    assert_eq!(sanitizer.sanitize_value("password", "secret"), "<redacted>");
}

#[test]
fn test_field_sanitizer_sanitize_value_keeps_non_sensitive_field_borrowed() {
    let sanitizer = FieldSanitizer::default();
    let value = "debug";

    assert_eq!(
        sanitizer.sanitize_value("log_level", value),
        Cow::Borrowed(value)
    );
}

#[test]
fn test_field_sanitizer_sanitize_value_uses_level_specific_policy() {
    let mut fields = SensitiveFields::new();
    fields.insert("session_id", SensitivityLevel::Low);
    fields.insert("license_key", SensitivityLevel::Medium);
    fields.insert("api_key", SensitivityLevel::High);
    fields.insert("private_key", SensitivityLevel::Secret);
    let policy = FieldSanitizePolicy {
        sensitive_fields: fields,
        mask_policies: MaskPolicies {
            low: MaskPolicy::preserve_edges(2, 2, "****", 4),
            medium: MaskPolicy::preserve_suffix(3, "****", 3),
            high: MaskPolicy::fixed("****"),
            secret: MaskPolicy::fixed("<secret>"),
        },
    };
    let sanitizer = FieldSanitizer::new(policy);

    assert_eq!(sanitizer.sanitize_value("session-id", "abcdef"), "ab****ef");
    assert_eq!(sanitizer.sanitize_value("license-key", "abcdef"), "****def");
    assert_eq!(sanitizer.sanitize_value("api-key", "abcdef"), "****");
    assert_eq!(
        sanitizer.sanitize_value("private-key", "abcdef"),
        "<secret>",
    );
}

#[test]
fn test_field_sanitizer_insert_sensitive_field_extends_policy() {
    let mut sanitizer = FieldSanitizer::new(FieldSanitizePolicy::empty());
    sanitizer.insert_sensitive_field("license_key", SensitivityLevel::Medium);

    assert_eq!(sanitizer.sanitize_value("license-key", "abcdef"), "****f");
}

#[test]
fn test_field_sanitizer_policy_returns_current_policy() {
    let sanitizer = FieldSanitizer::default();

    assert_eq!(
        sanitizer.policy().sensitive_fields.level_for("password"),
        Some(SensitivityLevel::Secret),
    );
}

#[test]
fn test_field_sanitizer_policy_mut_customizes_masking() {
    let mut sanitizer = FieldSanitizer::default();
    sanitizer.policy_mut().mask_policies.high = MaskPolicy::preserve_edges(1, 1, "****", 2);

    assert_eq!(sanitizer.sanitize_value("api-key", "abcdef"), "a****f");
}

#[test]
fn test_field_sanitizer_extend_sensitive_fields_adds_multiple_fields() {
    let mut sanitizer = FieldSanitizer::new(FieldSanitizePolicy::empty());
    sanitizer.extend_sensitive_fields(
        ["primary_secret", "secondary_secret"],
        SensitivityLevel::High,
    );

    assert_eq!(sanitizer.sanitize_value("primary-secret", "abcdef"), "****");
    assert_eq!(
        sanitizer.sanitize_value("secondary.secret", "abcdef"),
        "****"
    );
}

#[test]
fn test_field_sanitizer_extend_preset_adds_group_fields() {
    let mut sanitizer = FieldSanitizer::new(FieldSanitizePolicy::empty());
    sanitizer.extend_preset(qubit_sanitize::SensitiveFieldPreset::Session);

    assert_eq!(sanitizer.sanitize_value("session-id", "abcdef"), "****f");
    assert_eq!(sanitizer.sanitize_value("session-token", "abcdef"), "****");
}

#[test]
fn test_field_sanitizer_sanitize_map_returns_sanitized_copy() {
    let sanitizer = FieldSanitizer::default();
    let mut input = BTreeMap::new();
    input.insert("password".to_string(), "secret".to_string());
    input.insert("name".to_string(), "alice".to_string());

    let output = sanitizer.sanitize_map(&input);

    assert_eq!(
        output.get("password").map(String::as_str),
        Some("<redacted>")
    );
    assert_eq!(output.get("name").map(String::as_str), Some("alice"));
    assert_eq!(input.get("password").map(String::as_str), Some("secret"));
}

#[test]
fn test_field_sanitizer_sanitize_map_in_place_updates_sensitive_values() {
    let sanitizer = FieldSanitizer::default();
    let mut input = BTreeMap::new();
    input.insert("access_token".to_string(), "abcdef".to_string());
    input.insert("mode".to_string(), "debug".to_string());

    sanitizer.sanitize_map_in_place(&mut input);

    assert_eq!(input.get("access_token").map(String::as_str), Some("****"));
    assert_eq!(input.get("mode").map(String::as_str), Some("debug"));
}
