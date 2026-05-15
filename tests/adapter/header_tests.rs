/*******************************************************************************
 *
 *    Copyright (c) 2026 Haixing Hu.
 *
 *    SPDX-License-Identifier: Apache-2.0
 *
 *    Licensed under the Apache License, Version 2.0.
 *
 ******************************************************************************/
//! Tests for [`HeaderSanitizer`](qubit_sanitize::HeaderSanitizer).

use std::borrow::Cow;

use qubit_sanitize::HeaderSanitizer;

#[test]
fn test_header_sanitizer_masks_sensitive_header_value() {
    let sanitizer = HeaderSanitizer::default();

    assert_eq!(
        sanitizer.sanitize_value("Authorization", "Bearer abcdef"),
        "****",
    );
    assert_eq!(
        sanitizer.sanitize_value("X-OpenAI-Api-Key", "abcdef"),
        "****",
    );
}

#[test]
fn test_header_sanitizer_keeps_non_sensitive_header_borrowed() {
    let sanitizer = HeaderSanitizer::default();
    let value = "application/json";

    assert_eq!(
        sanitizer.sanitize_value("Content-Type", value),
        Cow::Borrowed(value),
    );
}

#[test]
fn test_header_sanitizer_sanitize_pair_preserves_name() {
    let sanitizer = HeaderSanitizer::default();

    assert_eq!(
        sanitizer.sanitize_pair("Cookie", "sid=abcdef"),
        ("Cookie".to_string(), "****".to_string()),
    );
}
