/*******************************************************************************
 *
 *    Copyright (c) 2026 Haixing Hu.
 *
 *    SPDX-License-Identifier: Apache-2.0
 *
 *    Licensed under the Apache License, Version 2.0.
 *
 ******************************************************************************/
//! Tests for [`FormUrlEncodedSanitizer`](qubit_sanitize::FormUrlEncodedSanitizer).

use qubit_sanitize::FormUrlEncodedSanitizer;

#[test]
fn test_form_urlencoded_sanitizer_masks_sensitive_fields() {
    let sanitizer = FormUrlEncodedSanitizer::default();

    assert_eq!(
        sanitizer.sanitize_str("username=alice&password=secret&openai_api_key=abcdef&empty="),
        "username=alice&password=%3Credacted%3E&openai_api_key=****&empty=",
    );
}

#[test]
fn test_form_urlencoded_sanitizer_preserves_duplicate_fields() {
    let sanitizer = FormUrlEncodedSanitizer::default();

    assert_eq!(
        sanitizer.sanitize_str("token=first&token=second&mode=debug"),
        "token=****&token=****&mode=debug",
    );
}
