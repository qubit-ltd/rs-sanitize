/*******************************************************************************
 *
 *    Copyright (c) 2026 Haixing Hu.
 *
 *    SPDX-License-Identifier: Apache-2.0
 *
 *    Licensed under the Apache License, Version 2.0.
 *
 ******************************************************************************/
//! Tests for [`EnvSanitizer`](qubit_sanitize::EnvSanitizer).

use qubit_sanitize::EnvSanitizer;

#[test]
fn test_env_sanitizer_masks_prefixed_sensitive_key() {
    let sanitizer = EnvSanitizer::default();

    assert_eq!(sanitizer.sanitize_value("OPENAI_API_KEY", "abcdef"), "****");
}

#[test]
fn test_env_sanitizer_sanitize_assignment_masks_secret() {
    let sanitizer = EnvSanitizer::default();

    assert_eq!(
        sanitizer.sanitize_assignment("PASSWORD=secret"),
        "PASSWORD=<redacted>",
    );
}

#[test]
fn test_env_sanitizer_keeps_non_assignment_unchanged() {
    let sanitizer = EnvSanitizer::default();

    assert_eq!(sanitizer.sanitize_assignment("PATH"), "PATH");
}

#[test]
fn test_env_sanitizer_sanitize_os_pair_renders_lossy_pair() {
    let sanitizer = EnvSanitizer::default();

    assert_eq!(
        sanitizer.sanitize_os_pair("SERVICE_TOKEN", "abcdef"),
        ("SERVICE_TOKEN".to_string(), "****".to_string()),
    );
}
