/*******************************************************************************
 *
 *    Copyright (c) 2026 Haixing Hu.
 *
 *    SPDX-License-Identifier: Apache-2.0
 *
 *    Licensed under the Apache License, Version 2.0.
 *
 ******************************************************************************/
//! Tests for [`ArgvSanitizer`](qubit_sanitize::ArgvSanitizer).

use qubit_sanitize::ArgvSanitizer;

#[test]
fn test_argv_sanitizer_masks_sensitive_option_next_value() {
    let sanitizer = ArgvSanitizer::default();

    assert_eq!(
        sanitizer.sanitize_argv([
            "docker",
            "login",
            "--password",
            "secret",
            "--username",
            "alice"
        ]),
        [
            "docker",
            "login",
            "--password",
            "<redacted>",
            "--username",
            "alice"
        ],
    );
}

#[test]
fn test_argv_sanitizer_masks_sensitive_inline_option() {
    let sanitizer = ArgvSanitizer::default();

    assert_eq!(
        sanitizer.sanitize_argv(["client", "--token=abcdef", "--mode", "debug"]),
        ["client", "--token=****", "--mode", "debug"],
    );
}

#[test]
fn test_argv_sanitizer_masks_assignment_tokens() {
    let sanitizer = ArgvSanitizer::default();

    assert_eq!(
        sanitizer.sanitize_argv(["env", "OPENAI_API_KEY=abcdef", "MODE=debug"]),
        ["env", "OPENAI_API_KEY=****", "MODE=debug"],
    );
}

#[test]
fn test_argv_sanitizer_keeps_shell_payload_unparsed() {
    let sanitizer = ArgvSanitizer::default();

    assert_eq!(
        sanitizer.sanitize_argv(["sh", "-c", "echo $OPENAI_API_KEY"]),
        ["sh", "-c", "echo $OPENAI_API_KEY"],
    );
}

#[test]
fn test_argv_sanitizer_formats_display_string() {
    let sanitizer = ArgvSanitizer::default();

    assert_eq!(
        sanitizer.sanitize_argv_display(["cmd", "--client-secret", "abcdef"]),
        r#"["cmd", "--client-secret", "<redacted>"]"#,
    );
}
