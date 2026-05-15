/*******************************************************************************
 *
 *    Copyright (c) 2026 Haixing Hu.
 *
 *    SPDX-License-Identifier: Apache-2.0
 *
 *    Licensed under the Apache License, Version 2.0.
 *
 ******************************************************************************/
//! Tests for [`UrlSanitizer`](qubit_sanitize::UrlSanitizer).

use qubit_sanitize::UrlSanitizer;
use url::Url;

#[test]
fn test_url_sanitizer_sanitize_url_masks_sensitive_components() {
    let sanitizer = UrlSanitizer::default();
    let url = Url::parse(
        "https://alice:secret@example.com/path?access_token=abcdef&mode=debug#session-fragment",
    )
    .expect("test URL should parse");

    assert_eq!(
        sanitizer.sanitize_url(&url),
        "https://****:****@example.com/path?access_token=****&mode=debug#****",
    );
}

#[test]
fn test_url_sanitizer_sanitize_str_parses_and_masks_prefixed_query_name() {
    let sanitizer = UrlSanitizer::default();

    assert_eq!(
        sanitizer
            .sanitize_str("https://example.com/callback?openai_api_key=abcdef&state=ok")
            .expect("test URL should parse"),
        "https://example.com/callback?openai_api_key=****&state=ok",
    );
}

#[test]
fn test_url_sanitizer_sanitize_str_reports_parse_error() {
    let sanitizer = UrlSanitizer::default();

    assert!(sanitizer.sanitize_str("not a url").is_err());
}
