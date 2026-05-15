# Qubit Sanitize

[![Rust CI](https://github.com/qubit-ltd/rs-sanitize/actions/workflows/ci.yml/badge.svg)](https://github.com/qubit-ltd/rs-sanitize/actions/workflows/ci.yml)
[![Coverage](https://img.shields.io/endpoint?url=https://qubit-ltd.github.io/rs-sanitize/coverage-badge.json)](https://qubit-ltd.github.io/rs-sanitize/coverage/)
[![Crates.io](https://img.shields.io/crates/v/qubit-sanitize.svg?color=blue)](https://crates.io/crates/qubit-sanitize)
[![Rust](https://img.shields.io/badge/rust-1.94+-blue.svg?logo=rust)](https://www.rust-lang.org)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![中文文档](https://img.shields.io/badge/文档-中文版-blue.svg)](README.zh_CN.md)

Reusable field-value sanitization utilities for Rust.

## Overview

Qubit Sanitize provides a small, reusable layer for masking sensitive field
values in logs, diagnostics, and structured debug output. It focuses on the
common part shared by HTTP clients, command runners, configuration objects, and
other crates: given a `(field, value)` pair, decide whether the field is
sensitive and return the safe value to display.

This crate intentionally does not parse protocol-specific formats. HTTP crates
should parse URLs, headers, forms, JSON, or multipart bodies themselves; command
crates should parse argv or environment assignments themselves. Once they have a
field name and a value, they can delegate the masking decision to
`FieldSanitizer`.

## Features

- Field-name canonicalization for separator-insensitive matching
- Built-in sensitive field defaults for credentials, tokens, HTTP auth, cookies,
  and sessions
- Configurable sensitivity levels: `Low`, `Medium`, `High`, and `Secret`
- Level-specific masking through `MaskPolicies`
- Mask strategies for fixed replacement, edge preservation, suffix
  preservation, and full removal
- A `FieldSanitizer` object that sanitizes single field-value pairs
- Convenience helpers for sanitizing `BTreeMap<String, String>` values by key
- No runtime dependencies

## Quick Start

```rust
use qubit_sanitize::FieldSanitizer;

let sanitizer = FieldSanitizer::default();

assert_eq!(
    sanitizer.sanitize_value("password", "correct-horse-battery-staple"),
    "<redacted>",
);
assert_eq!(sanitizer.sanitize_value("mode", "debug"), "debug");
```

## Sensitivity Levels

Sensitive fields are assigned one of four levels:

| Level | Intended use | Default mask |
| --- | --- | --- |
| `Low` | Values where a small prefix and suffix help diagnostics | `ab****yz` |
| `Medium` | Identifiers where only the tail should remain visible | `****z` |
| `High` | Tokens or API keys that should not expose edges | `****` |
| `Secret` | Passwords, private keys, or client secrets | `<redacted>` |

The defaults are conservative for operational logs. You can replace any level's
masking strategy through `MaskPolicies`.

## Mask Policies

```rust
use qubit_sanitize::MaskPolicy;

let edge = MaskPolicy::preserve_edges(2, 2, "****", 4);
assert_eq!(edge.mask("abcdefgh"), "ab****gh");

let suffix = MaskPolicy::preserve_suffix(4, "****", 4);
assert_eq!(suffix.mask("1234567890"), "****7890");

let fixed = MaskPolicy::fixed("****");
assert_eq!(fixed.mask("secret"), "****");
```

Empty values are kept empty. This avoids changing the semantics of fields that
are present but intentionally blank.

## Sensitive Fields

`SensitiveFields::default()` contains common sensitive names such as:

- `password`, `passwd`, `secret`, `client_secret`, `private_key`
- `api_key`, `x_api_key`
- `token`, `access_token`, `refresh_token`, `id_token`
- `authorization`, `proxy_authorization`, `cookie`, `set_cookie`
- `session`, `session_id`, `session_token`

Field names are canonicalized before lookup. Separators such as `_`, `-`, `.`,
and whitespace are ignored, and names are lowercased:

```rust
use qubit_sanitize::canonicalize_field_name;

assert_eq!(canonicalize_field_name(" access-token "), "accesstoken");
assert_eq!(canonicalize_field_name("access_token"), "accesstoken");
assert_eq!(canonicalize_field_name("access.token"), "accesstoken");
```

## Custom Fields

```rust
use qubit_sanitize::{
    FieldSanitizer,
    SensitivityLevel,
};

let mut sanitizer = FieldSanitizer::default();
sanitizer.insert_sensitive_field("license_key", SensitivityLevel::Medium);

assert_eq!(sanitizer.sanitize_value("license-key", "abcdef"), "****f");
```

You can also start from an empty policy when you do not want built-in field
names:

```rust
use qubit_sanitize::{
    FieldSanitizePolicy,
    FieldSanitizer,
    SensitivityLevel,
};

let mut sanitizer = FieldSanitizer::new(FieldSanitizePolicy::empty());
sanitizer.insert_sensitive_field("tenant_secret", SensitivityLevel::Secret);
```

## Map Sanitization

```rust
use std::collections::BTreeMap;

use qubit_sanitize::FieldSanitizer;

let sanitizer = FieldSanitizer::default();
let mut values = BTreeMap::new();
values.insert("password".to_string(), "secret".to_string());
values.insert("name".to_string(), "alice".to_string());

let sanitized = sanitizer.sanitize_map(&values);

assert_eq!(sanitized["password"], "<redacted>");
assert_eq!(sanitized["name"], "alice");
assert_eq!(values["password"], "secret");
```

For mutable structured data, use `sanitize_map_in_place`.

## Integration Guidance

The crate's boundary is deliberately narrow:

- Use it for field-name matching and value masking.
- Keep format parsing in the caller crate.
- Do not pass whole shell command lines, JSON bodies, or URLs directly unless
  the caller has already split them into field-value pairs.

For example, an HTTP crate should parse query parameters and call
`sanitize_value("access_token", value)`. A command runner should parse
`--token value` or `TOKEN=value` and call `sanitize_value("token", value)`.

## Testing

A minimal local run:

```bash
cargo test
cargo clippy --all-targets --all-features -- -D warnings
```

To mirror what continuous integration enforces, run the repository scripts from
the project root: `./align-ci.sh` brings local tooling and configuration in line
with CI, then `./ci-check.sh` runs the same checks the pipeline uses. For test
coverage, use `./coverage.sh` to generate or open reports.

## Contributing

Issues and pull requests are welcome.

- Keep this crate focused on reusable field-value sanitization primitives.
- Put protocol-specific parsing in downstream crates.
- Add or update tests when changing matching or masking behavior.
- Update this README and public rustdoc when user-visible behavior changes.
- Before submitting, run `./align-ci.sh` and then `./ci-check.sh`.

By contributing, you agree to license your contributions under the
[Apache License, Version 2.0](LICENSE), the same license as this project.

## License

Copyright © 2026 Haixing Hu, Qubit Co. Ltd.

This project is licensed under the [Apache License, Version 2.0](LICENSE). See
the `LICENSE` file in the repository for the full text.

## Author

**Haixing Hu** — Qubit Co. Ltd.

| | |
| --- | --- |
| **Repository** | [github.com/qubit-ltd/rs-sanitize](https://github.com/qubit-ltd/rs-sanitize) |
| **Documentation** | [docs.rs/qubit-sanitize](https://docs.rs/qubit-sanitize) |
| **Crate** | [crates.io/crates/qubit-sanitize](https://crates.io/crates/qubit-sanitize) |
