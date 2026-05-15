/*******************************************************************************
 *
 *    Copyright (c) 2026 Haixing Hu.
 *
 *    SPDX-License-Identifier: Apache-2.0
 *
 *    Licensed under the Apache License, Version 2.0.
 *
 ******************************************************************************/
//! # Qubit Sanitize
//!
//! Provides reusable sanitization utilities for logs, diagnostics, and
//! structured debug output.
//!

pub mod adapter;
pub mod core;

pub use adapter::{
    ArgvSanitizer, EnvSanitizer, FormUrlEncodedSanitizer, HeaderSanitizer, UrlSanitizer,
};
pub use core::{
    DEFAULT_SENSITIVE_FIELD_NAMES, FieldSanitizePolicy, FieldSanitizer, MaskPolicies, MaskPolicy,
    SensitiveFieldPreset, SensitiveFields, SensitivityLevel, canonicalize_field_name,
};
