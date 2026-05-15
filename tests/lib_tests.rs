/*******************************************************************************
 *
 *    Copyright (c) 2026 Haixing Hu.
 *
 *    SPDX-License-Identifier: Apache-2.0
 *
 *    Licensed under the Apache License, Version 2.0.
 *
 ******************************************************************************/
//! Tests for crate-level exports.

use qubit_sanitize::{
    DEFAULT_SENSITIVE_FIELD_NAMES,
    FieldSanitizePolicy,
    FieldSanitizer,
    MaskPolicies,
    MaskPolicy,
    SensitiveFieldPreset,
    SensitiveFields,
    SensitivityLevel,
};

#[test]
fn test_lib_exports_public_api() {
    let _ = DEFAULT_SENSITIVE_FIELD_NAMES;
    let _ = FieldSanitizePolicy::default();
    let _ = FieldSanitizer::default();
    let _ = MaskPolicies::default();
    let _ = MaskPolicy::fixed("****");
    let _ = SensitiveFieldPreset::Credentials;
    let _ = SensitiveFields::default();
    let _ = SensitivityLevel::High;
}
