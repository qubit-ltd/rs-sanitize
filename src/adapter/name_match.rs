/*******************************************************************************
 *
 *    Copyright (c) 2026 Haixing Hu.
 *
 *    SPDX-License-Identifier: Apache-2.0
 *
 *    Licensed under the Apache License, Version 2.0.
 *
 ******************************************************************************/
use std::borrow::Cow;

use crate::{
    FieldSanitizer,
    SensitivityLevel,
    canonicalize_field_name,
};

/// Returns the sensitivity level for an adapter field name.
///
/// Adapter inputs often include contextual prefixes, such as
/// `OPENAI_API_KEY`. Exact core matching is tried first, then suffix matching
/// is used to catch prefixed names while keeping core field matching unchanged.
///
/// # Parameters
///
/// * `sanitizer` - Core field sanitizer containing field names and masks.
/// * `name` - Adapter field, option, header, or environment variable name.
///
/// # Returns
///
/// `Some(level)` when the name should be sanitized, otherwise `None`.
pub(crate) fn sensitivity_for_adapter_name(
    sanitizer: &FieldSanitizer,
    name: &str,
) -> Option<SensitivityLevel> {
    let fields = &sanitizer.policy().sensitive_fields;
    if let Some(level) = fields.level_for(name) {
        return Some(level);
    }

    let canonical_name = canonicalize_field_name(name);
    if canonical_name.is_empty() {
        return None;
    }

    fields
        .iter()
        .filter_map(|(field, level)| {
            if canonical_name != field && canonical_name.ends_with(field) {
                Some((field.len(), level))
            } else {
                None
            }
        })
        .max_by_key(|(field_len, level)| (*field_len, *level))
        .map(|(_, level)| level)
}

/// Sanitizes one adapter value by name.
///
/// # Parameters
///
/// * `sanitizer` - Core field sanitizer containing field names and masks.
/// * `name` - Adapter field, option, header, or environment variable name.
/// * `value` - Value to sanitize when `name` is sensitive.
///
/// # Returns
///
/// Borrowed `value` when `name` is not sensitive, otherwise an owned masked
/// value according to the resolved sensitivity level.
pub(crate) fn sanitize_adapter_value<'a>(
    sanitizer: &FieldSanitizer,
    name: &str,
    value: &'a str,
) -> Cow<'a, str> {
    let Some(level) = sensitivity_for_adapter_name(sanitizer, name) else {
        return Cow::Borrowed(value);
    };
    mask_value_for_level(sanitizer, level, value)
}

/// Masks one value with the policy configured for `level`.
///
/// # Parameters
///
/// * `sanitizer` - Core field sanitizer containing mask policies.
/// * `level` - Sensitivity level whose mask policy should be applied.
/// * `value` - Value to mask.
///
/// # Returns
///
/// Borrowed `value` when the mask policy preserves it, otherwise an owned
/// masked value.
pub(crate) fn mask_value_for_level<'a>(
    sanitizer: &FieldSanitizer,
    level: SensitivityLevel,
    value: &'a str,
) -> Cow<'a, str> {
    sanitizer
        .policy()
        .mask_policies
        .for_level(level)
        .mask(value)
}
