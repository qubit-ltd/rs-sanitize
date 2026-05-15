/*******************************************************************************
 *
 *    Copyright (c) 2026 Haixing Hu.
 *
 *    SPDX-License-Identifier: Apache-2.0
 *
 *    Licensed under the Apache License, Version 2.0.
 *
 ******************************************************************************/
use std::{
    borrow::Cow,
    collections::BTreeMap,
};

use super::{
    FieldSanitizePolicy,
    SensitiveFieldPreset,
    SensitivityLevel,
};

/// Sanitizes values by looking up their field names in a configurable policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldSanitizer {
    /// Field matching and masking policy.
    policy: FieldSanitizePolicy,
}

impl FieldSanitizer {
    /// Creates a sanitizer from an explicit policy.
    ///
    /// # Parameters
    ///
    /// * `policy` - Field matching and masking policy.
    ///
    /// # Returns
    ///
    /// New field sanitizer.
    pub const fn new(policy: FieldSanitizePolicy) -> Self {
        Self { policy }
    }

    /// Returns the underlying policy.
    ///
    /// # Returns
    ///
    /// Borrowed sanitization policy.
    pub const fn policy(&self) -> &FieldSanitizePolicy {
        &self.policy
    }

    /// Returns the underlying policy mutably.
    ///
    /// # Returns
    ///
    /// Mutable sanitization policy for advanced customization.
    pub fn policy_mut(&mut self) -> &mut FieldSanitizePolicy {
        &mut self.policy
    }

    /// Adds one sensitive field to this sanitizer.
    ///
    /// # Parameters
    ///
    /// * `field` - Field name to mark sensitive.
    /// * `level` - Sensitivity level assigned to the field.
    pub fn insert_sensitive_field(&mut self, field: &str, level: SensitivityLevel) {
        self.policy.sensitive_fields.insert(field, level);
    }

    /// Adds each field with the same sensitivity level.
    ///
    /// # Parameters
    ///
    /// * `fields` - Field names to add.
    /// * `level` - Sensitivity level assigned to every field.
    pub fn extend_sensitive_fields<I, S>(&mut self, fields: I, level: SensitivityLevel)
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        self.policy.sensitive_fields.extend(fields, level);
    }

    /// Adds one predefined field group.
    ///
    /// # Parameters
    ///
    /// * `preset` - Predefined group to insert.
    pub fn extend_preset(&mut self, preset: SensitiveFieldPreset) {
        self.policy.sensitive_fields.extend_preset(preset);
    }

    /// Sanitizes one field-value pair.
    ///
    /// # Parameters
    ///
    /// * `field` - Field name used for sensitivity lookup.
    /// * `value` - Field value to sanitize.
    ///
    /// # Returns
    ///
    /// Borrowed `value` when `field` is not sensitive, otherwise an owned masked
    /// value according to the field's configured sensitivity level.
    pub fn sanitize_value<'a>(&self, field: &str, value: &'a str) -> Cow<'a, str> {
        let Some(level) = self.policy.sensitive_fields.level_for(field) else {
            return Cow::Borrowed(value);
        };
        self.policy.mask_policies.for_level(level).mask(value)
    }

    /// Returns a sanitized copy of a string map.
    ///
    /// # Parameters
    ///
    /// * `map` - Source map whose keys are treated as field names.
    ///
    /// # Returns
    ///
    /// New map preserving keys and sanitizing sensitive values.
    pub fn sanitize_map(&self, map: &BTreeMap<String, String>) -> BTreeMap<String, String> {
        map.iter()
            .map(|(field, value)| {
                (
                    field.clone(),
                    self.sanitize_value(field, value.as_str()).into_owned(),
                )
            })
            .collect()
    }

    /// Sanitizes sensitive values in a string map in place.
    ///
    /// # Parameters
    ///
    /// * `map` - Mutable map whose keys are treated as field names.
    pub fn sanitize_map_in_place(&self, map: &mut BTreeMap<String, String>) {
        for (field, value) in map {
            let sanitized = self.sanitize_value(field, value.as_str());
            if let Cow::Owned(sanitized) = sanitized {
                *value = sanitized;
            }
        }
    }
}

impl Default for FieldSanitizer {
    /// Creates a sanitizer with [`FieldSanitizePolicy::default`].
    fn default() -> Self {
        Self::new(FieldSanitizePolicy::default())
    }
}
