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

use crate::{FieldSanitizer, NameMatchMode};

/// Sanitizes header name-value pairs without depending on an HTTP type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeaderSanitizer {
    /// Core sanitizer used for header values.
    field_sanitizer: FieldSanitizer,
}

impl HeaderSanitizer {
    /// Creates a header sanitizer from a core field sanitizer.
    ///
    /// # Parameters
    ///
    /// * `field_sanitizer` - Core sanitizer used for header values.
    ///
    /// # Returns
    ///
    /// New header sanitizer.
    pub const fn new(field_sanitizer: FieldSanitizer) -> Self {
        Self { field_sanitizer }
    }

    /// Returns the underlying core field sanitizer.
    ///
    /// # Returns
    ///
    /// Borrowed core field sanitizer.
    pub const fn field_sanitizer(&self) -> &FieldSanitizer {
        &self.field_sanitizer
    }

    /// Returns the underlying core field sanitizer mutably.
    ///
    /// # Returns
    ///
    /// Mutable core field sanitizer.
    pub fn field_sanitizer_mut(&mut self) -> &mut FieldSanitizer {
        &mut self.field_sanitizer
    }

    /// Sanitizes one header value by header name.
    ///
    /// # Parameters
    ///
    /// * `name` - Header name.
    /// * `value` - Header value.
    ///
    /// # Returns
    ///
    /// Borrowed `value` when `name` is not sensitive, otherwise an owned masked
    /// value.
    pub fn sanitize_value<'a>(&self, name: &str, value: &'a str) -> Cow<'a, str> {
        self.field_sanitizer
            .sanitize_value(name, value, NameMatchMode::ExactOrSuffix)
    }

    /// Sanitizes one header pair.
    ///
    /// # Parameters
    ///
    /// * `name` - Header name.
    /// * `value` - Header value.
    ///
    /// # Returns
    ///
    /// Owned pair preserving the header name and sanitizing the value when
    /// needed.
    pub fn sanitize_pair(&self, name: &str, value: &str) -> (String, String) {
        (
            name.to_string(),
            self.sanitize_value(name, value).into_owned(),
        )
    }
}

impl Default for HeaderSanitizer {
    /// Creates a header sanitizer using [`FieldSanitizer::default`].
    fn default() -> Self {
        Self::new(FieldSanitizer::default())
    }
}
