/*******************************************************************************
 *
 *    Copyright (c) 2026 Haixing Hu.
 *
 *    SPDX-License-Identifier: Apache-2.0
 *
 *    Licensed under the Apache License, Version 2.0.
 *
 ******************************************************************************/
use std::ffi::OsStr;

use crate::FieldSanitizer;

use super::name_match::{
    mask_value_for_level,
    sanitize_adapter_value,
    sensitivity_for_adapter_name,
};

/// Sanitizes structured argv vectors for logs and diagnostics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArgvSanitizer {
    /// Core sanitizer used for option and assignment values.
    field_sanitizer: FieldSanitizer,
}

impl ArgvSanitizer {
    /// Creates an argv sanitizer from a core field sanitizer.
    ///
    /// # Parameters
    ///
    /// * `field_sanitizer` - Core sanitizer used for option values.
    ///
    /// # Returns
    ///
    /// New argv sanitizer.
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

    /// Sanitizes one structured argv vector.
    ///
    /// This method handles `--token value`, `--token=value`, and
    /// `PASSWORD=value` forms. It does not parse shell syntax inside a single
    /// argument.
    ///
    /// # Parameters
    ///
    /// * `argv` - Program and argument vector to render safely.
    ///
    /// # Returns
    ///
    /// Sanitized argv tokens in input order.
    pub fn sanitize_argv<I, S>(&self, argv: I) -> Vec<String>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        let mut sanitized = Vec::new();
        let mut pending_sensitive_level = None;
        let mut parse_options = true;

        for arg in argv {
            let arg = arg.as_ref().to_string_lossy().into_owned();
            if let Some(level) = pending_sensitive_level.take() {
                sanitized
                    .push(mask_value_for_level(&self.field_sanitizer, level, &arg).into_owned());
                continue;
            }

            if arg == "--" {
                parse_options = false;
                sanitized.push(arg);
                continue;
            }

            if let Some(value) = self.sanitize_assignment_arg(&arg) {
                sanitized.push(value);
                continue;
            }

            if parse_options {
                if let Some(value) = self.sanitize_inline_option_arg(&arg) {
                    sanitized.push(value);
                    continue;
                }
                if let Some(level) = option_name(&arg)
                    .and_then(|name| sensitivity_for_adapter_name(&self.field_sanitizer, name))
                {
                    pending_sensitive_level = Some(level);
                }
            }

            sanitized.push(arg);
        }

        sanitized
    }

    /// Sanitizes one argv vector and formats it in argv-debug style.
    ///
    /// # Parameters
    ///
    /// * `argv` - Program and argument vector to render safely.
    ///
    /// # Returns
    ///
    /// Debug-style sanitized argv string, for example
    /// `["cmd", "--token", "****"]`.
    pub fn sanitize_argv_display<I, S>(&self, argv: I) -> String
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        format!("{:?}", self.sanitize_argv(argv))
    }

    /// Sanitizes one `KEY=value` argv token when the key is sensitive.
    ///
    /// # Parameters
    ///
    /// * `arg` - Argument token.
    ///
    /// # Returns
    ///
    /// `Some(sanitized)` for assignment-like arguments, otherwise `None`.
    fn sanitize_assignment_arg(&self, arg: &str) -> Option<String> {
        let (key, value) = arg.split_once('=')?;
        if key.is_empty() {
            return None;
        }
        let sanitized_value = sanitize_adapter_value(&self.field_sanitizer, key, value);
        if matches!(sanitized_value, std::borrow::Cow::Borrowed(_)) {
            return None;
        }
        Some(format!("{key}={sanitized_value}"))
    }

    /// Sanitizes one `--key=value` option token when the key is sensitive.
    ///
    /// # Parameters
    ///
    /// * `arg` - Argument token.
    ///
    /// # Returns
    ///
    /// `Some(sanitized)` when `arg` is a sensitive inline option, otherwise
    /// `None`.
    fn sanitize_inline_option_arg(&self, arg: &str) -> Option<String> {
        if !arg.starts_with('-') || arg == "-" {
            return None;
        }
        let (left, value) = arg.split_once('=')?;
        let name = option_name(left)?;
        let level = sensitivity_for_adapter_name(&self.field_sanitizer, name)?;
        let sanitized_value =
            mask_value_for_level(&self.field_sanitizer, level, value).into_owned();
        Some(format!("{left}={sanitized_value}"))
    }
}

impl Default for ArgvSanitizer {
    /// Creates an argv sanitizer using [`FieldSanitizer::default`].
    fn default() -> Self {
        Self::new(FieldSanitizer::default())
    }
}

/// Returns an option name without leading dashes.
///
/// # Parameters
///
/// * `arg` - Argument token that may be an option.
///
/// # Returns
///
/// `Some(name)` for option-looking arguments, otherwise `None`.
fn option_name(arg: &str) -> Option<&str> {
    if !arg.starts_with('-') || arg == "-" {
        return None;
    }
    let name = arg.trim_start_matches('-');
    if name.is_empty() { None } else { Some(name) }
}
