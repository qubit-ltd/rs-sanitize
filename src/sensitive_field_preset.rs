/*******************************************************************************
 *
 *    Copyright (c) 2026 Haixing Hu.
 *
 *    SPDX-License-Identifier: Apache-2.0
 *
 *    Licensed under the Apache License, Version 2.0.
 *
 ******************************************************************************/
/// Predefined groups of sensitive field names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SensitiveFieldPreset {
    /// Passwords, client secrets, private keys, and secret-like names.
    Credentials,
    /// API keys, access tokens, refresh tokens, and JWT-like names.
    AuthTokens,
    /// HTTP authentication and cookie fields.
    Http,
    /// Session identifiers and session tokens.
    Session,
}
