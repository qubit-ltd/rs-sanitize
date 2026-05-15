/*******************************************************************************
 *
 *    Copyright (c) 2026 Haixing Hu.
 *
 *    SPDX-License-Identifier: Apache-2.0
 *
 *    Licensed under the Apache License, Version 2.0.
 *
 ******************************************************************************/
use crate::SensitivityLevel;

/// Built-in sensitive field names used by [`crate::SensitiveFields::default`].
pub const DEFAULT_SENSITIVE_FIELD_NAMES: [(&str, SensitivityLevel); 24] = [
    ("password", SensitivityLevel::Secret),
    ("passwd", SensitivityLevel::Secret),
    ("secret", SensitivityLevel::Secret),
    ("client_secret", SensitivityLevel::Secret),
    ("private_key", SensitivityLevel::Secret),
    ("api_key", SensitivityLevel::High),
    ("x_api_key", SensitivityLevel::High),
    ("token", SensitivityLevel::High),
    ("access_token", SensitivityLevel::High),
    ("refresh_token", SensitivityLevel::High),
    ("id_token", SensitivityLevel::High),
    ("authorization", SensitivityLevel::High),
    ("proxy_authorization", SensitivityLevel::High),
    ("cookie", SensitivityLevel::High),
    ("set_cookie", SensitivityLevel::High),
    ("session", SensitivityLevel::Medium),
    ("session_id", SensitivityLevel::Medium),
    ("session_token", SensitivityLevel::High),
    ("jwt", SensitivityLevel::High),
    ("jwt_token", SensitivityLevel::High),
    ("auth_token", SensitivityLevel::High),
    ("auth_app_token", SensitivityLevel::High),
    ("auth_user_token", SensitivityLevel::High),
    ("license_key", SensitivityLevel::Medium),
];
