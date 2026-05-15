/*******************************************************************************
 *
 *    Copyright (c) 2026 Haixing Hu.
 *
 *    SPDX-License-Identifier: Apache-2.0
 *
 *    Licensed under the Apache License, Version 2.0.
 *
 ******************************************************************************/
//! Adapters for sanitizing structured objects with core masking policies.

mod argv;
mod env;
mod form_urlencoded;
mod header;
mod name_match;
mod url;

pub use argv::ArgvSanitizer;
pub use env::EnvSanitizer;
pub use form_urlencoded::FormUrlEncodedSanitizer;
pub use header::HeaderSanitizer;
pub use url::UrlSanitizer;
