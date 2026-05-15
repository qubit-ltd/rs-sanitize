/*******************************************************************************
 *
 *    Copyright (c) 2026 Haixing Hu.
 *
 *    SPDX-License-Identifier: Apache-2.0
 *
 *    Licensed under the Apache License, Version 2.0.
 *
 ******************************************************************************/
//! HTTP-specific sanitization adapters.

mod body_bytes;
mod body_input_kind;
mod body_sanitizer;
mod content_type;
mod header_sanitizer;
mod multipart;
mod redaction_markers;

pub use body_sanitizer::HttpBodySanitizer;
pub use header_sanitizer::HttpHeaderSanitizer;
