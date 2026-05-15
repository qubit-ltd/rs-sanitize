/*******************************************************************************
 *
 *    Copyright (c) 2026 Haixing Hu.
 *
 *    SPDX-License-Identifier: Apache-2.0
 *
 *    Licensed under the Apache License, Version 2.0.
 *
 ******************************************************************************/
use http::HeaderValue;
use serde_json::Value;
use url::form_urlencoded;

use crate::{FieldSanitizer, NameMatchMode};

const INVALID_JSON_REDACTED: &str = "<redacted: invalid JSON>";
const INVALID_OR_TRUNCATED_JSON_REDACTED: &str = "<redacted: invalid or truncated JSON>";
const INVALID_NDJSON_REDACTED: &str = "<redacted: invalid NDJSON>";
const INVALID_OR_TRUNCATED_NDJSON_REDACTED: &str = "<redacted: invalid or truncated NDJSON>";
const INVALID_CONTENT_TYPE_REDACTED: &str = "<redacted: invalid content type body>";
const MULTIPART_BODY_REDACTED: &str = "<redacted: multipart body>";
const MULTIPART_PART_REDACTED: &str = "<redacted: multipart part>";
const MULTIPART_FILE_PART_REDACTED: &str = "<redacted: file part>";
const MULTIPART_UNNAMED_FIELD: &str = "<unnamed>";
const MAX_MULTIPART_BOUNDARY_LEN: usize = 70;

/// Sanitizes HTTP body bytes for logs and diagnostics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpBodySanitizer {
    /// Core sanitizer used for body field values.
    field_sanitizer: FieldSanitizer,
}

impl HttpBodySanitizer {
    /// Creates an HTTP body sanitizer from a core field sanitizer.
    ///
    /// # Parameters
    ///
    /// * `field_sanitizer` - Core sanitizer used for body field values.
    ///
    /// # Returns
    ///
    /// New HTTP body sanitizer.
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

    /// Sanitizes a complete HTTP body.
    ///
    /// Use this method when `body` contains the complete source bytes. The
    /// sanitizer may parse structured media types such as JSON, NDJSON,
    /// URL-encoded forms, and multipart bodies because it can inspect the whole
    /// payload. It does not append any truncation marker.
    ///
    /// Use [`Self::sanitize_body_preview`] instead when the caller only has a
    /// bounded prefix of a larger body. Preview sanitization is more
    /// conservative for structured formats that cannot be parsed safely from a
    /// truncated prefix.
    ///
    /// # Parameters
    ///
    /// * `body` - Complete HTTP body bytes.
    /// * `content_type` - Optional `Content-Type` header used to select
    ///   structured parsing rules.
    ///
    /// # Returns
    ///
    /// Log-safe body text. Binary bodies are rendered as a byte-count marker.
    /// Bodies with a present but non-UTF-8 `Content-Type` are fully redacted
    /// because the structured parser cannot choose a safe media-type rule.
    pub fn sanitize_body(&self, body: &[u8], content_type: Option<&HeaderValue>) -> String {
        self.sanitize_body_inner(body, body.len(), content_type, BodyInputKind::Complete)
    }

    /// Sanitizes a caller-provided HTTP body preview.
    ///
    /// Use this method when `body_prefix` is already limited by the caller, for
    /// example before logging a large body. `source_len` is the total body
    /// length when known; values smaller than `body_prefix.len()` are treated as
    /// `body_prefix.len()`. When the source length is greater than the prefix
    /// length, the rendered output includes a truncation marker.
    ///
    /// Unlike [`Self::sanitize_body`], this method must assume the bytes may be
    /// incomplete. For structured media types, malformed or truncated input is
    /// redacted instead of being rendered as plain text, which avoids leaking
    /// partial sensitive values from invalid JSON, NDJSON, or multipart data.
    ///
    /// # Parameters
    ///
    /// * `body_prefix` - Body bytes available for preview rendering.
    /// * `source_len` - Total source body length when known.
    /// * `content_type` - Optional `Content-Type` header used to select
    ///   structured parsing rules.
    ///
    /// # Returns
    ///
    /// Log-safe preview text with a truncation marker when `source_len` exceeds
    /// `body_prefix.len()`. Bodies with a present but non-UTF-8 `Content-Type`
    /// are fully redacted because the structured parser cannot choose a safe
    /// media-type rule.
    pub fn sanitize_body_preview(
        &self,
        body_prefix: &[u8],
        source_len: usize,
        content_type: Option<&HeaderValue>,
    ) -> String {
        self.sanitize_body_inner(
            body_prefix,
            source_len.max(body_prefix.len()),
            content_type,
            BodyInputKind::Preview,
        )
    }

    /// Sanitizes complete or preview body bytes.
    ///
    /// # Parameters
    ///
    /// * `bytes` - Body bytes to render.
    /// * `source_len` - Full source length used for preview and binary markers.
    /// * `content_type` - Optional `Content-Type` header.
    /// * `input_kind` - Whether `bytes` are complete or a preview prefix.
    ///
    /// # Returns
    ///
    /// Log-safe body text.
    fn sanitize_body_inner(
        &self,
        bytes: &[u8],
        source_len: usize,
        content_type: Option<&HeaderValue>,
        input_kind: BodyInputKind,
    ) -> String {
        if bytes.is_empty() {
            return input_kind.empty_output(source_len);
        }

        let suffix = input_kind.truncation_suffix(bytes.len(), source_len);
        let content_type = match content_type_to_str(content_type) {
            Some(Ok(content_type)) => Some(content_type),
            Some(Err(_)) => return format!("{INVALID_CONTENT_TYPE_REDACTED}{suffix}"),
            None => None,
        };

        if content_type.is_some_and(is_multipart) {
            if input_kind.is_truncated(bytes.len(), source_len) {
                return format!("{MULTIPART_BODY_REDACTED}{suffix}");
            }
            if let Some(text) = self.sanitize_multipart(content_type, bytes) {
                return text;
            }
            return MULTIPART_BODY_REDACTED.to_string();
        }
        if content_type.is_some_and(is_ndjson) {
            if let Some(text) = self.sanitize_ndjson(bytes) {
                return format!("{text}{suffix}");
            }
            return format!("{}{suffix}", input_kind.invalid_ndjson_marker());
        }
        if self.is_json_body(content_type, bytes) {
            if let Some(text) = self.sanitize_json(bytes) {
                return format!("{text}{suffix}");
            }
            return format!("{}{suffix}", input_kind.invalid_json_marker());
        }
        if content_type.is_some_and(is_form_urlencoded) {
            return format!("{}{}", self.sanitize_form(bytes), suffix);
        }

        match std::str::from_utf8(bytes) {
            Ok(text) => format!("{text}{suffix}"),
            Err(_) => format!("<binary {} bytes>{suffix}", source_len.max(bytes.len())),
        }
    }

    /// Returns whether body bytes should be treated as JSON.
    ///
    /// # Parameters
    ///
    /// * `content_type` - Optional content type text.
    /// * `bytes` - Body bytes to inspect when no content type is present.
    ///
    /// # Returns
    ///
    /// `true` when the content type declares JSON or the bytes look like JSON.
    fn is_json_body(&self, content_type: Option<&str>, bytes: &[u8]) -> bool {
        if content_type.is_some_and(is_json) {
            return true;
        }
        let trimmed = trim_ascii_whitespace(bytes);
        matches!(trimmed.first(), Some(b'{') | Some(b'['))
    }

    /// Sanitizes one JSON document.
    ///
    /// # Parameters
    ///
    /// * `bytes` - UTF-8 JSON bytes.
    ///
    /// # Returns
    ///
    /// Sanitized compact JSON text, or `None` when parsing or rendering fails.
    fn sanitize_json(&self, bytes: &[u8]) -> Option<String> {
        let mut value = serde_json::from_slice::<Value>(bytes).ok()?;
        self.redact_json_value(&mut value);
        serde_json::to_string(&value).ok()
    }

    /// Sanitizes newline-delimited JSON.
    ///
    /// # Parameters
    ///
    /// * `bytes` - UTF-8 NDJSON bytes.
    ///
    /// # Returns
    ///
    /// Sanitized NDJSON text, or `None` when any non-empty line is invalid.
    fn sanitize_ndjson(&self, bytes: &[u8]) -> Option<String> {
        let text = std::str::from_utf8(bytes).ok()?;
        let trailing_newline = text.ends_with('\n');
        let mut sanitized_lines = Vec::new();
        for line in text.lines() {
            if line.trim().is_empty() {
                sanitized_lines.push(String::new());
                continue;
            }
            let mut value = serde_json::from_str::<Value>(line).ok()?;
            self.redact_json_value(&mut value);
            sanitized_lines.push(serde_json::to_string(&value).ok()?);
        }
        let mut result = sanitized_lines.join("\n");
        if trailing_newline {
            result.push('\n');
        }
        Some(result)
    }

    /// Redacts sensitive object fields in a JSON value.
    ///
    /// # Parameters
    ///
    /// * `value` - JSON value to mutate.
    fn redact_json_value(&self, value: &mut Value) {
        match value {
            Value::Object(map) => {
                for (key, value) in map.iter_mut() {
                    if let Some(masked) = self.mask_json_field_value(key, value) {
                        *value = Value::String(masked);
                    } else {
                        self.redact_json_value(value);
                    }
                }
            }
            Value::Array(items) => {
                for item in items {
                    self.redact_json_value(item);
                }
            }
            Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
        }
    }

    /// Masks a sensitive JSON field value.
    ///
    /// # Parameters
    ///
    /// * `field` - JSON object key used for sensitivity lookup.
    /// * `value` - JSON value to mask when the key is sensitive.
    ///
    /// # Returns
    ///
    /// `Some(masked)` when `field` is sensitive, otherwise `None`.
    fn mask_json_field_value(&self, field: &str, value: &Value) -> Option<String> {
        let level = self
            .field_sanitizer
            .sensitivity_for_name(field, NameMatchMode::ExactOrSuffix)?;
        let serialized;
        let value = match value {
            Value::String(value) => value.as_str(),
            _ => {
                serialized = value.to_string();
                serialized.as_str()
            }
        };
        Some(
            self.field_sanitizer
                .policy()
                .mask_policies
                .for_level(level)
                .mask(value)
                .into_owned(),
        )
    }

    /// Sanitizes URL-encoded form body bytes.
    ///
    /// # Parameters
    ///
    /// * `bytes` - URL-encoded form body bytes.
    ///
    /// # Returns
    ///
    /// Sanitized URL-encoded form text.
    fn sanitize_form(&self, bytes: &[u8]) -> String {
        let mut serializer = form_urlencoded::Serializer::new(String::new());
        for (key, value) in form_urlencoded::parse(bytes) {
            let sanitized_value = self.field_sanitizer.sanitize_value(
                key.as_ref(),
                value.as_ref(),
                NameMatchMode::ExactOrSuffix,
            );
            serializer.append_pair(key.as_ref(), sanitized_value.as_ref());
        }
        serializer.finish()
    }

    /// Sanitizes a complete multipart body into a log summary.
    ///
    /// # Parameters
    ///
    /// * `content_type` - Multipart content type text.
    /// * `bytes` - Complete multipart body bytes.
    ///
    /// # Returns
    ///
    /// Sanitized multipart summary, or `None` when the body must be redacted.
    fn sanitize_multipart(&self, content_type: Option<&str>, bytes: &[u8]) -> Option<String> {
        let boundary = multipart_boundary(content_type?)?;
        let text = std::str::from_utf8(bytes).ok()?;
        let segments = multipart_part_segments(text, &boundary)?;
        let mut lines = Vec::with_capacity(segments.len());
        for segment in segments {
            lines.push(self.sanitize_multipart_part(segment)?);
        }
        if lines.is_empty() {
            return Some("<multipart>\n</multipart>".to_string());
        }
        Some(format!("<multipart>\n{}\n</multipart>", lines.join("\n")))
    }

    /// Sanitizes one multipart part into a summary line.
    ///
    /// # Parameters
    ///
    /// * `segment` - Raw part segment without boundary delimiter lines.
    ///
    /// # Returns
    ///
    /// Log-safe `name=value` line, or `None` when part headers are malformed.
    fn sanitize_multipart_part(&self, segment: &str) -> Option<String> {
        let (headers, body) = split_multipart_headers_and_body(segment)?;
        let mut content_disposition = None;
        let mut content_type = None;
        for line in headers.lines().filter(|line| !line.trim().is_empty()) {
            let (header_name, header_value) = line.split_once(':')?;
            let header_name = header_name.trim();
            let header_value = header_value.trim();
            if header_name.eq_ignore_ascii_case("content-disposition") {
                content_disposition = Some(header_value);
            } else if header_name.eq_ignore_ascii_case("content-type") {
                content_type = Some(header_value);
            }
        }
        let name = content_disposition.and_then(|value| header_parameter(value, "name"));
        let filename = content_disposition.and_then(|value| {
            header_parameter(value, "filename").or_else(|| header_parameter(value, "filename*"))
        });
        let field_name = name.as_deref().unwrap_or(MULTIPART_UNNAMED_FIELD);
        let value =
            self.sanitize_multipart_part_value(field_name, filename.as_deref(), content_type, body);
        Some(format!("{field_name}={value}"))
    }

    /// Sanitizes one multipart part value.
    ///
    /// # Parameters
    ///
    /// * `field_name` - Parsed multipart field name.
    /// * `filename` - Optional filename from `Content-Disposition`.
    /// * `content_type` - Optional part-level content type.
    /// * `body` - Part body text.
    ///
    /// # Returns
    ///
    /// Log-safe part value.
    fn sanitize_multipart_part_value(
        &self,
        field_name: &str,
        filename: Option<&str>,
        content_type: Option<&str>,
        body: &str,
    ) -> String {
        if self
            .field_sanitizer
            .sensitivity_for_name(field_name, NameMatchMode::ExactOrSuffix)
            .is_some()
        {
            return self
                .field_sanitizer
                .sanitize_value(field_name, body, NameMatchMode::ExactOrSuffix)
                .into_owned();
        }
        if filename.is_some() {
            return MULTIPART_FILE_PART_REDACTED.to_string();
        }
        if field_name == MULTIPART_UNNAMED_FIELD {
            return MULTIPART_PART_REDACTED.to_string();
        }
        let Some(content_type) = content_type else {
            return body.to_string();
        };
        if is_json(content_type) {
            return self
                .sanitize_json(body.as_bytes())
                .unwrap_or_else(|| MULTIPART_PART_REDACTED.to_string());
        }
        if is_ndjson(content_type) {
            return self
                .sanitize_ndjson(body.as_bytes())
                .unwrap_or_else(|| MULTIPART_PART_REDACTED.to_string());
        }
        if is_form_urlencoded(content_type) {
            return self.sanitize_form(body.as_bytes());
        }
        if is_text(content_type) {
            return body.to_string();
        }
        MULTIPART_PART_REDACTED.to_string()
    }
}

impl Default for HttpBodySanitizer {
    /// Creates an HTTP body sanitizer using [`FieldSanitizer::default`].
    fn default() -> Self {
        Self::new(FieldSanitizer::default())
    }
}

/// Body input kind used to select complete-body or preview rendering behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BodyInputKind {
    /// Complete body bytes.
    Complete,
    /// Caller-limited body prefix.
    Preview,
}

impl BodyInputKind {
    /// Returns output for an empty byte slice.
    ///
    /// # Parameters
    ///
    /// * `source_len` - Total source length.
    ///
    /// # Returns
    ///
    /// Empty complete body text or a preview marker.
    fn empty_output(self, source_len: usize) -> String {
        match self {
            Self::Complete => String::new(),
            Self::Preview => format!("<empty>{}", self.truncation_suffix(0, source_len)),
        }
    }

    /// Returns whether the provided bytes are a truncated preview.
    ///
    /// # Parameters
    ///
    /// * `bytes_len` - Available byte count.
    /// * `source_len` - Total source byte count.
    ///
    /// # Returns
    ///
    /// `true` only for previews whose source is longer than the prefix.
    fn is_truncated(self, bytes_len: usize, source_len: usize) -> bool {
        self == Self::Preview && source_len > bytes_len
    }

    /// Returns the truncation suffix for rendered preview output.
    ///
    /// # Parameters
    ///
    /// * `bytes_len` - Rendered prefix byte count.
    /// * `source_len` - Total source byte count.
    ///
    /// # Returns
    ///
    /// Empty string for complete bodies and untruncated previews, otherwise a
    /// byte-count truncation marker.
    fn truncation_suffix(self, bytes_len: usize, source_len: usize) -> String {
        if !self.is_truncated(bytes_len, source_len) {
            return String::new();
        }
        let truncated = source_len.saturating_sub(bytes_len);
        format!("...<truncated {truncated} bytes>")
    }

    /// Returns the JSON parse failure marker for this input kind.
    ///
    /// # Returns
    ///
    /// JSON redaction marker.
    fn invalid_json_marker(self) -> &'static str {
        match self {
            Self::Complete => INVALID_JSON_REDACTED,
            Self::Preview => INVALID_OR_TRUNCATED_JSON_REDACTED,
        }
    }

    /// Returns the NDJSON parse failure marker for this input kind.
    ///
    /// # Returns
    ///
    /// NDJSON redaction marker.
    fn invalid_ndjson_marker(self) -> &'static str {
        match self {
            Self::Complete => INVALID_NDJSON_REDACTED,
            Self::Preview => INVALID_OR_TRUNCATED_NDJSON_REDACTED,
        }
    }
}

/// Converts an optional header value to UTF-8 text.
///
/// # Parameters
///
/// * `value` - Optional HTTP header value.
///
/// # Returns
///
/// `Some(Ok(text))` for valid UTF-8 header values, `Some(Err(_))` for present
/// but invalid values, and `None` when no header value is provided.
fn content_type_to_str(
    value: Option<&HeaderValue>,
) -> Option<Result<&str, http::header::ToStrError>> {
    value.map(HeaderValue::to_str)
}

/// Returns the media type portion of a Content-Type header.
///
/// # Parameters
///
/// * `content_type` - Raw Content-Type value.
///
/// # Returns
///
/// Trimmed text before the first semicolon.
fn media_type(content_type: &str) -> &str {
    content_type
        .split(';')
        .next()
        .map(str::trim)
        .unwrap_or_default()
}

/// Returns whether a content type has the expected media type.
///
/// # Parameters
///
/// * `content_type` - Raw Content-Type value.
/// * `expected` - Expected media type.
///
/// # Returns
///
/// `true` when media types match ignoring ASCII case.
fn has_media_type(content_type: &str, expected: &str) -> bool {
    media_type(content_type).eq_ignore_ascii_case(expected)
}

/// Returns whether a content type declares JSON.
///
/// # Parameters
///
/// * `content_type` - Raw Content-Type value.
///
/// # Returns
///
/// `true` for `application/json`, subtype aliases ending with `/json`, and
/// structured suffixes ending with `+json`.
fn is_json(content_type: &str) -> bool {
    let media_type = media_type(content_type).to_ascii_lowercase();
    media_type == "application/json"
        || media_type.ends_with("+json")
        || media_type.ends_with("/json")
}

/// Returns whether a content type declares newline-delimited JSON.
///
/// # Parameters
///
/// * `content_type` - Raw Content-Type value.
///
/// # Returns
///
/// `true` for `application/x-ndjson` and `application/ndjson`.
fn is_ndjson(content_type: &str) -> bool {
    let media_type = media_type(content_type);
    media_type.eq_ignore_ascii_case("application/x-ndjson")
        || media_type.eq_ignore_ascii_case("application/ndjson")
}

/// Returns whether a content type declares URL-encoded form data.
///
/// # Parameters
///
/// * `content_type` - Raw Content-Type value.
///
/// # Returns
///
/// `true` for `application/x-www-form-urlencoded`.
fn is_form_urlencoded(content_type: &str) -> bool {
    has_media_type(content_type, "application/x-www-form-urlencoded")
}

/// Returns whether a content type declares multipart data.
///
/// # Parameters
///
/// * `content_type` - Raw Content-Type value.
///
/// # Returns
///
/// `true` for any `multipart/*` media type.
fn is_multipart(content_type: &str) -> bool {
    media_type(content_type)
        .to_ascii_lowercase()
        .starts_with("multipart/")
}

/// Returns whether a content type declares textual data.
///
/// # Parameters
///
/// * `content_type` - Raw Content-Type value.
///
/// # Returns
///
/// `true` for any `text/*` media type.
fn is_text(content_type: &str) -> bool {
    media_type(content_type)
        .to_ascii_lowercase()
        .starts_with("text/")
}

/// Extracts a validated multipart boundary.
///
/// # Parameters
///
/// * `content_type` - Raw multipart Content-Type value.
///
/// # Returns
///
/// Decoded boundary when present and syntactically valid.
fn multipart_boundary(content_type: &str) -> Option<String> {
    if !is_multipart(content_type) {
        return None;
    }
    let boundary = header_parameter(content_type, "boundary")?;
    if is_valid_multipart_boundary(&boundary) {
        Some(boundary)
    } else {
        None
    }
}

/// Returns whether a boundary is safe to use as a multipart delimiter.
///
/// # Parameters
///
/// * `boundary` - Boundary parameter value without surrounding quotes.
///
/// # Returns
///
/// `true` when the value uses conservative RFC-compatible ASCII bytes.
fn is_valid_multipart_boundary(boundary: &str) -> bool {
    let len = boundary.len();
    (1..=MAX_MULTIPART_BOUNDARY_LEN).contains(&len)
        && boundary.bytes().all(is_valid_multipart_boundary_byte)
}

/// Returns whether one byte is valid in a multipart boundary.
///
/// # Parameters
///
/// * `byte` - Boundary byte to test.
///
/// # Returns
///
/// `true` for alphanumeric bytes and conservative punctuation.
fn is_valid_multipart_boundary_byte(byte: u8) -> bool {
    matches!(
        byte,
        b'0'..=b'9'
            | b'A'..=b'Z'
            | b'a'..=b'z'
            | b'\''
            | b'('
            | b')'
            | b'+'
            | b'_'
            | b','
            | b'-'
            | b'.'
            | b'/'
            | b':'
            | b'='
            | b'?'
    )
}

/// Extracts a semicolon-separated header parameter.
///
/// # Parameters
///
/// * `value` - Header value containing parameters.
/// * `parameter_name` - Parameter name to extract.
///
/// # Returns
///
/// Decoded parameter value, or `None` when absent or malformed.
fn header_parameter(value: &str, parameter_name: &str) -> Option<String> {
    for segment in header_parameter_segments(value)?.into_iter().skip(1) {
        let Some((name, raw_value)) = segment.split_once('=') else {
            continue;
        };
        if !name.trim().eq_ignore_ascii_case(parameter_name) {
            continue;
        }
        return decode_header_parameter(raw_value.trim());
    }
    None
}

/// Splits header parameters while respecting quoted semicolons.
///
/// # Parameters
///
/// * `value` - Header value containing parameters.
///
/// # Returns
///
/// Parameter segments, or `None` when quoting is malformed.
fn header_parameter_segments(value: &str) -> Option<Vec<&str>> {
    let mut segments = Vec::new();
    let mut start = 0;
    let mut in_quote = false;
    let mut escaped = false;
    for (index, ch) in value.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if in_quote && ch == '\\' {
            escaped = true;
            continue;
        }
        if ch == '"' {
            in_quote = !in_quote;
            continue;
        }
        if ch == ';' && !in_quote {
            segments.push(value[start..index].trim());
            start = index + ch.len_utf8();
        }
    }
    if in_quote || escaped {
        return None;
    }
    segments.push(value[start..].trim());
    Some(segments)
}

/// Decodes a simple HTTP header parameter value.
///
/// # Parameters
///
/// * `value` - Raw parameter value.
///
/// # Returns
///
/// Unquoted value, or `None` for malformed quoted strings.
fn decode_header_parameter(value: &str) -> Option<String> {
    if !value.starts_with('"') {
        return Some(value.trim().to_string());
    }
    if !value.ends_with('"') || value.len() < 2 {
        return None;
    }
    let mut result = String::new();
    let mut chars = value[1..value.len() - 1].chars();
    while let Some(ch) = chars.next() {
        let value = if ch == '\\' { chars.next()? } else { ch };
        if value == '\r' || value == '\n' {
            return None;
        }
        result.push(value);
    }
    Some(result)
}

/// Kind of multipart delimiter line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MultipartDelimiter {
    /// Delimiter before a regular part.
    Part,
    /// Final closing delimiter.
    Closing,
}

/// Splits a complete multipart body into part segments.
///
/// # Parameters
///
/// * `text` - Multipart body text.
/// * `boundary` - Boundary parameter without the leading `--`.
///
/// # Returns
///
/// Raw part segments without boundary delimiter lines, or `None` for malformed
/// multipart bodies.
fn multipart_part_segments<'a>(text: &'a str, boundary: &str) -> Option<Vec<&'a str>> {
    let mut current_start = None;
    let mut segments = Vec::new();
    let mut position = 0;
    while position < text.len() {
        let (line_start, line_end, next_position) = next_line_bounds(text, position);
        let line = &text[line_start..line_end];
        let Some(delimiter) = multipart_delimiter(line, boundary) else {
            position = next_position;
            continue;
        };
        if let Some(start) = current_start {
            let segment = strip_one_trailing_line_ending(&text[start..line_start]);
            if !segment.trim().is_empty() {
                segments.push(segment);
            }
        }
        if delimiter == MultipartDelimiter::Closing {
            if text[next_position..].trim().is_empty() {
                return Some(segments);
            }
            return None;
        }
        current_start = Some(next_position);
        position = next_position;
    }
    None
}

/// Returns the next line range and following scan position.
///
/// # Parameters
///
/// * `text` - Source text.
/// * `position` - Byte offset where the next line starts.
///
/// # Returns
///
/// `(line_start, line_end_without_line_ending, next_position)`.
fn next_line_bounds(text: &str, position: usize) -> (usize, usize, usize) {
    if let Some(relative_end) = text[position..].find('\n') {
        let line_end = position + relative_end;
        let trimmed_end = line_end
            .checked_sub(1)
            .filter(|index| text.as_bytes()[*index] == b'\r')
            .unwrap_or(line_end);
        return (position, trimmed_end, line_end + 1);
    }
    (position, text.len(), text.len())
}

/// Classifies a multipart delimiter line.
///
/// # Parameters
///
/// * `line` - Logical line without trailing line ending.
/// * `boundary` - Boundary parameter without the leading `--`.
///
/// # Returns
///
/// Delimiter kind for exact delimiter lines.
fn multipart_delimiter(line: &str, boundary: &str) -> Option<MultipartDelimiter> {
    let delimiter = format!("--{boundary}");
    if line == delimiter {
        Some(MultipartDelimiter::Part)
    } else if line == format!("{delimiter}--") {
        Some(MultipartDelimiter::Closing)
    } else {
        None
    }
}

/// Splits multipart part headers from the part body.
///
/// # Parameters
///
/// * `segment` - Raw part segment.
///
/// # Returns
///
/// Header text and body text.
fn split_multipart_headers_and_body(segment: &str) -> Option<(&str, &str)> {
    if let Some(index) = segment.find("\r\n\r\n") {
        return Some((&segment[..index], &segment[index + 4..]));
    }
    if let Some(index) = segment.find("\n\n") {
        return Some((&segment[..index], &segment[index + 2..]));
    }
    None
}

/// Removes one trailing multipart line ending.
///
/// # Parameters
///
/// * `value` - Text that may end with one line ending.
///
/// # Returns
///
/// Text without one trailing line ending.
fn strip_one_trailing_line_ending(value: &str) -> &str {
    value
        .strip_suffix("\r\n")
        .or_else(|| value.strip_suffix('\n'))
        .unwrap_or(value)
}

/// Trims ASCII whitespace from both ends of a byte slice.
///
/// # Parameters
///
/// * `bytes` - Bytes to trim.
///
/// # Returns
///
/// Borrowed trimmed slice.
fn trim_ascii_whitespace(bytes: &[u8]) -> &[u8] {
    let start = bytes
        .iter()
        .position(|byte| !byte.is_ascii_whitespace())
        .unwrap_or(bytes.len());
    let end = bytes
        .iter()
        .rposition(|byte| !byte.is_ascii_whitespace())
        .map(|index| index + 1)
        .unwrap_or(start);
    &bytes[start..end]
}
