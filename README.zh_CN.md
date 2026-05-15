# Qubit Sanitize

[![Rust CI](https://github.com/qubit-ltd/rs-sanitize/actions/workflows/ci.yml/badge.svg)](https://github.com/qubit-ltd/rs-sanitize/actions/workflows/ci.yml)
[![Coverage](https://img.shields.io/endpoint?url=https://qubit-ltd.github.io/rs-sanitize/coverage-badge.json)](https://qubit-ltd.github.io/rs-sanitize/coverage/)
[![Crates.io](https://img.shields.io/crates/v/qubit-sanitize.svg?color=blue)](https://crates.io/crates/qubit-sanitize)
[![Rust](https://img.shields.io/badge/rust-1.94+-blue.svg?logo=rust)](https://www.rust-lang.org)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![English](https://img.shields.io/badge/docs-English-blue.svg)](README.md)

Rust 通用字段值脱敏工具。

## 概览

Qubit Sanitize 提供一个小而清晰的通用脱敏层，面向日志、诊断信息和结构化
Debug 输出。它只解决多个 crate 都会重复遇到的共性问题：给定一个
`(field, value)` 字段名和值，判断这个字段是否敏感，并返回适合展示的安全值。

这个 crate 有意不解析具体协议格式。HTTP crate 应自己解析 URL、header、
form、JSON 或 multipart body；命令执行 crate 应自己解析 argv 或环境变量赋值。
当调用方已经拿到字段名和值以后，再把它们交给 `FieldSanitizer` 做统一脱敏。

## 特性

- 字段名规范化，支持忽略常见分隔符后匹配
- 内置凭证、token、HTTP 认证、cookie、session 等常见敏感字段
- 可配置敏感级别：`Low`、`Medium`、`High`、`Secret`
- 每个敏感级别可以绑定不同的 `MaskPolicy`
- 支持固定替换、保留首尾、保留尾部、完全移除等脱敏策略
- `FieldSanitizer` 对象专注处理单个字段值脱敏
- 提供 `BTreeMap<String, String>` 的复制式和原地脱敏便捷方法
- 无运行时依赖

## 快速开始

```rust
use qubit_sanitize::FieldSanitizer;

let sanitizer = FieldSanitizer::default();

assert_eq!(
    sanitizer.sanitize_value("password", "correct-horse-battery-staple"),
    "<redacted>",
);
assert_eq!(sanitizer.sanitize_value("mode", "debug"), "debug");
```

## 敏感级别

敏感字段可以配置为四个级别：

| 级别 | 适用场景 | 默认脱敏结果 |
| --- | --- | --- |
| `Low` | 可以保留少量首尾字符辅助排查的低风险值 | `ab****yz` |
| `Medium` | 只适合保留尾部一小段的标识类值 | `****z` |
| `High` | token、API key 等不应暴露首尾的值 | `****` |
| `Secret` | 密码、私钥、client secret 等最高风险值 | `<redacted>` |

默认策略面向运行日志偏保守。如果某个业务场景需要不同展示方式，可以替换
`MaskPolicies` 中任意级别对应的策略。

## 脱敏策略

```rust
use qubit_sanitize::MaskPolicy;

let edge = MaskPolicy::preserve_edges(2, 2, "****", 4);
assert_eq!(edge.mask("abcdefgh"), "ab****gh");

let suffix = MaskPolicy::preserve_suffix(4, "****", 4);
assert_eq!(suffix.mask("1234567890"), "****7890");

let fixed = MaskPolicy::fixed("****");
assert_eq!(fixed.mask("secret"), "****");
```

空值会保持为空。这样可以保留“字段存在但值为空”的语义，同时不泄露敏感内容。

## 敏感字段

`SensitiveFields::default()` 内置了一组常见敏感字段，例如：

- `password`、`passwd`、`secret`、`client_secret`、`private_key`
- `api_key`、`x_api_key`
- `token`、`access_token`、`refresh_token`、`id_token`
- `authorization`、`proxy_authorization`、`cookie`、`set_cookie`
- `session`、`session_id`、`session_token`

字段名在匹配前会先规范化：去掉 `_`、`-`、`.`、空白字符并转小写。因此下面这些
名字会匹配到同一个字段：

```rust
use qubit_sanitize::canonicalize_field_name;

assert_eq!(canonicalize_field_name(" access-token "), "accesstoken");
assert_eq!(canonicalize_field_name("access_token"), "accesstoken");
assert_eq!(canonicalize_field_name("access.token"), "accesstoken");
```

## 自定义字段

```rust
use qubit_sanitize::{
    FieldSanitizer,
    SensitivityLevel,
};

let mut sanitizer = FieldSanitizer::default();
sanitizer.insert_sensitive_field("license_key", SensitivityLevel::Medium);

assert_eq!(sanitizer.sanitize_value("license-key", "abcdef"), "****f");
```

如果不想使用内置字段，可以从空策略开始：

```rust
use qubit_sanitize::{
    FieldSanitizePolicy,
    FieldSanitizer,
    SensitivityLevel,
};

let mut sanitizer = FieldSanitizer::new(FieldSanitizePolicy::empty());
sanitizer.insert_sensitive_field("tenant_secret", SensitivityLevel::Secret);
```

## Map 脱敏

```rust
use std::collections::BTreeMap;

use qubit_sanitize::FieldSanitizer;

let sanitizer = FieldSanitizer::default();
let mut values = BTreeMap::new();
values.insert("password".to_string(), "secret".to_string());
values.insert("name".to_string(), "alice".to_string());

let sanitized = sanitizer.sanitize_map(&values);

assert_eq!(sanitized["password"], "<redacted>");
assert_eq!(sanitized["name"], "alice");
assert_eq!(values["password"], "secret");
```

如果需要直接修改已有结构，可以使用 `sanitize_map_in_place`。

## 集成建议

这个 crate 的边界应保持很窄：

- 它负责字段名匹配和值脱敏。
- 具体格式解析由调用方 crate 完成。
- 不要把整段 shell 命令、JSON body 或 URL 直接交给它，除非调用方已经拆成字段名和值。

例如，HTTP crate 应先解析 query 参数，再调用
`sanitize_value("access_token", value)`；命令执行 crate 应先解析
`--token value` 或 `TOKEN=value`，再调用 `sanitize_value("token", value)`。

## 测试

最小本地验证：

```bash
cargo test
cargo clippy --all-targets --all-features -- -D warnings
```

如需和 CI 保持一致，请在项目根目录运行：`./align-ci.sh` 会对齐本地工具和配置，
然后 `./ci-check.sh` 执行与流水线一致的完整检查。覆盖率报告可通过
`./coverage.sh` 生成或查看。

## 贡献

欢迎提交 issue 和 pull request。

- 请保持本 crate 聚焦在通用字段值脱敏原语。
- 协议或格式解析逻辑应放在下游 crate。
- 修改匹配或脱敏行为时必须增加或更新测试。
- 用户可见行为变化时同步更新 README 和公开 rustdoc。
- 提交前请运行 `./align-ci.sh` 和 `./ci-check.sh`。

贡献代码即表示你同意将贡献内容按本项目相同的
[Apache License, Version 2.0](LICENSE) 授权。

## 许可证

Copyright © 2026 Haixing Hu, Qubit Co. Ltd.

本项目基于 [Apache License, Version 2.0](LICENSE) 开源。完整许可证文本见
`LICENSE` 文件。

## 作者

**Haixing Hu** — Qubit Co. Ltd.

| | |
| --- | --- |
| **Repository** | [github.com/qubit-ltd/rs-sanitize](https://github.com/qubit-ltd/rs-sanitize) |
| **Documentation** | [docs.rs/qubit-sanitize](https://docs.rs/qubit-sanitize) |
| **Crate** | [crates.io/crates/qubit-sanitize](https://crates.io/crates/qubit-sanitize) |
