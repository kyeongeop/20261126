//! 稳定错误码。
//!
//! 错误码字符串一旦发布即视为对外契约，只能新增、不得修改或复用，
//! 以保证发布制品管理平台各版本之间的错误处理逻辑保持兼容。

use std::fmt;

/// 错误码常量：新增错误时追加新常量，禁止改动已有常量的值。
pub mod code {
    pub const INVALID_ARGUMENT: &str = "DLP1001";
    pub const PATH_OUTSIDE_REPO: &str = "DLP1002";
    pub const PATH_NOT_FOUND: &str = "DLP1003";
    pub const NOT_ELF: &str = "DLP1004";
    pub const ELF_PARSE: &str = "DLP1005";
    pub const DYNAMIC_SECTION: &str = "DLP1006";
    pub const CONFIG_PARSE: &str = "DLP1007";
    pub const IO: &str = "DLP1008";
    pub const CYCLIC_DEPENDENCY: &str = "DLP1009";
    /// 预留编码：保留编号不复用，保证错误码表稳定。
    #[allow(dead_code)]
    pub const DEPENDENCY_MISSING_RESERVED: &str = "DLP1010";
}

/// 平台统一错误类型，携带稳定错误码与上下文信息。
#[derive(Debug, Clone)]
pub struct RiskError {
    pub code: &'static str,
    pub message: String,
}

impl RiskError {
    pub fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

impl fmt::Display for RiskError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {}", self.code, self.message)
    }
}

impl std::error::Error for RiskError {}

pub type RiskResult<T> = Result<T, RiskError>;

impl From<std::io::Error> for RiskError {
    fn from(value: std::io::Error) -> Self {
        RiskError::new(code::IO, value.to_string())
    }
}

/// 错误的 JSON 序列化结构，字段名保持稳定。
#[derive(serde::Serialize)]
pub struct ErrorBody {
    pub error_code: &'static str,
    pub message: String,
}

impl From<&RiskError> for ErrorBody {
    fn from(value: &RiskError) -> Self {
        Self {
            error_code: value.code,
            message: value.message.clone(),
        }
    }
}
