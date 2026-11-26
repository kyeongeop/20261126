//! 面板配置：允许目录名单、仓库根约束与环境搜索路径。

use crate::errors::{code, RiskError, RiskResult};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// 配置文件结构，字段名保持稳定。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PanelConfig {
    /// 允许的搜索目录名单。支持：
    /// - 绝对路径（针对变量展开后的目录做匹配）；
    /// - 以 `$ORIGIN/` 开头的相对模式（针对原始条目匹配）。
    #[serde(default)]
    pub allowed_directories: Vec<String>,

    /// 模拟 LD_LIBRARY_PATH 的目录列表，默认空（不启用该搜索层）。
    #[serde(default)]
    pub ld_library_path: Vec<String>,

    /// 依赖递归最大深度，默认 16，用于防御异常依赖链。
    #[serde(default = "default_max_depth")]
    pub max_depth: usize,
}

fn default_max_depth() -> usize {
    16
}

impl Default for PanelConfig {
    fn default() -> Self {
        Self {
            allowed_directories: Vec::new(),
            ld_library_path: Vec::new(),
            max_depth: default_max_depth(),
        }
    }
}

impl PanelConfig {
    pub fn load(path: &Path) -> RiskResult<Self> {
        let bytes = std::fs::read(path)
            .map_err(|e| RiskError::new(code::IO, format!("读取配置 {} 失败: {e}", path.display())))?;
        let cfg: PanelConfig = serde_json::from_slice(&bytes)
            .map_err(|e| RiskError::new(code::CONFIG_PARSE, format!("配置解析失败: {e}")))?;
        if cfg.max_depth == 0 {
            return Err(RiskError::new(
                code::INVALID_ARGUMENT,
                "max_depth 必须大于 0",
            ));
        }
        Ok(cfg)
    }

    /// 判断展开后的目录与原始条目是否被允许。
    pub fn is_allowed(&self, expanded: Option<&str>, raw: &str) -> bool {
        for allowed in &self.allowed_directories {
            if let Some(suffix) = allowed.strip_prefix("$ORIGIN") {
                if normalize_origin_pattern(raw) == normalize_origin_pattern(suffix) {
                    return true;
                }
                continue;
            }
            if let Some(dir) = expanded {
                if same_path(dir, allowed) {
                    return true;
                }
            }
        }
        false
    }
}

fn normalize_origin_pattern(value: &str) -> String {
    let trimmed = value.trim_start_matches('/');
    trimmed.trim_end_matches('/').to_string()
}

fn same_path(left: &str, right: &str) -> bool {
    let l = Path::new(left).components().collect::<Vec<_>>();
    let r = Path::new(right).components().collect::<Vec<_>>();
    l == r
}

/// 仓库沙箱：所有被分析文件必须位于仓库根之内。
#[derive(Debug, Clone)]
pub struct RepoSandbox {
    root: PathBuf,
}

impl RepoSandbox {
    pub fn new(root: impl AsRef<Path>) -> RiskResult<Self> {
        let root = root
            .as_ref()
            .canonicalize()
            .map_err(|e| RiskError::new(code::PATH_NOT_FOUND, format!("仓库根不可用: {e}")))?;
        Ok(Self { root })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// 将输入路径规范化并限制在仓库内；越界返回 DLP1002。
    pub fn resolve(&self, path: &Path) -> RiskResult<PathBuf> {
        let candidate = if path.is_absolute() {
            path.to_path_buf()
        } else {
            self.root.join(path)
        };
        let canonical = candidate
            .canonicalize()
            .map_err(|e| RiskError::new(code::PATH_NOT_FOUND, format!("{}: {e}", candidate.display())))?;
        if !canonical.starts_with(&self.root) {
            return Err(RiskError::new(
                code::PATH_OUTSIDE_REPO,
                format!("{} 不在仓库根 {} 之内", canonical.display(), self.root.display()),
            ));
        }
        Ok(canonical)
    }

    /// 仓库相对路径（使用 `/` 分隔，保证 JSON 稳定）。
    pub fn relative(&self, path: &Path) -> String {
        let rel = path.strip_prefix(&self.root).unwrap_or(path);
        rel.components()
            .filter_map(|c| match c {
                std::path::Component::Normal(part) => Some(part.to_string_lossy().to_string()),
                std::path::Component::CurDir => None,
                _ => Some(c.as_os_str().to_string_lossy().to_string()),
            })
            .collect::<Vec<_>>()
            .join("/")
    }

    /// 校验尚未创建的输出文件：其父目录必须存在且整体位于仓库内。
    pub fn resolve_output(&self, path: &Path) -> RiskResult<PathBuf> {
        let candidate = if path.is_absolute() {
            path.to_path_buf()
        } else {
            self.root.join(path)
        };
        let parent = candidate
            .parent()
            .ok_or_else(|| RiskError::new(code::INVALID_ARGUMENT, "输出路径缺少父目录"))?;
        let parent = parent.canonicalize().map_err(|e| {
            RiskError::new(
                code::PATH_NOT_FOUND,
                format!("输出目录 {} 不可用: {e}", parent.display()),
            )
        })?;
        if !parent.starts_with(&self.root) {
            return Err(RiskError::new(
                code::PATH_OUTSIDE_REPO,
                format!("{} 不在仓库根 {} 之内", candidate.display(), self.root.display()),
            ));
        }
        let file_name = candidate
            .file_name()
            .ok_or_else(|| RiskError::new(code::INVALID_ARGUMENT, "输出路径缺少文件名"))?;
        Ok(parent.join(file_name))
    }
}
