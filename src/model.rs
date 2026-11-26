//! 风险面板的数据模型，字段名同时作为 JSON 报告的稳定输出契约。

use serde::{Deserialize, Serialize};

/// 触发动态库搜索的路径来源类型，与 ld.so 语义保持一致。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PathOrigin {
    /// DT_RPATH（旧机制，作用于整个依赖链，先于 LD_LIBRARY_PATH）。
    Rpath,
    /// DT_RUNPATH（新机制，仅作用于该对象自身的直接依赖）。
    Runpath,
    /// LD_LIBRARY_PATH 环境变量（平台以配置形式注入，默认空）。
    LdLibraryPath,
    /// 系统默认目录 /lib、/usr/lib（仅展示，不参与仓库内解析）。
    SystemDefault,
}

/// 单个优先搜索目录项，保留原始条目与展开结果。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchEntry {
    /// 目录在所属来源中的优先级序号（从 0 开始）。
    pub order: usize,
    pub origin: PathOrigin,
    /// 原始条目，例如 `$ORIGIN/../lib`、空字符串等。
    pub raw: String,
    /// 变量展开后的绝对路径；无法展开时为 None。
    pub expanded: Option<String>,
    /// 原始条目是否为空（ld.so 将空项视为当前工作目录）。
    pub empty: bool,
    /// 是否包含未展开的变量（如未知的 `${PLATFORM}`）。
    pub unexpanded_variable: bool,
    /// 展开后是否逃逸出仓库根目录。
    pub escapes_repo: bool,
}

/// 依赖来源标签：说明一次库命中或未命中是由哪个对象的哪类路径决定的。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskSource {
    /// 产生该搜索路径的对象（仓库相对路径）。
    pub from_artifact: String,
    pub origin: PathOrigin,
    /// 命中或被优先考虑的目录（展开后），空项以 None 表示当前工作目录。
    pub directory: Option<String>,
    pub order: usize,
}

/// 风险等级。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

/// 风险类型稳定编码（与错误码相同，只增不改）。
pub mod finding_code {
    pub const EMPTY_PATH_ENTRY: &str = "DLP2001";
    pub const RPATH_LEGACY: &str = "DLP2002";
    pub const WORKDIR_LOOKUP: &str = "DLP2003";
    pub const REPO_ESCAPE: &str = "DLP2004";
    pub const UNEXPANDED_VARIABLE: &str = "DLP2005";
    pub const SHADOWED_LIBRARY: &str = "DLP2006";
    pub const MISSING_DEPENDENCY: &str = "DLP2007";
    pub const NON_ALLOWED_DIRECTORY: &str = "DLP2008";
    pub const CYCLIC_DEPENDENCY: &str = "DLP2009";
    pub const MULTI_LEVEL_INHERITANCE: &str = "DLP2010";
}

/// 面板上的单条风险。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub code: String,
    pub severity: Severity,
    pub title: String,
    pub detail: String,
    /// 风险归属的制品（仓库相对路径）。
    pub artifact: String,
    /// 风险来源链，按搜索优先级排列。
    pub sources: Vec<RiskSource>,
}

/// 一次依赖解析候选记录，用于还原“优先搜索目录如何决定加载结果”。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolvedCandidate {
    /// 被搜索的目录，None 表示空路径项（当前工作目录）。
    pub directory: Option<String>,
    pub origin: PathOrigin,
    pub order: usize,
    /// 该目录下是否存在同名库。
    pub exists: bool,
    /// 存在时给出仓库相对路径。
    pub resolved_to: Option<String>,
    /// 该目录是否在允许目录名单内。
    pub allowed: bool,
}

/// 依赖图中的一条边：父对象依赖某个 SONAME，以及完整解析过程。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DependencyEdge {
    pub parent: String,
    pub needed: String,
    pub depth: usize,
    /// 按 ld.so 搜索顺序展开的候选目录列表（含未命中项）。
    pub candidates: Vec<ResolvedCandidate>,
    /// 最终命中的仓库相对路径；未命中为 None。
    pub resolved: Option<String>,
    /// 命中所对应的风险来源。
    pub resolved_source: Option<RiskSource>,
}

/// 单个 ELF 制品的解析结果。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactReport {
    /// 仓库相对路径。
    pub path: String,
    pub sha256: String,
    pub class: String,
    pub machine: String,
    pub elf_type: String,
    pub soname: Option<String>,
    pub needed: Vec<String>,
    /// 原始 RPATH 字符串（DT_RPATH）。
    pub rpath_raw: Option<String>,
    /// 原始 RUNPATH 字符串（DT_RUNPATH）。
    pub runpath_raw: Option<String>,
    /// 展开后的优先搜索目录，按搜索优先级排序。
    pub search_entries: Vec<SearchEntry>,
}

/// 面板最外层报告。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PanelReport {
    pub schema_version: u32,
    pub root_artifact: String,
    pub repo_root: String,
    pub artifacts: Vec<ArtifactReport>,
    pub edges: Vec<DependencyEdge>,
    pub findings: Vec<Finding>,
    pub summary: ReportSummary,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ReportSummary {
    pub artifact_count: usize,
    pub edge_count: usize,
    pub finding_count: usize,
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub missing_dependencies: usize,
}
