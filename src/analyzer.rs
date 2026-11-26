//! 依赖链解析与风险识别：按 ld.so 语义还原优先搜索目录与风险来源。

use crate::config::{PanelConfig, RepoSandbox};
use crate::elf;
use crate::errors::{code, RiskError, RiskResult};
use crate::model::{
    finding_code, ArtifactReport, DependencyEdge, Finding, PanelReport, PathOrigin,
    ReportSummary, ResolvedCandidate, RiskSource, SearchEntry, Severity,
};
use crate::paths::{expand_entry, split_entries};
use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};

/// 已加载的仓库内制品。
struct Loaded {
    rel_path: String,
    info: elf::ElfDynamicInfo,
    search_entries: Vec<SearchEntry>,
}

/// 依赖图遍历上下文。
pub struct Analyzer<'a> {
    sandbox: &'a RepoSandbox,
    config: &'a PanelConfig,
    loaded: BTreeMap<String, Loaded>,
    findings: Vec<Finding>,
    edges: Vec<DependencyEdge>,
    visiting: HashSet<String>,
}

impl<'a> Analyzer<'a> {
    pub fn new(sandbox: &'a RepoSandbox, config: &'a PanelConfig) -> Self {
        Self {
            sandbox,
            config,
            loaded: BTreeMap::new(),
            findings: Vec::new(),
            edges: Vec::new(),
            visiting: HashSet::new(),
        }
    }

    pub fn run(mut self, root: &Path) -> RiskResult<PanelReport> {
        let root_abs = self.sandbox.resolve(root)?;
        self.load_artifact(&root_abs)?;
        let root_rel = self.sandbox.relative(&root_abs);

        self.traverse(&root_rel, 0)?;

        // 静态展示系统默认目录，不参与仓库内解析。
        let artifacts = self
            .loaded
            .values()
            .map(|item| ArtifactReport {
                path: item.rel_path.clone(),
                sha256: item.info.sha256.clone(),
                class: item.info.class.clone(),
                machine: item.info.machine.clone(),
                elf_type: item.info.elf_type.clone(),
                soname: item.info.soname.clone(),
                needed: item.info.needed.clone(),
                rpath_raw: item.info.rpath_raw.clone(),
                runpath_raw: item.info.runpath_raw.clone(),
                search_entries: item.search_entries.clone(),
            })
            .collect();

        let summary = self.build_summary();
        Ok(PanelReport {
            schema_version: 1,
            root_artifact: root_rel,
            repo_root: self.sandbox.root().to_string_lossy().into_owned(),
            artifacts,
            edges: self.edges,
            findings: self.findings,
            summary,
        })
    }

    fn load_artifact(&mut self, abs_path: &Path) -> RiskResult<()> {
        let rel_path = self.sandbox.relative(abs_path);
        if self.loaded.contains_key(&rel_path) {
            // 同一文件只解析一次：依赖回退路径与节区路径可能给出不同结果，
            // 缓存保证面板上每个制品的信息一致。
            return Ok(());
        }
        let bytes = std::fs::read(abs_path)?;
        let info = elf::parse_elf(&bytes)?;
        let origin_dir = abs_path.parent().unwrap_or_else(|| Path::new("/"));
        let search_entries = self.build_search_entries(&info, origin_dir);
        self.audit_artifact_entries(&rel_path, &search_entries);
        self.loaded.insert(
            rel_path.clone(),
            Loaded {
                rel_path,
                info,
                search_entries,
            },
        );
        Ok(())
    }

    /// 按 RPATH -> LD_LIBRARY_PATH -> RUNPATH 的层级生成条目，组内保留原始顺序。
    fn build_search_entries(
        &self,
        info: &elf::ElfDynamicInfo,
        origin_dir: &Path,
    ) -> Vec<SearchEntry> {
        let repo_root = self.sandbox.root();
        let mut entries = Vec::new();
        let mut order = 0usize;

        if let Some(rpath) = &info.rpath_raw {
            for raw in split_entries(rpath) {
                entries.push(expand_entry(&raw, origin_dir, repo_root, order, PathOrigin::Rpath));
                order += 1;
            }
        }
        for raw in &self.config.ld_library_path {
            entries.push(expand_entry(raw.as_str(), origin_dir, repo_root, order, PathOrigin::LdLibraryPath));
            order += 1;
        }
        if let Some(runpath) = &info.runpath_raw {
            for raw in split_entries(runpath) {
                entries.push(expand_entry(&raw, origin_dir, repo_root, order, PathOrigin::Runpath));
                order += 1;
            }
        }
        entries
    }

    /// 针对制品自身路径条目的静态审计：空项、旧 RPATH、逃逸、未展开变量、允许目录。
    fn audit_artifact_entries(&mut self, rel_path: &str, entries: &[SearchEntry]) {
        let has_rpath = entries.iter().any(|e| e.origin == PathOrigin::Rpath);
        if has_rpath {
            self.push(Finding {
                code: finding_code::RPATH_LEGACY.to_string(),
                severity: Severity::Medium,
                title: "使用已废弃的 DT_RPATH".to_string(),
                detail: "RPATH 作用于整个依赖链且先于 LD_LIBRARY_PATH，建议改用 RUNPATH".to_string(),
                artifact: rel_path.to_string(),
                sources: entries
                    .iter()
                    .filter(|e| e.origin == PathOrigin::Rpath)
                    .map(|e| self.source_of(rel_path, e))
                    .collect(),
            });
        }

        for entry in entries {
            if entry.empty {
                self.push(Finding {
                    code: finding_code::EMPTY_PATH_ENTRY.to_string(),
                    severity: Severity::High,
                    title: "路径串包含空路径项".to_string(),
                    detail: format!("{} 中存在空条目，ld.so 会将其解释为当前工作目录", origin_label(entry.origin)),
                    artifact: rel_path.to_string(),
                    sources: vec![self.source_of(rel_path, entry)],
                });
                continue;
            }
            if entry.escapes_repo {
                self.push(Finding {
                    code: finding_code::REPO_ESCAPE.to_string(),
                    severity: Severity::Critical,
                    title: "搜索目录逃逸出仓库".to_string(),
                    detail: format!(
                        "条目 `{}` 展开为 `{}`，位于仓库根之外，可能加载外部错误版本库",
                        entry.raw,
                        entry.expanded.clone().unwrap_or_default()
                    ),
                    artifact: rel_path.to_string(),
                    sources: vec![self.source_of(rel_path, entry)],
                });
            }
            if entry.unexpanded_variable {
                self.push(Finding {
                    code: finding_code::UNEXPANDED_VARIABLE.to_string(),
                    severity: Severity::Low,
                    title: "存在未展开的动态变量".to_string(),
                    detail: format!("条目 `{}` 含 $ORIGIN 之外的变量，不同机器展开结果不可控", entry.raw),
                    artifact: rel_path.to_string(),
                    sources: vec![self.source_of(rel_path, entry)],
                });
            }
            if !self.config.is_allowed(entry.expanded.as_deref(), &entry.raw) {
                self.push(Finding {
                    code: finding_code::NON_ALLOWED_DIRECTORY.to_string(),
                    severity: Severity::Medium,
                    title: "搜索目录不在允许名单内".to_string(),
                    detail: format!(
                        "目录 `{}` 未配置在 allowed_directories 中",
                        entry.expanded.clone().unwrap_or_else(|| entry.raw.clone())
                    ),
                    artifact: rel_path.to_string(),
                    sources: vec![self.source_of(rel_path, entry)],
                });
            }
        }
    }

    fn source_of(&self, artifact: &str, entry: &SearchEntry) -> RiskSource {
        RiskSource {
            from_artifact: artifact.to_string(),
            origin: entry.origin,
            directory: entry.expanded.clone(),
            order: entry.order,
        }
    }

    /// 深度优先遍历依赖链，处理多级继承与环。
    fn traverse(&mut self, rel_path: &str, depth: usize) -> RiskResult<()> {
        if depth >= self.config.max_depth {
            return Err(RiskError::new(
                code::CYCLIC_DEPENDENCY,
                format!("依赖链超过最大深度 {}，疑似异常依赖", self.config.max_depth),
            ));
        }
        if !self.visiting.insert(rel_path.to_string()) {
            self.push(Finding {
                code: finding_code::CYCLIC_DEPENDENCY.to_string(),
                severity: Severity::High,
                title: "依赖链存在环".to_string(),
                detail: format!("制品 {rel_path} 被重复入栈，依赖图存在循环引用"),
                artifact: rel_path.to_string(),
                sources: Vec::new(),
            });
            return Ok(());
        }

        let needed: Vec<String> = self
            .loaded
            .get(rel_path)
            .map(|item| item.info.needed.clone())
            .unwrap_or_default();
        for soname in needed {
            if is_system_library(&soname) {
                continue;
            }
            let edge = self.resolve_edge(rel_path, &soname, depth)?;
            let has_empty = edge
                .candidates
                .iter()
                .any(|c| c.directory.is_none());
            if has_empty {
                self.push(Finding {
                    code: finding_code::WORKDIR_LOOKUP.to_string(),
                    severity: Severity::High,
                    title: "依赖解析回退当前工作目录".to_string(),
                    detail: format!(
                        "解析 `{soname}` 时存在空路径项，ld.so 会在进程当前工作目录搜索同名库"
                    ),
                    artifact: rel_path.to_string(),
                    sources: edge
                        .candidates
                        .iter()
                        .filter(|c| c.directory.is_none())
                        .map(|c| RiskSource {
                            from_artifact: rel_path.to_string(),
                            origin: c.origin,
                            directory: None,
                            order: c.order,
                        })
                        .collect(),
                });
            }
            self.edges.push(edge.clone());
            if let Some(child) = edge.resolved.clone() {
                let child_abs = self.sandbox.resolve(Path::new(&child))?;
                self.load_artifact(&child_abs)?;
                if depth > 0 {
                    self.note_inherited_rpath(rel_path, &child, depth);
                }
                self.traverse(&child, depth + 1)?;
            }
        }

        self.visiting.remove(rel_path);
        Ok(())
    }

    /// RPATH 会沿依赖链继承：深层依赖可能被祖先的 RPATH 决定加载位置。
    fn note_inherited_rpath(&mut self, parent: &str, child: &str, depth: usize) {
        let inherited: Vec<RiskSource> = self
            .loaded
            .values()
            .filter(|item| item.rel_path != parent)
            .flat_map(|item| {
                item.search_entries
                    .iter()
                    .filter(|entry| entry.origin == PathOrigin::Rpath)
                    .map(|entry| self.source_of(&item.rel_path, entry))
            })
            .collect();
        if !inherited.is_empty() {
            self.push(Finding {
                code: finding_code::MULTI_LEVEL_INHERITANCE.to_string(),
                severity: Severity::Medium,
                title: "多级依赖受祖先 RPATH 影响".to_string(),
                detail: format!(
                    "第 {depth} 层依赖 {child} 的解析可能被上游制品的 RPATH 拦截，RUNPATH 不存在该继承行为"
                ),
                artifact: child.to_string(),
                sources: inherited,
            });
        }
    }

    /// 还原一次 NEEDED 解析：枚举所有候选目录，记录命中/未命中与风险来源。
    fn resolve_edge(
        &mut self,
        parent: &str,
        soname: &str,
        depth: usize,
    ) -> RiskResult<DependencyEdge> {
        let effective = self.effective_search_entries(parent);
        let mut candidates = Vec::new();
        let mut first_hit: Option<(ResolvedCandidate, RiskSource)> = None;
        let mut exists_seen = false;

        for entry in &effective {
            let directory = entry.expanded.clone();
            let in_repo = !entry.empty && !entry.escapes_repo;
            let (exists, resolved_to) = if in_repo {
                let candidate_path = PathBuf::from(directory.as_ref().unwrap()).join(soname);
                if candidate_path.is_file() {
                    let rel = self.sandbox.relative(&candidate_path);
                    (true, Some(rel))
                } else {
                    (false, None)
                }
            } else {
                (false, None)
            };
            let allowed = entry.empty || self.config.is_allowed(directory.as_deref(), &entry.raw);
            let candidate = ResolvedCandidate {
                directory,
                origin: entry.origin,
                order: entry.order,
                exists,
                resolved_to: resolved_to.clone(),
                allowed,
            };
            if exists {
                exists_seen = true;
                if first_hit.is_none() {
                    first_hit = Some((
                        candidate.clone(),
                        RiskSource {
                            from_artifact: parent.to_string(),
                            origin: entry.origin,
                            directory: entry.expanded.clone(),
                            order: entry.order,
                        },
                    ));
                }
            }
            candidates.push(candidate);
        }

        let (resolved, resolved_source) = match first_hit {
            Some((candidate, source)) => (candidate.resolved_to, Some(source)),
            None => {
                let detail = if effective.iter().any(|e| e.empty) {
                    format!("`{soname}` 在仓库候选目录中未找到；空路径项会回退到当前工作目录搜索，结果随部署机器变化")
                } else {
                    format!("`{soname}` 在所有仓库内候选目录中均未找到，将回退系统默认目录")
                };
                self.push(Finding {
                    code: finding_code::MISSING_DEPENDENCY.to_string(),
                    severity: Severity::High,
                    title: "依赖在仓库内无法解析".to_string(),
                    detail,
                    artifact: parent.to_string(),
                    sources: effective.iter().map(|e| self.source_of(parent, e)).collect(),
                });
                (None, None)
            }
        };

        if exists_seen {
            self.audit_shadowing(parent, soname, &candidates);
        }

        Ok(DependencyEdge {
            parent: parent.to_string(),
            needed: soname.to_string(),
            depth,
            candidates,
            resolved,
            resolved_source,
        })
    }

    /// 同一 SONAME 在多个候选目录出现即存在版本遮蔽，首个命中决定实际加载。
    fn audit_shadowing(
        &mut self,
        parent: &str,
        soname: &str,
        candidates: &[ResolvedCandidate],
    ) {
        let hits: Vec<&ResolvedCandidate> = candidates.iter().filter(|c| c.exists).collect();
        if hits.is_empty() {
            return;
        }
        let winner = hits[0];
        let shadowed = hits.len() > 1;
        let winner_disallowed = !winner.allowed;
        if !shadowed && !winner_disallowed {
            return;
        }
        let mut sources = vec![RiskSource {
            from_artifact: parent.to_string(),
            origin: winner.origin,
            directory: winner.directory.clone(),
            order: winner.order,
        }];
        let detail = if shadowed {
            let losers: Vec<String> = hits[1..]
                .iter()
                .filter_map(|c| c.resolved_to.clone())
                .collect();
            format!(
                "`{soname}` 在多个候选目录存在，实际加载 `{}`；以下副本被搜索顺序遮蔽：{}",
                winner.resolved_to.clone().unwrap_or_default(),
                losers.join("、")
            )
        } else {
            format!(
                "`{soname}` 实际从允许名单之外的目录 `{}` 加载",
                winner.directory.clone().unwrap_or_default()
            )
        };
        if shadowed {
            for loser in &hits[1..] {
                sources.push(RiskSource {
                    from_artifact: parent.to_string(),
                    origin: loser.origin,
                    directory: loser.directory.clone(),
                    order: loser.order,
                });
            }
        }
        self.push(Finding {
            code: finding_code::SHADOWED_LIBRARY.to_string(),
            severity: Severity::High,
            title: if shadowed {
                "优先目录决定了实际加载的库版本".to_string()
            } else {
                "库从未授权目录加载".to_string()
            },
            detail,
            artifact: parent.to_string(),
            sources,
        });
    }

    /// 计算一次依赖解析的有效搜索条目。
    ///
    /// ld.so 语义：
    /// 1. 链上所有对象的 DT_RPATH（按依赖链顺序，旧机制会继承）；
    /// 2. LD_LIBRARY_PATH（全局一次）；
    /// 3. 直接父对象自身的 DT_RUNPATH（RUNPATH 不继承）。
    fn effective_search_entries(&self, parent: &str) -> Vec<SearchEntry> {
        let mut effective: Vec<SearchEntry> = Vec::new();

        for item in self.loaded.values() {
            for entry in item
                .search_entries
                .iter()
                .filter(|e| e.origin == PathOrigin::Rpath)
            {
                effective.push(entry.clone());
            }
        }
        for entry in self
            .loaded
            .get(parent)
            .into_iter()
            .flat_map(|item| item.search_entries.iter())
            .filter(|e| e.origin == PathOrigin::LdLibraryPath || e.origin == PathOrigin::Runpath)
        {
            effective.push(entry.clone());
        }
        effective
    }

    fn push(&mut self, finding: Finding) {
        self.findings.push(finding);
    }

    fn build_summary(&self) -> ReportSummary {
        let mut summary = ReportSummary {
            artifact_count: self.loaded.len(),
            edge_count: self.edges.len(),
            finding_count: self.findings.len(),
            ..Default::default()
        };
        for finding in &self.findings {
            match finding.severity {
                Severity::Critical => summary.critical += 1,
                Severity::High => summary.high += 1,
                Severity::Medium => summary.medium += 1,
                Severity::Low => summary.low += 1,
            }
            if finding.code == finding_code::MISSING_DEPENDENCY {
                summary.missing_dependencies += 1;
            }
        }
        summary
    }
}

fn origin_label(origin: PathOrigin) -> &'static str {
    match origin {
        PathOrigin::Rpath => "DT_RPATH",
        PathOrigin::Runpath => "DT_RUNPATH",
        PathOrigin::LdLibraryPath => "LD_LIBRARY_PATH",
        PathOrigin::SystemDefault => "系统默认目录",
    }
}

/// 系统基础库由 ld.so 的系统默认目录提供，不纳入仓库内依赖解析与缺失统计。
fn is_system_library(soname: &str) -> bool {
    matches!(
        soname,
        "libc.so.6"
            | "libm.so.6"
            | "libdl.so.2"
            | "libpthread.so.0"
            | "librt.so.1"
            | "libresolv.so.2"
            | "libutil.so.1"
            | "ld-linux-x86-64.so.2"
            | "ld-linux.so.2"
            | "libgcc_s.so.1"
            | "libstdc++.so.6"
    )
}
