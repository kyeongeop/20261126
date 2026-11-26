//! RPATH / RUNPATH 条目展开，严格复刻 ld.so 的变量与分隔符语义。

use crate::model::PathOrigin;
use crate::model::SearchEntry;
use std::path::{Component, Path, PathBuf};

/// 将冒号分隔的原始路径串拆成条目。
///
/// 与 ld.so 一致：连续冒号或首尾冒号产生空条目，空条目表示当前工作目录。
pub fn split_entries(raw: &str) -> Vec<String> {
    raw.split(':').map(str::to_string).collect()
}

/// 展开单个条目。`origin` 为所属 ELF 文件所在目录的绝对路径。
pub fn expand_entry(
    raw: &str,
    origin: &Path,
    repo_root: &Path,
    order: usize,
    path_origin: PathOrigin,
) -> SearchEntry {
    let empty = raw.is_empty();

    if empty {
        // 空路径项：ld.so 视为当前工作目录，无法静态确定，保留 None 并标记风险。
        return SearchEntry {
            order,
            origin: path_origin,
            raw: raw.to_string(),
            expanded: None,
            empty: true,
            unexpanded_variable: false,
            escapes_repo: false,
        };
    }

    let (expanded_text, unexpanded) = substitute_variables(raw, origin);
    let expanded_path = if Path::new(&expanded_text).is_absolute() {
        normalize(&PathBuf::from(&expanded_text))
    } else {
        normalize(&origin.join(&expanded_text))
    };
    let expanded = expanded_path.to_string_lossy().into_owned();
    let escapes_repo = !expanded_path.starts_with(repo_root);

    SearchEntry {
        order,
        origin: path_origin,
        raw: raw.to_string(),
        expanded: Some(expanded),
        empty: false,
        unexpanded_variable: unexpanded,
        escapes_repo,
    }
}

/// 处理 `$ORIGIN`、`${ORIGIN}` 两种写法；其余变量保持原样并标记未展开。
fn substitute_variables(raw: &str, origin: &Path) -> (String, bool) {
    let origin_text = origin.to_string_lossy().into_owned();
    let mut out = String::with_capacity(raw.len());
    let mut rest = raw;
    let mut unexpanded = false;

    while let Some(pos) = rest.find('$') {
        out.push_str(&rest[..pos]);
        let after = &rest[pos + 1..];
        if let Some(braced) = after.strip_prefix('{') {
            if let Some(end) = braced.find('}') {
                let name = &braced[..end];
                if name == "ORIGIN" {
                    out.push_str(&origin_text);
                } else {
                    out.push_str("${");
                    out.push_str(name);
                    out.push('}');
                    unexpanded = true;
                }
                rest = &braced[end + 1..];
                continue;
            }
        } else {
            let end = after
                .find(|c: char| !c.is_ascii_alphanumeric() && c != '_')
                .unwrap_or(after.len());
            let name = &after[..end];
            if name == "ORIGIN" {
                out.push_str(&origin_text);
            } else {
                out.push('$');
                out.push_str(name);
                unexpanded = true;
            }
            rest = &after[end..];
            continue;
        }
        out.push('$');
        rest = after;
    }
    out.push_str(rest);
    (out, unexpanded)
}

/// 词法归一化（不触碰文件系统）：处理 `.`、`..` 与重复分隔符。
fn normalize(path: &Path) -> PathBuf {
    let mut stack: Vec<Component> = Vec::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => match stack.last() {
                Some(Component::Normal(_)) => {
                    stack.pop();
                }
                _ => stack.push(component),
            },
            other => stack.push(other),
        }
    }
    stack.iter().map(|c| c.as_os_str()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_empty_entries() {
        assert_eq!(split_entries("a::b:"), vec!["a", "", "b", ""]);
        assert_eq!(split_entries(""), vec![""]);
    }

    #[test]
    fn expands_origin_forms() {
        let origin = Path::new("/repo/bin");
        let repo = Path::new("/repo");
        let entry = expand_entry("$ORIGIN/../lib", origin, repo, 0, PathOrigin::Rpath);
        assert_eq!(entry.expanded.as_deref(), Some("/repo/lib"));
        assert!(!entry.escapes_repo);

        let braced = expand_entry("${ORIGIN}/lib", origin, repo, 1, PathOrigin::Runpath);
        assert_eq!(braced.expanded.as_deref(), Some("/repo/bin/lib"));
    }

    #[test]
    fn flags_empty_and_escape() {
        let origin = Path::new("/repo/bin");
        let repo = Path::new("/repo");
        let empty = expand_entry("", origin, repo, 0, PathOrigin::Rpath);
        assert!(empty.empty);
        assert!(empty.expanded.is_none());

        let escape = expand_entry("$ORIGIN/../../etc", origin, repo, 1, PathOrigin::Rpath);
        assert_eq!(escape.expanded.as_deref(), Some("/etc"));
        assert!(escape.escapes_repo);
    }

    #[test]
    fn keeps_unknown_variables() {
        let origin = Path::new("/repo/bin");
        let repo = Path::new("/repo");
        let entry = expand_entry("$ORIGIN/$PLATFORM", origin, repo, 0, PathOrigin::Runpath);
        assert!(entry.unexpanded_variable);
        assert_eq!(entry.expanded.as_deref(), Some("/repo/bin/$PLATFORM"));
    }
}
