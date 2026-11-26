//! Structural checks over the parsed member tree.

use std::collections::{HashMap, HashSet};

use serde_json::json;

use crate::archive::{Archive, MemberKind, ParseFinding};
use crate::codes::IssueCode;
use crate::digest::sha256_hex;
use crate::inspect::{has_binary_extension, has_shebang, inspect_member};
use crate::model::{Finding, FindingOrigin, MemberReport};
use crate::path::{
    analyze_hardlink_target, analyze_link_target, analyze_member_path, is_path_prefix,
};

#[derive(Debug, Clone)]
pub struct CheckOptions {
    pub max_link_depth: usize,
    pub flag_group_writable: bool,
    pub flag_exec_on_non_binary: bool,
}

impl Default for CheckOptions {
    fn default() -> Self {
        Self {
            max_link_depth: 40,
            flag_group_writable: true,
            flag_exec_on_non_binary: true,
        }
    }
}

#[derive(Debug, Clone)]
pub struct CheckOutcome {
    pub members: Vec<MemberReport>,
    pub findings: Vec<Finding>,
}

pub fn check_archive(archive: &Archive, options: &CheckOptions) -> CheckOutcome {
    let mut members: Vec<MemberReport> = archive
        .members
        .iter()
        .map(|member| {
            let safety = analyze_member_path(&member.name);
            let sha256 = match member.kind {
                MemberKind::File => member.data.as_deref().map(sha256_hex),
                MemberKind::Symlink | MemberKind::HardLink => member
                    .link_target
                    .as_deref()
                    .map(|target| sha256_hex(target.as_bytes())),
                _ => None,
            };
            MemberReport {
                index: member.index,
                name: member.name.clone(),
                path: if safety.normalized.is_empty() {
                    member.name.clone()
                } else {
                    safety.normalized.clone()
                },
                kind: member.kind,
                mode: member.mode,
                unix_mode: member.unix_mode,
                size: member.size,
                compressed_size: member.compressed_size,
                sha256,
                link_target: member.link_target.clone(),
                resolved_link_target: None,
                object: member
                    .data
                    .as_deref()
                    .filter(|_| member.kind == MemberKind::File)
                    .and_then(|data| inspect_member(&member.name, data)),
                shebang: member.data.as_deref().is_some_and(has_shebang),
                issues: Vec::new(),
            }
        })
        .collect();

    let mut archive_findings = Vec::new();
    for finding in &archive.parse_findings {
        attach_parse_finding(&mut members, &mut archive_findings, finding);
    }
    for (index, member) in archive.members.iter().enumerate() {
        let safety = analyze_member_path(&member.name);
        if safety.nul {
            add_issue(
                &mut members,
                index,
                IssueCode::NulInPath,
                "member path contains a NUL byte",
                json!({ "path": member.name }),
            );
        }
        if safety.absolute {
            add_issue(
                &mut members,
                index,
                IssueCode::AbsolutePath,
                "member path is absolute and would escape the extraction root",
                json!({ "path": member.name }),
            );
        }
        if safety.traversal {
            add_issue(
                &mut members,
                index,
                IssueCode::PathTraversal,
                if safety.escape {
                    "member path traverses above the archive root"
                } else {
                    "member path contains a parent-directory segment"
                },
                json!({ "path": member.name, "normalized": safety.normalized }),
            );
        }
        if safety.empty {
            add_issue(
                &mut members,
                index,
                IssueCode::EmptyMemberName,
                "member path is empty after normalization",
                json!({ "path": member.name }),
            );
        }
        if safety.ambiguous_separator {
            add_issue(
                &mut members,
                index,
                IssueCode::PathSeparatorAmbiguity,
                "member path mixes backslash separators with archive paths",
                json!({ "path": member.name }),
            );
        }
        if member.kind.is_special() {
            add_issue(
                &mut members,
                index,
                IssueCode::SpecialFile,
                "archive contains a device, FIFO or other special member",
                json!({ "kind": member.kind.as_str() }),
            );
        }
        check_link(
            &mut members,
            index,
            &member.name,
            member.kind,
            member.link_target.as_deref(),
        );
    }

    let by_path = first_path_map(&members);
    check_duplicates(&mut members);
    check_prefix_conflicts(&mut members, &by_path);
    check_links(&mut members, &by_path, options);
    for index in 0..members.len() {
        check_permissions(&mut members, index, options);
    }

    let mut findings: Vec<Finding> = members
        .iter()
        .flat_map(|member| member.issues.iter().cloned())
        .chain(archive_findings)
        .collect();
    deduplicate_findings(&mut findings);
    findings.sort_by(|left, right| left.sort_key().cmp(&right.sort_key()));
    for member in &mut members {
        deduplicate_findings(&mut member.issues);
        member
            .issues
            .sort_by(|left, right| left.code.as_str().cmp(right.code.as_str()));
    }
    CheckOutcome { members, findings }
}

fn add_issue(
    members: &mut [MemberReport],
    index: usize,
    code: IssueCode,
    message: impl Into<String>,
    details: serde_json::Value,
) {
    let Some(member) = members.get(index) else {
        return;
    };
    let finding = Finding {
        code,
        severity: code.severity(),
        member_index: Some(member.index),
        member_name: Some(member.name.clone()),
        member_path: Some(member.path.clone()),
        message: message.into(),
        details,
        origin: FindingOrigin::Structure,
    };
    members[index].issues.push(finding);
}

fn attach_parse_finding(
    members: &mut [MemberReport],
    archive_findings: &mut Vec<Finding>,
    finding: &ParseFinding,
) {
    if let Some(index) = finding.member_index {
        if let Some(member) = members.get(index) {
            members[index].issues.push(Finding {
                code: finding.code,
                severity: finding.code.severity(),
                member_index: Some(member.index),
                member_name: Some(member.name.clone()),
                member_path: Some(member.path.clone()),
                message: finding.message.clone(),
                details: finding.details.clone(),
                origin: FindingOrigin::Structure,
            });
            return;
        }
    }
    archive_findings.push(Finding {
        code: finding.code,
        severity: finding.code.severity(),
        member_index: finding.member_index,
        member_name: finding.member_name.clone(),
        member_path: finding.member_name.clone(),
        message: finding.message.clone(),
        details: finding.details.clone(),
        origin: FindingOrigin::Archive,
    });
}

fn first_path_map(members: &[MemberReport]) -> HashMap<String, usize> {
    let mut map = HashMap::new();
    for (index, member) in members.iter().enumerate() {
        if !member.path.is_empty() {
            map.entry(member.path.clone()).or_insert(index);
        }
    }
    map
}

fn check_link(
    members: &mut [MemberReport],
    index: usize,
    path: &str,
    kind: MemberKind,
    target: Option<&str>,
) {
    if !kind.is_link() {
        return;
    }
    let target = target.unwrap_or("");
    let analysis = if kind == MemberKind::HardLink {
        analyze_hardlink_target(target)
    } else {
        analyze_link_target(path, target)
    };
    if let Some(member) = members.get_mut(index) {
        member.resolved_link_target = Some(analysis.resolved.clone());
    }
    if target.is_empty() {
        let (code, message) = if kind == MemberKind::Symlink {
            (IssueCode::SymlinkDangling, "symlink has an empty target")
        } else {
            (
                IssueCode::HardLinkTargetMissing,
                "hard link has an empty target",
            )
        };
        add_issue(members, index, code, message, json!({ "target": target }));
        return;
    }
    if analysis.nul {
        add_issue(
            members,
            index,
            IssueCode::NulInPath,
            "link target contains a NUL byte",
            json!({ "target": target }),
        );
    }
    if analysis.absolute {
        let code = if kind == MemberKind::Symlink {
            IssueCode::SymlinkAbsoluteTarget
        } else {
            IssueCode::HardLinkAbsoluteTarget
        };
        add_issue(
            members,
            index,
            code,
            "link target is an absolute host path",
            json!({ "target": target }),
        );
    }
    if analysis.traversal {
        let code = if kind == MemberKind::Symlink {
            IssueCode::SymlinkTargetTraversal
        } else {
            IssueCode::HardLinkTargetTraversal
        };
        add_issue(
            members,
            index,
            code,
            if analysis.escape {
                "link target escapes the archive root"
            } else {
                "link target contains a parent-directory segment"
            },
            json!({ "target": target, "resolved": analysis.resolved }),
        );
    }
    if analysis.ambiguous_separator {
        add_issue(
            members,
            index,
            IssueCode::PathSeparatorAmbiguity,
            "link target mixes backslash separators",
            json!({ "target": target }),
        );
    }
}

fn check_duplicates(members: &mut [MemberReport]) {
    let mut exact: HashMap<String, Vec<usize>> = HashMap::new();
    let mut folded: HashMap<String, Vec<usize>> = HashMap::new();
    for (index, member) in members.iter().enumerate() {
        if member.path.is_empty() {
            continue;
        }
        exact.entry(member.path.clone()).or_default().push(index);
        folded
            .entry(member.path.to_lowercase())
            .or_default()
            .push(index);
    }
    for (path, indexes) in exact {
        if indexes.len() > 1 {
            for index in &indexes {
                add_issue(
                    members,
                    *index,
                    IssueCode::DuplicatePath,
                    "duplicate member path in archive",
                    json!({ "path": path, "members": indexes }),
                );
            }
        }
    }
    for indexes in folded.values() {
        if indexes.len() < 2 {
            continue;
        }
        let distinct: HashSet<String> = indexes
            .iter()
            .filter_map(|index| members.get(*index))
            .map(|member| member.path.clone())
            .collect();
        if distinct.len() > 1 {
            for index in indexes {
                add_issue(
                    members,
                    *index,
                    IssueCode::DuplicatePathCaseInsensitive,
                    "paths differ only by letter case and can collide on some filesystems",
                    json!({ "members": indexes }),
                );
            }
        }
    }
}

fn check_prefix_conflicts(members: &mut [MemberReport], by_path: &HashMap<String, usize>) {
    let mut conflicts: HashSet<(usize, usize)> = HashSet::new();
    for (index, member) in members.iter().enumerate() {
        let mut prefix = String::new();
        for segment in member.path.split('/') {
            if !prefix.is_empty() {
                if let Some(&ancestor) = by_path.get(&prefix) {
                    if ancestor != index && members[ancestor].kind != MemberKind::Directory {
                        conflicts.insert((ancestor, index));
                        conflicts.insert((index, ancestor));
                    }
                }
                prefix.push('/');
            }
            prefix.push_str(segment);
        }
    }
    for (left, right) in conflicts {
        if let Some(member) = members.get(left) {
            let path = member.path.clone();
            add_issue(
                members,
                left,
                IssueCode::PathPrefixConflict,
                "a non-directory member is also used as a path prefix",
                json!({ "path": path, "other_index": right }),
            );
        }
    }
}

fn path_exists(by_path: &HashMap<String, usize>, path: &str) -> bool {
    by_path.contains_key(path)
        || by_path
            .keys()
            .any(|candidate| is_path_prefix(path, candidate))
}

fn check_links(
    members: &mut [MemberReport],
    by_path: &HashMap<String, usize>,
    options: &CheckOptions,
) {
    let mut missing_hardlinks = Vec::new();
    let mut dangling = Vec::new();
    let mut loops = Vec::new();
    for (index, member) in members.iter().enumerate() {
        match member.kind {
            MemberKind::HardLink => {
                if let Some(target) = &member.resolved_link_target {
                    if !path_exists(by_path, target) {
                        missing_hardlinks.push((index, target.clone()));
                    }
                }
            }
            MemberKind::Symlink => {
                if member
                    .resolved_link_target
                    .as_deref()
                    .is_some_and(|target| !target.is_empty() && !path_exists(by_path, target))
                {
                    dangling.push((index, member.resolved_link_target.clone()));
                }
                if let Some(target) =
                    resolve_symlink_chain(index, members, by_path, options.max_link_depth)
                {
                    match target {
                        LinkResolution::Dangling(path) => dangling.push((index, Some(path))),
                        LinkResolution::Loop(path) => loops.push((index, Some(path))),
                        LinkResolution::Resolved => {}
                    }
                }
            }
            _ => {}
        }
    }
    for (index, target) in missing_hardlinks {
        add_issue(
            members,
            index,
            IssueCode::HardLinkTargetMissing,
            "hard link target is not present in the archive",
            json!({ "target": target }),
        );
    }
    for (index, target) in dangling {
        add_issue(
            members,
            index,
            IssueCode::SymlinkDangling,
            "symlink target is not present in the archive",
            json!({ "target": target }),
        );
    }
    for (index, target) in loops {
        add_issue(
            members,
            index,
            IssueCode::SymlinkLoop,
            "symlink chain contains a cycle or exceeds the depth limit",
            json!({ "target": target }),
        );
    }
}

enum LinkResolution {
    Resolved,
    Dangling(String),
    Loop(String),
}

fn resolve_symlink_chain(
    start: usize,
    members: &[MemberReport],
    by_path: &HashMap<String, usize>,
    max_depth: usize,
) -> Option<LinkResolution> {
    let mut visited = HashSet::new();
    visited.insert(start);
    let mut current = start;
    for _ in 0..max_depth {
        let Some(target) = members[current].resolved_link_target.clone() else {
            return Some(LinkResolution::Dangling(String::new()));
        };
        if target.is_empty() {
            return Some(LinkResolution::Dangling(target));
        }
        if !path_exists(by_path, &target) {
            return Some(LinkResolution::Dangling(target));
        }
        let Some(&next) = by_path.get(&target) else {
            return Some(LinkResolution::Resolved);
        };
        if members[next].kind != MemberKind::Symlink {
            return Some(LinkResolution::Resolved);
        }
        if !visited.insert(next) {
            return Some(LinkResolution::Loop(target));
        }
        current = next;
    }
    Some(LinkResolution::Loop(
        members[current]
            .resolved_link_target
            .clone()
            .unwrap_or_default(),
    ))
}

fn check_permissions(members: &mut [MemberReport], index: usize, options: &CheckOptions) {
    let (kind, mode, name, size, shebang, object) = {
        let Some(member) = members.get(index) else {
            return;
        };
        if member.kind.is_link() {
            return;
        }
        let Some(mode) = member.mode else {
            return;
        };
        (
            member.kind,
            mode,
            member.name.clone(),
            member.size,
            member.shebang,
            member.object.clone(),
        )
    };
    let permissions = mode & 0o7777;
    let file_type = mode & 0o170000;
    if file_type != 0 {
        let expected = match kind {
            MemberKind::File => 0o100000,
            MemberKind::Directory => 0o040000,
            MemberKind::Symlink => 0o120000,
            MemberKind::CharacterDevice => 0o020000,
            MemberKind::BlockDevice => 0o060000,
            MemberKind::Fifo => 0o010000,
            _ => 0,
        };
        if expected != 0 && file_type != expected {
            add_issue(
                members,
                index,
                IssueCode::PermissionModeInvalid,
                "mode file-type bits disagree with the member type",
                json!({ "mode": format!("{mode:06o}"), "file_type": format!("{file_type:06o}") }),
            );
        }
    }
    for (bit, code, message) in [
        (0o4000, IssueCode::PermissionSetuid, "setuid bit is set"),
        (0o2000, IssueCode::PermissionSetgid, "setgid bit is set"),
        (0o1000, IssueCode::PermissionSticky, "sticky bit is set"),
    ] {
        if permissions & bit != 0 {
            add_issue(
                members,
                index,
                code,
                message,
                json!({ "mode": format!("{:04o}", permissions) }),
            );
        }
    }
    if permissions & 0o002 != 0 {
        add_issue(
            members,
            index,
            IssueCode::PermissionWorldWritable,
            "all users can write this member",
            json!({ "mode": format!("{:04o}", permissions) }),
        );
    }
    if options.flag_group_writable && permissions & 0o020 != 0 {
        add_issue(
            members,
            index,
            IssueCode::PermissionGroupWritable,
            "group members can write this file",
            json!({ "mode": format!("{:04o}", permissions) }),
        );
    }
    if permissions & 0o400 == 0 {
        add_issue(
            members,
            index,
            IssueCode::PermissionMissingOwnerRead,
            "owner read bit is missing",
            json!({ "mode": format!("{:04o}", permissions) }),
        );
    }
    if kind == MemberKind::Directory && permissions & 0o100 == 0 {
        add_issue(
            members,
            index,
            IssueCode::PermissionDirectoryNotSearchable,
            "directory owner search bit is missing",
            json!({ "mode": format!("{:04o}", permissions) }),
        );
    }

    if let Some(object) = &object {
        if object.executable && permissions & 0o111 == 0 {
            add_issue(
                members,
                index,
                IssueCode::PermissionExecMissingForBinary,
                "object file is executable but no execute bit is set",
                json!({ "mode": format!("{:04o}", permissions), "object_kind": object.kind }),
            );
        }
        return;
    }
    let executable = permissions & 0o111 != 0;
    if shebang {
        return;
    }
    if executable && size > 0 && options.flag_exec_on_non_binary && has_binary_extension(&name) {
        add_issue(
            members,
            index,
            IssueCode::BinaryParseFailed,
            "member has a binary extension but object parsing failed",
            json!({ "name": name }),
        );
    } else if executable && size > 0 && options.flag_exec_on_non_binary {
        add_issue(
            members,
            index,
            IssueCode::PermissionExecOnNonBinary,
            "execute bit is set on a member that object cannot parse as a binary",
            json!({ "mode": format!("{:04o}", permissions) }),
        );
    }
}

fn deduplicate_findings(findings: &mut Vec<Finding>) {
    let mut seen = HashSet::new();
    findings.retain(|finding| seen.insert((finding.code.as_str(), finding.member_index)));
}
