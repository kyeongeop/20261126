//! Structure comparison for fixed-package re-uploads.

use std::collections::{BTreeMap, HashSet};

use serde_json::{json, Value};

use crate::archive::{Archive, ArchiveFormat, MemberKind};
use crate::codes::IssueCode;
use crate::digest::sha256_hex;
use crate::model::{ArchiveSummary, ChangeEntry, ComparisonReport, Finding, FindingOrigin};
use crate::path::analyze_member_path;

pub fn compare_structure(previous: &Archive, current: &Archive) -> ComparisonReport {
    let previous_map = member_map(previous);
    let current_map = member_map(current);
    let mut added = Vec::new();
    let mut removed = Vec::new();
    let mut changed = Vec::new();
    let mut findings = Vec::new();
    let mut unchanged = 0usize;

    for (path, index) in &current_map {
        if !previous_map.contains_key(path) {
            let member = &current.members[*index];
            added.push(ChangeEntry {
                path: path.clone(),
                previous_index: None,
                current_index: Some(member.index),
                fields: vec!["member".to_string()],
                detail: json!({ "kind": member.kind.as_str(), "size": member.size }),
            });
            findings.push(reupload_finding(
                IssueCode::ReuploadMemberAdded,
                Some(member.index),
                Some(&member.name),
                Some(path),
                "fix archive adds a member that did not exist in the previous version",
                json!({ "kind": member.kind.as_str() }),
            ));
        }
    }
    for (path, index) in &previous_map {
        if !current_map.contains_key(path) {
            let member = &previous.members[*index];
            removed.push(ChangeEntry {
                path: path.clone(),
                previous_index: Some(member.index),
                current_index: None,
                fields: vec!["member".to_string()],
                detail: json!({ "kind": member.kind.as_str(), "size": member.size }),
            });
            findings.push(reupload_finding(
                IssueCode::ReuploadMemberRemoved,
                Some(member.index),
                Some(&member.name),
                Some(path),
                "fix archive removes a member present in the previous version",
                json!({ "kind": member.kind.as_str() }),
            ));
        }
    }

    for (path, previous_index) in &previous_map {
        let Some(current_index) = current_map.get(path) else {
            continue;
        };
        let old = &previous.members[*previous_index];
        let new = &current.members[*current_index];
        let mut fields = Vec::new();
        if old.kind != new.kind {
            fields.push("type".to_string());
        }
        if old.mode.map(|mode| mode & 0o7777) != new.mode.map(|mode| mode & 0o7777) {
            fields.push("mode".to_string());
        }
        if old.link_target != new.link_target {
            fields.push("link_target".to_string());
        }
        let old_sha = member_sha(old.kind, old.data.as_deref(), old.link_target.as_deref());
        let new_sha = member_sha(new.kind, new.data.as_deref(), new.link_target.as_deref());
        if old_sha != new_sha {
            fields.push("content".to_string());
        }
        if fields.is_empty() {
            unchanged += 1;
            continue;
        }
        changed.push(ChangeEntry {
            path: path.clone(),
            previous_index: Some(old.index),
            current_index: Some(new.index),
            fields: fields.clone(),
            detail: json!({
                "previous": member_snapshot(old),
                "current": member_snapshot(new),
            }),
        });
        if old.kind != new.kind {
            findings.push(reupload_finding(
                IssueCode::ReuploadTypeChanged,
                Some(new.index),
                Some(&new.name),
                Some(path),
                "fix archive changes the member type",
                json!({
                    "previous": old.kind.as_str(),
                    "current": new.kind.as_str(),
                }),
            ));
        }
        if old.mode.map(|mode| mode & 0o7777) != new.mode.map(|mode| mode & 0o7777) {
            findings.push(reupload_finding(
                IssueCode::ReuploadModeChanged,
                Some(new.index),
                Some(&new.name),
                Some(path),
                "fix archive changes member permissions",
                json!({
                    "previous": old.mode.map(|mode| format!("{:04o}", mode & 0o7777)),
                    "current": new.mode.map(|mode| format!("{:04o}", mode & 0o7777)),
                }),
            ));
        }
        if old.link_target != new.link_target {
            findings.push(reupload_finding(
                IssueCode::ReuploadSymlinkTargetChanged,
                Some(new.index),
                Some(&new.name),
                Some(path),
                "fix archive changes a link target",
                json!({
                    "previous": old.link_target,
                    "current": new.link_target,
                }),
            ));
        }
        if old_sha != new_sha {
            findings.push(reupload_finding(
                IssueCode::ReuploadContentChanged,
                Some(new.index),
                Some(&new.name),
                Some(path),
                "fix archive member content differs from the previous version",
                json!({ "previous_sha256": old_sha, "current_sha256": new_sha }),
            ));
        }
    }

    added.sort_by(|left, right| left.path.cmp(&right.path));
    removed.sort_by(|left, right| left.path.cmp(&right.path));
    changed.sort_by(|left, right| left.path.cmp(&right.path));
    findings.sort_by(|left, right| left.sort_key().cmp(&right.sort_key()));
    let structural_change = changed
        .iter()
        .any(|change| change.fields.iter().any(|field| field != "content"));
    let same_structure = added.is_empty() && removed.is_empty() && !structural_change;
    ComparisonReport {
        previous: summary(previous),
        current: summary(current),
        unchanged,
        added,
        removed,
        changed,
        findings,
        same_structure,
    }
}

/// Compare structural findings after both archives have been checked.
pub fn compare_findings(
    previous: &[Finding],
    current: &[Finding],
    comparison: &mut ComparisonReport,
) {
    let previous_set: HashSet<(&str, Option<String>)> = previous
        .iter()
        .map(|finding| (finding.code.as_str(), finding.member_path.clone()))
        .collect();
    let current_set: HashSet<(&str, Option<String>)> = current
        .iter()
        .map(|finding| (finding.code.as_str(), finding.member_path.clone()))
        .collect();
    for finding in current {
        if !previous_set.contains(&(finding.code.as_str(), finding.member_path.clone())) {
            comparison.findings.push(reupload_finding(
                IssueCode::ReuploadNewIssue,
                finding.member_index,
                finding.member_name.as_deref(),
                finding.member_path.as_deref(),
                format!(
                    "fix archive introduces {} ({})",
                    finding.code.as_str(),
                    finding.message
                ),
                json!({ "issue_code": finding.code.as_str() }),
            ));
        }
    }
    for finding in previous {
        if !current_set.contains(&(finding.code.as_str(), finding.member_path.clone())) {
            comparison.findings.push(reupload_finding(
                IssueCode::ReuploadIssueFixed,
                finding.member_index,
                finding.member_name.as_deref(),
                finding.member_path.as_deref(),
                format!(
                    "previous issue {} ({}) is no longer present",
                    finding.code.as_str(),
                    finding.message
                ),
                json!({ "issue_code": finding.code.as_str() }),
            ));
        } else {
            comparison.findings.push(reupload_finding(
                IssueCode::ReuploadIssueRemains,
                finding.member_index,
                finding.member_name.as_deref(),
                finding.member_path.as_deref(),
                format!("previous issue {} is still present", finding.code.as_str()),
                json!({ "issue_code": finding.code.as_str() }),
            ));
        }
    }
    comparison
        .findings
        .sort_by(|left, right| left.sort_key().cmp(&right.sort_key()));
}

pub fn summary(archive: &Archive) -> ArchiveSummary {
    ArchiveSummary {
        fixture_path: String::new(),
        format: archive.format.as_str().to_string(),
        sha256: archive.sha256.clone(),
        declared_sha256: None,
        size: archive.size,
        member_count: archive.members.len(),
        total_uncompressed: archive.total_uncompressed(),
    }
}

fn member_map(archive: &Archive) -> BTreeMap<String, usize> {
    let mut map = BTreeMap::new();
    for (position, member) in archive.members.iter().enumerate() {
        let path = analyze_member_path(&member.name).normalized;
        if !path.is_empty() {
            map.entry(path).or_insert(position);
        }
    }
    map
}

fn member_sha(kind: MemberKind, data: Option<&[u8]>, target: Option<&str>) -> Option<String> {
    if kind == MemberKind::Symlink || kind == MemberKind::HardLink {
        target.map(|target| sha256_hex(target.as_bytes()))
    } else {
        data.map(sha256_hex)
    }
}

fn member_snapshot(member: &crate::archive::Member) -> Value {
    json!({
        "kind": member.kind.as_str(),
        "mode": member.mode.map(|mode| format!("{:04o}", mode & 0o7777)),
        "size": member.size,
        "sha256": member_sha(member.kind, member.data.as_deref(), member.link_target.as_deref()),
        "link_target": member.link_target,
    })
}

fn reupload_finding(
    code: IssueCode,
    member_index: Option<usize>,
    member_name: Option<&str>,
    member_path: Option<&str>,
    message: impl Into<String>,
    details: Value,
) -> Finding {
    Finding {
        code,
        severity: code.severity(),
        member_index,
        member_name: member_name.map(str::to_string),
        member_path: member_path.map(str::to_string),
        message: message.into(),
        details,
        origin: FindingOrigin::Reupload,
    }
}

#[allow(dead_code)]
fn _format_for_debug(format: ArchiveFormat) -> &'static str {
    format.as_str()
}
