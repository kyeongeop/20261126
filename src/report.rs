//! Report assembly and stable JSON serialization.

use serde_json::{json, Value};

use crate::archive::{Archive, MemberKind};
use crate::check::{check_archive, CheckOptions};
use crate::codes::{issue_catalog, IssueCode};
use crate::compare::{compare_findings, compare_structure};
use crate::error::error_catalog;
use crate::manifest::UploadManifest;
use crate::model::{
    ArchiveSummary, ComparisonReport, Finding, MemberReport, StructureReport, Verdict,
};
use crate::{FEATURE_ID, FEATURE_NAME_ZH, REPORT_SCHEMA_VERSION};

pub fn build_report(
    manifest_path: &str,
    manifest: &UploadManifest,
    archive_path: &str,
    archive: Archive,
    previous_archive_path: Option<String>,
    previous_archive: Option<Archive>,
    options: &CheckOptions,
) -> StructureReport {
    let current_check = check_archive(&archive, options);
    let mut archive_summary = summary_for(&archive, archive_path);
    archive_summary.declared_sha256 = manifest.archive_sha256.clone();
    let mut findings = current_check.findings.clone();
    if let Some(declared) = &manifest.archive_sha256 {
        if declared != &archive.sha256 {
            findings.push(Finding::archive(
                IssueCode::ArchiveHashMismatch,
                "outer archive SHA-256 does not match the upload manifest",
                json!({
                    "declared": declared,
                    "actual": archive.sha256,
                    "path": archive_path,
                }),
            ));
        }
    }

    let mut comparison = None;
    let mut previous_summary = None;
    if let Some(previous) = previous_archive {
        let path = previous_archive_path.unwrap_or_else(|| "previous archive".to_string());
        let previous_check = check_archive(&previous, options);
        let mut previous_report = summary_for(&previous, &path);
        previous_report.declared_sha256 = manifest.previous_archive_sha256.clone();
        if let Some(declared) = &manifest.previous_archive_sha256 {
            if declared != &previous.sha256 {
                findings.push(Finding::archive(
                    IssueCode::ArchiveHashMismatch,
                    "previous archive SHA-256 does not match the upload manifest",
                    json!({
                        "declared": declared,
                        "actual": previous.sha256,
                        "path": path,
                        "side": "previous",
                    }),
                ));
            }
        }
        let mut compared = compare_structure(&previous, &archive);
        compared.previous = previous_report.clone();
        compared.current = archive_summary.clone();
        compare_findings(
            &previous_check.findings,
            &current_check.findings,
            &mut compared,
        );
        findings.extend(compared.findings.iter().cloned());
        previous_summary = Some(previous_report);
        comparison = Some(compared);
    }

    deduplicate(&mut findings);
    findings.sort_by(|left, right| left.sort_key().cmp(&right.sort_key()));
    let verdict = if findings.iter().any(|finding| finding.is_blocking()) {
        Verdict::Blocked
    } else {
        Verdict::Accepted
    };
    StructureReport {
        manifest_path: manifest_path.to_string(),
        release: manifest.release.clone(),
        archive: archive_summary,
        previous: previous_summary,
        reupload: manifest.reupload,
        members: current_check.members,
        findings,
        comparison,
        verdict,
    }
}

pub fn summary_for(archive: &Archive, path: &str) -> ArchiveSummary {
    ArchiveSummary {
        fixture_path: path.to_string(),
        format: archive.format.as_str().to_string(),
        sha256: archive.sha256.clone(),
        declared_sha256: None,
        size: archive.size,
        member_count: archive.members.len(),
        total_uncompressed: archive.total_uncompressed(),
    }
}

pub fn report_json(report: &StructureReport) -> Value {
    let files = report
        .members
        .iter()
        .filter(|member| member.kind == MemberKind::File)
        .count();
    let directories = report
        .members
        .iter()
        .filter(|member| member.kind == MemberKind::Directory)
        .count();
    let symlinks = report
        .members
        .iter()
        .filter(|member| member.kind == MemberKind::Symlink)
        .count();
    let hard_links = report
        .members
        .iter()
        .filter(|member| member.kind == MemberKind::HardLink)
        .count();
    json!({
        "ok": true,
        "schema_version": REPORT_SCHEMA_VERSION,
        "feature": FEATURE_ID,
        "feature_name_zh": FEATURE_NAME_ZH,
        "verdict": report.verdict.as_str(),
        "status": report.verdict.as_str(),
        "verdict_label": report.verdict.label_zh(),
        "accepted": report.verdict == Verdict::Accepted,
        "reupload": report.reupload,
        "manifest": report.manifest_path,
        "release": {
            "name": report.release.name,
            "version": report.release.version,
            "build": report.release.build,
        },
        "archive": archive_json(&report.archive),
        "previous": report.previous.as_ref().map(archive_json),
        "summary": {
            "members": report.members.len(),
            "files": files,
            "directories": directories,
            "symlinks": symlinks,
            "hard_links": hard_links,
            "special_files": report.members.iter().filter(|member| member.kind.is_special()).count(),
            "total_uncompressed": report.archive.total_uncompressed,
            "blocking": report.blocking_count(),
            "warnings": report.warning_count(),
            "info": report.info_count(),
        },
        "members": report.members.iter().map(member_json).collect::<Vec<_>>(),
        "findings": report.findings.iter().map(finding_json).collect::<Vec<_>>(),
        "issues": report.findings.iter().map(finding_json).collect::<Vec<_>>(),
        "comparison": report.comparison.as_ref().map(comparison_json),
        "error_code_catalog": error_catalog(),
        "issue_code_catalog": issue_catalog(),
    })
}

pub fn report_json_string(report: &StructureReport) -> String {
    serde_json::to_string_pretty(&report_json(report))
        .expect("report JSON values are always serializable")
}

fn archive_json(summary: &ArchiveSummary) -> Value {
    json!({
        "path": summary.fixture_path,
        "format": summary.format,
        "sha256": summary.sha256,
        "declared_sha256": summary.declared_sha256,
        "hash_matches": summary.declared_sha256.as_ref().map(|declared| declared == &summary.sha256),
        "size": summary.size,
        "member_count": summary.member_count,
        "total_uncompressed": summary.total_uncompressed,
    })
}

fn member_json(member: &MemberReport) -> Value {
    let status = if member.issues.is_empty() {
        "ok"
    } else {
        member.status().as_str()
    };
    json!({
        "index": member.index,
        "name": member.name,
        "path": member.path,
        "kind": member.kind.as_str(),
        "kind_label": member.kind.label_zh(),
        "mode": member.mode_octal(),
        "unix_mode": member.unix_mode,
        "size": member.size,
        "compressed_size": member.compressed_size,
        "sha256": member.sha256,
        "link_target": member.link_target,
        "resolved_link_target": member.resolved_link_target,
        "object": member.object.as_ref().map(|object| object.to_json()),
        "status": status,
        "blocking": member.blocking_count(),
        "warnings": member.warning_count(),
        "issue_codes": member.issues.iter().map(|issue| issue.code.as_str()).collect::<Vec<_>>(),
        "issues": member.issues.iter().map(finding_json).collect::<Vec<_>>(),
    })
}

fn finding_json(finding: &Finding) -> Value {
    json!({
        "code": finding.code.as_str(),
        "name": finding.code.name(),
        "severity": finding.severity.as_str(),
        "severity_label": finding.severity.label_zh(),
        "title_zh": finding.code.title_zh(),
        "origin": finding.origin.as_str(),
        "member_index": finding.member_index,
        "member_name": finding.member_name,
        "member_path": finding.member_path,
        "message": finding.message,
        "details": finding.details,
    })
}

fn comparison_json(comparison: &ComparisonReport) -> Value {
    json!({
        "previous": archive_json(&comparison.previous),
        "current": archive_json(&comparison.current),
        "same_structure": comparison.same_structure,
        "unchanged": comparison.unchanged,
        "added": comparison.added.iter().map(change_json).collect::<Vec<_>>(),
        "removed": comparison.removed.iter().map(change_json).collect::<Vec<_>>(),
        "changed": comparison.changed.iter().map(change_json).collect::<Vec<_>>(),
        "summary": {
            "added": comparison.added.len(),
            "removed": comparison.removed.len(),
            "changed": comparison.changed.len(),
            "blocking": comparison.findings.iter().filter(|finding| finding.is_blocking()).count(),
            "warnings": comparison.findings.iter().filter(|finding| finding.severity == crate::codes::Severity::Warning).count(),
        },
        "findings": comparison.findings.iter().map(finding_json).collect::<Vec<_>>(),
    })
}

fn change_json(change: &crate::model::ChangeEntry) -> Value {
    json!({
        "path": change.path,
        "previous_index": change.previous_index,
        "current_index": change.current_index,
        "fields": change.fields,
        "detail": change.detail,
    })
}

fn deduplicate(findings: &mut Vec<Finding>) {
    let mut seen = std::collections::HashSet::new();
    findings.retain(|finding| {
        seen.insert((
            finding.code.as_str(),
            finding.member_index,
            finding.message.clone(),
        ))
    });
}
