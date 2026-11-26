//! Static archive (`.a`) inspection via `object`.

use std::collections::BTreeSet;

use object::read::archive::ArchiveFile;

use crate::model::{Status, SymbolRef};
use crate::symbols;

const MAX_ARCHIVE_CITATIONS: usize = 24;

#[derive(Debug, Clone)]
pub struct ArchiveInspection {
    pub parsed: bool,
    pub parse_error: Option<String>,
    pub member_count: usize,
    pub parsed_member_count: usize,
    pub names: BTreeSet<String>,
    pub citations: Vec<SymbolRef>,
    pub nx_status: Status,
    pub nx_evidence: Vec<String>,
}

impl Default for ArchiveInspection {
    fn default() -> Self {
        ArchiveInspection {
            parsed: false,
            parse_error: None,
            member_count: 0,
            parsed_member_count: 0,
            names: BTreeSet::new(),
            citations: Vec::new(),
            nx_status: Status::Unknown,
            nx_evidence: Vec::new(),
        }
    }
}

fn is_special_member(name: &str) -> bool {
    let trimmed = name.trim_end_matches('/');
    trimmed.is_empty()
        || trimmed == "/"
        || trimmed == "//"
        || trimmed.starts_with("/SYM")
        || trimmed.starts_with('/')
        || trimmed.starts_with("__.SYMDEF")
}

pub fn inspect_archive(data: &[u8]) -> ArchiveInspection {
    let mut result = ArchiveInspection::default();

    let archive = match ArchiveFile::parse(data) {
        Ok(archive) => {
            result.parsed = true;
            archive
        }
        Err(err) => {
            result.parse_error = Some(err.to_string());
            return result;
        }
    };

    let mut exec_members: Vec<String> = Vec::new();
    let mut noexec_members: Vec<String> = Vec::new();
    let mut unknown_stack_members: Vec<String> = Vec::new();
    let mut citations: Vec<SymbolRef> = Vec::new();

    for member_result in archive.members() {
        let member = match member_result {
            Ok(member) => member,
            Err(_) => continue,
        };

        let raw_name = String::from_utf8_lossy(member.name()).to_string();
        let member_name = raw_name.trim_end_matches('/').to_string();
        if is_special_member(&member_name) {
            continue;
        }
        result.member_count += 1;

        let bytes = match member.data(data) {
            Ok(bytes) => bytes,
            Err(_) => continue,
        };

        let prefix = format!("archive:{member_name}");
        let facts = symbols::collect(bytes, Some(&prefix));
        if !facts.parsed {
            continue;
        }
        result.parsed_member_count += 1;
        result.names.extend(facts.names);
        citations.extend(facts.citations);

        match facts.gnu_stack_exec {
            Some(true) => exec_members.push(member_name),
            Some(false) => noexec_members.push(member_name),
            None => unknown_stack_members.push(member_name),
        }
    }

    // De-duplicate and prioritize hardening evidence.
    citations.sort_by_key(|c| if c.evidence_kind.is_some() { 0 } else { 1 });
    citations.dedup_by(|a, b| a.name == b.name && a.origin == b.origin);
    citations.truncate(MAX_ARCHIVE_CITATIONS);
    result.citations = citations;

    if !exec_members.is_empty() {
        result.nx_status = Status::Fail;
        result.nx_evidence.push(format!(
            "members requesting executable stack (.note.GNU-stack X): {}",
            exec_members.join(", ")
        ));
    } else if !noexec_members.is_empty() && unknown_stack_members.is_empty() {
        result.nx_status = Status::Pass;
        result.nx_evidence.push(format!(
            "{} member(s) carry non-executable .note.GNU-stack: {}",
            noexec_members.len(),
            noexec_members.join(", ")
        ));
    } else if result.parsed_member_count == 0 {
        result.nx_status = Status::Unknown;
        result
            .nx_evidence
            .push("no parseable ELF members in archive".to_string());
    } else {
        result.nx_status = Status::Unknown;
        result.nx_evidence.push(format!(
            "stack marking not confirmable for members: {}",
            unknown_stack_members.join(", ")
        ));
    }

    result
}
