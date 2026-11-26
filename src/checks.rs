//! Build the five stable checks according to the per-target-type matrix.

use std::collections::BTreeSet;

use crate::artifact::InspectedArtifact;
use crate::codes;
use crate::elf::{DF_1_NOW, DF_BIND_NOW, DT_FLAGS, DT_FLAGS_1, PF_X};
use crate::model::{Check, Status, TargetType};

pub const PIE: &str = "pie";
pub const NX: &str = "nx";
pub const RELRO: &str = "relro";
pub const BIND_NOW: &str = "bind_now";
pub const SYMBOL_EVIDENCE: &str = "symbol_evidence";

/// Stable ordering of the five checks.
pub const CHECK_ORDER: [&str; 5] = [PIE, NX, RELRO, BIND_NOW, SYMBOL_EVIDENCE];

/// Requirement matrix. Static/relocatable targets cannot evidence final-link
/// properties (PIE/RELRO/BIND_NOW) so those are non-required / N-A; symbol
/// evidence is the primary static gate.
pub fn is_required(target: TargetType, check_id: &str) -> bool {
    match target {
        TargetType::Executable | TargetType::SharedLibrary => true,
        TargetType::StaticLibrary | TargetType::Relocatable => check_id == SYMBOL_EVIDENCE,
        TargetType::Other => false,
    }
}

fn missing_required(names: &BTreeSet<String>, required_symbols: &[String]) -> Vec<String> {
    required_symbols
        .iter()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty() && !names.contains(s))
        .collect()
}

pub fn build_checks(artifact: &InspectedArtifact) -> Vec<Check> {
    let target = artifact.target_type;
    vec![
        pie_check(artifact, target),
        nx_check(artifact, target),
        relro_check(artifact, target),
        bind_now_check(artifact, target),
        symbol_check(artifact, target),
    ]
}

fn pie_check(a: &InspectedArtifact, target: TargetType) -> Check {
    let required = is_required(target, PIE);
    let check = Check::new(
        PIE,
        "PIE",
        Status::Unknown,
        required,
        codes::PIE_UNKNOWN,
        "",
    );

    if matches!(target, TargetType::StaticLibrary | TargetType::Relocatable) {
        return Check::new(
            PIE,
            "PIE",
            Status::NotApplicable,
            false,
            codes::PIE_NOT_APPLICABLE,
            "PIE is a final-link property; relocatable/archive members cannot confirm it",
        );
    }

    let Some(structure) = a.structure.as_ref() else {
        return check
            .with_status(Status::Unknown)
            .with_code(codes::PIE_UNKNOWN)
            .with_summary("ELF structure unavailable; cannot confirm PIE")
            .evidence_line("parser produced no ELF header (see artifact error)");
    };

    if target == TargetType::SharedLibrary {
        return if structure.e_type == crate::classify::ET_DYN {
            Check::new(
                PIE,
                "PIE",
                Status::Pass,
                true,
                codes::PIE_PASS_DSO_PIC,
                "shared object is ET_DYN / position-independent code",
            )
            .evidence_line(format!("e_type={} (ET_DYN)", structure.e_type))
        } else {
            Check::new(
                PIE,
                "PIE",
                Status::Fail,
                true,
                codes::PIE_FAIL_NOT_PIE,
                "shared library is not ET_DYN",
            )
            .evidence_line(format!("e_type={}", structure.e_type))
        };
    }

    // Executable.
    match structure.e_type {
        crate::classify::ET_DYN => {
            let mut c = Check::new(
                PIE,
                "PIE",
                Status::Pass,
                required,
                codes::PIE_PASS,
                "position-independent executable (ET_DYN)",
            );
            c.evidence
                .push(format!("e_type={} (ET_DYN)", structure.e_type));
            if structure.has_interp() {
                c.evidence
                    .push("PT_INTERP present (dynamically linked PIE)".to_string());
            } else {
                c.evidence
                    .push("no PT_INTERP (possible static-PIE)".to_string());
            }
            if structure
                .dynamic
                .iter()
                .any(|(t, v)| *t == DT_FLAGS_1 && (v & 0x0800_0000) != 0)
            {
                c.evidence.push("DT_FLAGS_1 contains DF_1_PIE".to_string());
            }
            c
        }
        crate::classify::ET_EXEC => Check::new(
            PIE,
            "PIE",
            Status::Fail,
            required,
            codes::PIE_FAIL_ET_EXEC,
            "fixed-address ET_EXEC executable is not PIE",
        )
        .evidence_line(format!("e_type={} (ET_EXEC)", structure.e_type)),
        other => Check::new(
            PIE,
            "PIE",
            Status::Unknown,
            required,
            codes::PIE_UNKNOWN,
            "unrecognized ELF type for PIE determination",
        )
        .evidence_line(format!("e_type={other}")),
    }
}

fn nx_check(a: &InspectedArtifact, target: TargetType) -> Check {
    let required = is_required(target, NX);

    match target {
        TargetType::StaticLibrary => {
            if let Some(archive) = a.archive.as_ref() {
                let (status, code, summary) = match archive.nx_status {
                    Status::Pass => (
                        Status::Pass,
                        codes::NX_PASS_NOTE_NOEXEC,
                        "all members carry a non-executable .note.GNU-stack",
                    ),
                    Status::Fail => (
                        Status::Fail,
                        codes::NX_FAIL_NOTE_EXEC,
                        "at least one member requests an executable stack",
                    ),
                    _ => (
                        Status::Unknown,
                        codes::NX_UNKNOWN_MEMBER,
                        "member stack markings are missing or unreadable",
                    ),
                };
                let mut c = Check::new(NX, "NX", status, false, code, summary);
                c.evidence = archive.nx_evidence.clone();
                c
            } else {
                Check::new(
                    NX,
                    "NX",
                    Status::Unknown,
                    false,
                    codes::NX_UNKNOWN_MEMBER,
                    "archive facts unavailable",
                )
            }
        }
        TargetType::Relocatable => {
            let exec = a.symbols.as_ref().and_then(|s| s.gnu_stack_exec);
            match exec {
                Some(false) => Check::new(
                    NX,
                    "NX",
                    Status::Pass,
                    false,
                    codes::NX_PASS_NOTE_NOEXEC,
                    ".note.GNU-stack present without SHF_EXECINSTR",
                )
                .evidence_line("section .note.GNU-stack flags=0 (non-executable)"),
                Some(true) => Check::new(
                    NX,
                    "NX",
                    Status::Fail,
                    false,
                    codes::NX_FAIL_NOTE_EXEC,
                    ".note.GNU-stack carries SHF_EXECINSTR",
                ),
                None => Check::new(
                    NX,
                    "NX",
                    Status::Unknown,
                    false,
                    codes::NX_UNKNOWN_NO_STACK_SEGMENT,
                    ".note.GNU-stack absent; NX cannot be confirmed for the member",
                ),
            }
        }
        TargetType::Executable | TargetType::SharedLibrary => {
            let Some(structure) = a.structure.as_ref() else {
                return Check::new(
                    NX,
                    "NX",
                    Status::Unknown,
                    required,
                    codes::NX_UNKNOWN_NO_STACK_SEGMENT,
                    "ELF structure unavailable",
                );
            };
            match structure.gnu_stack_flags() {
                Some(flags) if flags & PF_X == 0 => Check::new(
                    NX,
                    "NX",
                    Status::Pass,
                    required,
                    codes::NX_PASS_STACK_NOEXEC,
                    "PT_GNU_STACK is present and non-executable",
                )
                .evidence_line(format!("PT_GNU_STACK p_flags=0x{flags:x} (RW, PF_X clear)")),
                Some(flags) => Check::new(
                    NX,
                    "NX",
                    Status::Fail,
                    required,
                    codes::NX_FAIL_STACK_EXEC,
                    "PT_GNU_STACK is executable",
                )
                .evidence_line(format!("PT_GNU_STACK p_flags=0x{flags:x} (PF_X set, RWE)")),
                None => Check::new(
                    NX,
                    "NX",
                    Status::Unknown,
                    required,
                    codes::NX_UNKNOWN_NO_STACK_SEGMENT,
                    "PT_GNU_STACK absent; NX cannot be confirmed",
                ),
            }
        }
        TargetType::Other => Check::new(
            NX,
            "NX",
            Status::NotApplicable,
            false,
            codes::NX_NOT_APPLICABLE,
            "not an object/archive target",
        ),
    }
}

fn relro_check(a: &InspectedArtifact, target: TargetType) -> Check {
    if matches!(
        target,
        TargetType::StaticLibrary | TargetType::Relocatable | TargetType::Other
    ) {
        return Check::new(
            RELRO,
            "RELRO",
            Status::NotApplicable,
            false,
            codes::RELRO_NOT_APPLICABLE,
            "RELRO is applied at final link/load; not present in relocatable/archive input",
        );
    }
    let required = is_required(target, RELRO);
    let Some(structure) = a.structure.as_ref() else {
        return Check::new(
            RELRO,
            "RELRO",
            Status::Unknown,
            required,
            codes::RELRO_UNKNOWN_NO_DYNAMIC,
            "ELF structure unavailable",
        );
    };
    if structure.has_relro() {
        Check::new(
            RELRO,
            "RELRO",
            Status::Pass,
            required,
            codes::RELRO_PASS,
            "PT_GNU_RELRO segment present",
        )
        .evidence_line("PT_GNU_RELRO found in program headers")
    } else if structure.has_dynamic_segment() || !structure.dynamic.is_empty() {
        Check::new(
            RELRO,
            "RELRO",
            Status::Fail,
            required,
            codes::RELRO_FAIL_MISSING,
            "dynamic object lacks PT_GNU_RELRO",
        )
    } else {
        Check::new(
            RELRO,
            "RELRO",
            Status::Unknown,
            required,
            codes::RELRO_UNKNOWN_NO_DYNAMIC,
            "no PT_GNU_RELRO and no PT_DYNAMIC; RELRO cannot be confirmed",
        )
    }
}

fn bind_now_check(a: &InspectedArtifact, target: TargetType) -> Check {
    if matches!(
        target,
        TargetType::StaticLibrary | TargetType::Relocatable | TargetType::Other
    ) {
        return Check::new(
            BIND_NOW,
            "BIND_NOW",
            Status::NotApplicable,
            false,
            codes::BIND_NOW_NOT_APPLICABLE,
            "binding mode is fixed at final link/load; not present in archive/relocatable input",
        );
    }
    let required = is_required(target, BIND_NOW);
    let Some(structure) = a.structure.as_ref() else {
        return Check::new(
            BIND_NOW,
            "BIND_NOW",
            Status::Unknown,
            required,
            codes::BIND_NOW_UNKNOWN_NO_DYNAMIC,
            "ELF structure unavailable",
        );
    };

    let mut evidence = Vec::new();
    for (tag, val) in &structure.dynamic {
        if *tag == crate::elf::DT_BIND_NOW {
            evidence.push("DT_BIND_NOW entry present".to_string());
        }
        if *tag == DT_FLAGS && (*val & DF_BIND_NOW) != 0 {
            evidence.push(format!("DT_FLAGS=0x{val:x} contains DF_BIND_NOW"));
        }
        if *tag == DT_FLAGS_1 && (*val & DF_1_NOW) != 0 {
            evidence.push(format!("DT_FLAGS_1=0x{val:x} contains DF_1_NOW"));
        }
    }

    if structure.bind_now() {
        Check::new(
            BIND_NOW,
            "BIND_NOW",
            Status::Pass,
            required,
            codes::BIND_NOW_PASS,
            "immediate binding enabled (BIND_NOW / NOW)",
        )
        .evidence_lines(evidence)
    } else if structure.has_dynamic_segment() || !structure.dynamic.is_empty() {
        Check::new(
            BIND_NOW,
            "BIND_NOW",
            Status::Fail,
            required,
            codes::BIND_NOW_FAIL_LAZY,
            "no BIND_NOW/NOW marker; lazy binding is used",
        )
        .evidence_line("dynamic section lacks DT_BIND_NOW, DF_BIND_NOW and DF_1_NOW")
    } else {
        Check::new(
            BIND_NOW,
            "BIND_NOW",
            Status::Unknown,
            required,
            codes::BIND_NOW_UNKNOWN_NO_DYNAMIC,
            "no dynamic section; BIND_NOW cannot be confirmed",
        )
    }
}

fn symbol_check(a: &InspectedArtifact, target: TargetType) -> Check {
    if target == TargetType::Other {
        return Check::new(
            SYMBOL_EVIDENCE,
            "Symbol evidence",
            Status::NotApplicable,
            false,
            codes::SYMBOL_NOT_APPLICABLE,
            "not an object/archive target",
        );
    }
    let required = is_required(target, SYMBOL_EVIDENCE);

    // Archive path.
    if target == TargetType::StaticLibrary {
        let Some(archive) = a.archive.as_ref() else {
            return Check::new(
                SYMBOL_EVIDENCE,
                "Symbol evidence",
                Status::Unknown,
                required,
                codes::SYMBOL_UNKNOWN_PARSE,
                "archive facts unavailable",
            );
        };
        if archive.member_count == 0 {
            return Check::new(
                SYMBOL_EVIDENCE,
                "Symbol evidence",
                Status::Unknown,
                required,
                codes::SYMBOL_UNKNOWN_EMPTY_ARCHIVE,
                "archive contains no members",
            );
        }
        if !archive.parsed || archive.parsed_member_count == 0 {
            return Check::new(
                SYMBOL_EVIDENCE,
                "Symbol evidence",
                Status::Unknown,
                required,
                codes::SYMBOL_UNKNOWN_PARSE,
                "archive members could not be parsed",
            );
        }
        let missing = missing_required(&archive.names, &a.required_symbols);
        if !missing.is_empty() {
            return Check::new(
                SYMBOL_EVIDENCE,
                "Symbol evidence",
                Status::Fail,
                required,
                codes::SYMBOL_FAIL_REQUIRED_MISSING,
                format!("required symbol(s) absent: {}", missing.join(", ")),
            )
            .evidence_line(format!("archive unique symbols: {}", archive.names.len()));
        }
        let has_hardening = archive.citations.iter().any(|s| s.evidence_kind.is_some());
        let code = if has_hardening {
            codes::SYMBOL_PASS_HARDENING
        } else {
            codes::SYMBOL_PASS
        };
        let summary = format!(
            "{} member(s), {} unique symbol names; concrete citations attached",
            archive.parsed_member_count,
            archive.names.len()
        );
        return Check::new(
            SYMBOL_EVIDENCE,
            "Symbol evidence",
            Status::Pass,
            required,
            code,
            summary,
        )
        .evidence_line(format!("members considered: {}", archive.member_count))
        .symbols(archive.citations.clone());
    }

    // ELF / relocatable path.
    let Some(symbols) = a.symbols.as_ref() else {
        return Check::new(
            SYMBOL_EVIDENCE,
            "Symbol evidence",
            Status::Unknown,
            required,
            codes::SYMBOL_UNKNOWN_PARSE,
            "symbol table unavailable",
        );
    };
    if !symbols.parsed {
        return Check::new(
            SYMBOL_EVIDENCE,
            "Symbol evidence",
            Status::Unknown,
            required,
            codes::SYMBOL_UNKNOWN_PARSE,
            "object could not be parsed for symbols",
        );
    }
    let missing = missing_required(&symbols.names, &a.required_symbols);
    if !missing.is_empty() {
        return Check::new(
            SYMBOL_EVIDENCE,
            "Symbol evidence",
            Status::Fail,
            required,
            codes::SYMBOL_FAIL_REQUIRED_MISSING,
            format!("required symbol(s) absent: {}", missing.join(", ")),
        );
    }
    if !symbols.has_symbol_surface() {
        return Check::new(
            SYMBOL_EVIDENCE,
            "Symbol evidence",
            Status::Unknown,
            required,
            codes::SYMBOL_UNKNOWN_NO_TABLE,
            "no symbol/dynamic-symbol entries found",
        );
    }
    let has_hardening = symbols.citations.iter().any(|s| s.evidence_kind.is_some());
    let code = if has_hardening {
        codes::SYMBOL_PASS_HARDENING
    } else {
        codes::SYMBOL_PASS
    };
    Check::new(
        SYMBOL_EVIDENCE,
        "Symbol evidence",
        Status::Pass,
        required,
        code,
        format!(
            "symtab={} entries, dynsym={} entries, {} unique names",
            symbols.symtab_count,
            symbols.dynsym_count,
            symbols.names.len()
        ),
    )
    .evidence_line(format!("symtab entries: {}", symbols.symtab_count))
    .evidence_line(format!("dynsym entries: {}", symbols.dynsym_count))
    .symbols(symbols.citations.clone())
}
