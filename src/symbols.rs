//! Symbol-table evidence gathered through the `object` crate.

use std::collections::BTreeSet;

use object::read::{File, Object, ObjectSection, ObjectSymbol, SectionFlags};

use crate::model::SymbolRef;

const MAX_CITATIONS: usize = 24;

#[derive(Debug, Clone, Default)]
pub struct SymbolFacts {
    pub parsed: bool,
    pub parse_error: Option<String>,
    pub symtab_count: usize,
    pub dynsym_count: usize,
    /// Every base symbol name (version suffix stripped), for required-symbol
    /// matching.
    pub names: BTreeSet<String>,
    /// Prioritized, de-duplicated concrete citations.
    pub citations: Vec<SymbolRef>,
    /// `true` = `.note.GNU-stack` requests exec; `false` = present and
    /// non-exec; `None` = section absent or object not parsed.
    pub gnu_stack_exec: Option<bool>,
}

/// Classify a symbol name as evidence for a compiler mitigation.
pub fn hardening_kind(name: &str) -> Option<&'static str> {
    let base = name.split('@').next().unwrap_or(name);
    if base.contains("__stack_chk_fail") || base.contains("__stack_chk_guard") {
        return Some("stack_canary");
    }
    if base.starts_with("__") && base.contains("_chk") {
        return Some("fortify");
    }
    None
}

fn base_name(name: &str) -> String {
    name.split('@').next().unwrap_or(name).to_string()
}

fn push_citation(
    out: &mut Vec<SymbolRef>,
    seen: &mut BTreeSet<(String, String)>,
    citation: SymbolRef,
) {
    if out.len() >= MAX_CITATIONS {
        return;
    }
    let key = (citation.name.clone(), citation.origin.clone());
    if seen.insert(key) {
        out.push(citation);
    }
}

/// Parse one object blob and collect symbol facts. `origin_prefix` is used to
/// qualify origins for archive members.
pub fn collect(data: &[u8], origin_prefix: Option<&str>) -> SymbolFacts {
    let mut facts = SymbolFacts::default();
    let file = match File::parse(data) {
        Ok(file) => {
            facts.parsed = true;
            file
        }
        Err(err) => {
            facts.parse_error = Some(err.to_string());
            return facts;
        }
    };

    let qualify = |table: &str| -> String {
        match origin_prefix {
            Some(prefix) => format!("{prefix}/{table}"),
            None => table.to_string(),
        }
    };

    let mut seen = BTreeSet::new();
    let mut hardening: Vec<SymbolRef> = Vec::new();
    let mut anchors: Vec<SymbolRef> = Vec::new();
    let mut defined_sample: Vec<SymbolRef> = Vec::new();

    // Full symbol table.
    let sym_origin = qualify("symtab");
    for symbol in file.symbols() {
        facts.symtab_count += 1;
        let Ok(raw_name) = symbol.name() else {
            continue;
        };
        if raw_name.is_empty() {
            continue;
        }
        let name = base_name(raw_name);
        facts.names.insert(name.clone());
        if let Some(kind) = hardening_kind(&name) {
            hardening.push(SymbolRef::new(name.clone(), sym_origin.clone()).with_kind(kind));
        } else if name.to_ascii_lowercase().contains("mgate") {
            anchors.push(SymbolRef::new(name.clone(), sym_origin.clone()));
        } else if symbol.is_definition() && defined_sample.len() < 8 {
            defined_sample.push(SymbolRef::new(name.clone(), sym_origin.clone()));
        }
    }

    // Dynamic symbol table.
    let dyn_origin = qualify("dynsym");
    for symbol in file.dynamic_symbols() {
        facts.dynsym_count += 1;
        let Ok(raw_name) = symbol.name() else {
            continue;
        };
        if raw_name.is_empty() {
            continue;
        }
        let name = base_name(raw_name);
        facts.names.insert(name.clone());
        if let Some(kind) = hardening_kind(&name) {
            hardening.push(SymbolRef::new(name.clone(), dyn_origin.clone()).with_kind(kind));
        } else if name.to_ascii_lowercase().contains("mgate") {
            anchors.push(SymbolRef::new(name.clone(), dyn_origin.clone()));
        } else if symbol.is_definition() && defined_sample.len() < 8 {
            defined_sample.push(SymbolRef::new(name.clone(), dyn_origin.clone()));
        }
    }

    // `.note.GNU-stack` section flags for relocatable members.
    for section in file.sections() {
        if matches!(section.name(), Ok(name) if name == ".note.GNU-stack") {
            if let SectionFlags::Elf { sh_flags, .. } = section.flags() {
                let raw_flags: u64 = sh_flags.0;
                let exec_bit: u64 = object::elf::SHF_EXECINSTR.0;
                facts.gnu_stack_exec = Some((raw_flags & exec_bit) != 0);
            } else {
                facts.gnu_stack_exec = Some(false);
            }
        }
    }

    // Prioritize hardening evidence, then stable anchors, then samples.
    for citation in hardening {
        push_citation(&mut facts.citations, &mut seen, citation);
    }
    for citation in anchors {
        push_citation(&mut facts.citations, &mut seen, citation);
    }
    for citation in defined_sample {
        push_citation(&mut facts.citations, &mut seen, citation);
    }

    facts
}

impl SymbolFacts {
    pub fn has_symbol_surface(&self) -> bool {
        self.dynsym_count > 0 || self.symtab_count > 0 || !self.names.is_empty()
    }

    pub fn has_required_name(&self, required: &str) -> bool {
        let wanted = base_name(required);
        if self.names.contains(&wanted) {
            return true;
        }
        // Tolerate manifests that include a version suffix or a glob-ish token
        // by checking exact base-name equality only.
        self.names.iter().any(|name| name == &wanted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_known_hardening_symbols() {
        assert_eq!(
            hardening_kind("__stack_chk_fail@GLIBC_2.4"),
            Some("stack_canary")
        );
        assert_eq!(hardening_kind("__snprintf_chk"), Some("fortify"));
        assert_eq!(hardening_kind("mgate_static_add"), None);
    }
}
