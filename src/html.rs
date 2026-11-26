//! Self-contained HTML view for the archive structure report.

use std::fmt::Write;

use crate::model::{StructureReport, Verdict};
use crate::report::report_json;
use crate::{FEATURE_ID, FEATURE_NAME_ZH};

pub fn render_html(report: &StructureReport) -> String {
    let mut html = String::with_capacity(16_384);
    let (tone, verdict) = match report.verdict {
        Verdict::Accepted => ("ok", report.verdict.label_zh()),
        Verdict::Blocked => ("bad", report.verdict.label_zh()),
    };
    let _ = write!(
        html,
        r#"<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{feature} · {name} {version}</title>
<style>
:root{{--bg:#f6f7f9;--panel:#fff;--ink:#17202a;--muted:#68737d;--line:#dde3e8;--ok:#18794e;--warn:#9a6700;--bad:#b42318;--accent:#244f7a}}
*{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--ink);font:14px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}}
header{{background:var(--accent);color:#fff;padding:22px 28px}}header h1{{margin:0;font-size:20px}}header p{{margin:6px 0 0;opacity:.82}}
main{{max-width:1220px;margin:0 auto;padding:22px}}.cards{{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-bottom:18px}}
.card{{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:14px}}.card b{{display:block;font-size:24px}}.card span{{color:var(--muted)}}
.tone-ok{{color:var(--ok)}}.tone-bad{{color:var(--bad)}}.tone-warn{{color:var(--warn)}}
section{{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:18px;margin:16px 0}}
section h2{{font-size:16px;margin:0 0 12px}}table{{width:100%;border-collapse:collapse}}th,td{{text-align:left;padding:8px;border-bottom:1px solid var(--line);vertical-align:top}}
th{{color:var(--muted);font-weight:600;font-size:12px;text-transform:uppercase}}code,.mono{{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px}}
.badge{{display:inline-block;border-radius:999px;padding:1px 8px;font-size:12px;font-weight:600}}.badge.ok{{background:#e7f6ed;color:var(--ok)}}.badge.warning{{background:#fff4d6;color:var(--warn)}}.badge.blocking{{background:#fde8e7;color:var(--bad)}}.badge.info{{background:#eef2f6;color:var(--muted)}}
.bar{{height:8px;border-radius:999px;background:#e8edf1;overflow:hidden;margin:8px 0}}.bar i{{display:block;height:100%;background:var(--bad)}}
details pre{{max-height:360px;overflow:auto;background:#0f1720;color:#e7edf3;padding:14px;border-radius:8px}}
.muted{{color:var(--muted)}}.empty{{color:var(--ok)}}ul{{margin:6px 0;padding-left:20px}}
</style></head><body>
<header><h1>{feature} · {feature_name}</h1><p>{name} {version} · {manifest} · {archive_format}</p></header>
<main>
"#,
        feature = FEATURE_ID,
        feature_name = FEATURE_NAME_ZH,
        name = escape(&report.release.name),
        version = escape(&report.release.version),
        manifest = escape(&report.manifest_path),
        archive_format = escape(&report.archive.format),
    );

    let _ = write!(
        html,
        r#"<div class="cards">
<div class="card"><span>结论</span><b class="tone-{tone}">{verdict}</b><span>{reason}</span></div>
<div class="card"><span>成员</span><b>{members}</b><span>文件 {files} · 目录 {dirs} · 链接 {links}</span></div>
<div class="card"><span>阻断</span><b class="tone-bad">{blocking}</b><span>需修复后重新上传</span></div>
<div class="card"><span>警告 / 提示</span><b>{warnings} / {info}</b><span>不直接阻断</span></div>
<div class="card"><span>外层 SHA-256</span><b class="mono">{sha}</b><span>{hash_state}</span></div>
</div>
"#,
        tone = tone,
        verdict = escape(verdict),
        reason = if report.reupload {
            "修复包已与上版结构对比"
        } else {
            "首版上传结构检查"
        },
        members = report.members.len(),
        files = report
            .members
            .iter()
            .filter(|member| member.kind.as_str() == "file")
            .count(),
        dirs = report
            .members
            .iter()
            .filter(|member| member.kind.as_str() == "directory")
            .count(),
        links = report
            .members
            .iter()
            .filter(|member| member.kind.is_link())
            .count(),
        blocking = report.blocking_count(),
        warnings = report.warning_count(),
        info = report.info_count(),
        sha = escape(short_hash(&report.archive.sha256)),
        hash_state = hash_state(report),
    );

    html.push_str("<section><h2>压缩包成员树</h2>");
    if report.members.is_empty() {
        html.push_str("<p class=\"muted\">压缩包没有成员。</p>");
    } else {
        html.push_str(
            "<table><thead><tr><th>#</th><th>路径</th><th>类型</th><th>权限</th><th>大小</th><th>摘要</th><th>状态</th><th>问题码</th></tr></thead><tbody>",
        );
        for member in &report.members {
            let status = if member.issues.is_empty() {
                "ok".to_string()
            } else {
                member.status().as_str().to_string()
            };
            let _ = write!(
                html,
                "<tr><td>{}</td><td class=\"mono\">{}</td><td>{}</td><td class=\"mono\">{}</td><td>{}</td><td class=\"mono\">{}</td><td><span class=\"badge {}\">{}</span></td><td class=\"mono\">{}</td></tr>",
                member.index,
                escape(&member.path),
                member.kind.label_zh(),
                member.mode_octal().unwrap_or_else(|| "—".to_string()),
                member.size,
                member
                    .sha256
                    .as_deref()
                    .map(short_hash)
                    .map(escape)
                    .unwrap_or_else(|| "—".to_string()),
                status,
                status,
                escape(
                    &member
                        .issues
                        .iter()
                        .map(|issue| issue.code.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            );
        }
        html.push_str("</tbody></table>");
    }
    html.push_str("</section>");

    html.push_str("<section><h2>具体问题</h2>");
    if report.findings.is_empty() {
        html.push_str("<p class=\"empty\">未发现结构问题。</p>");
    } else {
        html.push_str(
            "<table><thead><tr><th>级别</th><th>编码</th><th>成员</th><th>说明</th></tr></thead><tbody>",
        );
        for finding in &report.findings {
            let _ = write!(
                html,
                "<tr><td><span class=\"badge {}\">{}</span></td><td class=\"mono\">{}</td><td class=\"mono\">{}</td><td>{}<div class=\"muted\">{}</div></td></tr>",
                finding.severity.as_str(),
                finding.severity.label_zh(),
                finding.code.as_str(),
                escape(
                    finding
                        .member_path
                        .as_deref()
                        .or(finding.member_name.as_deref())
                        .unwrap_or("(archive)")
                ),
                escape(finding.code.title_zh()),
                escape(&finding.message),
            );
        }
        html.push_str("</tbody></table>");
    }
    html.push_str("</section>");

    if let Some(comparison) = &report.comparison {
        let _ = write!(
            html,
            "<section><h2>与上版结构对比</h2><p class=\"muted\">上版 <span class=\"mono\">{}</span> · {} 个成员 → 当前 {} 个成员</p><div class=\"cards\"><div class=\"card\"><span>未变化</span><b>{}</b></div><div class=\"card\"><span>新增</span><b>{}</b></div><div class=\"card\"><span>删除</span><b class=\"tone-bad\">{}</b></div><div class=\"card\"><span>变化</span><b>{}</b></div></div>",
            escape(&comparison.previous.fixture_path),
            comparison.previous.member_count,
            comparison.current.member_count,
            comparison.unchanged,
            comparison.added.len(),
            comparison.removed.len(),
            comparison.changed.len(),
        );
        if !comparison.added.is_empty() {
            html.push_str("<h3>新增成员</h3><ul>");
            for change in &comparison.added {
                let _ = write!(html, "<li class=\"mono\">{}</li>", escape(&change.path));
            }
            html.push_str("</ul>");
        }
        if !comparison.removed.is_empty() {
            html.push_str("<h3>删除成员</h3><ul>");
            for change in &comparison.removed {
                let _ = write!(html, "<li class=\"mono\">{}</li>", escape(&change.path));
            }
            html.push_str("</ul>");
        }
        if !comparison.changed.is_empty() {
            html.push_str("<h3>变化成员</h3><ul>");
            for change in &comparison.changed {
                let _ = write!(
                    html,
                    "<li class=\"mono\">{} <span class=\"muted\">[{}]</span></li>",
                    escape(&change.path),
                    escape(&change.fields.join(", "))
                );
            }
            html.push_str("</ul>");
        }
        html.push_str("</section>");
    }

    let json = serde_json::to_string_pretty(&report_json(report)).unwrap_or_default();
    let _ = write!(
        html,
        "<details><summary>机器可读报告 JSON</summary><pre>{}</pre></details></main></body></html>",
        escape(&json)
    );
    html
}

fn hash_state(report: &StructureReport) -> String {
    match &report.archive.declared_sha256 {
        None => "清单未声明摘要".to_string(),
        Some(declared) if declared == &report.archive.sha256 => "与清单一致".to_string(),
        Some(_) => "与清单不一致".to_string(),
    }
}

fn short_hash(hash: &str) -> &str {
    hash.get(..16).unwrap_or(hash)
}

fn escape(input: &str) -> String {
    let mut output = String::with_capacity(input.len());
    for character in input.chars() {
        match character {
            '&' => output.push_str("&amp;"),
            '<' => output.push_str("&lt;"),
            '>' => output.push_str("&gt;"),
            '"' => output.push_str("&quot;"),
            '\'' => output.push_str("&#39;"),
            _ => output.push(character),
        }
    }
    output
}
