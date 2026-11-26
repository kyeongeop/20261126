//! Static, self-contained HTML report ("the release page").

use crate::report::GateReport;

pub fn escape_html(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(ch),
        }
    }
    out
}

fn badge_class(status: &str) -> &'static str {
    match status {
        "pass" => "pass",
        "fail" => "fail",
        "unknown" => "unknown",
        _ => "na",
    }
}

fn status_label(status: &str) -> &str {
    match status {
        "pass" => "PASS",
        "fail" => "FAIL",
        "unknown" => "UNKNOWN",
        "not_applicable" => "N/A",
        "not_gated" => "NOT GATED",
        other => other,
    }
}

pub fn render_html(report: &GateReport) -> String {
    let summary = &report.summary;
    let blocked = !summary.release_allowed;
    let banner_class = if blocked { "blocked" } else { "passed" };
    let banner_text = if blocked {
        "发布被阻止 · RELEASE BLOCKED"
    } else {
        "门禁通过 · GATE PASSED"
    };

    let mut html = String::new();
    html.push_str("<!DOCTYPE html><html lang=\"zh-CN\"><head><meta charset=\"utf-8\">");
    html.push_str("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">");
    html.push_str("<title>多目标加固门禁 · Multi-target Hardening Gate</title>");
    html.push_str(STYLE);
    html.push_str("</head><body><main>");

    html.push_str("<header class=\"top\"><div>");
    html.push_str("<h1>多目标加固门禁 <span class=\"sub\">Multi-target Hardening Gate</span></h1>");
    html.push_str(
        "<p class=\"platform\">发布制品管理平台 · Release Artifact Management Platform</p>",
    );
    if let (Some(name), Some(version)) = (&report.release_name, &report.release_version) {
        html.push_str(&format!(
            "<p class=\"release\">Release: <strong>{} {}</strong></p>",
            escape_html(name),
            escape_html(version)
        ));
    }
    html.push_str("</div>");
    html.push_str(&format!(
        "<section class=\"banner {banner_class}\" data-decision=\"{}\">",
        summary.decision
    ));
    html.push_str(&format!("<div class=\"banner-text\">{banner_text}</div>"));
    html.push_str(&format!(
        "<div class=\"banner-meta\">exit code {} · decision <code>{}</code></div>",
        summary.exit_code, summary.decision
    ));
    html.push_str("</section></header>");

    html.push_str("<section class=\"counts\">");
    for (label, value, class) in [
        ("Targets", summary.total_targets, "total"),
        ("Required", summary.required_targets, "total"),
        ("Passed", summary.passed, "pass"),
        ("Failed", summary.failed, "fail"),
        ("Unknown", summary.unknown, "unknown"),
    ] {
        html.push_str(&format!(
            "<div class=\"count {class}\"><span class=\"num\">{value}</span><span class=\"lbl\">{label}</span></div>"
        ));
    }
    html.push_str("</section>");

    if !summary.blocking_targets.is_empty() {
        html.push_str(
            "<section class=\"blocking\"><h2>阻止发布的必需目标 · Blocking files</h2><ul>",
        );
        for path in &summary.blocking_targets {
            html.push_str(&format!(
                "<li class=\"blocking-file\" data-file=\"{}\"><code>{}</code></li>",
                escape_html(path),
                escape_html(path)
            ));
        }
        html.push_str("</ul></section>");
    }

    html.push_str("<section><h2>目标矩阵 · Target matrix</h2>");
    html.push_str("<table class=\"matrix\"><thead><tr><th>文件 File</th><th>类型 Type</th>");
    for label in ["PIE", "NX", "RELRO", "BIND_NOW", "符号证据 Symbol"] {
        html.push_str(&format!("<th>{label}</th>"));
    }
    html.push_str("<th>结论 Verdict</th></tr></thead><tbody>");
    for artifact in &report.artifacts {
        let a = &artifact.inspected;
        let e = &artifact.evaluation;
        html.push_str(&format!(
            "<tr class=\"target-row\" data-file=\"{}\" data-type=\"{}\" data-status=\"{}\">",
            escape_html(&a.display_path),
            a.target_type.as_str(),
            e.status
        ));
        html.push_str(&format!(
            "<td class=\"file-cell\"><code class=\"file-path\">{}</code>",
            escape_html(&a.display_path)
        ));
        if let Some(hash) = &a.sha256 {
            let short: String = hash.chars().take(12).collect();
            html.push_str(&format!(
                "<div class=\"hash\" title=\"{hash}\">sha256:{short}…</div>"
            ));
        }
        html.push_str("</td>");
        html.push_str(&format!(
            "<td><span class=\"type\">{}</span></td>",
            a.target_type.as_str()
        ));
        for check in &e.checks {
            html.push_str(&format!(
                "<td><span class=\"badge {}\" data-check=\"{}\" data-status=\"{}\">{}</span></td>",
                badge_class(check.status.as_str()),
                check.id,
                check.status.as_str(),
                status_label(check.status.as_str())
            ));
        }
        html.push_str(&format!(
            "<td><span class=\"verdict {}\">{}</span></td>",
            badge_class(&e.status),
            status_label(&e.status)
        ));
        html.push_str("</tr>");
    }
    html.push_str("</tbody></table></section>");

    html.push_str("<section class=\"details\"><h2>逐项证据 · Check details</h2>");
    for artifact in &report.artifacts {
        let a = &artifact.inspected;
        let e = &artifact.evaluation;
        html.push_str(&format!(
            "<article class=\"target-detail status-{}\" data-file=\"{}\">",
            badge_class(&e.status),
            escape_html(&a.display_path)
        ));
        html.push_str(&format!(
            "<h3><code>{}</code> <span class=\"type\">{}</span> <span class=\"badge {}\">{}</span></h3>",
            escape_html(&a.display_path),
            a.target_type.as_str(),
            badge_class(&e.status),
            status_label(&e.status)
        ));
        if let Some(code) = &a.error_code {
            let message = a.error_message.as_deref().unwrap_or("");
            html.push_str(&format!(
                "<p class=\"artifact-error\">错误码 <code>{}</code>: {}</p>",
                escape_html(code),
                escape_html(message)
            ));
        }
        html.push_str("<ul class=\"check-list\">");
        for check in &e.checks {
            html.push_str(&format!(
                "<li class=\"check check-{}\" data-check=\"{}\">",
                badge_class(check.status.as_str()),
                check.id
            ));
            html.push_str(&format!(
                "<div class=\"check-head\"><span class=\"badge {}\">{}</span> <strong>{}</strong> <code class=\"reason\">{}</code>",
                badge_class(check.status.as_str()),
                status_label(check.status.as_str()),
                escape_html(&check.label),
                escape_html(&check.reason_code)
            ));
            if check.required {
                html.push_str("<span class=\"req\">required</span>");
            }
            html.push_str("</div>");
            if !check.summary.is_empty() {
                html.push_str(&format!(
                    "<p class=\"summary\">{}</p>",
                    escape_html(&check.summary)
                ));
            }
            if !check.evidence.is_empty() {
                html.push_str("<ul class=\"evidence\">");
                for line in &check.evidence {
                    html.push_str(&format!("<li>{}</li>", escape_html(line)));
                }
                html.push_str("</ul>");
            }
            if !check.symbols.is_empty() {
                html.push_str(
                    "<div class=\"symbols\"><span class=\"sym-title\">符号证据 / symbols:</span> ",
                );
                let citations: Vec<String> = check
                    .symbols
                    .iter()
                    .map(|s| {
                        let kind = s
                            .evidence_kind
                            .as_ref()
                            .map(|k| format!(" <em class=\"kind\">[{k}]</em>"))
                            .unwrap_or_default();
                        format!(
                            "<code title=\"{}\">{}</code>{}",
                            escape_html(&s.origin),
                            escape_html(&s.name),
                            kind
                        )
                    })
                    .collect();
                html.push_str(&citations.join(" "));
                html.push_str("</div>");
            }
            html.push_str("</li>");
        }
        html.push_str("</ul></article>");
    }
    html.push_str("</section>");

    if !report.ignored_files.is_empty() {
        html.push_str(
            "<section class=\"ignored\"><h2>已扫描但非加固目标 · Non-artifact files</h2><ul>",
        );
        for path in &report.ignored_files {
            html.push_str(&format!("<li><code>{}</code></li>", escape_html(path)));
        }
        html.push_str("</ul></section>");
    }

    html.push_str("<footer><p>状态取值：<code>pass</code> · <code>fail</code> · <code>unknown</code>（无法确认）· <code>not_applicable</code>。必需目标在默认 fail-closed 策略下，<code>fail</code> 与 <code>unknown</code> 均阻止发布。</p></footer>");
    html.push_str("</main></body></html>");
    html
}

const STYLE: &str = r#"<style>
:root{--bg:#0f1420;--card:#171e2e;--ink:#e8edf7;--mut:#9fb0cc;--line:#28324a;--pass:#1f9d63;--fail:#d64545;--unknown:#c98a12;--na:#5b6b8c;--accent:#4f8cff}
*{box-sizing:border-box}body{margin:0;background:#f4f6fb;color:#1c2740;font:14px/1.55 -apple-system,"Segoe UI",Roboto,"Noto Sans CJK SC","Microsoft YaHei",sans-serif}
main{max-width:1180px;margin:0 auto;padding:28px 22px 60px}
h1{font-size:24px;margin:0}h2{font-size:18px;margin:26px 0 12px}.sub{font-size:13px;color:var(--mut);font-weight:500}
.platform{color:#5b6b8c;margin:4px 0}.top{display:flex;justify-content:space-between;gap:18px;align-items:flex-start;flex-wrap:wrap}
.banner{border-radius:12px;padding:16px 22px;color:#fff;min-width:280px;text-align:center;box-shadow:0 8px 24px rgba(20,40,90,.18)}
.banner.passed{background:linear-gradient(135deg,#1f9d63,#157a4b)}.banner.blocked{background:linear-gradient(135deg,#d64545,#9c2b2b)}
.banner-text{font-size:20px;font-weight:800;letter-spacing:.5px}.banner-meta{opacity:.9;font-size:12px;margin-top:6px}
.counts{display:flex;gap:12px;flex-wrap:wrap;margin:22px 0}.count{background:#fff;border:1px solid #e3e8f4;border-radius:12px;padding:12px 18px;min-width:110px;display:flex;flex-direction:column;align-items:center}
.count .num{font-size:26px;font-weight:800}.count .lbl{color:#66759a;font-size:12px;text-transform:uppercase;letter-spacing:.04em}
.count.pass .num{color:var(--pass)}.count.fail .num{color:var(--fail)}.count.unknown .num{color:var(--unknown)}
.blocking{background:#fdecec;border:1px solid #f3c2c2;border-radius:12px;padding:14px 18px}.blocking h2{margin:0 0 8px;color:#9c2b2b;font-size:16px}.blocking ul{margin:0;padding-left:18px}.blocking-file code{color:#8a1f1f;font-weight:700}
table.matrix{width:100%;border-collapse:collapse;background:#fff;border:1px solid #e3e8f4;border-radius:12px;overflow:hidden}
.matrix th,.matrix td{padding:10px 12px;border-bottom:1px solid #eef1f8;text-align:center;vertical-align:middle}.matrix th{background:#101a30;color:#dbe5ff;font-size:12px;text-transform:uppercase;letter-spacing:.03em}
.matrix td.file-cell{text-align:left}.file-path{font-weight:700}.hash{color:#8a97b5;font-size:11px}.type{background:#eef3ff;color:#2f5bd0;border-radius:999px;padding:2px 10px;font-size:12px}
.badge{display:inline-block;border-radius:6px;padding:2px 9px;font-size:11px;font-weight:800;color:#fff;letter-spacing:.03em;white-space:nowrap}
.badge.pass,.verdict.pass{background:var(--pass)}.badge.fail,.verdict.fail{background:var(--fail)}.badge.unknown,.verdict.unknown{background:var(--unknown)}.badge.na,.verdict.na{background:var(--na)}
.verdict{border-radius:6px;padding:3px 10px;color:#fff;font-size:11px;font-weight:800}.verdict.na{background:var(--na)}
.details .target-detail{background:#fff;border:1px solid #e3e8f4;border-left:5px solid var(--na);border-radius:12px;padding:14px 18px;margin:14px 0}
.target-detail.status-pass{border-left-color:var(--pass)}.target-detail.status-fail{border-left-color:var(--fail)}.target-detail.status-unknown{border-left-color:var(--unknown)}
.target-detail h3{margin:0 0 8px;display:flex;gap:10px;align-items:center;flex-wrap:wrap;font-size:15px}
.check-list{list-style:none;margin:0;padding:0}.check{border-top:1px dashed #e3e8f4;padding:10px 0}.check-head{display:flex;gap:10px;align-items:center;flex-wrap:wrap}.reason{color:#7a5bd0;font-size:12px}.req{background:#fff2d6;color:#9a6a00;border-radius:6px;padding:1px 8px;font-size:11px;font-weight:700}
.summary{margin:6px 0;color:#33405f}.evidence{margin:4px 0;padding-left:20px;color:#55628a;font-size:12.5px}.symbols{margin-top:6px;font-size:12.5px}.sym-title{color:#66759a}.symbols code{background:#f1f4fb;border:1px solid #e0e6f5;border-radius:5px;padding:1px 6px;margin:2px 3px 2px 0;display:inline-block}.kind{color:#1f9d63;font-style:normal;font-weight:700}
.artifact-error{background:#fdecec;border-radius:8px;padding:8px 10px;color:#8a1f1f}.ignored{color:#55628a}.ignored code{color:#33405f}footer{margin-top:30px;color:#8a97b5;font-size:12px}
code{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
</style>"#;
