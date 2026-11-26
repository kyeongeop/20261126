//! 报告输出：机器可读 JSON 与自包含的动态库路径风险 HTML 面板。

use crate::errors::{code, ErrorBody, RiskError, RiskResult};
use crate::model::{PanelReport, Severity};

pub fn to_json(report: &PanelReport) -> RiskResult<String> {
    serde_json::to_string_pretty(report)
        .map_err(|e| RiskError::new(code::IO, format!("报告序列化失败: {e}")))
}

pub fn error_json(error: &RiskError) -> String {
    let body = ErrorBody::from(error);
    serde_json::to_string_pretty(&body).unwrap_or_else(|_| {
        format!("{{\"error_code\":\"{}\",\"message\":\"序列化失败\"}}", code::IO)
    })
}

pub fn to_html(report: &PanelReport) -> String {
    let data = serde_json::to_string(report).unwrap_or_else(|_| "{}".to_string());
    let mut html = String::with_capacity(8 * 1024);
    html.push_str(
        r#"<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>动态库路径风险面板</title>
<style>
:root { --bg:#0f1420; --card:#182033; --line:#283350; --fg:#e6ebf5; --muted:#8fa0bf;
  --crit:#ff4d6d; --high:#ff8a3d; --med:#ffd166; --low:#4cc9f0; --ok:#3ddc97; }
* { box-sizing: border-box; }
body { margin:0; background:var(--bg); color:var(--fg);
  font:14px/1.6 -apple-system,"Segoe UI",Roboto,"PingFang SC","Microsoft YaHei",sans-serif; }
header { padding:24px 32px; border-bottom:1px solid var(--line); background:#131a2b; }
h1 { margin:0 0 6px; font-size:22px; }
.sub { color:var(--muted); font-size:13px; word-break:break-all; }
main { padding:24px 32px 48px; max-width:1280px; margin:0 auto; }
.cards { display:grid; grid-template-columns:repeat(auto-fit,minmax(150px,1fr)); gap:14px; margin-bottom:24px; }
.card { background:var(--card); border:1px solid var(--line); border-radius:10px; padding:16px; }
.card .num { font-size:26px; font-weight:700; }
.card .lbl { color:var(--muted); font-size:12px; margin-top:4px; }
section { background:var(--card); border:1px solid var(--line); border-radius:12px;
  padding:20px; margin-bottom:22px; }
section h2 { margin:0 0 14px; font-size:17px; }
table { width:100%; border-collapse:collapse; font-size:13px; }
th,td { text-align:left; padding:9px 10px; border-bottom:1px solid var(--line);
  vertical-align:top; word-break:break-word; }
th { color:var(--muted); font-weight:600; }
.badge { display:inline-block; padding:2px 9px; border-radius:999px; font-size:12px;
  font-weight:600; white-space:nowrap; }
.s-critical { background:rgba(255,77,109,.16); color:var(--crit); }
.s-high { background:rgba(255,138,61,.16); color:var(--high); }
.s-medium { background:rgba(255,209,102,.16); color:var(--med); }
.s-low { background:rgba(76,201,240,.16); color:var(--low); }
.tag { display:inline-block; padding:1px 7px; border:1px solid var(--line);
  border-radius:6px; font-size:11px; color:var(--muted); margin:1px 3px 1px 0; }
.tag.rpath { border-color:var(--high); color:var(--high); }
.tag.runpath { border-color:var(--low); color:var(--low); }
.tag.ld { border-color:var(--med); color:var(--med); }
.tag.sys { border-color:var(--muted); color:var(--muted); }
.flow { display:flex; flex-wrap:wrap; align-items:center; gap:6px; margin:8px 0; }
.dir { padding:5px 10px; border-radius:8px; border:1px solid var(--line);
  background:#101828; font-family:ui-monospace,Menlo,monospace; font-size:12px; }
.dir.bad { border-color:var(--crit); }
.dir.warn { border-color:var(--med); }
.arrow { color:var(--muted); }
.tree { font-family:ui-monospace,Menlo,monospace; font-size:13px; }
.tree .node { padding:3px 0; }
.tree .hit { color:var(--ok); }
.tree .miss { color:var(--high); }
.muted { color:var(--muted); }
.code { font-family:ui-monospace,Menlo,monospace; color:var(--muted); font-size:12px; }
details { margin:6px 0; }
summary { cursor:pointer; color:var(--muted); }
.empty { color:var(--muted); padding:12px 0; }
</style>
</head>
<body>
"#,
    );
    html.push_str("<header><h1>动态库路径风险面板</h1>");
    html.push_str(&format!(
        "<div class=\"sub\">根制品：{}<br>仓库根：{}</div></header><main>",
        escape(&report.root_artifact),
        escape(&report.repo_root)
    ));
    html.push_str(&summary_cards(report));
    html.push_str(&findings_section(report));
    html.push_str(&artifacts_section(report));
    html.push_str(&edges_section(report));
    html.push_str(&format!(
        "<script>window.__PANEL_DATA__ = {data};</script></main></body></html>"
    ));
    html
}

fn escape(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn severity_class(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical => "s-critical",
        Severity::High => "s-high",
        Severity::Medium => "s-medium",
        Severity::Low => "s-low",
    }
}

fn severity_label(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical => "严重",
        Severity::High => "高",
        Severity::Medium => "中",
        Severity::Low => "低",
    }
}

fn summary_cards(report: &PanelReport) -> String {
    let s = &report.summary;
    format!(
        r#"<div class="cards">
<div class="card"><div class="num">{artifact_count}</div><div class="lbl">分析制品</div></div>
<div class="card"><div class="num">{edge_count}</div><div class="lbl">依赖关系</div></div>
<div class="card"><div class="num" style="color:var(--crit)">{critical}</div><div class="lbl">严重风险</div></div>
<div class="card"><div class="num" style="color:var(--high)">{high}</div><div class="lbl">高风险</div></div>
<div class="card"><div class="num" style="color:var(--med)">{medium}</div><div class="lbl">中风险</div></div>
<div class="card"><div class="num" style="color:var(--low)">{low}</div><div class="lbl">低风险</div></div>
<div class="card"><div class="num">{missing}</div><div class="lbl">缺失依赖</div></div>
</div>"#,
        artifact_count = s.artifact_count,
        edge_count = s.edge_count,
        critical = s.critical,
        high = s.high,
        medium = s.medium,
        low = s.low,
        missing = s.missing_dependencies,
    )
}

fn findings_section(report: &PanelReport) -> String {
    let mut out = String::new();
    out.push_str("<section><h2>风险清单</h2>");
    if report.findings.is_empty() {
        out.push_str("<div class=\"empty\">未发现动态库路径风险。</div></section>");
        return out;
    }
    out.push_str(
        "<table><thead><tr><th>等级</th><th>编码</th><th>标题</th><th>说明</th><th>制品</th><th>风险来源</th></tr></thead><tbody>",
    );
    for finding in &report.findings {
        out.push_str(&format!(
            "<tr><td><span class=\"badge {cls}\">{label}</span></td><td class=\"code\">{code}</td><td>{title}</td><td>{detail}</td><td>{artifact}</td><td>",
            cls = severity_class(finding.severity),
            label = severity_label(finding.severity),
            code = finding.code,
            title = escape(&finding.title),
            detail = escape(&finding.detail),
            artifact = escape(&finding.artifact),
        ));
        if finding.sources.is_empty() {
            out.push_str("<span class=\"muted\">-</span>");
        }
        for source in &finding.sources {
            let dir = source.directory.clone().unwrap_or_else(|| "<空路径项/当前工作目录>".to_string());
            out.push_str(&format!(
                "<div class=\"code\">{} · {} · #{}</div>",
                escape(&source.from_artifact),
                origin_tag(source.origin),
                source.order
            ));
            out.push_str(&format!("<div class=\"muted\">{}</div>", escape(&dir)));
        }
        out.push_str("</td></tr>");
    }
    out.push_str("</tbody></table></section>");
    out
}

fn artifacts_section(report: &PanelReport) -> String {
    let mut out = String::new();
    out.push_str("<section><h2>制品与优先搜索目录</h2>");
    for artifact in &report.artifacts {
        out.push_str(&format!("<details open><summary><strong>{}</strong> <span class=\"code\">{}</span></summary>",
            escape(&artifact.path), escape(&artifact.sha256)));
        out.push_str(&format!(
            "<div class=\"sub\">类型 {} · {} · {} · SONAME: {} · NEEDED: {}</div>",
            escape(&artifact.elf_type),
            escape(&artifact.class),
            escape(&artifact.machine),
            artifact.soname.as_deref().unwrap_or("-"),
            if artifact.needed.is_empty() { "-".to_string() } else { artifact.needed.join(", ") }
        ));
        if artifact.search_entries.is_empty() {
            out.push_str("<div class=\"empty\">无 RPATH/RUNPATH 条目，仅走系统默认目录。</div>");
        } else {
            out.push_str("<div class=\"flow\">");
            for entry in &artifact.search_entries {
                let label = entry
                    .expanded
                    .clone()
                    .unwrap_or_else(|| "<空项=CWD>".to_string());
                let cls = if entry.escapes_repo || entry.empty {
                    "dir bad"
                } else if entry.unexpanded_variable {
                    "dir warn"
                } else {
                    "dir"
                };
                out.push_str(&format!(
                    "<span class=\"{cls}\">{} {}</span><span class=\"arrow\">→</span>",
                    origin_tag(entry.origin),
                    escape(&label)
                ));
            }
            out.push_str("<span class=\"dir tag sys\">系统默认目录</span></div>");
        }
        out.push_str("</details>");
    }
    out.push_str("</section>");
    out
}

fn edges_section(report: &PanelReport) -> String {
    let mut out = String::new();
    out.push_str("<section><h2>依赖链解析（候选目录按搜索优先级）</h2>");
    if report.edges.is_empty() {
        out.push_str("<div class=\"empty\">根制品没有动态依赖。</div></section>");
        return out;
    }
    for edge in &report.edges {
        let status = match &edge.resolved {
            Some(path) => format!("<span class=\"hit\">命中 {}</span>", escape(path)),
            None => "<span class=\"miss\">仓库内未命中</span>".to_string(),
        };
        out.push_str(&format!(
            "<div class=\"tree\"><div class=\"node\">L{depth} {parent} ▸ <strong>{needed}</strong> — {status}</div>",
            depth = edge.depth,
            parent = escape(&edge.parent),
            needed = escape(&edge.needed),
            status = status
        ));
        for candidate in &edge.candidates {
            let dir = candidate
                .directory
                .clone()
                .unwrap_or_else(|| "<空路径项/当前工作目录>".to_string());
            let mark = if candidate.exists { "✓" } else { "·" };
            let allow = if candidate.allowed { "允许" } else { "未授权" };
            out.push_str(&format!(
                "<div class=\"node muted\" style=\"padding-left:24px\">{mark} #{} {} {} [{}] {}</div>",
                candidate.order,
                origin_tag(candidate.origin),
                escape(&dir),
                allow,
                candidate
                    .resolved_to
                    .clone()
                    .map(|p| format!("→ {}", escape(&p)))
                    .unwrap_or_default()
            ));
        }
        out.push_str("</div>");
    }
    out.push_str("</section>");
    out
}

fn origin_tag(origin: crate::model::PathOrigin) -> String {
    let (cls, label) = match origin {
        crate::model::PathOrigin::Rpath => ("tag rpath", "RPATH"),
        crate::model::PathOrigin::Runpath => ("tag runpath", "RUNPATH"),
        crate::model::PathOrigin::LdLibraryPath => ("tag ld", "LD_LIB"),
        crate::model::PathOrigin::SystemDefault => ("tag sys", "SYS"),
    };
    format!("<span class=\"{cls}\">{label}</span>")
}
