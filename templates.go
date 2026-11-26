package main

import (
	"html/template"
	"time"
)

type releaseView struct {
	Release      Release
	Verification Verification
}

type pageData struct {
	Title    string
	Releases []releaseView
	Release  *releaseView
	Identity *principal
	Error    string
	Notice   string
}

var templateFuncs = template.FuncMap{
	"formatTime": func(value time.Time) string {
		return value.In(time.FixedZone("CST", 8*60*60)).Format("2006-01-02 15:04:05")
	},
	"roleName": func(role string) string {
		if role == roleAdmin {
			return "管理员"
		}
		return "发布者"
	},
}

const styleCSS = `
:root {
  color-scheme: light;
  --ink: #172033;
  --muted: #5d6779;
  --line: #dbe1ea;
  --paper: #f7f9fc;
  --accent: #2456d6;
  --good: #0c6b3d;
  --good-bg: #e6f6ed;
  --bad: #9f1d20;
  --bad-bg: #fdebec;
}
* { box-sizing: border-box; }
body {
  margin: 0;
  color: var(--ink);
  background: var(--paper);
  font: 15px/1.55 ui-sans-serif, system-ui, -apple-system, "Segoe UI", sans-serif;
}
main { width: min(1080px, calc(100% - 32px)); margin: 28px auto 64px; }
header {
  padding: 20px 0 16px;
  border-bottom: 1px solid var(--line);
}
header h1 { margin: 0 0 4px; font-size: 26px; }
header p, .lead { margin: 0; color: var(--muted); }
nav { display: flex; flex-wrap: wrap; gap: 10px; margin-top: 16px; }
a { color: var(--accent); text-decoration: none; }
a:hover { text-decoration: underline; }
.button {
  display: inline-block;
  padding: 9px 14px;
  border: 1px solid var(--accent);
  border-radius: 8px;
  background: var(--accent);
  color: white;
  font-weight: 650;
}
.button.secondary { background: white; color: var(--accent); }
table { width: 100%; border-collapse: collapse; margin-top: 22px; background: white; }
th, td { padding: 11px 12px; border-bottom: 1px solid var(--line); text-align: left; }
th { color: var(--muted); font-size: 13px; font-weight: 650; }
.badge {
  display: inline-block;
  padding: 3px 8px;
  border-radius: 99px;
  font-size: 12px;
  font-weight: 750;
}
.badge.good { color: var(--good); background: var(--good-bg); }
.badge.bad { color: var(--bad); background: var(--bad-bg); }
.panel, .card {
  margin-top: 20px;
  padding: 20px;
  border: 1px solid var(--line);
  border-radius: 12px;
  background: white;
}
.notice { border-left: 4px solid var(--accent); background: #eef3ff; }
.error { border-left: 4px solid var(--bad); background: var(--bad-bg); color: var(--bad); }
.signature-valid { border-left: 4px solid var(--good); background: var(--good-bg); }
.signature-invalid { border-left: 4px solid var(--bad); background: var(--bad-bg); }
.fields { display: grid; grid-template-columns: minmax(130px, 220px) 1fr; gap: 8px 18px; }
.fields dt { color: var(--muted); }
.fields dd { margin: 0; overflow-wrap: anywhere; font-family: ui-monospace, monospace; }
form { display: grid; gap: 16px; max-width: 720px; }
label { display: grid; gap: 6px; font-weight: 650; }
input, textarea {
  width: 100%;
  padding: 9px 11px;
  border: 1px solid #b9c2d0;
  border-radius: 8px;
  font: inherit;
  background: white;
}
.hint { color: var(--muted); font-weight: 400; }
footer { margin-top: 42px; color: var(--muted); font-size: 13px; }
`

const indexTemplate = `<!doctype html>
<html lang="zh-CN">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<title>{{.Title}}</title><link rel="stylesheet" href="/static/style.css"></head>
<body><main>
<header>
  <h1>内部软件包仓库</h1>
  <p>已发布版本不可变；每个归档均带有发布者签名和 SHA-256 内容摘要。</p>
  <nav>
    <a class="button" href="/publish">发布新版本</a>
    <a class="button secondary" href="/admin/repair">管理员创建修复版本</a>
  </nav>
</header>
{{if .Error}}<div class="panel error">{{.Error}}</div>{{end}}
{{if .Notice}}<div class="panel notice">{{.Notice}}</div>{{end}}
{{if .Releases}}
<table>
  <thead><tr><th>包</th><th>版本</th><th>发布者</th><th>发布时间</th><th>签名验证</th></tr></thead>
  <tbody>{{range .Releases}}<tr>
    <td><a href="/packages/{{.Release.Name}}/{{.Release.Version}}">{{.Release.Name}}</a></td>
    <td>{{.Release.Version}}{{if .Release.Repair}} <span class="hint">修复 {{.Release.Repair.OfVersion}}</span>{{end}}</td>
    <td>{{.Release.Publisher.User}}（{{roleName .Release.Publisher.Role}}）</td>
    <td>{{formatTime .Release.PublishedAt}}</td>
    <td>{{if .Verification.Valid}}<span class="badge good">通过</span>{{else}}<span class="badge bad">失败</span>{{end}}</td>
  </tr>{{end}}</tbody>
</table>
{{else}}
<div class="panel">尚无已发布版本。</div>
{{end}}
<footer>不可变发布 · HMAC-SHA256 签名 · SHA-256 内容寻址</footer>
</main></body></html>`

const releaseTemplate = `<!doctype html>
<html lang="zh-CN">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<title>{{.Release.Release.Name}} {{.Release.Release.Version}}</title><link rel="stylesheet" href="/static/style.css"></head>
<body><main>
{{$record := .Release.Release}}
<header>
  <p><a href="/">← 全部软件包</a></p>
  <h1>{{$record.Name}} <span class="hint">{{$record.Version}}</span></h1>
  {{if $record.Repair}}<p>修复版本：替代 {{$record.Repair.OfVersion}}，原因：{{$record.Repair.Reason}}</p>
  {{else}}<p>不可变发布版本</p>{{end}}
</header>
{{if .Release.Verification.Valid}}
<div class="panel signature-valid">
  <strong>签名验证通过</strong>
  <p>{{.Release.Verification.Detail}}</p>
  <a class="button" href="/packages/{{$record.Name}}/{{$record.Version}}/download">下载归档</a>
</div>
{{else}}
<div class="panel signature-invalid">
  <strong>签名验证失败</strong>
  <p>{{.Release.Verification.Detail}} 为避免分发被篡改的内容，下载已禁用。</p>
</div>
{{end}}
<section class="card">
  <h2>发布记录</h2>
  <dl class="fields">
    <dt>包</dt><dd>{{$record.Name}}</dd>
    <dt>版本</dt><dd>{{$record.Version}}</dd>
    <dt>发布者</dt><dd>{{$record.Publisher.User}}</dd>
    <dt>角色</dt><dd>{{roleName $record.Publisher.Role}}</dd>
    <dt>发布时间</dt><dd>{{formatTime $record.PublishedAt}}</dd>
    {{if $record.Publisher.RemoteAddr}}<dt>来源地址</dt><dd>{{$record.Publisher.RemoteAddr}}</dd>{{end}}
    {{if $record.Repair}}<dt>修复自</dt><dd>{{$record.Repair.OfVersion}}</dd>{{end}}
    {{if $record.Repair}}<dt>修复原因</dt><dd>{{$record.Repair.Reason}}</dd>{{end}}
  </dl>
</section>
<section class="card">
  <h2>签名与内容摘要</h2>
  <dl class="fields">
    <dt>验证状态</dt><dd>{{if .Release.Verification.Valid}}通过{{else}}失败{{end}}</dd>
    <dt>签名算法</dt><dd>{{$record.Signature.Algorithm}}</dd>
    <dt>签名密钥</dt><dd>{{$record.Signature.KeyID}}</dd>
    <dt>签名时间</dt><dd>{{formatTime $record.Signature.SignedAt}}</dd>
    <dt>声明摘要</dt><dd>{{.Release.Verification.ExpectedDigest}}</dd>
    <dt>实际摘要</dt><dd>{{.Release.Verification.ActualDigest}}</dd>
    <dt>归档大小</dt><dd>{{$record.Archive.Size}} 字节，{{$record.Archive.Entries}} 个条目</dd>
  </dl>
  <p><a href="/packages/{{$record.Name}}/{{$record.Version}}/manifest.json">查看签名清单 JSON</a></p>
</section>
<footer>此版本记录以只写方式存储，重复上传或管理员改写都会被拒绝。</footer>
</main></body></html>`

const publishTemplate = `<!doctype html>
<html lang="zh-CN">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<title>{{.Title}}</title><link rel="stylesheet" href="/static/style.css"></head>
<body><main>
<header>
  <p><a href="/">← 全部软件包</a></p>
  <h1>发布新版本</h1>
  <p>发布后不可覆盖；相同包名和版本号的再次上传将返回冲突。</p>
</header>
{{if .Error}}<div class="panel error">{{.Error}}</div>{{end}}
{{if .Identity}}
<div class="panel notice">当前身份：{{.Identity.User}}（{{roleName .Identity.Role}}）</div>
{{end}}
<form method="post" action="/upload" enctype="multipart/form-data" class="panel">
  <label>包名<input name="name" required maxlength="128" pattern="[A-Za-z0-9][A-Za-z0-9._-]{0,127}"></label>
  <label>版本号<input name="version" required maxlength="128" pattern="[A-Za-z0-9][A-Za-z0-9._+-]{0,127}"></label>
  <label>tar 归档<input name="package" type="file" required accept=".tar,application/x-tar"></label>
  <div><button class="button" type="submit">签名并发布</button></div>
</form>
<footer>只有 publisher 角色可在此发布新版本。</footer>
</main></body></html>`

const repairTemplate = `<!doctype html>
<html lang="zh-CN">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<title>{{.Title}}</title><link rel="stylesheet" href="/static/style.css"></head>
<body><main>
<header>
  <p><a href="/">← 全部软件包</a></p>
  <h1>管理员创建修复版本</h1>
  <p>修复会创建新的版本号并引用原版本；原版本保持完全不变。</p>
</header>
{{if .Error}}<div class="panel error">{{.Error}}</div>{{end}}
{{if .Identity}}
<div class="panel notice">当前身份：{{.Identity.User}}（{{roleName .Identity.Role}}）</div>
{{end}}
<form method="post" action="/repair" enctype="multipart/form-data" class="panel">
  <label>包名<input name="name" required maxlength="128" pattern="[A-Za-z0-9][A-Za-z0-9._-]{0,127}"></label>
  <label>原版本（不可改写）<input name="replaces" required maxlength="128" pattern="[A-Za-z0-9][A-Za-z0-9._+-]{0,127}"></label>
  <label>修复版本号（新版本）<input name="version" required maxlength="128" pattern="[A-Za-z0-9][A-Za-z0-9._+-]{0,127}"></label>
  <label>修复原因<input name="reason" required maxlength="512" placeholder="例如：修复启动脚本中的错误"></label>
  <label>tar 归档<input name="package" type="file" required accept=".tar,application/x-tar"></label>
  <div><button class="button" type="submit">签名并发布修复版本</button></div>
</form>
<footer>只有 admin 角色可创建修复版本；修复版本号必须与已发布版本不同。</footer>
</main></body></html>`

const errorTemplate = `<!doctype html>
<html lang="zh-CN">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<title>{{.Title}}</title><link rel="stylesheet" href="/static/style.css"></head>
<body><main>
<header><h1>{{.Title}}</h1><p>{{.Error}}</p></header>
<nav><a class="button secondary" href="/">返回全部软件包</a></nav>
</main></body></html>`
