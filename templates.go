package main

import (
	"html/template"
	"time"
)

const layoutHTML = `
{{define "layout"}}<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{.Title}} · 内部软件包仓库</title>
<style>
:root{--bg:#0f172a;--panel:#ffffff;--ink:#0f172a;--muted:#64748b;--line:#e2e8f0;--brand:#1d4ed8;--brand2:#1e40af;--ok:#15803d;--warn:#b45309;--danger:#b91c1c;--chip:#eff6ff;}
*{box-sizing:border-box}
body{margin:0;font:15px/1.6 -apple-system,"Segoe UI","PingFang SC","Microsoft YaHei",sans-serif;background:#f1f5f9;color:var(--ink)}
header.top{background:linear-gradient(120deg,#0b2a6b,#1d4ed8);color:#fff;padding:14px 28px;display:flex;align-items:center;gap:22px;flex-wrap:wrap}
header.top .brand{font-weight:700;font-size:17px;letter-spacing:.5px}
header.top nav{display:flex;gap:4px;flex-wrap:wrap}
header.top nav a{color:#dbeafe;text-decoration:none;padding:6px 12px;border-radius:8px;font-size:14px}
header.top nav a:hover{background:rgba(255,255,255,.14);color:#fff}
header.top nav a.active{background:rgba(255,255,255,.22);color:#fff;font-weight:600}
header.top .spacer{flex:1}
header.top .who{font-size:13px;color:#dbeafe}
main{max-width:1180px;margin:26px auto;padding:0 22px 60px}
.grid{display:grid;gap:16px}
.cards{grid-template-columns:repeat(auto-fit,minmax(180px,1fr));margin-bottom:20px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:16px 18px;box-shadow:0 1px 2px rgba(15,23,42,.05)}
.card .k{color:var(--muted);font-size:13px}
.card .v{font-size:26px;font-weight:700;margin-top:2px}
.panel{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:20px 22px;margin-bottom:18px;box-shadow:0 1px 2px rgba(15,23,42,.05)}
.panel h2{margin:0 0 14px;font-size:18px}
.panel h3{margin:18px 0 8px;font-size:15px}
table{width:100%;border-collapse:collapse;font-size:14px}
th,td{text-align:left;padding:9px 10px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--muted);font-weight:600;font-size:12.5px;text-transform:uppercase;letter-spacing:.04em}
tr:last-child td{border-bottom:0}
a{color:var(--brand)}
.chip{display:inline-block;padding:2px 10px;border-radius:999px;font-size:12.5px;font-weight:600;background:var(--chip);color:var(--brand2);white-space:nowrap}
.st-pending{background:#fef3c7;color:#92400e}
.st-cooldown_completed{background:#dbeafe;color:#1e40af}
.st-deleted{background:#fee2e2;color:#991b1b}
.st-withdrawn{background:#e2e8f0;color:#475569}
.st-running,.st-queued,.st-in_progress,.st-building{background:#dcfce7;color:#166534}
.st-failed,.st-canceled{background:#fee2e2;color:#991b1b}
.st-succeeded,.st-success{background:#e0e7ff;color:#3730a3}
.btn{display:inline-block;border:1px solid var(--brand);background:var(--brand);color:#fff;padding:8px 16px;border-radius:9px;font-size:14px;cursor:pointer;text-decoration:none}
.btn:hover{background:var(--brand2)}
.btn.secondary{background:#fff;color:var(--brand)}
.btn.warn{background:var(--warn);border-color:var(--warn)}
.btn.danger{background:var(--danger);border-color:var(--danger)}
.btn.gray{background:#475569;border-color:#475569}
.btn[disabled]{opacity:.5;cursor:not-allowed}
.muted{color:var(--muted)}
.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12.5px}
.alert{border-radius:10px;padding:11px 14px;margin:10px 0;font-size:14px}
.alert.err{background:#fef2f2;border:1px solid #fecaca;color:#991b1b}
.alert.ok{background:#f0fdf4;border:1px solid #bbf7d0;color:#166534}
.alert.warn{background:#fffbeb;border:1px solid #fde68a;color:#92400e}
.kv{display:grid;grid-template-columns:170px 1fr;gap:6px 14px;font-size:14px}
.kv dt{color:var(--muted)}
.kv dd{margin:0}
form.inline{display:inline}
input,select,textarea{font:inherit;padding:8px 10px;border:1px solid #cbd5e1;border-radius:9px;width:100%;background:#fff}
label.f{display:block;margin:10px 0;font-size:14px}
label.f span{display:block;color:var(--muted);margin-bottom:4px;font-size:13px}
.row{display:grid;grid-template-columns:1fr 1fr;gap:12px}
.timeline{list-style:none;margin:0;padding:0}
.timeline li{position:relative;padding:0 0 14px 22px;border-left:2px solid var(--line);margin-left:6px}
.timeline li::before{content:"";position:absolute;left:-7px;top:3px;width:12px;height:12px;border-radius:50%;background:var(--brand)}
.timeline li.done::before{background:var(--ok)}
.timeline li.bad::before{background:var(--danger)}
.small{font-size:13px}
.cred{background:#0b1220;color:#cbd5e1;border-radius:10px;padding:12px 14px;font-size:13px;overflow:auto}
.pillrow{display:flex;gap:8px;flex-wrap:wrap;align-items:center}
</style>
</head>
<body>
<header class="top">
  <div class="brand">📦 内部软件包仓库</div>
  <nav>
    <a href="/" class="{{if eq .Active "home"}}active{{end}}">总览</a>
    <a href="/deletions" class="{{if eq .Active "deletions"}}active{{end}}">删除冷静期</a>
    <a href="/builds" class="{{if eq .Active "builds"}}active{{end}}">构建</a>
    <a href="/downloads" class="{{if eq .Active "downloads"}}active{{end}}">下载记录</a>
    <a href="/publish" class="{{if eq .Active "publish"}}active{{end}}">发布包</a>
    <a href="/api/packages">API</a>
  </nav>
  <div class="spacer"></div>
  <div class="who">单进程 · Go net/http · tar/sha256</div>
</header>
<main>
{{if .Flash}}<div class="alert ok">{{.Flash}}</div>{{end}}
{{if .Error}}<div class="alert err">{{.Error}}</div>{{end}}
{{template "content" .}}
</main>
</body></html>{{end}}`

var funcMap = template.FuncMap{
	"statusLabel": labelFor,
	"sliceDigest": func(d string) string {
		if len(d) > 22 {
			return d[:22] + "…"
		}
		return d
	},
	"fmtTime": func(t any) string {
		switch v := t.(type) {
		case time.Time:
			if v.IsZero() {
				return "—"
			}
			return v.Format("2006-01-02 15:04:05")
		case *time.Time:
			if v == nil {
				return "—"
			}
			return v.Format("2006-01-02 15:04:05")
		}
		return "—"
	},
}
