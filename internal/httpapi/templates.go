package httpapi

const detailHTML = `<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>文件详情 · {{.File.FileID}}</title>
<style>
  body { font-family: -apple-system, "Segoe UI", sans-serif; margin: 2rem; color: #1f2937; }
  h1 { margin-bottom: .25rem; }
  .meta { color: #6b7280; font-size: .9rem; margin-bottom: 1.5rem; }
  form.filters { display: flex; flex-wrap: wrap; gap: .75rem; align-items: end;
    background: #f9fafb; border: 1px solid #e5e7eb; padding: 1rem; border-radius: .5rem; }
  form.filters label { display: flex; flex-direction: column; font-size: .8rem; gap: .25rem; }
  input, select { padding: .4rem .5rem; border: 1px solid #d1d5db; border-radius: .375rem; min-width: 10rem; }
  button { padding: .45rem 1rem; background: #2563eb; color: #fff; border: 0; border-radius: .375rem; cursor: pointer; }
  button.secondary { background: #6b7280; }
  .error { background: #fef2f2; color: #b91c1c; padding: .6rem .8rem; border-radius: .375rem; margin: 1rem 0; }
  .versions { margin: 1rem 0; display: flex; gap: .5rem; flex-wrap: wrap; align-items: center; }
  .chip { font-size: .8rem; padding: .25rem .6rem; border-radius: 999px; border: 1px solid #d1d5db;
    text-decoration: none; color: #374151; background: #fff; }
  .chip.active { background: #2563eb; color: #fff; border-color: #2563eb; }
  table { width: 100%; border-collapse: collapse; margin-top: 1rem; }
  th, td { text-align: left; padding: .6rem .5rem; border-bottom: 1px solid #e5e7eb; vertical-align: top; font-size: .9rem; }
  th { color: #6b7280; font-weight: 600; }
  tr:target { background: #eff6ff; }
  tr.jump { background: #fef9c3; }
  .tag { display: inline-block; padding: .15rem .55rem; border-radius: 999px; font-size: .78rem; background: #eef2ff; color: #3730a3; }
  .detail { color: #6b7280; font-size: .82rem; }
  .detail b { color: #374151; font-weight: 600; }
  code { background: #f3f4f6; padding: .1rem .35rem; border-radius: .25rem; font-size: .78rem; }
  .empty { padding: 2rem; text-align: center; color: #6b7280; }
</style>
</head>
<body>
<p><a href="/">← 文件列表</a></p>
<h1>{{if .File.Name}}{{.File.Name}}{{else}}{{.File.FileID}}{{end}}</h1>
<div class="meta">
  文件 ID：<code>{{.File.FileID}}</code>
  {{if .File.CurrentPath}} · 当前路径：<code>{{.File.CurrentPath}}</code>{{end}}
  · 创建：{{.File.CreatedAt.Format "2006-01-02 15:04:05 UTC"}}
  · 最近事件：{{.File.UpdatedAt.Format "2006-01-02 15:04:05 UTC"}}
  · 有效事件 {{.File.EventCount}} 条
  {{if .File.DeletedKeys}} · 已删除 {{len .File.DeletedKeys}} 条{{end}}
</div>

<div class="versions">
  <strong>版本：</strong>
  <a class="chip {{if not .JumpVersion}}active{{end}}" href="/files/{{.File.FileID}}">全部版本</a>
  {{range .File.Versions}}
  <a class="chip {{if eq . $.JumpVersion}}active{{end}}"
     href="/files/{{$.File.FileID}}?version={{.}}#timeline">{{.}}</a>
  {{end}}
</div>

<form class="filters" method="get" action="/files/{{.File.FileID}}">
  <label>用户
    <input type="text" name="user" value="{{.FilterUser}}" placeholder="用户 ID">
  </label>
  <label>动作
    <select name="action">
      <option value="">全部动作</option>
      {{range .Actions}}
      <option value="{{.}}" {{if eq . $.FilterAction}}selected{{end}}>{{index $.ActionLabels .}}</option>
      {{end}}
    </select>
  </label>
  <label>版本
    <input type="text" name="version" value="{{.FilterVersion}}" placeholder="如 v1">
  </label>
  <label>开始时间
    <input type="datetime-local" name="from" value="{{.FilterFrom}}">
  </label>
  <label>结束时间
    <input type="datetime-local" name="to" value="{{.FilterTo}}">
  </label>
  <button type="submit">筛选</button>
  <a class="chip" href="/files/{{.File.FileID}}">重置</a>
</form>

{{if .FilterError}}<div class="error">筛选条件无效：{{.FilterError}}</div>{{end}}

<h2 id="timeline">访问时间线
  <span class="meta">（匹配 {{.Filtered}} / {{.Total}} 条）</span>
</h2>
{{if not .Rows}}
  <div class="empty">没有匹配的事件。</div>
{{else}}
<table>
  <thead><tr><th>时间 (UTC)</th><th>动作</th><th>用户</th><th>版本</th><th>详情</th><th>去重键</th></tr></thead>
  <tbody>
  {{range .Rows}}
  <tr id="{{.Anchor}}" class="{{if eq .Event.DedupKey $.JumpKey}}jump{{end}}">
    <td>{{.Event.OccurredAt.Format "2006-01-02 15:04:05"}}</td>
    <td><span class="tag">{{.ActionLabel}}</span></td>
    <td>{{.Event.ActorID}}</td>
    <td>
      <a class="chip" href="/files/{{.Event.FileID}}?version={{.Event.VersionID}}#timeline">{{.Event.VersionID}}</a>
    </td>
    <td class="detail">
      {{range .Details}}<div><b>{{index . 0}}</b>：{{index . 1}}</div>{{end}}
    </td>
    <td><a href="#{{.Anchor}}"><code>{{.Event.DedupKey}}</code></a></td>
  </tr>
  {{end}}
  </tbody>
</table>
{{end}}
</body>
</html>`
