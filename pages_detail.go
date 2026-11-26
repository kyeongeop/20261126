package main

const deletionDetailPage = `{{define "content"}}
{{$d := .D}}
<p><a href="/deletions">← 全部删除申请</a></p>

<div class="panel">
  <div class="pillrow" style="justify-content:space-between">
    <h2 style="margin:0">{{$d.ID}} · <span class="mono">{{$d.Target}}</span></h2>
    <span class="chip st-{{$d.Status}}" style="font-size:14px;padding:5px 14px">{{$d.StatusLabel}}</span>
  </div>
  <dl class="kv" style="margin-top:14px">
    <dt>删除原因</dt><dd>{{if $d.Reason}}{{$d.Reason}}{{else}}<span class="muted">未填写</span>{{end}}</dd>
    <dt>申请人</dt><dd><b>{{$d.RequestedBy}}</b> <span class="chip">{{$d.RequesterRole}}</span> · {{fmtTime $d.CreatedAt}}</dd>
    <dt>冷静期时长</dt><dd class="mono">{{$d.CooldownSeconds}} 秒</dd>
    <dt>到期时间</dt><dd>{{fmtTime $d.ExpiresAt}}
      {{if eq $d.Status "pending"}}
        {{if $d.Due}}<span class="chip st-cooldown_completed">已届满，可推进</span>
        {{else}}<span class="chip st-pending">冷静期中 · 剩余 {{$d.SecondsRemaining}} 秒</span>{{end}}
      {{end}}
    </dd>
    {{if $d.CooldownCompletedAt}}<dt>冷静期完成</dt><dd>{{fmtTime $d.CooldownCompletedAt}}</dd>{{end}}
    {{if $d.ConfirmedBy}}<dt>第二人确认</dt><dd><b>{{$d.ConfirmedBy}}</b> · {{fmtTime $d.ConfirmedAt}}</dd>{{end}}
    {{if $d.WithdrawnBy}}<dt>撤回人</dt><dd><b>{{$d.WithdrawnBy}}</b> · {{fmtTime $d.WithdrawnAt}}</dd>{{end}}
    {{if $d.DeletedAt}}<dt>删除完成</dt><dd>{{fmtTime $d.DeletedAt}}</dd>{{end}}
  </dl>

  {{if $d.Blocked}}
  <div class="alert err">
    <b>无法完成冷静期 / 删除：该包正被引用。</b>
    <ul style="margin:6px 0 0 18px">
      {{range $d.BlockReasons}}<li>{{.}}</li>{{end}}
    </ul>
  </div>
  {{end}}

  <h3>处理操作</h3>
  <div class="pillrow">
    {{if $d.CanWithdraw}}
    <form class="inline" method="post" action="/deletions/{{$d.ID}}/withdraw">
      <button class="btn gray" type="submit">↩ 撤回申请（恢复包可用）</button>
    </form>
    {{end}}
    {{if and $d.CanComplete}}
    <form class="inline" method="post" action="/deletions/{{$d.ID}}/complete">
      <button class="btn secondary" type="submit">⏱ 冷静期已到 · 推进到待确认</button>
    </form>
    {{end}}
  </div>

  {{if or (eq $d.Status "pending") (eq $d.Status "cooldown_completed")}}
  <div style="margin-top:16px;border-top:1px dashed var(--line);padding-top:14px">
    <h3>第二人确认（职责分离）</h3>
    <p class="muted small">必须由<b>不同于申请人 {{$d.RequestedBy}}</b> 的另一个管理员账号确认；
      {{if eq $d.Status "pending"}}且需冷静期届满、无活跃引用，确认时会自动完成冷静期检查。{{end}}</p>
    <form method="post" action="/deletions/{{$d.ID}}/confirm" class="row">
      <label class="f"><span>另一个管理员用户名</span><input name="username" placeholder="admin2" required></label>
      <label class="f"><span>密码</span><input name="password" type="password" placeholder="admin2-pass" required></label>
      <div style="grid-column:1/-1">
        <button class="btn danger" type="submit" {{if $d.Blocked}}disabled title="存在引用，无法删除"{{end}}>
          ✓ 第二人确认并删除
        </button>
        {{if $d.Blocked}}<span class="muted small">请先解除下方引用后再确认。</span>{{end}}
      </div>
    </form>
    <p class="muted small">也可直接调用 API：
      <span class="mono">curl -u admin2:admin2-pass -X POST .../api/deletion-requests/{{$d.ID}}/confirm</span>
    </p>
  </div>
  {{end}}
</div>

<div class="panel">
  <h2>受影响的构建（{{$d.Impact.BuildCount}}，进行中 {{$d.Impact.ActiveBuildCount}}）</h2>
  <table>
    <thead><tr><th>流水线</th><th>引用版本</th><th>状态</th><th>分支</th><th>触发人</th><th>开始时间</th></tr></thead>
    <tbody>
    {{range $d.AffectedBuilds}}
      <tr>
        <td>{{if .URL}}<a href="{{.URL}}">{{.Pipeline}}</a>{{else}}{{.Pipeline}}{{end}}</td>
        <td class="mono">{{.Package}}@{{if .Version}}{{.Version}}{{else}}*{{end}}</td>
        <td><span class="chip st-{{.Status}}">{{.Status}}</span></td>
        <td class="small">{{.Branch}}</td>
        <td>{{.Actor}}</td>
        <td class="small">{{fmtTime .StartedAt}}</td>
      </tr>
    {{else}}
      <tr><td colspan="6" class="muted">没有匹配的构建记录。可通过 <span class="mono">POST /api/builds</span> 上报。</td></tr>
    {{end}}
    </tbody>
  </table>
</div>

<div class="panel">
  <h2>受影响的下载（{{$d.Impact.DownloadCount}}）</h2>
  <table>
    <thead><tr><th>时间</th><th>包版本</th><th>下载用户</th><th>来源地址</th></tr></thead>
    <tbody>
    {{range $d.AffectedDownloads}}
      <tr><td class="small">{{fmtTime .At}}</td>
        <td class="mono">{{.Package}}@{{if .Version}}{{.Version}}{{else}}*{{end}}</td>
        <td>{{if .User}}{{.User}}{{else}}<span class="muted">匿名</span>{{end}}</td>
        <td class="mono small">{{.RemoteAddr}}</td></tr>
    {{else}}
      <tr><td colspan="4" class="muted">没有匹配的下载记录。通过下载接口产生的下载会自动记录。</td></tr>
    {{end}}
    </tbody>
  </table>
</div>

<div class="panel">
  <h2>引用方检查（{{$d.Impact.ReferrerCount}}）</h2>
  {{if $d.ReferencedBy}}
  <div class="alert err">以下活跃包正在依赖 <b class="mono">{{$d.PackageName}}</b>，因此它不能进入“冷静期完成/已删除”状态：</div>
  <table>
    <thead><tr><th>引用方包</th><th>版本</th><th>版本约束</th><th>来源</th></tr></thead>
    <tbody>
    {{range $d.ReferencedBy}}
      <tr><td><a href="/packages/{{.Package}}">{{.Package}}</a></td>
        <td class="mono">{{.Version}}</td><td class="mono">{{.Constraint}}</td><td class="small muted">{{.Source}}</td></tr>
    {{end}}
    </tbody>
  </table>
  {{else}}
  <div class="alert ok">没有发现活跃引用，冷静期届满后可由另一个管理员确认删除。</div>
  {{end}}
</div>

<div class="panel">
  <h2>审批轨迹</h2>
  <ul class="timeline">
    <li><b>申请删除</b> · {{$d.RequestedBy}} · {{fmtTime $d.CreatedAt}}<div class="muted small">{{$d.Target}} 进入冷静期，预计 {{fmtTime $d.ExpiresAt}} 到期</div></li>
    {{if $d.WithdrawnAt}}<li class="done"><b>已撤回</b> · {{$d.WithdrawnBy}} · {{fmtTime $d.WithdrawnAt}}<div class="muted small">包恢复可用</div></li>{{end}}
    {{if $d.CooldownCompletedAt}}<li class="done"><b>冷静期完成 / 引用检查通过</b> · {{fmtTime $d.CooldownCompletedAt}}</li>{{end}}
    {{if $d.ConfirmedAt}}<li class="done"><b>第二人确认</b> · {{$d.ConfirmedBy}} · {{fmtTime $d.ConfirmedAt}}</li>{{end}}
    {{if $d.DeletedAt}}<li class="bad"><b>执行删除</b> · {{fmtTime $d.DeletedAt}}</li>{{end}}
  </ul>
</div>
{{end}}`
