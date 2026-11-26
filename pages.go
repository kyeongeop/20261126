package main

const errorPage = `{{define "content"}}
<div class="panel">
  <h2>出错了</h2>
  <div class="alert err">{{.Error}}</div>
  <p><a class="btn secondary" href="/">返回总览</a></p>
</div>
{{end}}`

const dashboardPage = `{{define "content"}}
<div class="grid cards">
  <div class="card"><div class="k">软件包</div><div class="v">{{.PackageCount}}</div></div>
  <div class="card"><div class="k">进行中删除申请</div><div class="v" style="color:var(--warn)">{{.DeletionCount}}</div></div>
  <div class="card"><div class="k">构建记录 / 进行中</div><div class="v">{{.BuildCount}} <span class="small muted">/ {{.RunningBuilds}}</span></div></div>
  <div class="card"><div class="k">下载记录</div><div class="v">{{.DownloadCount}}</div></div>
</div>

<div class="panel">
  <h2>删除冷静期机制</h2>
  <p class="muted">维护者发起删除后，包进入 <span class="chip st-pending">待删除 · 冷静期中</span>，
  系统列出受影响的下载与构建；冷静期（当前配置 <b class="mono">{{.Cooldown}}</b>）内可随时撤回。
  到期并通过引用检查后进入 <span class="chip st-cooldown_completed">冷静期已满 · 待第二人确认</span>，
  必须由<b>另一个管理员账号</b>确认才会真正删除。仍被其他活跃包引用的包无法完成冷静期/删除。</p>
  <div class="pillrow">
    <a class="btn" href="/deletions">查看删除申请</a>
    <a class="btn secondary" href="/deletions?new=1">发起删除申请</a>
    <a class="btn secondary" href="/publish">发布 tar 包</a>
  </div>
  <h3>演示账号（可用 PKG_USERS 覆盖）</h3>
  <div class="cred">{{.DefaultCreds}}

# 例如第二人确认：
curl -u admin:admin-pass -X POST http://127.0.0.1:8080/api/deletion-requests/&lt;id&gt;/confirm
curl -u admin2:admin2-pass -X POST http://127.0.0.1:8080/api/deletion-requests/&lt;id&gt;/confirm</div>
</div>

<div class="panel">
  <h2>软件包</h2>
  <table>
    <thead><tr><th>包名</th><th>版本数</th><th>最新版本</th><th>依赖</th><th></th></tr></thead>
    <tbody>
    {{range .Packages}}
      {{$latest := ""}}{{$depCount := 0}}
      {{range $v := .Versions}}{{if gt $v.CreatedAt.Unix 0}}{{end}}{{end}}
      <tr>
        <td><a href="/packages/{{.Name}}"><b>{{.Name}}</b></a></td>
        <td>{{len .Versions}}</td>
        <td class="mono">
          {{- range $ver, $v := .Versions -}}
            {{if not $v.Deleted}}{{$ver}} {{end}}
          {{- end}}
        </td>
        <td class="muted small">
          {{- range $ver, $v := .Versions -}}
            {{len $v.Dependencies}} deps;
          {{- end}}
        </td>
        <td><a class="btn secondary" href="/packages/{{.Name}}">详情 / 删除</a></td>
      </tr>
    {{else}}
      <tr><td colspan="5" class="muted">暂无软件包，可运行 <span class="mono">bash demo.sh</span> 或在“发布包”页上传 tar。</td></tr>
    {{end}}
    </tbody>
  </table>
</div>

<div class="panel">
  <h2>最近的删除申请</h2>
  <table>
    <thead><tr><th>ID</th><th>目标</th><th>状态</th><th>申请人</th><th>到期时间</th></tr></thead>
    <tbody>
    {{range .Deletions}}
      <tr>
        <td><a href="/deletions/{{.ID}}">{{.ID}}</a></td>
        <td class="mono">{{.Target}}</td>
        <td><span class="chip st-{{.Status}}">{{.StatusLabel}}</span></td>
        <td>{{.RequestedBy}}</td>
        <td class="small">{{fmtTime .ExpiresAt}}{{if .Due}} <span class="chip st-cooldown_completed">已届满</span>{{else}} <span class="muted">剩 {{.SecondsRemaining}}s</span>{{end}}</td>
      </tr>
    {{else}}
      <tr><td colspan="5" class="muted">还没有删除申请。</td></tr>
    {{end}}
    </tbody>
  </table>
</div>

<div class="panel">
  <h2>最近构建</h2>
  <table>
    <thead><tr><th>流水线</th><th>引用包</th><th>状态</th><th>触发人</th></tr></thead>
    <tbody>
    {{range .RecentBuilds}}
      <tr><td>{{.Pipeline}}</td><td class="mono">{{.Package}}@{{.Version}}</td>
      <td><span class="chip st-{{.Status}}">{{.Status}}</span></td><td>{{.Actor}}</td></tr>
    {{else}}<tr><td colspan="4" class="muted">暂无构建。</td></tr>{{end}}
    </tbody>
  </table>
</div>
{{end}}`

const deletionsListPage = `{{define "content"}}
<div class="panel">
  <h2>发起删除申请</h2>
  <form method="post" action="/deletions">
    <div class="row">
      <label class="f"><span>包名 *</span><input name="name" list="pkg-names" placeholder="例如 core-utils" required>
        <datalist id="pkg-names">{{range .Packages}}<option value="{{.Name}}">{{end}}</datalist>
      </label>
      <label class="f"><span>版本（留空 = 删除整个包的所有版本）</span><input name="version" placeholder="例如 1.4.0"></label>
    </div>
    <label class="f"><span>删除原因</span><textarea name="reason" rows="2" placeholder="为什么要删除？"></textarea></label>
    <div class="row">
      <label class="f"><span>维护者账号</span><input name="username" placeholder="maintainer"></label>
      <label class="f"><span>密码</span><input name="password" type="password" placeholder="maintainer-pass"></label>
    </div>
    <p class="muted small">表单会通过 JSON API 提交；也可直接使用浏览器弹出的 Basic 登录。默认演示账号 maintainer/maintainer-pass 或 admin/admin-pass。</p>
    <button class="btn danger" type="submit">提交删除申请（进入冷静期）</button>
  </form>
</div>

<div class="panel">
  <h2>全部删除申请</h2>
  <table>
    <thead><tr><th>ID</th><th>目标</th><th>状态</th><th>影响（下载/构建/引用）</th><th>申请人 → 确认人</th><th>到期</th><th></th></tr></thead>
    <tbody>
    {{range .Deletions}}
      <tr>
        <td><a href="/deletions/{{.ID}}"><b>{{.ID}}</b></a></td>
        <td class="mono">{{.Target}}</td>
        <td><span class="chip st-{{.Status}}">{{.StatusLabel}}</span>
          {{if .Blocked}}<div class="alert err small" style="margin-top:6px">被引用阻止</div>{{end}}
        </td>
        <td class="small">{{.Impact.DownloadCount}} / {{.Impact.BuildCount}}（进行中 {{.Impact.ActiveBuildCount}}）/ {{.Impact.ReferrerCount}}</td>
        <td class="small">{{.RequestedBy}}{{if .ConfirmedBy}} → <b>{{.ConfirmedBy}}</b>{{end}}</td>
        <td class="small">{{fmtTime .ExpiresAt}}</td>
        <td><a class="btn secondary" href="/deletions/{{.ID}}">处理</a></td>
      </tr>
    {{else}}
      <tr><td colspan="7" class="muted">暂无删除申请。</td></tr>
    {{end}}
    </tbody>
  </table>
</div>
{{end}}`
