package main

const buildsPage = `{{define "content"}}
<div class="panel">
  <h2>上报构建 / 流水线</h2>
  <form method="post" action="/api/builds?format=html" class="row">
    <label class="f"><span>流水线名称</span><input name="pipeline" placeholder="checkout-service #4822"></label>
    <label class="f"><span>引用的包名 *</span><input name="package" required placeholder="core-utils"></label>
    <label class="f"><span>版本</span><input name="version" placeholder="1.5.0"></label>
    <label class="f"><span>状态</span>
      <select name="status"><option>running</option><option>queued</option><option>succeeded</option><option>failed</option><option>canceled</option></select>
    </label>
    <label class="f"><span>分支</span><input name="branch" placeholder="main"></label>
    <label class="f"><span>触发人</span><input name="actor" placeholder="ci-bot"></label>
    <div style="grid-column:1/-1"><button class="btn" type="submit">上报构建</button></div>
  </form>
</div>
<div class="panel">
  <h2>构建记录{{if .Package}} · {{.Package}}{{end}}</h2>
  <p class="muted small">进行中/排队的构建会在删除申请中作为重点影响对象列出。</p>
  <table>
    <thead><tr><th>流水线</th><th>包</th><th>状态</th><th>分支</th><th>触发人</th><th>开始</th></tr></thead>
    <tbody>
    {{range .Builds}}
      <tr><td>{{.Pipeline}}</td>
        <td class="mono"><a href="/packages/{{.Package}}">{{.Package}}</a>@{{.Version}}</td>
        <td><span class="chip st-{{.Status}}">{{.Status}}</span></td>
        <td>{{.Branch}}</td><td>{{.Actor}}</td><td class="small">{{fmtTime .StartedAt}}</td></tr>
    {{else}}<tr><td colspan="6" class="muted">暂无构建记录。</td></tr>{{end}}
    </tbody>
  </table>
</div>
{{end}}`

const downloadsPage = `{{define "content"}}
<div class="panel">
  <h2>下载记录{{if .Package}} · {{.Package}}{{end}}</h2>
  <p class="muted small">通过 <span class="mono">/packages/{name}/{version}/download</span> 下载 tar 包会自动记录；也可通过 <span class="mono">POST /api/downloads</span> 补录。</p>
  <table>
    <thead><tr><th>时间</th><th>包版本</th><th>用户</th><th>来源地址</th><th>User-Agent</th></tr></thead>
    <tbody>
    {{range .Downloads}}
      <tr><td class="small">{{fmtTime .At}}</td>
        <td class="mono">{{.Package}}@{{if .Version}}{{.Version}}{{else}}*{{end}}</td>
        <td>{{.User}}</td><td class="mono small">{{.RemoteAddr}}</td>
        <td class="small muted">{{.UserAgent}}</td></tr>
    {{else}}<tr><td colspan="5" class="muted">暂无下载记录。</td></tr>{{end}}
    </tbody>
  </table>
</div>
{{end}}`

const publishPage = `{{define "content"}}
<div class="panel">
  <h2>发布 tar 软件包</h2>
  <p class="muted">上传 <code>archive/tar</code> 归档；服务用 <code>crypto/sha256</code> 计算摘要并按内容寻址存储。
  归档内的 <code>package.json</code> / <code>manifest.json</code> / <code>dependencies.txt</code> 依赖会被解析为引用关系。</p>
  <form method="post" action="/publish" enctype="multipart/form-data">
    <div class="row">
      <label class="f"><span>包名 *</span><input name="name" required placeholder="my-lib"></label>
      <label class="f"><span>版本 *</span><input name="version" required placeholder="1.0.0"></label>
    </div>
    <label class="f"><span>tar 文件 *（字段名 package/file/artifact 均可）</span><input type="file" name="package" accept=".tar,application/x-tar" required></label>
    <button class="btn" type="submit">发布</button>
  </form>
  <h3>或用 curl</h3>
  <div class="cred">curl -F name=my-lib -F version=1.0.0 -F package=@my-lib-1.0.0.tar http://127.0.0.1:8080/publish</div>
</div>
{{end}}`

const packagePage = `{{define "content"}}
{{$pkg := .Pkg}}
<p><a href="/">← 全部包</a></p>
<div class="panel">
  <div class="pillrow" style="justify-content:space-between">
    <h2 style="margin:0">📦 {{$pkg.Name}}</h2>
    <a class="btn danger" href="/deletions?new=1&name={{$pkg.Name}}">申请删除（冷静期）</a>
  </div>
  {{if .ActiveDeletion}}
  <div class="alert warn">该包存在进行中的删除申请
    <a href="/deletions/{{.ActiveDeletion.ID}}"><b>{{.ActiveDeletion.ID}}</b></a>
    ，状态 <span class="chip st-{{.ActiveDeletion.Status}}">{{.ActiveDeletion.StatusLabel}}</span>。</div>
  {{end}}
  {{if .ReferencedBy}}
  <div class="alert err">该包被 <b>{{len .ReferencedBy}}</b> 个活跃包版本引用，删除申请将无法完成冷静期：
    {{range .ReferencedBy}}<a href="/packages/{{.Package}}" style="margin-right:8px" class="mono">{{.Package}}@{{.Version}}</a>{{end}}
  </div>
  {{else}}
  <div class="alert ok">当前没有其他活跃包引用该包。</div>
  {{end}}

  <h3>版本</h3>
  <table>
    <thead><tr><th>版本</th><th>摘要</th><th>大小</th><th>tar 条目</th><th>依赖</th><th>发布时间</th><th></th></tr></thead>
    <tbody>
    {{range $ver, $v := $pkg.Versions}}
      <tr {{if $v.Deleted}}style="opacity:.55"{{end}}>
        <td class="mono"><a href="/packages/{{$pkg.Name}}/{{$ver}}">{{$ver}}</a>{{if $v.Deleted}} <span class="chip st-deleted">已删除</span>{{end}}</td>
        <td class="mono small">{{sliceDigest $v.Digest}}</td>
        <td>{{$v.Size}} B</td>
        <td>{{$v.Entries}}</td>
        <td class="small">{{range $v.Dependencies}}<span class="chip" style="margin:1px">{{.Package}}</span> {{end}}</td>
        <td class="small">{{fmtTime $v.CreatedAt}}</td>
        <td>{{if not $v.Deleted}}<a class="btn secondary" href="/packages/{{$pkg.Name}}/{{$ver}}/download">下载</a>{{end}}</td>
      </tr>
    {{end}}
    </tbody>
  </table>
</div>

<div class="panel">
  <h2>受影响的构建（{{len .Builds}}）</h2>
  <table><thead><tr><th>流水线</th><th>版本</th><th>状态</th><th>触发人</th></tr></thead><tbody>
  {{range .Builds}}
    <tr><td>{{.Pipeline}}</td><td class="mono">{{.Version}}</td>
      <td><span class="chip st-{{.Status}}">{{.Status}}</span></td><td>{{.Actor}}</td></tr>
  {{else}}<tr><td colspan="4" class="muted">暂无。</td></tr>{{end}}
  </tbody></table>
</div>

<div class="panel">
  <h2>最近下载（{{len .Downloads}}）</h2>
  <table><thead><tr><th>时间</th><th>版本</th><th>用户</th></tr></thead><tbody>
  {{range .Downloads}}
    <tr><td class="small">{{fmtTime .At}}</td><td class="mono">{{.Version}}</td><td>{{.User}}</td></tr>
  {{else}}<tr><td colspan="3" class="muted">暂无。</td></tr>{{end}}
  </tbody></table>
</div>
{{end}}`

const versionPage = `{{define "content"}}
{{$v := .V}}
<p><a href="/packages/{{$v.Name}}">← {{$v.Name}}</a></p>
<div class="panel">
  <h2>{{$v.Name}}@{{$v.Version}}</h2>
  <dl class="kv">
    <dt>sha256 摘要</dt><dd class="mono">{{$v.Digest}}</dd>
    <dt>大小</dt><dd>{{$v.Size}} 字节 · tar 条目 {{$v.Entries}}</dd>
    <dt>发布者</dt><dd>{{$v.UploadedBy}} · {{fmtTime $v.CreatedAt}}</dd>
    <dt>依赖</dt><dd>{{range $v.Dependencies}}<span class="chip">{{.Package}} {{.Constraint}}</span> {{else}}<span class="muted">无</span>{{end}}</dd>
  </dl>
  <p class="pillrow">
    <a class="btn" href="/packages/{{$v.Name}}/{{$v.Version}}/download">下载 tar</a>
    <a class="btn secondary" href="/api/packages/{{$v.Name}}/versions/{{$v.Version}}">JSON 元数据</a>
    <a class="btn secondary" href="/packages/{{$v.Name}}/{{$v.Version}}/manifest.json">manifest.json</a>
  </p>
</div>
{{end}}`
