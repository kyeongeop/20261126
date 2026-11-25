package httpapi

import (
	"html/template"
	"net/http"
	"sort"
	"strings"

	"fileshare/internal/timeline"
)

var actionLabels = map[timeline.Action]string{
	timeline.ActionCreate:   "创建",
	timeline.ActionGrant:    "授权",
	timeline.ActionPreview:  "预览",
	timeline.ActionDownload: "下载",
	timeline.ActionRevoke:   "撤销",
	timeline.ActionMove:     "移动",
	timeline.ActionUpdate:   "更新",
}

type rowView struct {
	Event       timeline.Event
	ActionLabel string
	Details     [][2]string
	Anchor      string
}

type pageView struct {
	File          timeline.FileInfo
	Rows          []rowView
	Total         int
	Filtered      int
	FilterUser    string
	FilterAction  string
	FilterVersion string
	FilterFrom    string
	FilterTo      string
	FilterError   string
	JumpVersion   string
	JumpKey       string
	Actions       []timeline.Action
	ActionLabels  map[timeline.Action]string
}

var detailOrder = []string{
	"file_name", "path", "from_path", "to_path",
	"grantee", "grantee_id", "revokee", "revokee_id",
	"user", "user_id", "role", "permission",
	"client", "ip", "user_agent", "note",
}

func detailPairs(details map[string]string) [][2]string {
	pairs := make([][2]string, 0, len(details))
	seen := map[string]bool{}
	for _, key := range detailOrder {
		if value, ok := details[key]; ok {
			pairs = append(pairs, [2]string{key, value})
			seen[key] = true
		}
	}
	rest := make([]string, 0, len(details))
	for key := range details {
		if !seen[key] {
			rest = append(rest, key)
		}
	}
	sort.Strings(rest)
	for _, key := range rest {
		pairs = append(pairs, [2]string{key, details[key]})
	}
	return pairs
}

var detailTmpl = template.Must(template.New("detail").Parse(detailHTML))

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	files := s.store.ListFiles()
	var b strings.Builder
	b.WriteString("<!doctype html><html lang=\"zh-CN\"><head><meta charset=\"utf-8\">")
	b.WriteString("<title>团队文件共享</title></head><body>")
	b.WriteString("<h1>团队文件</h1><ul>")
	if len(files) == 0 {
		b.WriteString("<li>暂无文件，请通过 API 上报事件。</li>")
	}
	for _, f := range files {
		b.WriteString("<li><a href=\"/files/")
		b.WriteString(template.HTMLEscapeString(f.FileID))
		b.WriteString("\">")
		b.WriteString(template.HTMLEscapeString(displayName(f)))
		b.WriteString("</a></li>")
	}
	b.WriteString("</ul></body></html>")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(b.String()))
}

func displayName(f timeline.FileInfo) string {
	if f.Name != "" {
		return f.Name
	}
	return f.FileID
}

func (s *Server) handleDetailPage(w http.ResponseWriter, r *http.Request) {
	fileID := r.PathValue("fileID")
	info, err := s.store.GetFile(fileID)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	filter, _, filterErr := parseFilter(r, fileID)
	view := pageView{
		File:          info,
		Actions:       timeline.Actions,
		ActionLabels:  actionLabels,
		FilterUser:    filter.User,
		FilterAction:  string(filter.Action),
		FilterVersion: filter.VersionID,
		JumpVersion:   r.URL.Query().Get("version"),
		JumpKey:       r.URL.Query().Get("event"),
	}
	if filterErr != nil {
		view.FilterError = filterErr.Error()
	}
	if !filter.From.IsZero() {
		view.FilterFrom = filter.From.Format("2006-01-02T15:04")
	}
	if !filter.To.IsZero() {
		view.FilterTo = filter.To.Format("2006-01-02T15:04")
	}

	if filterErr == nil {
		page, listErr := s.store.List(filter, 0)
		if listErr != nil {
			view.FilterError = listErr.Error()
		} else {
			view.Total = page.Total
			view.Filtered = page.Filtered
			for _, ev := range page.Events {
				view.Rows = append(view.Rows, rowView{
					Event:       ev,
					ActionLabel: actionLabels[ev.Action],
					Details:     detailPairs(ev.Details),
					Anchor:      ev.DedupKey,
				})
			}
		}
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := detailTmpl.Execute(w, view); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}
