package main

import (
	"fmt"
	"net/http"
	"strings"
	"time"
)

// filterDTO 是筛选条件的线上表示：时间支持 RFC3339 或 YYYY-MM-DD，
// 指针类型的 recursive 用于区分“未传”和显式 false（默认递归子目录）。
type filterDTO struct {
	Owner                 string `json:"owner"`
	OwnerName             string `json:"owner_name"`
	Directory             string `json:"directory"`
	Dir                   string `json:"dir"`
	Path                  string `json:"path"`
	Recursive             *bool  `json:"recursive"`
	IncludeSubdirectories *bool  `json:"include_subdirectories"`
	CreatedFrom           string `json:"created_from"`
	CreatedTo             string `json:"created_to"`
	From                  string `json:"from"`
	To                    string `json:"to"`
	StartDate             string `json:"start_date"`
	EndDate               string `json:"end_date"`
	Status                string `json:"status"`
	LinkStatus            string `json:"link_status"`
}

func queryBool(r *http.Request, keys ...string) *bool {
	q := r.URL.Query()
	for _, k := range keys {
		if v := q.Get(k); v != "" {
			b := v == "1" || strings.EqualFold(v, "true") || v == "是"
			return &b
		}
	}
	return nil
}

func firstQuery(r *http.Request, keys ...string) string {
	q := r.URL.Query()
	for _, k := range keys {
		if v := strings.TrimSpace(q.Get(k)); v != "" {
			return v
		}
	}
	return ""
}

func filterFromQuery(r *http.Request) (Filter, error) {
	dto := filterDTO{
		Owner:                 firstQuery(r, "owner", "owner_name", "ownerName"),
		Directory:             firstQuery(r, "directory", "dir", "path"),
		CreatedFrom:           firstQuery(r, "created_from", "from", "start_date", "start"),
		CreatedTo:             firstQuery(r, "created_to", "to", "end_date", "end"),
		Status:                firstQuery(r, "status", "link_status", "linkStatus"),
		Recursive:             queryBool(r, "recursive"),
		IncludeSubdirectories: queryBool(r, "include_subdirectories"),
	}
	return dto.toFilter()
}

// parseTimeBoundary 解析时间边界。dateOnlyEnd=true 时把 YYYY-MM-DD
// 解释为当天结束（实现为次日零点的排他上界）。
func parseTimeBoundary(raw string, endBoundary bool) (*time.Time, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	if t, err := time.Parse(time.RFC3339, raw); err == nil {
		return &t, nil
	}
	if t, err := time.Parse("2006-01-02 15:04:05", raw); err == nil {
		return &t, nil
	}
	if t, err := time.Parse("2006-01-02", raw); err == nil {
		if endBoundary {
			t = t.AddDate(0, 0, 1)
		}
		return &t, nil
	}
	return nil, fmt.Errorf("无法解析时间 %q，请使用 YYYY-MM-DD 或 RFC3339 格式", raw)
}

func (d filterDTO) toFilter() (Filter, error) {
	owner := firstNonEmpty(d.Owner, d.OwnerName)
	directory := firstNonEmpty(d.Directory, d.Dir, d.Path)
	fromRaw := firstNonEmpty(d.CreatedFrom, d.From, d.StartDate)
	toRaw := firstNonEmpty(d.CreatedTo, d.To, d.EndDate)
	status := strings.TrimSpace(firstNonEmpty(d.Status, d.LinkStatus))

	if status != "" && !strings.EqualFold(status, "all") {
		normalized := ShareStatus(strings.ToLower(status))
		if !normalized.Valid() {
			return Filter{}, fmt.Errorf("无效的链接状态 %q，可选 active/revoked/expired/all", status)
		}
		status = string(normalized)
	}

	from, err := parseTimeBoundary(fromRaw, false)
	if err != nil {
		return Filter{}, err
	}
	to, err := parseTimeBoundary(toRaw, true)
	if err != nil {
		return Filter{}, err
	}
	if from != nil && to != nil && from.After(*to) {
		return Filter{}, fmt.Errorf("创建时间区间不合法：开始时间晚于结束时间")
	}

	recursive := true
	if d.Recursive != nil {
		recursive = *d.Recursive
	} else if d.IncludeSubdirectories != nil {
		recursive = *d.IncludeSubdirectories
	}

	return Filter{
		Owner:       owner,
		Directory:   directory,
		Recursive:   recursive,
		CreatedFrom: from,
		CreatedTo:   to,
		Status:      status,
	}, nil
}
