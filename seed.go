package main

import (
	"fmt"
	"time"
)

type seedFile struct {
	id, name, dir, ownerID, owner string
}

type seedLink struct {
	file      int
	day       time.Time
	status    ShareStatus
	token     string
	expireDay *time.Time
}

// seedDB 构造一份覆盖多负责人、多层目录、多个创建月份与三种状态的演示数据。
func seedDB() dbData {
	files := []seedFile{
		{"F-1001", "2026产品路线图.pptx", "/产品文档", "u001", "张伟"},
		{"F-1002", "批量撤销需求说明书.docx", "/产品文档/PRD", "u001", "张伟"},
		{"F-1003", "Q4产品规划.pdf", "/产品文档", "u002", "李娜"},
		{"F-1004", "管理后台改版.fig", "/设计稿", "u004", "陈静"},
		{"F-1005", "图标库-v3.sketch", "/设计稿", "u004", "陈静"},
		{"F-1006", "分享服务架构图.png", "/研发", "u003", "王强"},
		{"F-1007", "openapi.yaml", "/研发/API", "u003", "王强"},
		{"F-1008", "权限模型设计.md", "/研发/API", "u001", "张伟"},
		{"F-1009", "admin-console.tsx", "/研发/前端", "u002", "李娜"},
		{"F-1010", "批量事务与回滚设计.md", "/研发", "u003", "王强"},
		{"F-1011", "双11投放方案.xlsx", "/市场活动", "u002", "李娜"},
		{"F-1012", "活动海报-final.psd", "/市场活动", "u004", "陈静"},
		{"F-1013", "员工手册2026版.pdf", "/人事制度", "u005", "赵敏"},
		{"F-1014", "研发值班表.xlsx", "/研发", "u003", "王强"},
	}

	day := func(month time.Month, d int) time.Time {
		return time.Date(2026, month, d, 2, 0, 0, 0, time.UTC)
	}
	expire := func(month time.Month, d int) *time.Time {
		t := time.Date(2026, month, d, 16, 0, 0, 0, time.UTC)
		return &t
	}

	links := []seedLink{
		{0, day(time.January, 8), StatusActive, "tk-road-01", expire(time.December, 31)},
		{0, day(time.March, 2), StatusActive, "tk-road-02", nil},
		{1, day(time.January, 20), StatusActive, "tk-prd-batch", expire(time.November, 30)},
		{1, day(time.February, 11), StatusActive, "tk-prd-review", expire(time.May, 1)},
		{2, day(time.April, 15), StatusActive, "tk-q4-plan", expire(time.December, 20)},
		{2, day(time.May, 6), StatusRevoked, "tk-q4-old", nil},
		{3, day(time.June, 1), StatusActive, "tk-admin-fig", nil},
		{3, day(time.July, 9), StatusActive, "tk-admin-handoff", expire(time.October, 1)},
		{4, day(time.February, 22), StatusExpired, "tk-icons-v2", expire(time.August, 31)},
		{4, day(time.September, 3), StatusActive, "tk-icons-v3", nil},
		{5, day(time.March, 18), StatusActive, "tk-arch-png", nil},
		{5, day(time.August, 14), StatusActive, "tk-arch-review", expire(time.December, 15)},
		{6, day(time.May, 27), StatusActive, "tk-openapi", nil},
		{6, day(time.October, 8), StatusActive, "tk-openapi-partner", expire(time.November, 20)},
		{7, day(time.June, 25), StatusActive, "tk-auth-model", nil},
		{8, day(time.July, 30), StatusExpired, "tk-console-old", expire(time.September, 1)},
		{8, day(time.October, 21), StatusActive, "tk-console-new", nil},
		{9, day(time.August, 5), StatusActive, "tk-tx-design", nil},
		{10, day(time.September, 12), StatusActive, "tk-1111-plan", expire(time.November, 11)},
		{10, day(time.October, 1), StatusActive, "tk-1111-agency", expire(time.November, 10)},
		{10, day(time.October, 18), StatusActive, "tk-1111-budget", expire(time.December, 1)},
		{11, day(time.October, 25), StatusActive, "tk-poster-final", nil},
		{11, day(time.November, 2), StatusRevoked, "tk-poster-wip", nil},
		{12, day(time.January, 30), StatusActive, "tk-handbook", nil},
		{13, day(time.November, 15), StatusActive, "tk-oncall-q4", expire(time.December, 31)},
		{1, day(time.November, 18), StatusActive, "tk-prd-emergency", expire(time.November, 25)},
		{6, day(time.November, 20), StatusActive, "tk-openapi-v2", nil},
		{3, day(time.November, 22), StatusActive, "tk-admin-hotfix", nil},
	}

	shares := make([]Share, 0, len(links))
	for i, lk := range links {
		f := files[lk.file]
		sh := Share{
			ID:        fmt.Sprintf("SH-%04d", i+1),
			FileID:    f.id,
			FileName:  f.name,
			Directory: f.dir,
			OwnerID:   f.ownerID,
			OwnerName: f.owner,
			LinkToken: lk.token,
			Status:    lk.status,
			CreatedAt: lk.day,
			ExpiresAt: lk.expireDay,
		}
		if lk.status == StatusRevoked {
			revoked := lk.day.AddDate(0, 0, 3)
			sh.RevokedAt = &revoked
			sh.RevokeReason = "历史安全巡检：外链范围过大"
			sh.RevokeBatchID = "RV-SEED-HISTORY"
			sh.RevokeOperator = "security-bot"
		}
		shares = append(shares, sh)
	}

	return dbData{Version: 1, Shares: shares, Audits: []AuditEvent{}}
}
