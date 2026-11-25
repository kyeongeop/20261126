package main

import (
	"os"
	"testing"
	"time"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	dir := t.TempDir()
	s, err := OpenStore(dir)
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	return s
}

func date(s string) *time.Time {
	tm, err := time.Parse("2006-01-02", s)
	if err != nil {
		panic(err)
	}
	return &tm
}

func TestSeedLoads(t *testing.T) {
	s := newTestStore(t)
	shares := s.ListShares(Filter{})
	if len(shares) < 20 {
		t.Fatalf("种子分享数量异常: %d", len(shares))
	}
	if _, err := os.Stat(s.DBPath()); err != nil {
		t.Fatalf("db.json 未生成: %v", err)
	}
}

func TestFilterByOwner(t *testing.T) {
	s := newTestStore(t)
	got := s.ListShares(Filter{Owner: "张伟"})
	if len(got) == 0 {
		t.Fatal("按负责人筛选为空")
	}
	for _, sh := range got {
		if sh.OwnerName != "张伟" {
			t.Fatalf("筛选串入其他负责人: %s", sh.OwnerName)
		}
	}
	// 也允许按 owner_id 筛选，且大小写不敏感。
	got = s.ListShares(Filter{Owner: "U003"})
	for _, sh := range got {
		if sh.OwnerID != "u003" {
			t.Fatalf("按 owner_id 筛选失败，得到 %s", sh.OwnerID)
		}
	}
}

func TestFilterByDirectoryRecursive(t *testing.T) {
	s := newTestStore(t)
	all := s.ListShares(Filter{Directory: "/研发", Recursive: true})
	exact := s.ListShares(Filter{Directory: "/研发", Recursive: false})
	if len(all) <= len(exact) {
		t.Fatalf("递归筛选应包含子目录: recursive=%d exact=%d", len(all), len(exact))
	}
	for _, sh := range all {
		if sh.Directory != "/研发" &&
			!hasPrefix(sh.Directory, "/研发/") {
			t.Fatalf("目录越界: %s", sh.Directory)
		}
	}
	for _, sh := range exact {
		if sh.Directory != "/研发" {
			t.Fatalf("非递归模式串入子目录: %s", sh.Directory)
		}
	}
}

func hasPrefix(s, p string) bool {
	return len(s) >= len(p) && s[:len(p)] == p
}

func TestFilterByCreatedRangeAndStatus(t *testing.T) {
	s := newTestStore(t)
	got := s.ListShares(Filter{
		CreatedFrom: date("2026-11-01"),
		CreatedTo:   addDay(date("2026-12-01")),
	})
	if len(got) == 0 {
		t.Fatal("11 月创建的分享不应为空")
	}
	for _, sh := range got {
		if sh.CreatedAt.Before(*date("2026-11-01")) ||
			!sh.CreatedAt.Before(*addDay(date("2026-12-01"))) {
			t.Fatalf("时间越界: %s", sh.CreatedAt)
		}
	}

	active := s.ListShares(Filter{Status: "active"})
	for _, sh := range active {
		if sh.Status != StatusActive {
			t.Fatalf("状态筛选失效: %s", sh.Status)
		}
	}
}

func addDay(tm *time.Time) *time.Time {
	t := tm.AddDate(0, 0, 1)
	return &t
}

func TestPreviewCountsDistinctFiles(t *testing.T) {
	s := newTestStore(t)
	p := s.Preview(Filter{Owner: "李娜", Status: "active"})
	if p.RevocableLinks == 0 {
		t.Fatal("李娜应有有效链接")
	}
	if p.AffectedFiles == 0 || p.AffectedFiles > p.RevocableLinks {
		t.Fatalf("受影响文件数应在 1..链接数 之间: files=%d links=%d",
			p.AffectedFiles, p.RevocableLinks)
	}
	idSet := map[string]struct{}{}
	for _, fi := range p.Files {
		idSet[fi.FileID] = struct{}{}
	}
	if len(idSet) != p.AffectedFiles {
		t.Fatalf("文件聚合数量不一致: set=%d count=%d", len(idSet), p.AffectedFiles)
	}
	if p.MatchedFiles < p.AffectedFiles {
		t.Fatalf("命中文件总数不应小于受影响文件数: matched=%d affected=%d",
			p.MatchedFiles, p.AffectedFiles)
	}
	// 李娜的市场方案文件有多条 active 链接，应出现链接数 > 文件数的情况。
	all := s.Preview(Filter{Directory: "/市场活动", Recursive: true, Status: "active"})
	if all.RevocableLinks <= all.AffectedFiles {
		t.Fatalf("测试数据应存在同一文件多条链接: links=%d files=%d",
			all.RevocableLinks, all.AffectedFiles)
	}
}
