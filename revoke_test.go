package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBatchRevokeSuccessAndAuditPersisted(t *testing.T) {
	dir := t.TempDir()
	s, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	f := Filter{Owner: "王强", Directory: "/研发/API", Recursive: true, Status: "active"}
	p := s.Preview(f)
	if p.RevocableLinks == 0 {
		t.Fatal("前置数据：王强在 /研发/API 应有有效链接")
	}

	beforeActive := p.RevocableLinks
	beforeFiles := p.AffectedFiles

	res, err := s.BatchRevoke(RevokeInput{
		Filter:   f,
		Reason:   "安全事件：外链密钥疑似泄露",
		Operator: "admin-test",
	})
	if err != nil {
		t.Fatalf("BatchRevoke: %v", err)
	}
	if res.RevokedLinks != beforeActive {
		t.Fatalf("撤销链接数与预览不一致: got %d want %d", res.RevokedLinks, beforeActive)
	}
	if res.AffectedFiles != beforeFiles {
		t.Fatalf("受影响文件数与预览不一致: got %d want %d", res.AffectedFiles, beforeFiles)
	}
	if res.BatchID == "" || res.Audit.BatchID != res.BatchID {
		t.Fatal("审计批次号缺失或不一致")
	}
	if len(res.Audit.Targets) != beforeActive {
		t.Fatalf("审计目标快照数量错误: %d", len(res.Audit.Targets))
	}

	// 链接仍保留，但状态已推进为 revoked，并写入原因/批次。
	after := s.ListShares(f)
	if len(after) != 0 {
		t.Fatalf("按 active 筛选应已清空，仍有 %d 条", len(after))
	}
	revoked := s.ListShares(Filter{Owner: "王强", Directory: "/研发/API", Recursive: true, Status: "revoked"})
	if len(revoked) < beforeActive {
		t.Fatalf("撤销后的记录必须保留: got %d", len(revoked))
	}
	for _, sh := range revoked {
		if sh.RevokeReason == "" || sh.RevokeBatchID != res.BatchID || sh.RevokedAt == nil {
			t.Fatalf("撤销元数据不完整: %+v", sh)
		}
	}

	audits := s.ListAudits()
	if len(audits) != 1 || audits[0].BatchID != res.BatchID {
		t.Fatalf("审计记录异常: %+v", audits)
	}
	got, err := s.GetAudit(res.BatchID)
	if err != nil || got.Reason != "安全事件：外链密钥疑似泄露" {
		t.Fatalf("按批次查询审计失败: %v %+v", err, got)
	}

	// 重新打开数据文件，验证审计与撤销状态已持久化（撤销完成后审计仍在）。
	s2, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s2.GetAudit(res.BatchID); err != nil {
		t.Fatalf("重启后审计记录丢失: %v", err)
	}
	if p2 := s2.Preview(f); p2.RevocableLinks != 0 {
		t.Fatalf("重启后撤销状态丢失，仍有 %d 条有效", p2.RevocableLinks)
	}
}

func TestBatchRevokeNothing(t *testing.T) {
	s := newTestStore(t)
	_, err := s.BatchRevoke(RevokeInput{
		Filter: Filter{Owner: "不存在的人", Status: "active"},
		Reason: "测试原因",
	})
	if !errors.Is(err, ErrNothingToRevoke) {
		t.Fatalf("期望 ErrNothingToRevoke, got %v", err)
	}
	if len(s.ListAudits()) != 0 {
		t.Fatal("无可撤销对象时不应产生已提交审计")
	}
}

func TestBatchRevokeRollbackWhenCommitFails(t *testing.T) {
	s := newTestStore(t)
	f := Filter{Owner: "李娜", Status: "active"}
	before := s.Preview(f)
	if before.RevocableLinks == 0 {
		t.Fatal("前置数据缺失")
	}

	rawBefore, err := os.ReadFile(s.DBPath())
	if err != nil {
		t.Fatal(err)
	}

	// 注入落盘失败：模拟磁盘/权限错误。
	s.writeFileAtomic = func(path string, data []byte) error {
		return errors.New("simulated disk failure")
	}

	_, err = s.BatchRevoke(RevokeInput{Filter: f, Reason: "安全事件回滚演练"})
	if err == nil {
		t.Fatal("落盘失败时 BatchRevoke 应返回错误")
	}

	// 内存状态整体回滚：链接仍是 active，审计没有新增。
	after := s.Preview(f)
	if after.RevocableLinks != before.RevocableLinks {
		t.Fatalf("内存未回滚: before=%d after=%d", before.RevocableLinks, after.RevocableLinks)
	}
	if len(s.ListAudits()) != 0 {
		t.Fatal("回滚后不应存在审计记录")
	}

	// 磁盘文件保持提交前版本，没有半批数据。
	rawAfter, err := os.ReadFile(s.DBPath())
	if err != nil {
		t.Fatal(err)
	}
	if string(rawAfter) != string(rawBefore) {
		t.Fatal("落盘失败后数据文件被改动，原子性被破坏")
	}

	// 恢复写入能力后，同一操作可以成功（服务仍可继续工作）。
	s.writeFileAtomic = atomicWriteJSON
	res, err := s.BatchRevoke(RevokeInput{Filter: f, Reason: "恢复后重试成功"})
	if err != nil {
		t.Fatalf("恢复后重试失败: %v", err)
	}
	if res.RevokedLinks != before.RevocableLinks {
		t.Fatalf("重试撤销数量错误: %d", res.RevokedLinks)
	}
}

func TestAtomicWriteLeavesNoTempFiles(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "db.json")
	if err := atomicWriteJSON(path, []byte(`{"ok":true}`)); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".db.json.tmp-") {
			t.Fatalf("原子写入后残留临时文件: %s", e.Name())
		}
	}
}
