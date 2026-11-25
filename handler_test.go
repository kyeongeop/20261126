package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func newTestServer(t *testing.T) (*Server, *httptest.Server) {
	t.Helper()
	s := NewServer(newTestStore(t))
	ts := httptest.NewServer(s.Routes())
	t.Cleanup(ts.Close)
	return s, ts
}

func postJSON(t *testing.T, url string, body any) (*http.Response, map[string]any) {
	t.Helper()
	raw, _ := json.Marshal(body)
	resp, err := http.Post(url, "application/json", bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp, out
}

func getJSON(t *testing.T, url string) (*http.Response, map[string]any) {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("解码响应失败 %s: %v", url, err)
	}
	return resp, out
}

func TestAPIHealthAndMeta(t *testing.T) {
	_, ts := newTestServer(t)
	resp, body := getJSON(t, ts.URL+"/api/health")
	if resp.StatusCode != 200 || body["status"] != "ok" {
		t.Fatalf("health 异常: %d %v", resp.StatusCode, body)
	}
	resp, meta := getJSON(t, ts.URL+"/api/meta")
	if resp.StatusCode != 200 {
		t.Fatalf("meta 状态码: %d", resp.StatusCode)
	}
	if owners, _ := meta["owners"].([]any); len(owners) == 0 {
		t.Fatal("meta 缺少负责人")
	}
}

func TestAPIPreviewGETQuery(t *testing.T) {
	_, ts := newTestServer(t)
	resp, body := getJSON(t, ts.URL+
		"/api/shares/revoke/preview?owner=%E7%8E%8B%E5%BC%BA&directory=/%E7%A0%94%E5%8F%91/API&status=active")
	if resp.StatusCode != 200 {
		t.Fatalf("preview 状态码: %d %v", resp.StatusCode, body)
	}
	if int(body["revocable_links"].(float64)) == 0 {
		t.Fatalf("预览应有可撤销链接: %v", body)
	}
	if int(body["affected_files"].(float64)) == 0 {
		t.Fatal("预览必须给出受影响文件数")
	}
}

func TestAPIRevokeRequiresReason(t *testing.T) {
	_, ts := newTestServer(t)
	resp, body := postJSON(t, ts.URL+"/api/shares/batch-revoke", map[string]any{
		"owner":  "李娜",
		"status": "active",
	})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("缺少原因应 400, got %d", resp.StatusCode)
	}
	errBody, _ := body["error"].(map[string]any)
	if errBody["code"] != "reason_required" {
		t.Fatalf("错误码应为 reason_required: %v", body)
	}
}

func TestAPIFullPreviewThenRevokeFlow(t *testing.T) {
	_, ts := newTestServer(t)
	criteria := map[string]any{
		"directory":    "/市场活动",
		"recursive":    true,
		"status":       "active",
		"created_from": "2026-09-01",
		"created_to":   "2026-12-31",
	}

	prevResp, preview := postJSON(t, ts.URL+"/api/admin/revocations/preview", criteria)
	if prevResp.StatusCode != 200 {
		t.Fatalf("预览失败: %d %v", prevResp.StatusCode, preview)
	}
	wantLinks := int(preview["revocable_links"].(float64))
	wantFiles := int(preview["affected_files"].(float64))
	if wantLinks == 0 || wantFiles == 0 {
		t.Fatalf("测试条件应命中数据: %v", preview)
	}

	// 嵌套 criteria 形式也应被接受。
	revResp, result := postJSON(t, ts.URL+"/api/admin/revocations", map[string]any{
		"criteria": criteria,
		"reason":   "安全事件 SEC-2026-1126：市场物料外链全面收敛",
		"operator": "security-admin",
	})
	if revResp.StatusCode != 200 {
		t.Fatalf("撤销失败: %d %v", revResp.StatusCode, result)
	}
	if int(result["revoked_links"].(float64)) != wantLinks {
		t.Fatalf("撤销数与预览不符: %v vs %d", result["revoked_links"], wantLinks)
	}
	if int(result["affected_files"].(float64)) != wantFiles {
		t.Fatalf("文件数与预览不符: %v vs %d", result["affected_files"], wantFiles)
	}
	batchID := result["batch_id"].(string)

	// 重复撤销同一条件应 409，而不是静默成功。
	againResp, again := postJSON(t, ts.URL+"/api/shares/batch-revoke", map[string]any{
		"directory": "/市场活动",
		"status":    "active",
		"reason":    "再次撤销",
	})
	_ = again
	if againResp.StatusCode != http.StatusConflict {
		t.Fatalf("无可撤销对象应 409, got %d", againResp.StatusCode)
	}

	// 审计列表与详情都能查到该批次。
	audResp, audits := getJSON(t, ts.URL+"/api/admin/audits")
	if audResp.StatusCode != 200 || int(audits["total"].(float64)) < 1 {
		t.Fatalf("审计列表异常: %d %v", audResp.StatusCode, audits)
	}
	oneResp, one := getJSON(t, ts.URL+"/api/audits/"+batchID)
	if oneResp.StatusCode != 200 {
		t.Fatalf("审计详情异常: %d %v", oneResp.StatusCode, one)
	}
	if one["reason"] == "" || one["batch_id"] != batchID {
		t.Fatalf("审计详情内容异常: %v", one)
	}
	targets, _ := one["targets"].([]any)
	if len(targets) != wantLinks {
		t.Fatalf("审计目标数错误: %d", len(targets))
	}
}

func TestAPIInvalidStatusAndDate(t *testing.T) {
	_, ts := newTestServer(t)
	resp, body := getJSON(t, ts.URL+"/api/shares?status=bogus")
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("非法状态应 400, got %d", resp.StatusCode)
	}
	_ = body
	resp2, body2 := getJSON(t, ts.URL+"/api/shares/revoke/preview?created_from=not-a-date")
	if resp2.StatusCode != http.StatusBadRequest {
		t.Fatalf("非法日期应 400, got %d %v", resp2.StatusCode, body2)
	}
}

func TestAPIIndexServed(t *testing.T) {
	_, ts := newTestServer(t)
	resp, err := http.Get(ts.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("首页状态码: %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct == "" || ct[:9] != "text/html" {
		t.Fatalf("首页 Content-Type 异常: %q", ct)
	}
}
