package main

import (
	"fmt"
	"io"
	"strings"
)

// WriteTextReport renders a scan report suitable for pre-install console
// output. It explicitly prints each risky source ("被替换来源") and the
// proposed candidate ("候选来源").
func WriteTextReport(w io.Writer, r *Report) error {
	fmt.Fprintf(w, "depguard 配置检查报告  project=%s\n", orDash(r.Project))
	fmt.Fprintf(w, "扫描依赖包: %d  问题: %d (error=%d warning=%d)  结论: %s\n",
		r.Summary.ScannedPackages, r.Summary.Total, r.Summary.Errors, r.Summary.Warnings, verdict(r.OK))

	if len(r.Summary.ByRule) > 0 {
		parts := []string{}
		for _, info := range Rules {
			if n := r.Summary.ByRule[info.ID]; n > 0 {
				parts = append(parts, fmt.Sprintf("%s %s/%s=%d", info.ID, info.TitleZH, info.Slug, n))
			}
		}
		fmt.Fprintln(w, "规则命中: "+strings.Join(parts, "  "))
	}

	if len(r.Findings) > 0 {
		fmt.Fprintln(w, "\n== 发现 ==")
		for _, f := range r.Findings {
			loc := f.Package
			if f.Version != "" {
				loc += "@" + f.Version
			}
			if loc == "" {
				loc = "(configuration)"
			}
			fmt.Fprintf(w, "\n[%s] (%s) %s %s — %s\n", f.RuleID, f.Severity, f.TitleZH, loc, f.Message)
			if len(f.Evidence) > 0 {
				for k, v := range f.Evidence {
					fmt.Fprintf(w, "    evidence  %s = %s\n", k, v)
				}
			}
			if f.ReplacedSource != "" {
				fmt.Fprintf(w, "    被替换来源 (replaced) : %s\n", f.ReplacedSource)
			}
			if f.Candidate != nil {
				fmt.Fprintf(w, "    候选来源   (candidate): %s\n", FormatCandidate(f.Candidate))
			}
			if f.Recommendation != "" {
				fmt.Fprintf(w, "    建议: %s\n", f.Recommendation)
			}
		}
	}

	if len(r.Replacements) > 0 {
		fmt.Fprintln(w, "\n== 安装前来源替换计划 (replacement plan) ==")
		for _, rp := range r.Replacements {
			loc := rp.Package
			if rp.Version != "" {
				loc += "@" + rp.Version
			}
			fmt.Fprintf(w, "- %s  [%s]\n", loc, strings.Join(rp.FindingIDs, ","))
			fmt.Fprintf(w, "    替换前/被替换: %s\n", rp.ReplacedSource)
			fmt.Fprintf(w, "    替换为/候选  : %s\n", FormatCandidate(&rp.Candidate))
		}
	}

	if r.OK {
		fmt.Fprintln(w, "\nPASS: 没有 error 级依赖混淆风险，允许进入安装步骤。")
	} else {
		fmt.Fprintln(w, "\nBLOCK: 存在 error 级风险，安装前必须处理上述来源。")
	}
	return nil
}

// FormatCandidate renders a candidate source with digest/verification state.
func FormatCandidate(c *SourceCandidate) string {
	if c == nil {
		return ""
	}
	var b strings.Builder
	b.WriteString(c.SourceURL)
	tags := []string{}
	if c.RegistryID != "" {
		tags = append(tags, "registry="+c.RegistryID)
	}
	if c.SHA256 != "" {
		tags = append(tags, c.SHA256)
	}
	switch {
	case c.Verified:
		tags = append(tags, "verified-internal")
	case c.Available:
		tags = append(tags, "available-unverified")
	default:
		tags = append(tags, "not-published-internal")
	}
	if len(tags) > 0 {
		b.WriteString("  (")
		b.WriteString(strings.Join(tags, ", "))
		b.WriteString(")")
	}
	if c.Note != "" {
		b.WriteString("  note=" + c.Note)
	}
	return b.String()
}

func verdict(ok bool) string {
	if ok {
		return "PASS"
	}
	return "FAIL"
}

func orDash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "-"
	}
	return s
}
