package formatter

import (
	"fmt"
	"strings"

	"mdns-survey/pkg/parser"
)

// FormatResult 将 SurveyResult 格式化为 README 规范要求的 YAML/Text 文本
func FormatResult(res *parser.SurveyResult) string {
	if res == nil {
		return ""
	}

	var sb strings.Builder
	sb.WriteString("services:\n")

	for _, svc := range res.Services {
		sb.WriteString(fmt.Sprintf("  %s:\n", svc.ServiceKey))
		if svc.Name != "" {
			sb.WriteString(fmt.Sprintf("    Name=%s\n", svc.Name))
		}
		if svc.IPv4 != "" {
			sb.WriteString(fmt.Sprintf("    IPv4=%s\n", svc.IPv4))
		} else {
			sb.WriteString("    IPv4=x.x.x.x\n")
		}
		if svc.IPv6 != "" {
			sb.WriteString(fmt.Sprintf("    IPv6=%s\n", svc.IPv6))
		}
		if svc.Hostname != "" {
			sb.WriteString(fmt.Sprintf("    Hostname=%s\n", svc.Hostname))
		}
		if svc.TTL > 0 {
			sb.WriteString(fmt.Sprintf("    TTL=%d\n", svc.TTL))
		}

		for _, attr := range svc.Attributes {
			if attr != "" {
				sb.WriteString(fmt.Sprintf("    %s\n", attr))
			}
		}
	}

	sb.WriteString("answers:\n")
	sb.WriteString("  PTR:\n")
	for _, ptr := range res.PTRs {
		sb.WriteString(fmt.Sprintf("    %s\n", ptr))
	}

	return sb.String()
}
