package formatter

import (
	"strings"
	"testing"

	"mdns-survey/pkg/parser"
)

func TestFormatResult(t *testing.T) {
	res := &parser.SurveyResult{
		Services: []parser.ServiceAsset{
			{
				ServiceKey:  "5000/tcp http",
				Name:        "slw-nas",
				IPv4:        "192.168.1.100",
				IPv6:        "fe80::265e:beff:fe69:a313",
				Hostname:    "slw-nas.local",
				TTL:         10,
				Attributes:  []string{"path=/"},
			},
		},
		PTRs: []string{
			"_http._tcp.local",
		},
	}

	out := FormatResult(res)

	expectedSnippets := []string{
		"services:",
		"  5000/tcp http:",
		"    Name=slw-nas",
		"    IPv4=192.168.1.100",
		"    IPv6=fe80::265e:beff:fe69:a313",
		"    Hostname=slw-nas.local",
		"    TTL=10",
		"    path=/",
		"answers:",
		"  PTR:",
		"    _http._tcp.local",
	}

	for _, snippet := range expectedSnippets {
		if !strings.Contains(out, snippet) {
			t.Errorf("expected output to contain %q, output:\n%s", snippet, out)
		}
	}
}
