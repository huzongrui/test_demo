package mdns

import (
	"testing"
)

func TestBuildQueryPackets(t *testing.T) {
	msgs := BuildQueryPackets()
	if len(msgs) == 0 {
		t.Fatalf("expected query packets, got 0")
	}

	// 验证第一个是否是 _services._dns-sd._udp.local.
	firstQ := msgs[0].Question
	if len(firstQ) == 0 || firstQ[0].Name != "_services._dns-sd._udp.local." {
		t.Errorf("expected first query to be _services._dns-sd._udp.local., got %v", firstQ)
	}
}
