package utils

import (
	"net"
	"testing"
)

func TestParseIPs(t *testing.T) {
	// 1. CIDR 测试
	ips, ipNet, err := ParseIPs("192.168.1.0/30")
	if err != nil {
		t.Fatalf("ParseCIDR failed: %v", err)
	}
	if ipNet == nil || len(ips) != 4 {
		t.Fatalf("expected 4 IPs for /30, got %d", len(ips))
	}

	// 2. 范围测试
	ipsRange, _, err := ParseIPs("192.168.1.1-192.168.1.5")
	if err != nil {
		t.Fatalf("ParseRange failed: %v", err)
	}
	if len(ipsRange) != 5 {
		t.Fatalf("expected 5 IPs for range 1-5, got %d", len(ipsRange))
	}

	// 3. 单个 IP 测试
	ipsSingle, _, err := ParseIPs("10.0.0.1")
	if err != nil {
		t.Fatalf("ParseSingle failed: %v", err)
	}
	if len(ipsSingle) != 1 || !ipsSingle[0].Equal(net.ParseIP("10.0.0.1")) {
		t.Fatalf("unexpected single IP result")
	}
}

func TestParsePorts(t *testing.T) {
	ports, err := ParsePorts("80,445,5000-5003")
	if err != nil {
		t.Fatalf("ParsePorts failed: %v", err)
	}

	expected := []int{80, 445, 5000, 5001, 5002, 5003}
	for _, p := range expected {
		if !ports[p] {
			t.Errorf("expected port %d to be included", p)
		}
	}
	if ports[81] {
		t.Errorf("did not expect port 81")
	}
}
