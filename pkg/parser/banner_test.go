package parser

import (
	"net"
	"testing"

	"github.com/miekg/dns"
	"mdns-survey/pkg/mdns"
)

func TestParseResponses(t *testing.T) {
	// 构建与 README 示例类似的测试 DNS 报文
	msg := new(dns.Msg)
	msg.SetQuestion("_services._dns-sd._udp.local.", dns.TypePTR)

	// PTR 记录
	ptrHttp := &dns.PTR{
		Hdr: dns.RR_Header{Name: "_http._tcp.local.", Rrtype: dns.TypePTR, Class: dns.ClassINET, Ttl: 10},
		Ptr: "slw-nas._http._tcp.local.",
	}
	ptrQdiscover := &dns.PTR{
		Hdr: dns.RR_Header{Name: "_qdiscover._tcp.local.", Rrtype: dns.TypePTR, Class: dns.ClassINET, Ttl: 10},
		Ptr: "slw-nas._qdiscover._tcp.local.",
	}
	ptrDeviceInfo := &dns.PTR{
		Hdr: dns.RR_Header{Name: "_device-info._tcp.local.", Rrtype: dns.TypePTR, Class: dns.ClassINET, Ttl: 10},
		Ptr: "slw-nas(AFP)._device-info._tcp.local.",
	}

	// SRV 记录
	srvHttp := &dns.SRV{
		Hdr:    dns.RR_Header{Name: "slw-nas._http._tcp.local.", Rrtype: dns.TypeSRV, Class: dns.ClassINET, Ttl: 10},
		Port:   5000,
		Target: "slw-nas.local.",
	}
	srvQdiscover := &dns.SRV{
		Hdr:    dns.RR_Header{Name: "slw-nas._qdiscover._tcp.local.", Rrtype: dns.TypeSRV, Class: dns.ClassINET, Ttl: 10},
		Port:   5000,
		Target: "slw-nas.local.",
	}

	// TXT 记录
	txtHttp := &dns.TXT{
		Hdr: dns.RR_Header{Name: "slw-nas._http._tcp.local.", Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 10},
		Txt: []string{"path=/"},
	}
	txtQdiscover := &dns.TXT{
		Hdr: dns.RR_Header{Name: "slw-nas._qdiscover._tcp.local.", Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 10},
		Txt: []string{"accessType=https", "accessPort=86", "model=TS-X64", "fwVer=5.2.9"},
	}
	txtDeviceInfo := &dns.TXT{
		Hdr: dns.RR_Header{Name: "slw-nas(AFP)._device-info._tcp.local.", Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 10},
		Txt: []string{"model=Xserve"},
	}

	// A / AAAA 记录
	aRec := &dns.A{
		Hdr: dns.RR_Header{Name: "slw-nas.local.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 10},
		A:   net.ParseIP("192.168.1.100"),
	}

	msg.Answer = []dns.RR{ptrHttp, ptrQdiscover, ptrDeviceInfo, srvHttp, srvQdiscover, txtHttp, txtQdiscover, txtDeviceInfo, aRec}

	results := []mdns.ResponseResult{
		{Msg: msg, RemoteIP: net.ParseIP("192.168.1.100")},
	}

	res := ParseResponses(results, nil, nil, nil)
	if res == nil {
		t.Fatalf("expected survey result, got nil")
	}

	if len(res.Services) != 3 {
		t.Fatalf("expected 3 services, got %d", len(res.Services))
	}

	// 验证 PTR 列表
	if len(res.PTRs) != 3 {
		t.Fatalf("expected 3 PTRs, got %d", len(res.PTRs))
	}

	// 找到 qdiscover 服务验证 TXT 关联
	var qdiscService *ServiceAsset
	for i := range res.Services {
		if res.Services[i].ServiceType == "qdiscover" {
			qdiscService = &res.Services[i]
			break
		}
	}
	if qdiscService == nil {
		t.Fatalf("expected qdiscover service asset")
	}

	if len(qdiscService.Attributes) == 0 || qdiscService.Attributes[0] != "accessType=https,accessPort=86,model=TS-X64,fwVer=5.2.9" {
		t.Errorf("unexpected qdiscover attributes: %v", qdiscService.Attributes)
	}
}
