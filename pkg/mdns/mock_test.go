package mdns_test

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
	"mdns-survey/pkg/formatter"
	"mdns-survey/pkg/mdns"
	"mdns-survey/pkg/parser"
)

// StartMockMDNSServer 启动一个在后台运行的 Mock UDP mDNS 服务端
func StartMockMDNSServer(t *testing.T) (*net.UDPConn, int) {
	addr, err := net.ResolveUDPAddr("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to resolve local address: %v", err)
	}

	conn, err := net.ListenUDP("udp4", addr)
	if err != nil {
		t.Fatalf("failed to start mock UDP listener: %v", err)
	}

	mockPort := conn.LocalAddr().(*net.UDPAddr).Port

	go func() {
		defer conn.Close()
		buf := make([]byte, 65535)
		for {
			_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
			n, remoteAddr, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}

			req := new(dns.Msg)
			if err := req.Unpack(buf[:n]); err != nil {
				continue
			}

			// 构造完整匹配 README 示例的 DNS 响应报文
			resp := new(dns.Msg)
			resp.SetReply(req)
			resp.SetEdns0(4096, true)
			resp.Authoritative = true

			// 1. PTR 记录
			ptrWorkstation := &dns.PTR{
				Hdr: dns.RR_Header{Name: "_workstation._tcp.local.", Rrtype: dns.TypePTR, Class: dns.ClassINET, Ttl: 10},
				Ptr: "slw-nas [24:5e:be:69:a3:13]._workstation._tcp.local.",
			}
			ptrHttp := &dns.PTR{
				Hdr: dns.RR_Header{Name: "_http._tcp.local.", Rrtype: dns.TypePTR, Class: dns.ClassINET, Ttl: 10},
				Ptr: "slw-nas._http._tcp.local.",
			}
			ptrSmb := &dns.PTR{
				Hdr: dns.RR_Header{Name: "_smb._tcp.local.", Rrtype: dns.TypePTR, Class: dns.ClassINET, Ttl: 10},
				Ptr: "slw-nas._smb._tcp.local.",
			}
			ptrQdiscover := &dns.PTR{
				Hdr: dns.RR_Header{Name: "_qdiscover._tcp.local.", Rrtype: dns.TypePTR, Class: dns.ClassINET, Ttl: 10},
				Ptr: "slw-nas._qdiscover._tcp.local.",
			}
			ptrDeviceInfo := &dns.PTR{
				Hdr: dns.RR_Header{Name: "_device-info._tcp.local.", Rrtype: dns.TypePTR, Class: dns.ClassINET, Ttl: 10},
				Ptr: "slw-nas(AFP)._device-info._tcp.local.",
			}
			ptrAfp := &dns.PTR{
				Hdr: dns.RR_Header{Name: "_afpovertcp._tcp.local.", Rrtype: dns.TypePTR, Class: dns.ClassINET, Ttl: 10},
				Ptr: "slw-nas(AFP)._afpovertcp._tcp.local.",
			}

			resp.Answer = append(resp.Answer, ptrWorkstation, ptrHttp, ptrSmb, ptrQdiscover, ptrDeviceInfo, ptrAfp)

			// 2. SRV 记录
			srvWorkstation := &dns.SRV{
				Hdr:    dns.RR_Header{Name: "slw-nas [24:5e:be:69:a3:13]._workstation._tcp.local.", Rrtype: dns.TypeSRV, Class: dns.ClassINET, Ttl: 10},
				Port:   9,
				Target: "slw-nas.local.",
			}
			srvHttp := &dns.SRV{
				Hdr:    dns.RR_Header{Name: "slw-nas._http._tcp.local.", Rrtype: dns.TypeSRV, Class: dns.ClassINET, Ttl: 10},
				Port:   5000,
				Target: "slw-nas.local.",
			}
			srvSmb := &dns.SRV{
				Hdr:    dns.RR_Header{Name: "slw-nas._smb._tcp.local.", Rrtype: dns.TypeSRV, Class: dns.ClassINET, Ttl: 10},
				Port:   445,
				Target: "slw-nas.local.",
			}
			srvQdiscover := &dns.SRV{
				Hdr:    dns.RR_Header{Name: "slw-nas._qdiscover._tcp.local.", Rrtype: dns.TypeSRV, Class: dns.ClassINET, Ttl: 10},
				Port:   5000,
				Target: "slw-nas.local.",
			}
			srvAfp := &dns.SRV{
				Hdr:    dns.RR_Header{Name: "slw-nas(AFP)._afpovertcp._tcp.local.", Rrtype: dns.TypeSRV, Class: dns.ClassINET, Ttl: 10},
				Port:   548,
				Target: "slw-nas.local.",
			}

			resp.Extra = append(resp.Extra, srvWorkstation, srvHttp, srvSmb, srvQdiscover, srvAfp)

			// 3. TXT 记录
			txtHttp := &dns.TXT{
				Hdr: dns.RR_Header{Name: "slw-nas._http._tcp.local.", Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 10},
				Txt: []string{"path=/"},
			}
			txtQdiscover := &dns.TXT{
				Hdr: dns.RR_Header{Name: "slw-nas._qdiscover._tcp.local.", Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 10},
				Txt: []string{"accessType=https", "accessPort=86", "model=TS-X64", "displayModel=TS-464C", "fwVer=5.2.9", "fwBuildNum=20260214"},
			}
			txtDeviceInfo := &dns.TXT{
				Hdr: dns.RR_Header{Name: "slw-nas(AFP)._device-info._tcp.local.", Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 10},
				Txt: []string{"model=Xserve"},
			}

			resp.Extra = append(resp.Extra, txtHttp, txtQdiscover, txtDeviceInfo)

			// 4. A / AAAA 记录
			aRec := &dns.A{
				Hdr: dns.RR_Header{Name: "slw-nas.local.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 10},
				A:   net.ParseIP("127.0.0.1"),
			}
			aaaaRec := &dns.AAAA{
				Hdr:  dns.RR_Header{Name: "slw-nas.local.", Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 10},
				AAAA: net.ParseIP("fe80::265e:beff:fe69:a313"),
			}

			resp.Extra = append(resp.Extra, aRec, aaaaRec)

			rawResp, err := resp.Pack()
			if err == nil {
				_, _ = conn.WriteToUDP(rawResp, remoteAddr)
			}
		}
	}()

	return conn, mockPort
}

func TestEndToEndMockSurvey(t *testing.T) {
	_, mockPort := StartMockMDNSServer(t)

	client := mdns.NewClient(1*time.Second, 10)
	client.Port = mockPort

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	targetIPs := []net.IP{net.ParseIP("127.0.0.1")}
	resultsChan, err := client.Probe(ctx, targetIPs)
	if err != nil {
		t.Fatalf("failed to probe mock server: %v", err)
	}

	var rawResults []mdns.ResponseResult
	for res := range resultsChan {
		rawResults = append(rawResults, res)
	}

	if len(rawResults) == 0 {
		t.Fatalf("expected raw responses from mock server, got 0")
	}

	// 执行深度解析与渲染
	surveyResult := parser.ParseResponses(rawResults, targetIPs, nil, nil)
	outputStr := formatter.FormatResult(surveyResult)

	// 断言验证包含全量预期的 Service Key
	expectedKeys := []string{
		"9/tcp workstation",
		"5000/tcp http",
		"445/tcp smb",
		"5000/tcp qdiscover",
		"device-info",
		"548/tcp afpovertcp",
	}

	for _, key := range expectedKeys {
		if !strings.Contains(outputStr, key) {
			t.Errorf("expected output to contain service key %q, output:\n%s", key, outputStr)
		}
	}

	// 验证详细 Banner 属性
	expectedBanners := []string{
		"Name=slw-nas [24:5e:be:69:a3:13]",
		"Hostname=slw-nas.local",
		"path=/",
		"accessType=https,accessPort=86,model=TS-X64,displayModel=TS-464C,fwVer=5.2.9,fwBuildNum=20260214",
		"model=Xserve",
		"Name=slw-nas(AFP)",
	}

	for _, banner := range expectedBanners {
		if !strings.Contains(outputStr, banner) {
			t.Errorf("expected output to contain banner %q, output:\n%s", banner, outputStr)
		}
	}

	// 验证 answers PTR 列表
	expectedPTRs := []string{
		"_workstation._tcp.local",
		"_http._tcp.local",
		"_smb._tcp.local",
		"_qdiscover._tcp.local",
		"_device-info._tcp.local",
		"_afpovertcp._tcp.local",
	}

	for _, ptr := range expectedPTRs {
		if !strings.Contains(outputStr, ptr) {
			t.Errorf("expected output to contain PTR %q, output:\n%s", ptr, outputStr)
		}
	}
}
