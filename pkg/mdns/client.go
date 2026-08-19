package mdns

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// MDNSMulticastAddr 标准 mDNS 组播地址
const (
	MDNSMulticastIPv4 = "224.0.0.251:5353"
)

// StandardServices 常见 mDNS DNS-SD 查询服务列表
var StandardServices = []string{
	"_services._dns-sd._udp.local.",
	"_http._tcp.local.",
	"_smb._tcp.local.",
	"_workstation._tcp.local.",
	"_device-info._tcp.local.",
	"_qdiscover._tcp.local.",
	"_afpovertcp._tcp.local.",
	"_airplay._tcp.local.",
	"_ssh._tcp.local.",
	"_sftp-ssh._tcp.local.",
	"_printer._tcp.local.",
	"_ipp._tcp.local.",
}

// ResponseResult 封装收到的 mDNS 响应报文与源 IP
type ResponseResult struct {
	Msg      *dns.Msg
	RemoteIP net.IP
}

// Client mDNS 探测客户端
type Client struct {
	Timeout     time.Duration
	Concurrency int
	Port        int
}

// NewClient 创建 mDNS 客户端
func NewClient(timeout time.Duration, concurrency int) *Client {
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	if concurrency <= 0 {
		concurrency = 100
	}
	return &Client{
		Timeout:     timeout,
		Concurrency: concurrency,
		Port:        5353,
	}
}

// BuildQueryPackets 生成针对已知服务列表的 mDNS 查询报文
func BuildQueryPackets() []*dns.Msg {
	var msgs []*dns.Msg

	// 生成包含主 DNS-SD 服务的消息
	msg := new(dns.Msg)
	msg.SetQuestion("_services._dns-sd._udp.local.", dns.TypePTR)
	msg.SetEdns0(4096, true)
	msg.RecursionDesired = false
	msgs = append(msgs, msg)

	// 对常用服务类型进行针对性 PTR 查询
	for _, service := range StandardServices {
		if service == "_services._dns-sd._udp.local." {
			continue
		}
		m := new(dns.Msg)
		m.SetQuestion(service, dns.TypePTR)
		m.SetEdns0(4096, true)
		m.RecursionDesired = false
		msgs = append(msgs, m)
	}

	return msgs
}

// Probe 执行 mDNS 探测（组播 + 指定 IP 列表的单播）
func (c *Client) Probe(ctx context.Context, targetIPs []net.IP) (<-chan ResponseResult, error) {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return nil, fmt.Errorf("failed to listen on UDP socket: %v", err)
	}

	results := make(chan ResponseResult, 500)
	var wg sync.WaitGroup

	// 1. 启动并发接收器
	wg.Add(1)
	go func() {
		defer wg.Done()
		buffer := make([]byte, 65535)
		for {
			_ = conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
			n, remoteAddr, err := conn.ReadFromUDP(buffer)
			if err != nil {
				select {
				case <-ctx.Done():
					return
				default:
					if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
						continue
					}
					return
				}
			}

			if n > 0 {
				msg := new(dns.Msg)
				if err := msg.Unpack(buffer[:n]); err == nil {
					select {
					case results <- ResponseResult{Msg: msg, RemoteIP: remoteAddr.IP}:
					case <-ctx.Done():
						return
					}
				}
			}
		}
	}()

	// 2. 发送组播查询
	queryMsgs := BuildQueryPackets()
	mcastAddr, err := net.ResolveUDPAddr("udp4", MDNSMulticastIPv4)
	if err == nil {
		for _, q := range queryMsgs {
			raw, err := q.Pack()
			if err == nil {
				_, _ = conn.WriteToUDP(raw, mcastAddr)
			}
		}
	}

	// 3. 发送单播查询（如有指定的 Target IPs）
	if len(targetIPs) > 0 {
		ipChan := make(chan net.IP, len(targetIPs))
		for _, ip := range targetIPs {
			ipChan <- ip
		}
		close(ipChan)

		var sendWg sync.WaitGroup
		workers := c.Concurrency
		if workers > len(targetIPs) {
			workers = len(targetIPs)
		}

		for i := 0; i < workers; i++ {
			sendWg.Add(1)
			go func() {
				defer sendWg.Done()
				for ip := range ipChan {
					port := c.Port
					if port <= 0 {
						port = 5353
					}
					targetAddr := &net.UDPAddr{IP: ip, Port: port}
					for _, q := range queryMsgs {
						raw, err := q.Pack()
						if err == nil {
							_, _ = conn.WriteToUDP(raw, targetAddr)
						}
					}
				}
			}()
		}
		sendWg.Wait()
	}

	// 4. 定时超时后关闭通道
	go func() {
		select {
		case <-time.After(c.Timeout):
		case <-ctx.Done():
		}
		conn.Close()
		wg.Wait()
		close(results)
	}()

	return results, nil
}
