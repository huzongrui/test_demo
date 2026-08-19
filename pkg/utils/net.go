package utils

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

// ParseIPs 解析包含 CIDR、单个 IP 或 IP 范围（192.168.1.1-192.168.1.50）的字符串
func ParseIPs(ipStr string) ([]net.IP, *net.IPNet, error) {
	ipStr = strings.TrimSpace(ipStr)
	if ipStr == "" {
		return nil, nil, fmt.Errorf("empty IP input")
	}

	// 尝试 CIDR 格式，如 192.168.1.0/24
	if strings.Contains(ipStr, "/") {
		ip, ipNet, err := net.ParseCIDR(ipStr)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid CIDR format: %v", err)
		}
		var ips []net.IP
		for ip := ip.Mask(ipNet.Mask); ipNet.Contains(ip); incrementIP(ip) {
			dup := make(net.IP, len(ip))
			copy(dup, ip)
			ips = append(ips, dup)
		}
		return ips, ipNet, nil
	}

	// 尝试范围格式，如 192.168.1.1-192.168.1.100 或 192.168.1.1-100
	if strings.Contains(ipStr, "-") {
		parts := strings.Split(ipStr, "-")
		if len(parts) != 2 {
			return nil, nil, fmt.Errorf("invalid IP range format: %s", ipStr)
		}
		startIP := net.ParseIP(strings.TrimSpace(parts[0]))
		if startIP == nil {
			return nil, nil, fmt.Errorf("invalid start IP: %s", parts[0])
		}

		endStr := strings.TrimSpace(parts[1])
		endIP := net.ParseIP(endStr)
		if endIP == nil {
			// 可能是简写形式如 192.168.1.1-50
			lastDot := strings.LastIndex(parts[0], ".")
			if lastDot != -1 {
				prefix := parts[0][:lastDot+1]
				endIP = net.ParseIP(prefix + endStr)
			}
		}
		if endIP == nil {
			return nil, nil, fmt.Errorf("invalid end IP: %s", parts[1])
		}

		var ips []net.IP
		curr := make(net.IP, len(startIP.To4()))
		copy(curr, startIP.To4())
		target := endIP.To4()

		for {
			dup := make(net.IP, len(curr))
			copy(dup, curr)
			ips = append(ips, dup)

			if curr.Equal(target) {
				break
			}
			incrementIP(curr)
			// 防止无限循环（如果 start > end）
			if bytesCompare(curr, target) > 0 {
				break
			}
		}
		return ips, nil, nil
	}

	// 单个 IP
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil, nil, fmt.Errorf("invalid IP: %s", ipStr)
	}
	return []net.IP{ip}, nil, nil
}

func incrementIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func bytesCompare(a, b net.IP) int {
	for i := 0; i < len(a) && i < len(b); i++ {
		if a[i] < b[i] {
			return -1
		} else if a[i] > b[i] {
			return 1
		}
	}
	return 0
}

// ParsePorts 解析端口字符串，如 "1-65535", "80,445,5000", "80,8080-8085"
func ParsePorts(portStr string) (map[int]bool, error) {
	portStr = strings.TrimSpace(portStr)
	ports := make(map[int]bool)

	if portStr == "" || portStr == "*" {
		// 表示所有端口
		return nil, nil
	}

	parts := strings.Split(portStr, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if strings.Contains(part, "-") {
			rangeParts := strings.Split(part, "-")
			if len(rangeParts) != 2 {
				return nil, fmt.Errorf("invalid port range: %s", part)
			}
			start, err1 := strconv.Atoi(strings.TrimSpace(rangeParts[0]))
			end, err2 := strconv.Atoi(strings.TrimSpace(rangeParts[1]))
			if err1 != nil || err2 != nil || start > end || start < 1 || end > 65535 {
				return nil, fmt.Errorf("invalid port range values: %s", part)
			}
			for p := start; p <= end; p++ {
				ports[p] = true
			}
		} else {
			p, err := strconv.Atoi(part)
			if err != nil || p < 1 || p > 65535 {
				return nil, fmt.Errorf("invalid port number: %s", part)
			}
			ports[p] = true
		}
	}

	return ports, nil
}

// MatchesIP 判断测试 IP 是否属于指定网段/列表中
func MatchesIP(ip net.IP, ipNet *net.IPNet, ipList []net.IP) bool {
	if ipNet != nil {
		return ipNet.Contains(ip)
	}
	for _, target := range ipList {
		if target.Equal(ip) {
			return true
		}
	}
	return false
}

// MatchesPort 判断端口是否在允许端口集合中（如果 allowedPorts 为 nil 代表不限制）
func MatchesPort(port int, allowedPorts map[int]bool) bool {
	if allowedPorts == nil {
		return true
	}
	return allowedPorts[port]
}
