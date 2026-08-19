package parser

import (
	"fmt"
	"net"
	"sort"
	"strings"

	"github.com/miekg/dns"
	"mdns-survey/pkg/mdns"
	"mdns-survey/pkg/utils"
)

// ServiceAsset 表示解析后的单项 mDNS 服务资产
type ServiceAsset struct {
	ServiceKey  string   `yaml:"key"`
	Port        int      `yaml:"port"`
	Proto       string   `yaml:"proto"`
	ServiceType string   `yaml:"service_type"`
	Name        string   `yaml:"name"`
	IPv4        string   `yaml:"ipv4"`
	IPv6        string   `yaml:"ipv6"`
	Hostname    string   `yaml:"hostname"`
	TTL         uint32   `yaml:"ttl"`
	Attributes  []string `yaml:"attributes"`
}

// SurveyResult 包含解析汇总后的资产和 Answers PTR 列表
type SurveyResult struct {
	Services []ServiceAsset
	PTRs     []string
}

// ServiceDefaultPorts 常见服务的默认端口辅助映射
var ServiceDefaultPorts = map[string]int{
	"workstation": 9,
	"smb":         445,
	"afpovertcp":  548,
	"http":        80,
	"https":       443,
}

// ParseResponses 深度解析提取全量 mDNS 报文
func ParseResponses(results []mdns.ResponseResult, targetIPs []net.IP, targetIPNet *net.IPNet, targetPorts map[int]bool) *SurveyResult {
	// 索引各类记录
	ptrMap := make(map[string]string)        // instance -> serviceDomain (e.g. slw-nas._http._tcp.local. -> _http._tcp.local.)
	srvMap := make(map[string]*dns.SRV)      // instance -> SRV
	txtMap := make(map[string][]string)      // instance -> TXT lines
	aMap := make(map[string]string)          // hostname -> IPv4
	aaaaMap := make(map[string]string)       // hostname -> IPv6
	ipToHostMap := make(map[string]string)   // ip -> hostname
	instanceIPMap := make(map[string]net.IP) // instance -> remoteIP
	ptrDomainSet := make(map[string]bool)    // unique PTR domains

	for _, res := range results {
		msg := res.Msg
		if msg == nil {
			continue
		}

		allRRs := append(msg.Answer, msg.Ns...)
		allRRs = append(allRRs, msg.Extra...)

		for _, rr := range allRRs {
			switch r := rr.(type) {
			case *dns.PTR:
				domain := strings.TrimSuffix(r.Hdr.Name, ".")
				ptrDomainSet[domain] = true
				instance := strings.TrimSuffix(r.Ptr, ".")
				ptrMap[instance] = domain
				if res.RemoteIP != nil {
					instanceIPMap[instance] = res.RemoteIP
				}

			case *dns.SRV:
				instance := strings.TrimSuffix(r.Hdr.Name, ".")
				srvMap[instance] = r
				targetHost := strings.TrimSuffix(r.Target, ".")
				if res.RemoteIP != nil {
					ipToHostMap[res.RemoteIP.String()] = targetHost
				}

			case *dns.TXT:
				instance := strings.TrimSuffix(r.Hdr.Name, ".")
				txtMap[instance] = append(txtMap[instance], r.Txt...)

			case *dns.A:
				host := strings.TrimSuffix(r.Hdr.Name, ".")
				aMap[host] = r.A.String()

			case *dns.AAAA:
				host := strings.TrimSuffix(r.Hdr.Name, ".")
				aaaaMap[host] = r.AAAA.String()
			}
		}
	}

	var services []ServiceAsset

	// 整合各 Instance 资产
	for instance, serviceDomain := range ptrMap {
		serviceType, proto := parseServiceDomain(serviceDomain)

		// 剥离实例名并还原 DNS 转义字符
		name := instance
		suffix := "." + serviceDomain
		if strings.HasSuffix(instance, suffix) {
			name = strings.TrimSuffix(instance, suffix)
		}
		name = unescapeDNSName(name)

		srv := srvMap[instance]
		var port int
		var hostname string
		var ttl uint32

		if srv != nil {
			port = int(srv.Port)
			hostname = strings.TrimSuffix(srv.Target, ".")
			ttl = srv.Hdr.Ttl
		} else {
			if defPort, ok := ServiceDefaultPorts[serviceType]; ok {
				port = defPort
			}
		}

		// 查找 IP 地址
		var ipv4, ipv6 string
		if hostname != "" {
			ipv4 = aMap[hostname]
			ipv6 = aaaaMap[hostname]
		}

		remoteIP := instanceIPMap[instance]
		if ipv4 == "" && remoteIP != nil && remoteIP.To4() != nil {
			ipv4 = remoteIP.String()
		}

		// 如果没有获取到 Hostname，用 IP 或 Instance 名字推导
		if hostname == "" {
			if remoteHost, ok := ipToHostMap[ipv4]; ok {
				hostname = remoteHost
			} else if ipv4 != "" {
				hostname = name + ".local"
			}
		}

		// 解析 TXT 记录与 Banner 属性
		rawTxts := txtMap[instance]
		txtAttrs := formatTxtAttributes(serviceType, rawTxts)

		// 构造 ServiceKey
		var serviceKey string
		if serviceType == "device-info" || port == 0 {
			serviceKey = serviceType
		} else {
			if proto == "" {
				proto = "tcp"
			}
			serviceKey = fmt.Sprintf("%d/%s %s", port, proto, serviceType)
		}

		asset := ServiceAsset{
			ServiceKey:  serviceKey,
			Port:        port,
			Proto:       proto,
			ServiceType: serviceType,
			Name:        name,
			IPv4:        ipv4,
			IPv6:        ipv6,
			Hostname:    hostname,
			TTL:         ttl,
			Attributes:  txtAttrs,
		}

		// 进行 IP 和 Port 的校验过滤
		parsedIP := net.ParseIP(ipv4)
		if parsedIP == nil && remoteIP != nil {
			parsedIP = remoteIP
		}

		// 匹配 IP 网段条件
		if parsedIP != nil && (len(targetIPs) > 0 || targetIPNet != nil) {
			if !utils.MatchesIP(parsedIP, targetIPNet, targetIPs) {
				continue
			}
		}

		// 匹配端口范围条件 (device-info 特殊无端口资产保留)
		if serviceType != "device-info" && targetPorts != nil && port > 0 {
			if !utils.MatchesPort(port, targetPorts) {
				continue
			}
		}

		services = append(services, asset)
	}

	// 排序保证输出稳定
	sort.Slice(services, func(i, j int) bool {
		if services[i].Port != services[j].Port {
			return services[i].Port < services[j].Port
		}
		return services[i].ServiceKey < services[j].ServiceKey
	})

	// 整理 PTR 汇总
	var ptrList []string
	for ptr := range ptrDomainSet {
		if ptr == "_services._dns-sd._udp.local" {
			continue
		}
		ptrList = append(ptrList, ptr)
	}
	sort.Strings(ptrList)

	return &SurveyResult{
		Services: services,
		PTRs:     ptrList,
	}
}

// parseServiceDomain 提取 short name 和 protocol
func parseServiceDomain(domain string) (serviceType, proto string) {
	// 例如 _http._tcp.local -> serviceType: http, proto: tcp
	parts := strings.Split(domain, ".")
	var serviceParts []string
	for _, p := range parts {
		if strings.HasPrefix(p, "_") {
			clean := strings.TrimPrefix(p, "_")
			if clean == "tcp" || clean == "udp" {
				proto = clean
			} else if clean != "dns-sd" {
				serviceParts = append(serviceParts, clean)
			}
		}
	}
	if len(serviceParts) > 0 {
		serviceType = serviceParts[0]
	} else if strings.Contains(domain, "device-info") {
		serviceType = "device-info"
	} else {
		serviceType = domain
	}
	return serviceType, proto
}

// formatTxtAttributes 格式化 TXT 记录中的 Key=Value
func formatTxtAttributes(serviceType string, txts []string) []string {
	if len(txts) == 0 {
		return nil
	}

	// 清理去重
	seen := make(map[string]bool)
	var cleanTxts []string
	for _, t := range txts {
		t = strings.TrimSpace(t)
		if t != "" && !seen[t] {
			seen[t] = true
			cleanTxts = append(cleanTxts, t)
		}
	}

	// 如果包含多个以逗号或特定描述信息的 TXT 键值，对特定服务（如 qdiscover）多属性合并显示
	if serviceType == "qdiscover" && len(cleanTxts) > 1 {
		return []string{strings.Join(cleanTxts, ",")}
	}

	return cleanTxts
}

// unescapeDNSName 还原 DNS 域名中的转义字符（例如 "\ " -> " ", "\(" -> "(" 等）
func unescapeDNSName(s string) string {
	s = strings.ReplaceAll(s, "\\ ", " ")
	s = strings.ReplaceAll(s, "\\(", "(")
	s = strings.ReplaceAll(s, "\\)", ")")
	s = strings.ReplaceAll(s, "\\[", "[")
	s = strings.ReplaceAll(s, "\\]", "]")
	return s
}
