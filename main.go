package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"time"

	"mdns-survey/pkg/formatter"
	"mdns-survey/pkg/mdns"
	"mdns-survey/pkg/parser"
	"mdns-survey/pkg/utils"
)

func main() {
	var (
		ipArg       string
		portArg     string
		timeoutSec  int
		concurrency int
		outputFile  string
	)

	flag.StringVar(&ipArg, "i", "", "Target IP, CIDR, or IP range (e.g. 192.168.1.0/24, 192.168.1.1-100)")
	flag.StringVar(&ipArg, "ip", "", "Target IP, CIDR, or IP range (e.g. 192.168.1.0/24, 192.168.1.1-100)")

	flag.StringVar(&portArg, "p", "", "Target port or port range (e.g. 1-65535, 80,445,5000)")
	flag.StringVar(&portArg, "port", "", "Target port or port range (e.g. 1-65535, 80,445,5000)")

	flag.IntVar(&timeoutSec, "t", 3, "Timeout in seconds for mDNS discovery")
	flag.IntVar(&timeoutSec, "timeout", 3, "Timeout in seconds for mDNS discovery")

	flag.IntVar(&concurrency, "c", 100, "Concurrency limit for unicast probing")
	flag.IntVar(&concurrency, "concurrent", 100, "Concurrency limit for unicast probing")

	flag.StringVar(&outputFile, "o", "", "Save output result to specified file")
	flag.StringVar(&outputFile, "output", "", "Save output result to specified file")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "mDNS Asset Survey CLI Tool\n\nUsage:\n")
		fmt.Fprintf(os.Stderr, "  %s -i <IP/CIDR/Range> -p <Port/Range> [options]\n\nOptions:\n", os.Args[0])
		flag.PrintDefaults()
	}

	flag.Parse()

	// 解析 IP 参数
	var targetIPs []net.IP
	var targetIPNet *net.IPNet
	if ipArg != "" {
		ips, ipNet, err := utils.ParseIPs(ipArg)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] Error parsing IP argument: %v\n", err)
			os.Exit(1)
		}
		targetIPs = ips
		targetIPNet = ipNet
	}

	// 解析端口参数
	var targetPorts map[int]bool
	if portArg != "" {
		ports, err := utils.ParsePorts(portArg)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] Error parsing port argument: %v\n", err)
			os.Exit(1)
		}
		targetPorts = ports
	}

	client := mdns.NewClient(time.Duration(timeoutSec)*time.Second, concurrency)

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutSec+2)*time.Second)
	defer cancel()

	resultsChan, err := client.Probe(ctx, targetIPs)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] Probe error: %v\n", err)
		os.Exit(1)
	}

	var rawResults []mdns.ResponseResult
	for res := range resultsChan {
		rawResults = append(rawResults, res)
	}

	// 深度解析与过滤整合
	surveyResult := parser.ParseResponses(rawResults, targetIPs, targetIPNet, targetPorts)

	// 渲染格式化输出
	outputStr := formatter.FormatResult(surveyResult)

	if outputFile != "" {
		err := os.WriteFile(outputFile, []byte(outputStr), 0644)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] Error writing output file: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("[+] Result saved to %s\n", outputFile)
	} else {
		fmt.Print(outputStr)
	}
}
