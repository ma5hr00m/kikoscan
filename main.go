package main

import (
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	DEBUG = iota
	INFO
	WARN
	ERROR

	defaultThreads = 100
)

var logLevelColors = map[int]string{
	DEBUG: "\033[36m",
	INFO:  "\033[32m",
	WARN:  "\033[33m",
	ERROR: "\033[31m",
}

var (
	resetColor  = "\033[0m"
	boldColor   = "\033[1m"
	dimColor    = "\033[2m"
	portColor   = "\033[36m"
	closedColor = "\033[31m"
)

var currentLogLevel = INFO

type Scanner struct {
	Target    string
	Ports     []int
	InfoLevel int
	ScanType  int
	Threads   int
	Results   []ScanResult
	StartTime time.Time
}

func NewScanner(target string, ports []int, infoLevel int, scanType int, threads int) *Scanner {
	return &Scanner{
		Target:    target,
		Ports:     ports,
		InfoLevel: infoLevel,
		ScanType:  scanType,
		Threads:   threads,
	}
}

func (s *Scanner) Start() error {
	s.StartTime = time.Now()
	targets := expandTargets(s.Target)
	if len(targets) == 0 {
		return fmt.Errorf("unable to resolve target: %s", s.Target)
	}

	log(INFO, "Starting scan, targets: %d, ports: %d", len(targets), len(s.Ports))

	for _, ip := range targets {
		log(DEBUG, "Scanning target: %s", ip)
		s.Results = append(s.Results, s.scanPorts(ip)...)
	}

	duration := time.Since(s.StartTime)
	log(INFO, "Scan completed in: %v", duration)
	return nil
}

func (s *Scanner) scanPorts(ip string) []ScanResult {
	var results []ScanResult
	portsChan := make(chan int, len(s.Ports))
	resultsChan := make(chan ScanResult, len(s.Ports))
	var wg sync.WaitGroup

	for i := 0; i < s.Threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for port := range portsChan {
				var result ScanResult
				switch s.ScanType {
				case 0:
					result = tcpScan(ip, port, s.InfoLevel)
				case 1:
					result = synScan(ip, port)
				case 2:
					result = udpScan(ip, port)
				}
				resultsChan <- result
			}
		}()
	}

	go func() {
		for _, port := range s.Ports {
			portsChan <- port
		}
		close(portsChan)
	}()

	go func() {
		wg.Wait()
		close(resultsChan)
	}()

	for result := range resultsChan {
		results = append(results, result)
	}

	return results
}

type ScanResult struct {
	IP        string    `json:"ip"`
	Port      int       `json:"port"`
	State     string    `json:"state"`
	Service   string    `json:"service"`
	Banner    string    `json:"banner,omitempty"`
	Proto     string    `json:"protocol"`
	Timestamp time.Time `json:"timestamp"`
}

var commonPorts = map[int]string{
	21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
	53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
	443: "HTTPS", 445: "SMB", 3306: "MySQL", 3389: "RDP",
	5432: "PostgreSQL", 6379: "Redis", 8080: "HTTP-Proxy",
}

func log(level int, format string, args ...interface{}) {
	if level >= currentLogLevel {
		color := logLevelColors[level]
		levelStr := [...]string{"DEBUG", "INFO", "WARN", "ERROR"}[level]
		timestamp := time.Now().Format("15:04:05")
		fmt.Printf("%s[%s] %s ▶ %s%s\n",
			color, timestamp, levelStr, fmt.Sprintf(format, args...), resetColor)
	}
}

type Config struct {
	target       string
	ports        string
	scanMethod   string
	infoLevel    int
	outputFormat string
	outputFile   string
	logLevel     string
	threads      int
}

func parseFlags() *Config {
	config := &Config{}

	flag.StringVar(&config.target, "t", "", "目标IP、域名或CIDR范围")
	flag.StringVar(&config.ports, "p", "", "端口范围（如：80,443 或 1-1000）")
	flag.StringVar(&config.scanMethod, "s", "tcp", "扫描类型（tcp/syn/udp）")
	flag.IntVar(&config.infoLevel, "i", 0, "信息收集级别（0-2）")
	flag.StringVar(&config.outputFormat, "o", "text", "输出格式（text/json/csv）")
	flag.StringVar(&config.outputFile, "f", "", "输出文件路径")
	flag.StringVar(&config.logLevel, "l", "info", "日志级别（debug/info/warn/error）")
	flag.IntVar(&config.threads, "T", defaultThreads, "并发线程数")

	flag.Parse()
	setLogLevel(config.logLevel)

	var ports []int
	if config.ports != "" {
		ports = parsePortRange(config.ports)
	} else {
		ports = getPortsByLevel(config.infoLevel)
	}

	return &Config{
		target:       config.target,
		ports:        portsToString(ports),
		scanMethod:   config.scanMethod,
		infoLevel:    config.infoLevel,
		outputFormat: config.outputFormat,
		outputFile:   config.outputFile,
		logLevel:     config.logLevel,
		threads:      config.threads,
	}
}

func portsToString(ports []int) string {
	var portStrings []string
	for _, port := range ports {
		portStrings = append(portStrings, strconv.Itoa(port))
	}
	return strings.Join(portStrings, ",")
}

func validateConfig(config *Config) error {
	if config.target == "" {
		return fmt.Errorf("please specify target using -target parameter")
	}
	if len(parsePortRange(config.ports)) == 0 {
		return fmt.Errorf("no valid ports specified")
	}
	return nil
}

func setLogLevel(level string) {
	switch strings.ToLower(level) {
	case "debug":
		currentLogLevel = DEBUG
	case "info":
		currentLogLevel = INFO
	case "warn":
		currentLogLevel = WARN
	case "error":
		currentLogLevel = ERROR
	}
}

func parseScanType(scanType string) int {
	switch strings.ToLower(scanType) {
	case "tcp":
		return 0
	case "syn":
		return 1
	case "udp":
		return 2
	default:
		log(WARN, "unsupported scan type, using default TCP scan")
		return 0
	}
}

func main() {
	config := parseFlags()
	if err := validateConfig(config); err != nil {
		fmt.Println("配置错误:", err)
		os.Exit(1)
	}

	setLogLevel(config.logLevel)
	scanType := parseScanType(config.scanMethod)
	ports := parsePortRange(config.ports)
	if len(ports) == 0 {
		ports = getPortsByLevel(config.infoLevel)
	}

	scanner := NewScanner(config.target, ports, config.infoLevel, scanType, config.threads)
	if err := scanner.Start(); err != nil {
		fmt.Println("扫描错误:", err)
		os.Exit(1)
	}

	if err := outputResults(scanner.Results, config.outputFormat, config.outputFile, config.infoLevel); err != nil {
		fmt.Println("输出结果错误:", err)
		os.Exit(1)
	}
}

func outputResults(results []ScanResult, format string, outputFile string, infoLevel int) error {
	var output string

	switch format {
	case "json":
		jsonData, err := json.MarshalIndent(results, "", "  ")
		if err != nil {
			return fmt.Errorf("json encoding failed: %v", err)
		}
		output = string(jsonData)
	case "csv":
		var csvData strings.Builder
		writer := csv.NewWriter(&csvData)
		headers := []string{"IP", "Port", "Protocol", "State", "Service", "Banner", "Timestamp"}
		if err := writer.Write(headers); err != nil {
			return fmt.Errorf("failed to write csv headers: %v", err)
		}
		for _, r := range results {
			record := []string{
				r.IP,
				strconv.Itoa(r.Port),
				r.Proto,
				r.State,
				r.Service,
				r.Banner,
				r.Timestamp.Format(time.RFC3339),
			}
			if err := writer.Write(record); err != nil {
				return fmt.Errorf("failed to write csv record: %v", err)
			}
		}
		writer.Flush()
		output = csvData.String()
	case "text":
		fmt.Printf("\n%sScan Results for: %s%s%s\n", boldColor, boldColor, results[0].IP, resetColor)
		fmt.Printf("%sTime: %s%s\n", dimColor, time.Now().Format("2006-01-02 15:04:05"), resetColor)
		fmt.Printf("%s%s%s\n", dimColor, strings.Repeat("─", 50), resetColor)

		resultsByIP := make(map[string][]ScanResult)
		for _, r := range results {
			resultsByIP[r.IP] = append(resultsByIP[r.IP], r)
		}

		for _, ipResults := range resultsByIP {
			sort.Slice(ipResults, func(i, j int) bool {
				return ipResults[i].Port < ipResults[j].Port
			})

			for _, r := range ipResults {
				state := r.State
				stateColor := dimColor
				switch state {
				case "open":
					stateColor = logLevelColors[INFO]
				case "filtered":
					stateColor = logLevelColors[WARN]
				case "closed":
					stateColor = closedColor
				}

				if infoLevel == 0 {
					portStr := fmt.Sprintf("%d/%s", r.Port, r.Proto)
					fmt.Printf("%s%-12s%s %s%-8s%s %s%s%s",
						portColor, portStr, resetColor,
						stateColor, state, resetColor,
						dimColor, r.Service, resetColor)

					if r.Banner != "" {
						banner := r.Banner
						if len(banner) > 50 {
							banner = banner[:47] + "..."
						}
						fmt.Printf(" %s%s%s", dimColor, banner, resetColor)
					}
					fmt.Println()
				} else {
					fmt.Printf("\n%sPort %s%d/%s%s\n",
						boldColor,
						portColor, r.Port, r.Proto,
						resetColor)
					fmt.Printf("  Status  : %s%s%s\n", stateColor, state, resetColor)
					fmt.Printf("  Service : %s\n", r.Service)
					if r.Banner != "" {
						fmt.Printf("  Banner  : %s%s%s\n", dimColor, r.Banner, resetColor)
					}
					fmt.Printf("  Time    : %s\n", r.Timestamp.Format("15:04:05"))
				}
			}

			openPorts := 0
			for _, r := range ipResults {
				if r.State == "open" {
					openPorts++
				}
			}
			fmt.Printf("\n%s%s%s\n", dimColor, strings.Repeat("─", 50), resetColor)
			fmt.Printf("%sTotal:%s %d ports scanned, %s%d open%s\n",
				boldColor, resetColor,
				len(ipResults),
				logLevelColors[INFO], openPorts, resetColor)
		}

		output = ""
	}

	if outputFile != "" {
		if err := os.WriteFile(outputFile, []byte(output), 0644); err != nil {
			return fmt.Errorf("failed to write output file: %v", err)
		}
	}

	fmt.Println(output)
	return nil
}

func expandTargets(target string) []string {
	if strings.Contains(target, "/") {
		return expandCIDR(target)
	}

	ips := resolveTarget(target)
	if len(ips) > 0 {
		return ips
	}
	log(ERROR, "无法解析目标: %s", target)
	return nil
}

func expandCIDR(cidr string) []string {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil
	}

	var ips []string
	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); incrementIP(ip) {
		ips = append(ips, ip.String())
	}

	if len(ips) > 0 {
		ips = ips[1 : len(ips)-1]
	}
	return ips
}

func incrementIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func parsePortRange(portRange string) []int {
	var ports []int
	ranges := strings.Split(portRange, ",")

	for _, r := range ranges {
		if strings.Contains(r, "-") {
			parts := strings.Split(r, "-")
			if len(parts) != 2 {
				continue
			}
			start, err1 := strconv.Atoi(strings.TrimSpace(parts[0]))
			end, err2 := strconv.Atoi(strings.TrimSpace(parts[1]))
			if err1 != nil || err2 != nil || start > end {
				continue
			}
			for port := start; port <= end; port++ {
				ports = append(ports, port)
			}
		} else {
			port, err := strconv.Atoi(strings.TrimSpace(r))
			if err == nil && port > 0 && port < 65536 {
				ports = append(ports, port)
			}
		}
	}

	return ports
}

func resolveTarget(target string) []string {
	if ip := net.ParseIP(target); ip != nil {
		if ipv4 := ip.To4(); ipv4 != nil {
			return []string{ipv4.String()}
		}
		return []string{ip.String()}
	}

	ips, err := net.LookupIP(target)
	if err != nil {
		log(DEBUG, "DNS解析错误: %v", err)
		return nil
	}

	var results []string
	for _, ip := range ips {
		if ipv4 := ip.To4(); ipv4 != nil {
			results = append(results, ipv4.String())
		}
	}

	if len(results) == 0 {
		log(DEBUG, "未找到IPv4地址")
		return nil
	}

	return results
}

func getPortsByLevel(level int) []int {
	switch level {
	case 0:
		ports := make([]int, 0, len(commonPorts))
		for port := range commonPorts {
			ports = append(ports, port)
		}
		sort.Ints(ports)
		return ports
	case 1:
		ports := make([]int, 0, 1000)
		for i := 1; i <= 1000; i++ {
			ports = append(ports, i)
		}
		return ports
	case 2:
		ports := make([]int, 0, 65535)
		for i := 1; i <= 65535; i++ {
			ports = append(ports, i)
		}
		return ports
	default:
		return []int{80, 443}
	}
}

func tcpScan(ip string, port int, infoLevel int) ScanResult {
	result := ScanResult{
		IP:        ip,
		Port:      port,
		Proto:     "TCP",
		Timestamp: time.Now(),
	}

	address := fmt.Sprintf("%s:%d", ip, port)
	conn, err := net.DialTimeout("tcp", address, 2*time.Second)

	if err != nil {
		result.State = "closed"
		return result
	}
	defer conn.Close()

	result.State = "open"
	result.Service = commonPorts[port]

	if infoLevel >= 1 {
		if err := conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
			return result
		}

		buffer := make([]byte, 1024)
		_, err = conn.Write([]byte("\r\n"))
		if err == nil {
			n, _ := conn.Read(buffer)
			if n > 0 {
				result.Banner = strings.TrimSpace(string(buffer[:n]))
			}
		}
	}

	return result
}

func synScan(ip string, port int) ScanResult {
	result := ScanResult{
		IP:        ip,
		Port:      port,
		Proto:     "SYN",
		Timestamp: time.Now(),
	}
	result.State = "closed"
	result.Service = commonPorts[port]
	return result
}

func udpScan(ip string, port int) ScanResult {
	result := ScanResult{
		IP:        ip,
		Port:      port,
		Proto:     "UDP",
		Timestamp: time.Now(),
	}
	address := fmt.Sprintf("%s:%d", ip, port)
	conn, err := net.DialTimeout("udp", address, 2*time.Second)

	if err != nil {
		result.State = "closed"
		return result
	}
	defer conn.Close()

	result.State = "open|filtered"
	result.Service = commonPorts[port]
	return result
}
