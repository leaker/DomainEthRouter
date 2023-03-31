package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/getlantern/systray"
	"github.com/gofika/util/yamlutil"
	"github.com/leaker/DomainEthRouter/res"
	"golang.org/x/exp/slices"
)

type RouteEntry struct {
	IP             net.IP
	Mask           net.IPMask
	DefaultGateway string
}

func (r *RouteEntry) String() string {
	return fmt.Sprintf("%s %s", r.CIDR(), r.DefaultGateway)
}

func (r *RouteEntry) CIDR() string {
	ones, _ := r.Mask.Size()
	return fmt.Sprintf("%s/%d", r.IP.String(), ones)
}

type Config struct {
	Domains          []string `yaml:"domains"`
	NetworkInterface string   `yaml:"network_interface"`
}

func main() {
	var config Config
	err := yamlutil.ReadFile("config.yaml", &config)
	if err != nil {
		log.Fatalf("Error reading config.yaml: %v", err)
	}

	log.Println("Program started")

	// Check if the program is running with administrator privileges
	if !isAdmin() {
		runAsAdmin()
		return
	}
	// Specify the network interface to use
	networkInterface := config.NetworkInterface

	onReady := func() {
		systray.SetIcon(res.AppIcon)
		systray.SetTitle("Route Manager")
		mClean := systray.AddMenuItem("Clean Routes", "Clear all domains routes")
		mQuit := systray.AddMenuItem("Quit", "Quit the whole app")

		for {
			select {
			case <-mQuit.ClickedCh:
				systray.Quit()
				os.Exit(0)
			case <-mClean.ClickedCh:
				ClearRoutes(networkInterface, config.Domains)
			}
		}
	}
	// Run systray
	go systray.Run(onReady, nil)

	adapterIP, defaultGateway, err := getInterfaceInfo(networkInterface)
	if err != nil {
		log.Fatalf("Failed to get interface info: %v", err)
	}
	log.Printf("Interface '%s' IP:%s, Gateway:%s", networkInterface, adapterIP, defaultGateway)

	tipLines := []string{}

	for {
		// Get the current routing table
		routes, err := getCurrentRoutes()
		if err != nil {
			log.Fatalf("Failed to get current routing table: %v", err)
		}
		adapterIP, defaultGateway, err = getInterfaceInfo(networkInterface)

		// Resolve IP addresses for the provided domain list
		for _, domain := range config.Domains {
			ips, err := net.LookupIP(domain)
			if err != nil {
				log.Printf("Error resolving domain %s: %v", domain, err)
				continue
			}

			// Set routing table entries for each IP address
			for _, ip := range ips {
				ipStr := ip.String()
				line := fmt.Sprintf("%s - %s", ipStr, domain)
				if !slices.Contains(tipLines, line) {
					tipLines = append(tipLines, line)
				}
				routeIndex := slices.IndexFunc(routes, func(route *RouteEntry) bool {
					return ipStr+"/32" == route.CIDR()
				})
				if routeIndex != -1 {
					log.Printf("IP address %s (%s) already exists in the routing table", ipStr, domain)
					continue
				}
				err = addRoute(ipStr, networkInterface, defaultGateway)
				if err != nil {
					log.Printf("Failed to add route for IP address %s (%s): %v", ipStr, domain, err)
				} else {
					log.Printf("Successfully added route for IP address %s (%s)", ipStr, domain)
				}
			}
		}

		systray.SetTooltip(fmt.Sprintf("Managed Routers: %d. direct to %s(%s)", len(tipLines), networkInterface, adapterIP))
		time.Sleep(5 * time.Minute) // Update every 5 minutes
	}
}

func isAdmin() bool {
	if runtime.GOOS != "windows" {
		return false
	}

	_, err := os.Open("\\\\.\\PHYSICALDRIVE0")
	if err != nil {
		fmt.Println("Please run this program as an administrator.")
		return false
	}
	return true
}

func runAsAdmin() {
	exePath, err := os.Executable()
	if err != nil {
		fmt.Printf("Failed to retrieve executable file path: %v\n", err)
		return
	}

	cmd := exec.Command("runas", "/user:Administrator", exePath)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	err = cmd.Run()
	if err != nil {
		fmt.Printf("Failed to start the process with administrator privileges: %v\n", err)
	}
}

func getRouteInfo() (string, error) {
	cmd := exec.Command("netstat", "-rn")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("Failed to execute command: %v, Output: %s", err, output)
	}

	return string(output), nil
}

func addRoute(ip string, networkInterface string, defaultGateway string) error {
	cmd := exec.Command("netsh", "interface", "ipv4", "add", "route", ip+"/32", networkInterface, defaultGateway, "store=active")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("Failed to execute command: %v, Output: %s", err, output)
	}
	return nil
}

func delRoute(ip string, networkInterface string, defaultGateway string) error {
	cmd := exec.Command("netsh", "interface", "ipv4", "delete", "route", ip+"/32", networkInterface, defaultGateway, "store=active")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("Failed to execute command: %v, Output: %s", err, output)
	}
	return nil
}

func getCurrentRoutes() (routes []*RouteEntry, err error) {
	cmd := exec.Command("cmd", "/c", "chcp", "437", "&&", "route", "print", "-4")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	output, err := cmd.CombinedOutput()
	if err != nil {
		err = fmt.Errorf("Failed to execute command: %v, Output: %s", err, output)
		return
	}
	routes = []*RouteEntry{}
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) >= 5 {
			defaultDateway := fields[2]
			gatewayIP := net.ParseIP(defaultDateway)
			if gatewayIP == nil {
				continue
			}
			maskStr := fields[1]
			maskBytes := net.ParseIP(maskStr).To4()
			mask := net.IPv4Mask(maskBytes[0], maskBytes[1], maskBytes[2], maskBytes[3])
			ones, _ := mask.Size()
			cidrStr := fmt.Sprintf("%s/%d", fields[0], ones)
			ip, _, nerr := net.ParseCIDR(cidrStr)
			if nerr != nil {
				err = fmt.Errorf("Failed to parse CIDR: %v, Input: %s", nerr, cidrStr)
				return
			}
			routes = append(routes, &RouteEntry{IP: ip, Mask: mask, DefaultGateway: defaultDateway})
		}
	}
	return
}

type NetAdapter struct {
	Name           string `json:"Name"`
	InterfaceIndex int    `json:"InterfaceIndex"`
}

type IPAddress struct {
	IPAddress string `json:"IPAddress"`
}

type NetAdapterConfiguration struct {
	Index          int         `json:"Index"`
	IPAddress      []IPAddress `json:"IPAddress"`
	DefaultGateway string      `json:"DefaultGateway"`
}

func getInterfaceInfo(interfaceName string) (ipAddress string, defaultGateway string, err error) {

	psCommand := fmt.Sprintf(`$ErrorActionPreference = 'Stop'
$interface = Get-NetAdapter -Name "%s"
$ifIndex = $interface.ifIndex
$ipProps = Get-NetIPConfiguration -InterfaceIndex $ifIndex
$ipAddress = $ipProps.IPv4Address.IPAddress
$defaultGateway = $ipProps.IPv4DefaultGateway.NextHop
@{
	"IPAddress" = $ipAddress
	"DefaultGateway" = $defaultGateway
} | ConvertTo-Json`, interfaceName)

	cmd := exec.Command("powershell", "-Command", psCommand)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	var out bytes.Buffer
	cmd.Stdout = &out
	err = cmd.Run()
	if err != nil {
		return
	}

	type NetInterface struct {
		IPAddress      string
		DefaultGateway string
	}
	var data NetInterface
	err = json.Unmarshal([]byte(strings.TrimSpace(out.String())), &data)
	if err != nil {
		return
	}

	if data.IPAddress == "" || data.DefaultGateway == "" {
		err = fmt.Errorf("could not find IP address or gateway for interface: %s", interfaceName)
		return
	}
	ipAddress = data.IPAddress
	defaultGateway = data.DefaultGateway
	return
}

func ClearRoutes(networkInterface string, domains []string) { // Get the current routing table
	routes, err := getCurrentRoutes()
	if err != nil {
		log.Fatalf("Failed to get current routing table: %v", err)
	}

	// Resolve IP addresses for the provided domain list
	for _, domain := range domains {
		ips, err := net.LookupIP(domain)
		if err != nil {
			log.Printf("Error resolving domain %s: %v", domain, err)
			continue
		}
		for _, route := range routes {
			for _, ip := range ips {
				ipStr := ip.String()
				if ipStr+"/32" == route.CIDR() {
					err = delRoute(ipStr, networkInterface, route.DefaultGateway)
					if err != nil {
						log.Printf("Failed to del route for IP address %s/32 - %s (%s): %v", ipStr, route.DefaultGateway, domain, err)
					} else {
						log.Printf("Successfully deleted route for IP address %s/32 - %s (%s)", ipStr, route.DefaultGateway, domain)
					}
				}
			}
		}
	}
}
