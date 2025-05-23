package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

type ASNResponse struct {
	ASN          int      `json:"asn"`
	Org          string   `json:"org"`
	Prefixes     []string `json:"prefixes"`
	PrefixesIPv6 []string `json:"prefixesIPv6"`
}

type IPResponse struct {
	ASN struct {
		ASN   int    `json:"asn"`
		Org   string `json:"org"`
		Route string `json:"route"`
	} `json:"asn"`
}

type Result struct {
	ASN   string   `json:"asn"`
	Owner string   `json:"owner"`
	CIDR  []string `json:"cidr,omitempty"`
}

var jsonOutput bool
var ipv4Only bool
var ipv6Only bool
var asOnly bool

func main() {
	var rootCmd = &cobra.Command{
		Use:   "asntool [query]",
		Short: "Get ASN, owner, and CIDR for IP, domain, or ASN",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			if ipv4Only && ipv6Only {
				log.Fatal("Error: flags -4 and -6 are mutually exclusive")
			}
			query := args[0]
			result, err := processQuery(query)
			if err != nil {
				log.Fatalf("Error: %v", err)
			}
			printResult(result)
		},
	}
	rootCmd.Flags().BoolVarP(&jsonOutput, "json", "j", false, "Output in JSON format")
	rootCmd.Flags().BoolVarP(&ipv4Only, "4", "4", false, "Show only IPv4 prefixes")
	rootCmd.Flags().BoolVarP(&ipv6Only, "6", "6", false, "Show only IPv6 prefixes")
	rootCmd.Flags().BoolVarP(&asOnly, "a", "a", false, "Show only ASN and owner (no CIDRs)")
	if err := rootCmd.Execute(); err != nil {
		log.Fatal(err)
	}
}

func resolveDomain(domain string) (string, error) {
	ips, err := net.LookupIP(domain)
	if err != nil {
		return "", fmt.Errorf("failed to resolve domain %s: %v", domain, err)
	}
	for _, ip := range ips {
		if ip.To4() != nil {
			return ip.String(), nil
		}
	}
	return "", fmt.Errorf("no IPv4 found for domain %s", domain)
}

func cleanASN(asn string) (string, error) {
	asn = strings.ToLower(asn)
	if strings.HasPrefix(asn, "as") {
		asn = asn[2:]
	}
	if _, err := strconv.Atoi(asn); err != nil {
		return "", fmt.Errorf("invalid ASN format: %s", asn)
	}
	return asn, nil
}

func stripURL(input string) string {
	input = strings.TrimSpace(input)

	re := regexp.MustCompile(`^(?:https?://)?(?:www\.)?([^/:\s]+)`)
	match := re.FindStringSubmatch(input)
	if len(match) > 1 {
		return match[1]
	}
	return input
}

func isValidIP(ip string) bool {
	ipv4Regex := regexp.MustCompile(`^(?:\d{1,3}\.){3}\d{1,3}$`)
	ipv6Regex := regexp.MustCompile(`^[0-9a-fA-F:]+$`)
	return ipv4Regex.MatchString(ip) || ipv6Regex.MatchString(ip)
}

func fetchIPInfo(ip string) (*Result, error) {
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get("https://api.ipapi.is?q=" + ip)
	if err != nil {
		return nil, fmt.Errorf("error fetching IP %s: %v", ip, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API request failed for IP %s: status %d", ip, resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading response for IP %s: %v", ip, err)
	}

	var ipResp IPResponse
	if err := json.Unmarshal(body, &ipResp); err != nil {
		return nil, fmt.Errorf("error parsing IP response for %s: %v", ip, err)
	}

	if ipResp.ASN.ASN == 0 {
		return nil, fmt.Errorf("no ASN data for IP %s", ip)
	}

	return &Result{
		ASN:   strconv.Itoa(ipResp.ASN.ASN),
		Owner: ipResp.ASN.Org,
		CIDR:  []string{ipResp.ASN.Route},
	}, nil
}

func fetchASNInfo(asn string) (*Result, error) {
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get("https://api.ipapi.is?q=AS" + asn)
	if err != nil {
		return nil, fmt.Errorf("error fetching AS%s: %v", asn, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API request failed for AS%s: status %d", asn, resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading response for AS%s: %v", asn, err)
	}

	var asnResp ASNResponse
	if err := json.Unmarshal(body, &asnResp); err != nil {
		return nil, fmt.Errorf("error parsing ASN response for AS%s: %v", asn, err)
	}

	var cidr []string
	if ipv6Only {
		cidr = asnResp.PrefixesIPv6
	} else if ipv4Only {
		cidr = asnResp.Prefixes
	} else {
		cidr = append(asnResp.Prefixes, asnResp.PrefixesIPv6...)
	}
	if len(cidr) == 0 {
		log.Printf("Warning: No prefixes for AS%s, returning empty CIDR", asn)
	}

	return &Result{
		ASN:   "AS" + asn,
		Owner: asnResp.Org,
		CIDR:  cidr,
	}, nil
}

func processQuery(query string) (*Result, error) {
	query = stripURL(query)

	if strings.ToLower(query[:2]) == "as" || regexp.MustCompile(`^\d+$`).MatchString(query) {
		asn, err := cleanASN(query)
		if err != nil {
			return nil, err
		}
		return fetchASNInfo(asn)
	}

	if isValidIP(query) {
		ipInfo, err := fetchIPInfo(query)
		if err != nil {
			return nil, err
		}
		asnInfo, err := fetchASNInfo(ipInfo.ASN)
		if err != nil || len(asnInfo.CIDR) == 0 {
			log.Printf("Warning: No CIDR from ASN query, falling back to IP info")
			return ipInfo, nil
		}
		return asnInfo, nil
	}

	ip, err := resolveDomain(query)
	if err != nil {
		return nil, err
	}
	ipInfo, err := fetchIPInfo(ip)
	if err != nil {
		return nil, err
	}
	asnInfo, err := fetchASNInfo(ipInfo.ASN)
	if err != nil || len(asnInfo.CIDR) == 0 {
		log.Printf("Warning: No CIDR from ASN query, falling back to IP info")
		return ipInfo, nil
	}
	return asnInfo, nil
}

func printResult(result *Result) {
	if jsonOutput {
		output := map[string]string{
			"asn":   result.ASN,
			"owner": result.Owner,
		}
		if !asOnly {
			jsonBytes, _ := json.MarshalIndent(result, "", "  ")
			fmt.Println(string(jsonBytes))
		} else {
			jsonBytes, _ := json.MarshalIndent(output, "", "  ")
			fmt.Println(string(jsonBytes))
		}
	} else {
		green := color.New(color.FgGreen).SprintFunc()
		cyan := color.New(color.FgCyan).SprintFunc()
		yellow := color.New(color.FgYellow).SprintFunc()

		fmt.Printf("ASN: %s\n", green(result.ASN))
		fmt.Printf("Owner: %s\n", cyan(result.Owner))
		if !asOnly {
			fmt.Println("CIDR:")
			for _, cidr := range result.CIDR {
				if cidr != "" {
					fmt.Printf("  %s\n", yellow(cidr))
				}
			}
		}
	}
}
