package main

import (
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/cookiejar"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

var justsuccess bool = false
var successlist map[string][]string
var httpcc http.Client
var formatType string
var outputDir string
var rateLimiter chan struct{}

// Timeout handling: abort the whole scan after too many consecutive timeouts
// (host likely went down), resetting the counter whenever a request succeeds.
var scanTimeout time.Duration = 20 * time.Second
var maxConsecutiveTimeouts int = 3
var consecutiveTimeouts int = 0
var scanAborted bool = false

// baselineSignature describes the 200-response a site returns for a path that
// should NOT exist (soft-404 / SPA catch-all / wildcard routing).
type baselineSignature struct {
	BodySize    int64
	ContentType string
}

// baselines holds the fingerprints of "false" paths probed before scanning.
// A real hit that matches any of these is treated as a false positive.
var baselines []baselineSignature

func init() {
	successlist = make(map[string][]string)
}

func initRateLimiter(requestsPerSecond int) {
	rateLimiter = make(chan struct{}, requestsPerSecond)

	// Fill the channel initially
	for i := 0; i < requestsPerSecond; i++ {
		rateLimiter <- struct{}{}
	}

	// Start a goroutine to refill tokens at the specified rate
	go func() {
		ticker := time.NewTicker(time.Second / time.Duration(requestsPerSecond))
		defer ticker.Stop()
		for range ticker.C {
			select {
			case rateLimiter <- struct{}{}:
			default:
				// Channel is full, skip
			}
		}
	}()
}

func main() {

	address := flag.String("url", "", "URL to scan (e.g., https://example.com)")
	format := flag.String("f", "", "output format: json or csv")
	outDir := flag.String("o", "", "output directory path")
	gitfile := flag.Bool("git", false, "scan git-related files")
	Sensfile := flag.Bool("sens", false, "try sens lists")
	Envfile := flag.Bool("env", false, "try env lists")
	Shellfile := flag.Bool("shell", false, "try shellfile lists")
	Allfile := flag.Bool("all", false, "try all lists")
	success := flag.Bool("v", false, "show success result  only")
	rateLimit := flag.Int("rate", 0, "rate limit: requests per second (0 = no limit)")
	timeoutSec := flag.Int("timeout", 20, "per-request timeout in seconds")
	maxTimeouts := flag.Int("maxtimeouts", 3, "abort scan after this many consecutive timeouts")
	flag.Parse()
	formatType = *format
	outputDir = *outDir
	if *timeoutSec > 0 {
		scanTimeout = time.Duration(*timeoutSec) * time.Second
	}
	if *maxTimeouts > 0 {
		maxConsecutiveTimeouts = *maxTimeouts
	}
	if !*gitfile && !*Sensfile && !*Envfile && !*Shellfile {

		*Allfile = true
	}
	if *Allfile {
		*gitfile = true
		*Sensfile = true
		*gitfile = true
		*Envfile = true
	}
	if *success {
		justsuccess = true
	}
	if *address == "" {
		println("please set url with --url or -h for help")
		return
	}

	// Add site availability check
	if !checkSiteIsUp(*address) {
		fmt.Printf("🚨 Host %s is unreachable, aborting scan\n", *address)
		return
	}

	//ex, err := os.Executable()
	//if err != nil {go
	//	panic(err)
	//}
	//exPath := filepath.Dir(ex)
	appPath, err := os.Executable()
	if err != nil {
		fmt.Printf("Failed to get application path: %v\n", err)
		return
	}
	appDir := filepath.Dir(appPath) // Directory where the application is running

	// Default paths
	defaultLocalPath := filepath.Join(appDir, "SensitiveList.json") // ./SensitiveList.json
	defaultGlobalPath := "/usr/local/bin/SensitiveList.json"        // /usr/local/bin/SensitiveList.json
	// Check if the file exists in the application's directory
	configfilepath := defaultLocalPath
	if _, err := os.Stat(configfilepath); os.IsNotExist(err) {
		// If not found in the app directory, fall back to /usr/local/bin
		fmt.Printf("SensitiveList.json not found in %s, trying %s\n", appDir, defaultGlobalPath)
		configfilepath = defaultGlobalPath
	}

	jsonFile, err := os.Open(configfilepath)
	if err != nil {
		fmt.Printf("%s", "Can not read json file")
	}
	byteValue, _ := ioutil.ReadAll(jsonFile)

	// we initialize our Users array
	paths := SensitiveList{}

	// we unmarshal our byteArray which contains our
	// jsonFile's content into 'users' which we defined above
	json.Unmarshal(byteValue, &paths)
	defer jsonFile.Close()
	jar, err := cookiejar.New(nil)
	if err != nil {
		println(err.Error())
	}

	httpcc = http.Client{
		Jar: jar,
		Transport: &http.Transport{
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
			DisableKeepAlives: true,
		},
	}

	// Initialize rate limiter if specified
	if *rateLimit > 0 {
		initRateLimiter(*rateLimit)
		fmt.Printf("⚡ Rate limit set to %d requests/second\n", *rateLimit)
	}

	// Establish a false-positive baseline: probe paths that should never exist.
	// If the site answers 200 for them, record the signature so real hits that
	// look identical can be discarded as false positives.
	establishBaseline(*address)

	if *gitfile {
		for i := 0; i < len(paths.Git); i++ {
			if scanAborted {
				break
			}
			checkurl(*address+paths.Git[i].Path, paths.Git[i].Content, paths.Git[i].Lentgh, "Git")
		}
	}
	if *Sensfile {
		for i := 0; i < len(paths.Sensitive); i++ {
			if scanAborted {
				break
			}
			checkurl(*address+paths.Sensitive[i].Path, paths.Sensitive[i].Content, paths.Sensitive[i].Lentgh, "Sensitive")
		}
	}
	if *Envfile {
		for i := 0; i < len(paths.Env); i++ {
			if scanAborted {
				break
			}
			checkurl(*address+paths.Env[i].Path, paths.Env[i].Content, paths.Env[i].Lentgh, "Env")
		}
	}
	if *Shellfile {
		for i := 0; i < len(paths.Shell); i++ {
			if scanAborted {
				break
			}
			checkurl(*address+paths.Shell[i].Path, paths.Shell[i].Content, paths.Shell[i].Lentgh, "Shell")
		}
	}

	switch formatType {
	case "json":
		writeJSONOutput(successlist, outputDir)
	case "csv":
		writeCSVOutput(successlist, outputDir)
	default:
		printResults(successlist)
	}

}

func checkurl(url string, content string, len string, category string) {
	if scanAborted {
		return
	}
	// Apply rate limiting if enabled
	if rateLimiter != nil {
		<-rateLimiter // Wait for a token
	}

	// Set the per-request timeout
	httpcc.Timeout = scanTimeout

	resp, err := httpcc.Head(url)

	if err != nil {
		//println(err.Error())
		if strings.Contains(err.Error(), "http: server gave HTTP response to HTTPS clien") {
			os.Exit(3)
		}
		if isTimeout(err) {
			registerTimeout(url)
			return
		}

		resp, err = httpcc.Get(url)
		if err != nil {
			if isTimeout(err) {
				registerTimeout(url)
			}
			return
		}
	}
	if err == nil {
		// A response came back: the host is alive, so reset the timeout counter.
		consecutiveTimeouts = 0
		if !justsuccess {
			fmt.Printf("Checking '%s', '%s',\n", url, resp.Status)
		}
		if resp.StatusCode == 200 {
			if resp.Header.Get("Content-Type") != "" {
				respcontetnt := resp.Header.Get("Content-Type")
				var ignore []string = []string{}
				if strings.Contains(content, "#") {
					arrayslpit := strings.Split(content, "#")
					for _, i := range arrayslpit {
						if i != "" {
							ignore = append(ignore, i)
						}
					}
				}

				if respcontetnt == content || content == "*" || checkifinarry(ignore, respcontetnt) {
					// Fetch the real body so we can measure its size accurately
					// (HEAD often omits Content-Length) and compare it against the
					// false-positive baseline.
					bodySize, bodyContentType := fetchBody(url)
					if bodyContentType == "" {
						bodyContentType = respcontetnt
					}

					// Discard hits that look identical to a known-false path.
					if isFalsePositive(bodySize, bodyContentType) {
						if !justsuccess {
							fmt.Printf("False positive (matches baseline) '%s', size=%d, '%s'\n", url, bodySize, bodyContentType)
						}
						return
					}

					if len == "*" {
						fmt.Printf("Success '%s', '%s', '%s',\n", url, resp.Status, resp.Header.Get("Content-Type"))
						if _, exists := successlist[category]; !exists {
							successlist[category] = []string{}
						}
						successlist[category] = append(successlist[category], url)
					} else {
						lennumber, err := strconv.ParseInt(len, 0, 64)
						if err == nil {
							if lennumber >= bodySize {
								fmt.Printf("Success '%s', '%s', '%s',\n", url, resp.Status, resp.Header.Get("Content-Type"))
								if _, exists := successlist[category]; !exists {
									successlist[category] = []string{}
								}
								successlist[category] = append(successlist[category], url)
							}
						}
					}
				}
			}
		} else {

		}
	}
}

// isTimeout reports whether an error is a request timeout. It handles both the
// typed net.Error case and the client-timeout ("context deadline exceeded")
// message string, which the plain lowercase "timeout" check used to miss.
func isTimeout(err error) bool {
	if err == nil {
		return false
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "timeout") || strings.Contains(msg, "deadline exceeded")
}

// registerTimeout records a timeout and aborts the scan once too many happen
// consecutively (the counter is reset elsewhere whenever a request succeeds).
func registerTimeout(url string) {
	consecutiveTimeouts++
	fmt.Printf("⏱️  Timeout while checking '%s' (%d/%d consecutive)\n", url, consecutiveTimeouts, maxConsecutiveTimeouts)
	if consecutiveTimeouts >= maxConsecutiveTimeouts {
		scanAborted = true
		fmt.Printf("🚨 %d consecutive timeouts reached — aborting scan\n", maxConsecutiveTimeouts)
	}
}

// fetchBody performs a GET and returns the actual body size (in bytes) and the
// Content-Type header. Returns (-1, "") if the request fails.
func fetchBody(url string) (int64, string) {
	if rateLimiter != nil {
		<-rateLimiter
	}
	resp, err := httpcc.Get(url)
	if err != nil {
		return -1, ""
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return -1, resp.Header.Get("Content-Type")
	}
	return int64(len(body)), resp.Header.Get("Content-Type")
}

// randomString returns a random hex string of the given byte length.
func randomString(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		// Fall back to a fixed token; still very unlikely to exist as a path.
		return "znonexistentznonexistentz"
	}
	return hex.EncodeToString(b)
}

// establishBaseline probes several paths that should never exist. Any that
// answer 200 are fingerprinted (body size + content-type) so that real hits
// which look identical can be flagged as false positives.
func establishBaseline(address string) {
	base := strings.TrimRight(address, "/")
	token := randomString(16)
	probes := []string{
		base + "/" + token + ".html",
		base + "/" + token,
		base + "/js/" + token + ".env",
		base + "/" + token + "/" + token + ".php",
	}

	for _, p := range probes {
		if rateLimiter != nil {
			<-rateLimiter
		}
		resp, err := httpcc.Get(p)
		if err != nil {
			continue
		}
		body, _ := ioutil.ReadAll(resp.Body)
		ct := resp.Header.Get("Content-Type")
		sc := resp.StatusCode
		resp.Body.Close()

		if sc == 200 {
			sig := baselineSignature{BodySize: int64(len(body)), ContentType: ct}
			if !hasBaseline(sig) {
				baselines = append(baselines, sig)
			}
		}
	}

	if len(baselines) > 0 {
		fmt.Printf("⚠️  Site returns 200 for non-existent paths (soft-404). Recorded %d baseline signature(s) for false-positive filtering:\n", len(baselines))
		for _, b := range baselines {
			fmt.Printf("   └─ size=%d bytes, content-type=%s\n", b.BodySize, b.ContentType)
		}
	}
}

// hasBaseline reports whether an equivalent signature is already recorded.
func hasBaseline(sig baselineSignature) bool {
	for _, b := range baselines {
		if b.ContentType == sig.ContentType && b.BodySize == sig.BodySize {
			return true
		}
	}
	return false
}

// isFalsePositive reports whether a hit's body size and content-type match any
// recorded baseline signature closely enough to be considered a false positive.
// Bodies match when the content-type is identical and the size is within ~2%
// (or 16 bytes) of the baseline, tolerating tiny dynamic differences.
func isFalsePositive(bodySize int64, contentType string) bool {
	if len(baselines) == 0 || bodySize < 0 {
		return false
	}
	for _, b := range baselines {
		if !sameContentType(b.ContentType, contentType) {
			continue
		}
		diff := bodySize - b.BodySize
		if diff < 0 {
			diff = -diff
		}
		tolerance := b.BodySize / 50 // 2%
		if tolerance < 16 {
			tolerance = 16
		}
		if diff <= tolerance {
			return true
		}
	}
	return false
}

// sameContentType compares content-type headers ignoring charset/parameters.
func sameContentType(a, b string) bool {
	norm := func(s string) string {
		if i := strings.Index(s, ";"); i >= 0 {
			s = s[:i]
		}
		return strings.TrimSpace(strings.ToLower(s))
	}
	return norm(a) == norm(b)
}
func checkifinarry(array []string, check string) bool {
	if len(array) == 0 {
		return false
	}
	for _, i2 := range array {
		if strings.Contains(check, i2) {
			return false
		}
	}
	return true
}

type Sensitive struct {
	Path    string `json:"path"`
	Content string `json:"content"`
	Lentgh  string `json:"lentgh"`
}
type SensitiveList struct {
	Sensitive []Sensitive `json:"Sensitive"`
	Git       []Sensitive `json:"Gitfile"`
	Env       []Sensitive `json:"Env"`
	Shell     []Sensitive `json:"Shell"`
}

func writeJSONOutput(results map[string][]string, outputDir string) {
	output := struct {
		TotalCount int                 `json:"total_count"`
		Categories map[string][]string `json:"categories"`
		Summary    map[string]int      `json:"summary"`
	}{
		Categories: results,
		Summary:    make(map[string]int),
	}

	for category, files := range results {
		output.Summary[category] = len(files)
		output.TotalCount += len(files)
	}

	jsonData, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		fmt.Printf("Error creating JSON output: %v\n", err)
		return
	}

	if outputDir != "" {
		// Create directory if it doesn't exist
		dir := filepath.Dir(outputDir)
		if err := os.MkdirAll(dir, 0755); err != nil {
			fmt.Printf("Error creating directory: %v\n", err)
			return
		}

		// Use outputDir directly as it contains the filename
		if err := os.WriteFile(outputDir, jsonData, 0644); err != nil {
			fmt.Printf("Error writing JSON file: %v\n", err)
			return
		}
		fmt.Printf("📝 Results saved to: %s\n", outputDir)
	} else {
		fmt.Println(string(jsonData))
	}
}

func writeCSVOutput(results map[string][]string, outputDir string) {
	var output strings.Builder
	output.WriteString("Category,URL\n")

	for category, urls := range results {
		for _, url := range urls {
			output.WriteString(fmt.Sprintf("%s,%s\n", category, url))
		}
	}

	if outputDir != "" {
		// Create directory if it doesn't exist
		dir := filepath.Dir(outputDir)
		if err := os.MkdirAll(dir, 0755); err != nil {
			fmt.Printf("Error creating directory: %v\n", err)
			return
		}

		// Use outputDir directly as it contains the filename
		if err := os.WriteFile(outputDir, []byte(output.String()), 0644); err != nil {
			fmt.Printf("Error writing CSV file: %v\n", err)
			return
		}
		fmt.Printf("📝 Results saved to: %s\n", outputDir)
	} else {
		fmt.Print(output.String())
	}
}

func printResults(results map[string][]string) {
	totalFiles := 0
	for _, files := range results {
		totalFiles += len(files)
	}

	fmt.Printf("\n🎯 Found %d sensitive files:\n\n", totalFiles)

	for category, urls := range results {
		fmt.Printf("📁 %s (%d files):\n", category, len(urls))
		for _, url := range urls {
			fmt.Printf("  └─ %s\n", url)
		}
		fmt.Println()
	}
}

// Add new function for site availability check
func checkSiteIsUp(url string) bool {
	client := &http.Client{
		Timeout: scanTimeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	resp, err := client.Head(url)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	// Consider any 2xx/3xx status as "up"
	if resp.StatusCode >= 200 && resp.StatusCode < 501 {
		fmt.Printf("✅ Host is reachable (%s)\n", resp.Status)
		return true
	}
	return false
}
