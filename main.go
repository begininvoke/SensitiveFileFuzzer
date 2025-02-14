package main

import (
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
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

func init() {
	successlist = make(map[string][]string)
}

func main() {

	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

	address := flag.String("url", "", "URL to scan (e.g., https://example.com)")
	format := flag.String("f", "", "output format: json or csv")
	outDir := flag.String("o", "", "output directory path")
	gitfile := flag.Bool("git", false, "scan git-related files")
	Sensfile := flag.Bool("sens", false, "try sens lists")
	Envfile := flag.Bool("env", false, "try env lists")
	Shellfile := flag.Bool("shell", false, "try shellfile lists")
	Allfile := flag.Bool("all", false, "try all lists")
	success := flag.Bool("v", false, "show success result  only")
	flag.Parse()
	formatType = *format
	outputDir = *outDir
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
	//ex, err := os.Executable()
	//if err != nil {
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

	httpcc = http.Client{Jar: jar}
	if *gitfile {
		for i := 0; i < len(paths.Git); i++ {
			checkurl(*address+paths.Git[i].Path, paths.Git[i].Content, paths.Git[i].Lentgh, "Git")
		}
	}
	if *Sensfile {
		for i := 0; i < len(paths.Sensitive); i++ {
			checkurl(*address+paths.Sensitive[i].Path, paths.Sensitive[i].Content, paths.Sensitive[i].Lentgh, "Sensitive")
		}
	}
	if *Envfile {
		for i := 0; i < len(paths.Env); i++ {
			checkurl(*address+paths.Env[i].Path, paths.Env[i].Content, paths.Env[i].Lentgh, "Env")
		}
	}
	if *Shellfile {
		for i := 0; i < len(paths.Shell); i++ {
			checkurl(*address+paths.Shell[i].Path, paths.Shell[i].Content, paths.Shell[i].Lentgh, "Shell")
		}
	}

	totalFiles := 0
	for _, files := range successlist {
		totalFiles += len(files)
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
	// Set timeout of 20 seconds
	httpcc.Timeout = 20 * time.Second

	resp, err := httpcc.Head(url)

	if err != nil {
		println(err.Error())
		if strings.Contains(err.Error(), "http: server gave HTTP response to HTTPS clien") {
			os.Exit(3)
		}
		if strings.Contains(err.Error(), "timeout") {
			fmt.Printf("Timeout occurred while checking '%s'\n", url)
			return
		}

		resp, err = httpcc.Get(url)

	}
	if err == nil {
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
					if len == "*" {
						fmt.Printf("Success '%s', '%s', '%s',\n", url, resp.Status, resp.Header.Get("Content-Type"))
						if _, exists := successlist[category]; !exists {
							successlist[category] = []string{}
						}
						successlist[category] = append(successlist[category], url)
					} else {
						lennumber, err := strconv.ParseInt(len, 0, 64)
						if err == nil {
							if lennumber >= resp.ContentLength {
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
	Env       []Sensitive `json:Env`
	Shell     []Sensitive `json:shell`
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
