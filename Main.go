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
)

var justsuccess bool = false
var successlist []string
var httpcc http.Client

func main() {

	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

	address := flag.String("url", "", "url address https://google.com")
	configfile := flag.String("config", "", "config json file path ")
	gitfile := flag.Bool("git", false, "try git lists")
	Sensfile := flag.Bool("sens", false, "try sens lists")
	Envfile := flag.Bool("env", false, "try env lists")
	Shellfile := flag.Bool("shell", false, "try shellfile lists")
	Allfile := flag.Bool("all", false, "try all lists")
	success := flag.Bool("v", false, "show success result  only")
	flag.Parse()
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
	ex, err := os.Executable()
	if err != nil {
		panic(err)
	}
	exPath := filepath.Dir(ex)

	configfilepath := exPath + "/SensitiveList.json"
	if *configfile != "" {
		configfilepath = *configfile
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
			checkurl(*address+paths.Git[i].Path, paths.Git[i].Content, paths.Git[i].Lentgh)
		}
	}
	if *Sensfile {
		for i := 0; i < len(paths.Sensitive); i++ {
			checkurl(*address+paths.Sensitive[i].Path, paths.Sensitive[i].Content, paths.Sensitive[i].Lentgh)
		}
	}
	if *Envfile {
		for i := 0; i < len(paths.Env); i++ {
			checkurl(*address+paths.Env[i].Path, paths.Env[i].Content, paths.Env[i].Lentgh)
		}
	}
	if *Shellfile {
		for i := 0; i < len(paths.Shell); i++ {
			checkurl(*address+paths.Shell[i].Path, paths.Shell[i].Content, paths.Shell[i].Lentgh)
		}
	}
	fmt.Printf("%d  %s", len(successlist), " Found")

	if len(successlist) > 0 {

		for _, v := range successlist {
			println(v)
		}
	}

}

func checkurl(url string, content string, len string) {

	resp, err := httpcc.Head(url)

	if err != nil {
		if strings.Contains(err.Error(), "http: server gave HTTP response to HTTPS clien") {
			os.Exit(3)
		}
		println(err.Error())

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
						successlist = append(successlist, url)
					} else {
						lennumber, err := strconv.ParseInt(len, 0, 64)
						if err == nil {
							if lennumber >= resp.ContentLength {
								fmt.Printf("Success '%s', '%s', '%s',\n", url, resp.Status, resp.Header.Get("Content-Type"))
								successlist = append(successlist, url)
							}
						}

					}

				}

			}

		} else {
			//fmt.Printf("'%s', '%s',\n", url, resp.Status)
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
