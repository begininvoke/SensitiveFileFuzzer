<!-- PROJECT SHIELDS -->
<!--
*** I'm using markdown "reference style" links for readability.
*** Reference links are enclosed in brackets [ ] instead of parentheses ( ).
*** See the bottom of this document for the declaration of the reference variables
*** for contributors-url, forks-url, etc. This is an optional, concise syntax you may use.
*** https://www.markdownguide.org/basic-syntax/#reference-style-links
-->
[![Contributors][contributors-shield]][contributors-url]
[![Forks][forks-shield]][forks-url]
[![Stargazers][stars-shield]][stars-url]
[![Issues][issues-shield]][issues-url]
[![MIT License][license-shield]][license-url]
[![LinkedIn][linkedin-shield]][linkedin-url]
# Sensitive File Founder on WebSite

A tool for fuzzing files on the website
Included shell[[webbackdor]] file name list {--shell}, .env file list {--env}, git file list{--git} and sensitive file list {--sens}

## Usage

```bash
git clone https://github.com/begininvoke/SensitiveFileFuzzer.git
cd SensitiveFileFuzzer
go build
./SensitiveFileFuzzer -url https://site.com --shell
```
## Help
```bash
./SensitiveFileFuzzer -h
Usage of ./SensitiveFile:
  -all
        try all lists
  -env
        try env lists
  -git
        try git lists
  -sens
        try sens lists
  -shell
        try shellfile lists
  -url string
        url address https://google.com
  -v    show success result  only
```
## config
To avoid mistakes you can enter custom settings for each route
Sample config :--cached
```json
{
  "path" : "/test.txt",
  "content" : "#application/json#text/html",
  "lentgh" : "*"

}
```


Content-Type:

content : "*" allow all responsegit and any header sets

content : "#application/json#text/html"  all headers except (text/html , application/json) which are separated by #

content : "application/json"  allow just application/json in response header

Content-Length:
lentgh : 10  allow response header Content-Length >= 10 

## Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

Please make sure to update tests as appropriate.

## License
[MIT](https://choosealicense.com/licenses/mit/)