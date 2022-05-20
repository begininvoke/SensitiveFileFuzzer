# Sensitive File Founder on WebSite

Foobar is a Python library for dealing with word pluralization.

## Usage

Use the package manager [pip](https://pip.pypa.io/en/stable/) to install foobar.

```bash
git clone https://github.com/begininvoke/SensitiveFileFuzzer.git
cd SensitiveFileFuzzer
go build
./SensitiveFileFuzzer -url https://site.com --shell
```
## config
To avoid mistakes you can enter custom settings for each route
Sample config :
```json
{
  "path" : "/test.txt",
  "content" : "#application/json#text/html",
  "lentgh" : "*"

}
```


Content-Type:

content : "*" allow all responsgie and any header sets

content : "#application/json#text/html"  all headers except (text/html , application/json) which are separated by #

content : "application/json"  allow just application/json in response header

Content-Length:
lentgh : 10  allow response header Content-Length >= 10 

## Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

Please make sure to update tests as appropriate.

## License
[MIT](https://choosealicense.com/licenses/mit/)