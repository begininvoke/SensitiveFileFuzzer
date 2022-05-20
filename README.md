Sensitive File Founder on WebSite



To avoid mistakes you can enter custom settings for each route
Sample config :

{
  "path" : "/test.txt",
  "content" : "#application/json#text/html",
  "lentgh" : "*"

}


Content-Type:

content : "*" allow all responsgie and any header sets

content : "#application/json#text/html"  all headers except (text/html , application/json) which are separated by #

content : "application/json"  allow just application/json in response header


Content-Length:
lentgh : 10  allow response header Content-Length >= 10 