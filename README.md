# Search Operators Dorks

Search operators, also known as dorks, are not limited to just Google, Shodan, and Censys. They can be used in various search engines, databases, and websites to refine and narrow down search results. Here are some examples of search operators and dorks that can be used in different contexts:

- Github: "filename:", "extension:", "path:", "language:", "repo:", "user:"
- Bing: "contains:", "filetype:", "instreamset:", "inurl:", "intitle:", "ip:"
- DuckDuckGo: "site:", "inurl:", "intitle:", "filetype:", "language:", "license:"
- Pastebin: "username:", "title:", "expiry:", "hits:", "password:", "email:"
- Twitter: "from:", "to:", "mention:", "since:", "until:", "filter:"
- LinkedIn: "title:", "company:", "school:", "location:", "industry:", "language:"

By using search operators and dorks, users can effectively and efficiently search for specific information and data in different contexts.

## Google

Search operators or dorks are special commands or keywords that can be used to refine and narrow down search results in Google. These operators can be used to search for specific types of files, search within a particular website, exclude certain words from the search, and more. Some examples of Google search operators include "site:", "filetype:", "intitle:", "inurl:", and "related:". These search operators can be combined in various ways to create more specific and targeted search queries.

- ```site:``` - This operator allows you to search for results within a specific website or domain. For example, ```site:wikipedia.org artificial intelligence``` will only return results related to artificial intelligence on Wikipedia.
- ```intext:``` - This operator will search for keywords within the body text of a page. For example, ```intext:password filetype:txt``` will return results for files with the keyword ```password``` in the body text and with the extension ```.txt```.
- ```inurl:``` - This operator will search for keywords within the URL of a page. For example, ```inurl:login``` will return results for pages with ```login``` in the URL.
- ```filetype:``` - This operator will search for specific file types. For example, ```filetype:pdf artificial intelligence``` will return results for PDF files related to artificial intelligence.
- ```intitle:``` - This operator will search for keywords within the title of a page. For example, ```intitle:password``` will return results for pages with ```password``` in the title.
- ```related:``` - This operator will find pages related to a specific website. For example, ```related:wikipedia.org``` will return results for websites related to Wikipedia.
- ```cache:``` - This operator will display the cached version of a page. For example, ```cache:wikipedia.org``` will display the cached version of the Wikipedia homepage.
- ```info:``` - This operator will display information about a specific website. For example, ```info:wikipedia.org``` will display information about the Wikipedia website.
- ```define:``` - This operator will display definitions for a specific word. For example, ```define: artificial intelligence``` will display definitions for the term ```artificial intelligence```.
- ```allintitle:``` - This operator will search for multiple keywords within the title of a page. For example, ```allintitle: password login``` will return results for pages with both ```password``` and ```login``` in the title.
- ```allinurl:``` - This operator will search for multiple keywords within the URL of a page. For example, ```allinurl: login password``` will return results for pages with both ```login``` and ```password``` in the URL.
- ```site:example.com intext:keyword``` - This operator will search for results within a specific website or domain, with specific keywords within the body text of a page. For example, ```site:wikipedia.org intext:artificial intelligence``` will only return results related to artificial intelligence on Wikipedia with the keyword ```artificial intelligence``` in the body text.
- ```site:example.com inurl:keyword``` - This operator will search for results within a specific website or domain, with specific keywords within the URL of a page. For example, ```site:wikipedia.org inurl:artificial intelligence``` will only return results related to artificial intelligence on Wikipedia with the keyword ```artificial intelligence``` in the URL.
- ```link:``` - This operator will find pages that link to a specific URL. For example, ```link:wikipedia.org``` will return pages that link to Wikipedia.
- ```related:``` - This operator will find pages related to a specific URL. For example, ```related:google.com``` will return pages related to Google.

## Shodan

Shodan also supports search operators, which are used to specify certain search criteria when looking for Internet-connected devices and systems. Some examples of Shodan search operators include "net:", "port:", "city:", "country:", "os:", and "has_screenshot:". These operators can be used to search for specific types of devices, services, and vulnerabilities. Additionally, Shodan supports filters that can be used to refine search results, such as "after:", "before:", and "last_update:". By using a combination of search operators and filters, Shodan users can find and analyze information about Internet-connected devices in a targeted and efficient manner.

- ```asn``` - To search for hosts within a specific ASN, use the following syntax: ```asn:<ASN number>```. For example, to find hosts within the ASN 15169 (Google), you would use ```asn:15169```.
- ```city``` - To search for hosts located in a specific city, use the following syntax: ```city:<city name>```. For example, to find hosts located in San Francisco, you would use ```city:san francisco```.
- ```country``` - To search for hosts located in a specific country, use the following syntax: ```country:<2-letter country code>```. For example, to find hosts located in Japan, you would use ```country:jp```.
- ```geo``` - To search for hosts within a specific geographic location, use the following syntax: ```geo:<latitude>,<longitude>,<radius>```. For example, to find hosts within a 50-mile radius of the coordinates 37.7749° N, 122.4194° W (San Francisco), you would use ```geo:37.7749,-122.4194,50```.
- ```hostname``` - To search for hosts by their hostname, use the following syntax: ```hostname:<hostname>```. For example, to find hosts with the hostname ```example.com```, you would use ```hostname:example.com```.
- ```ip``` - To search for hosts by their IP address, use the following syntax: ```ip:<IP address>```. For example, to find hosts with the IP address 216.58.194.174 (Google), you would use ```ip:216.58.194.174```.
- ```net``` - To search for hosts within a specific network range, use the following syntax: ```net:<CIDR notation>```. For example, to find hosts within the network range 192.168.0.0/24, you would use ```net:192.168.0.0/24```.
- ```os``` - To search for hosts running a specific operating system, use the following syntax: ```os:<operating system>```. For example, to find hosts running Windows 10, you would use ```os:windows 10```.
- ```port``` - To search for hosts with a specific open port, use the following syntax: ```port:<port number>```. For example, to find hosts with port 80 (HTTP) open, you would use ```port:80```.
- ```http.component``` - To search for web servers running a specific HTTP component, use the following syntax: ```http.component:<component name>```. For example, to find web servers running Apache, you would use ```http.component:apache```.
- ```ssl``` - To search for hosts with SSL enabled, use the following syntax: ```ssl:true```. For example, to find hosts with SSL enabled, you would use ```ssl:true```.
- ```org``` - To search for hosts within a specific organization, use the following syntax: ```org:<organization name>```. For example, to find hosts within the organization Google, you would use ```org:Google```.
- ```product``` - To search for hosts running a specific product, use the following syntax: ```product:<product name>```. For example, to find hosts running Apache Tomcat, you would use ```product:Apache Tomcat```.
- ```after``` - To search for hosts that were last seen after a specific date, use the following syntax: ```after:<date>```. For example, to find hosts that were last seen after January 1, 2022, you would use ```after:2022-01-01```.
- ```before``` - To search for hosts that were last seen before a specific date, use the following syntax: ```before:<date>```. For example, to find hosts that were last seen before January 1, 2022, you would use ```before:2022-01-01```.
- ```has_screenshot``` - To search for hosts that have a screenshot available, use the following syntax: ```has_screenshot:true```. For example, to find hosts with a screenshot available, you would use ```has_screenshot:true```.
- ```osversion``` - To search for hosts running a specific version of an operating system, use the following syntax: ```osversion:<operating system version>```. For example, to find hosts running Windows 10 version 21H1, you would use ```osversion:windows 10 21h1```.
- ```device``` - To search for hosts running a specific type of device, use the following syntax: ```device:<device type>```. For example, to find hosts running a router, you would use ```device:router```.
- ```geo``` - To search for hosts within a specific geographic location, use the following syntax: ```geo:<latitude>,<longitude>,<radius>```. For example, to find hosts within a 10-kilometer radius of New York City, you would use ```geo:40.7128,-74.0060,10```.
- ```hostname``` - To search for hosts with a specific hostname, use the following syntax: ```hostname:<hostname>```. For example, to find hosts with the hostname ```example.com```, you would use ```hostname:example.com```.
- ```http.component``` - To search for hosts running a specific HTTP component, use the following syntax: ```http.component:<component name>```. For example, to find hosts running Apache HTTP Server, you would use ```http.component:Apache httpd```.
- ```http.title``` - To search for hosts with a specific HTTP page title, use the following syntax: ```http.title:<page title>```. For example, to find hosts with the page title ```Welcome to our website```, you would use ```http.title:Welcome to our website```.
- ```http.status``` - To search for hosts with a specific HTTP status code, use the following syntax: ```http.status:<status code>```. For example, to find hosts with an HTTP status code of 404, you would use ```http.status:404```.
- ```net``` - To search for hosts within a specific network range, use the following syntax: ```net:<IP address>/<subnet mask>```. For example, to find hosts within the 192.168.1.0/24 network, you would use ```net:192.168.1.0/24```.
- ```ssl.cert.serial``` - To search for hosts with a specific SSL certificate serial number, use the following syntax: ```ssl.cert.serial:<serial number>```. For example, to find hosts with an SSL certificate serial number of 123456, you would use ```ssl.cert.serial:123456```.
- ```ssl``` - To search for hosts with SSL enabled, use the following syntax: ```ssl:<true/false>```. For example, to find hosts with SSL enabled, you would use ```ssl:true```.
- ```version``` - To search for hosts running a specific software version, use the following syntax: ```version:<version>```. For example, to find hosts running Apache version 2.4.18, you would use ```version:Apache 2.4.18```.
- ```bitcoin.ip``` - To search for Bitcoin nodes based on their IP address, use the following syntax: ```bitcoin.ip:<IP address>```. For example, to find Bitcoin nodes with the IP address 192.168.1.1, you would use ```bitcoin.ip:192.168.1.1```.
- ```bitcoin.ip_count``` - To search for Bitcoin nodes based on the number of IP addresses they have, use the following syntax: ```bitcoin.ip_count:<number of IPs>```. For example, to find Bitcoin nodes with 10 IP addresses, you would use ```bitcoin.ip_count:10```.
- ```bitcoin.port``` - To search for Bitcoin nodes based on their port number, use the following syntax: ```bitcoin.port:<port number>```. For example, to find Bitcoin nodes with port number 8333, you would use ```bitcoin.port:8333```.
- ```bitcoin.version``` - To search for Bitcoin nodes based on their software version, use the following syntax: ```bitcoin.version:<version>```. For example, to find Bitcoin nodes with software version 0.21.1, you would use ```bitcoin.version:0.21.1```.
- ```bitcoin.user_agent``` - To search for Bitcoin nodes based on their user agent string, use the following syntax: ```bitcoin.user_agent:<user agent>```. For example, to find Bitcoin nodes with the user agent string ```/Satoshi:0.21.1/```, you would use ```bitcoin.user_agent:/Satoshi:0.21.1/```.
- ```bitcoin.country``` - To search for Bitcoin nodes based on their country of origin, use the following syntax: ```bitcoin.country:<country code>```. For example, to find Bitcoin nodes from the United States, you would use ```bitcoin.country:US```.
- ```bitcoin.org``` - To search for Bitcoin nodes running on the official Bitcoin.org domain, use the following syntax: ```bitcoin.org:<true/false>```. For example, to find Bitcoin nodes running on Bitcoin.org, you would use ```bitcoin.org:true```.
- ```eth.ip``` - To search for Ethereum nodes based on their IP address, use the following syntax: ```eth.ip:<IP address>```. For example, to find Ethereum nodes with the IP address 192.168.1.1, you would use ```eth.ip:192.168.1.1```.
- ```eth.port``` - To search for Ethereum nodes based on their port number, use the following syntax: ```eth.port:<port number>```. For example, to find Ethereum nodes with port number 8545, you would use ```eth.port:8545```.
- ```http.component``` - To search for hosts running a specific HTTP component, use the following syntax: ```http.component:<component name>```. For example, to find hosts running Apache Tomcat, you would use ```http.component:Tomcat```.
- ```http.favicon.hash``` - To search for hosts based on their favicon hash, use the following syntax: ```http.favicon.hash:<favicon hash>```. For example, to find hosts with the favicon hash ```b09431d3f0e8df2dc2e89751047d0d4b```, you would use ```http.favicon.hash:b09431d3f0e8df2dc2e89751047d0d4b```.
- ```http.html``` - To search for hosts based on the content of their HTML pages, use the following syntax: ```http.html:<search term>```. For example, to find hosts with the word ```password``` in their HTML pages, you would use ```http.html:password```.
- ```http.status``` - To search for hosts based on their HTTP status code, use the following syntax: ```http.status:<status code>```. For example, to find hosts with HTTP status code 404, you would use ```http.status:404```.
- ```http.title``` - To search for hosts based on the content of their HTML title tag, use the following syntax: ```http.title:<search term>```. For example, to find hosts with the word ```login``` in their HTML title tag, you would use ```http.title:login```.
- ```http.component_category``` - To search for hosts running a specific category of HTTP component, use the following syntax: ```http.component_category:<category name>```. For example, to find hosts running web servers, you would use ```http.component_category:web-server```.
- ```ssl``` - To search for hosts with SSL/TLS certificates, use the following syntax: ```ssl:<search term>```. For example, to find hosts with SSL certificates issued by VeriSign, you would use ```ssl:issuer.verisign```.
- ```html``` - To search for hosts based on the content of their HTML pages, use the following syntax: ```html:<search term>```. For example, to find hosts with the word ```password``` in their HTML pages, you would use ```html:password```.
- ```net``` - To search for hosts based on their network range, use the following syntax: ```net:<network range>```. For example, to find hosts on the 192.168.0.0/16 network, you would use ```net:192.168.0.0/16```.

## Censys

Similar to Shodan, Censys also supports search operators to refine and narrow down search results when looking for Internet-connected devices and systems. Some examples of Censys search operators include "ip:", "autonomous_system.organization:", "location.country_code:", and "protocols:". These operators can be used to search for specific types of devices, services, and vulnerabilities. Additionally, Censys supports filters that can be used to refine search results, such as "after:", "before:", and "parsed.names:domain.com". By using a combination of search operators and filters, Censys users can find and analyze information about Internet-connected devices and systems in a targeted and efficient manner.

- ```location.city```: This operator searches for devices located in a specific city.
Example: location.city:```New York```
- ```autonomous_system.asn```: This operator searches for devices with a specific autonomous system number (ASN).
Example: autonomous_system.asn:```AS8075```
- ```autonomous_system.organization```: This operator searches for autonomous system (AS) organizations.
Example: autonomous_system.organization:```Microsoft Corp```
- ```ip```: This operator searches for a specific IP address or range.
Example: ip: ```192.0.2.1``` or ip: ```192.0.2.0/24```
- ```protocols```: This operator searches for specific protocols.
Example: protocols:```smtp```
- ```location.country```: This operator searches for devices located in a specific country.
Example: location.country:```United States```
- ```os```: This operator searches for devices running a specific operating system.
Example: os:```Windows```
- ```443.https.tls.certificate.parsed.subject.organization```: This operator searches for devices using HTTPS with a specific certificate subject organization.
Example: 443.https.tls.certificate.parsed.subject.organization:```Google LLC```
- ```443.https.tls.certificate.parsed.issuer.organization```: This operator searches for devices using HTTPS with a specific certificate issuer organization.
Example: 443.https.tls.certificate.parsed.issuer.organization:```DigiCert Inc```
- ```80.http.get.title```: This operator searches for web pages with a specific title.
Example: 80.http.get.title:```Login Page```
- ```tags```: This operator searches for devices with specific tags.
Example: tags:```database```'
- ```80.http.get.body.filetype```: This operator searches for web pages that contain a specific file type within the HTTP response body.
Example: 80.http.get.body.filetype:```pdf```
- ```80.http.get.body.base64```: This operator searches for web pages that contain specific Base64-encoded data within the HTTP response body.
Example: 80.http.get.body.base64:```VGhpcyBpcyBhIHRlc3Q=```
- ```80.http.get.body.hex```: This operator searches for web pages that contain specific hexadecimal data within the HTTP response body.
Example: 80.http.get.body.hex:```5468697320697320612074657374```
- ```80.http.get.body.url```: This operator searches for web pages that contain specific URLs within the HTTP response body.
Example: 80.http.get.body.url:```https://example.com/secret.pdf```
- ```80.http.get.body.email```: This operator searches for web pages that contain specific email addresses within the HTTP response body.
Example: 80.http.get.body.email:```john@example.com```
- ```80.http.get.body.text```: This operator searches for web pages that contain specific text within the HTTP response body.
Example: 80.http.get.body.text:```password```
- ```80.http.get.body.regex```: This operator searches for web pages that match a specific regular expression within the HTTP response body.
Example: 80.http.get.body.regex:```^[\w-]+@([\w-]+.)+[\w-]+$```
- ```80.http.get.body.xml_xpath```: This operator searches for web pages that contain specific XML elements identified by XPath expressions within the HTTP response body.
Example: 80.http.get.body.xml_xpath:```//title[contains(text(),'Censys Search Engine')]```
- ```80.http.get.body.jsonpath```: This operator searches for web pages that contain specific JSON elements identified by JSONPath expressions within the HTTP response body.
Example: 80.http.get.body.jsonpath:```$.users[?(@.username=='john')].password```
- ```80.http.get.body.css_selector```: This operator searches for web pages that contain specific HTML elements identified by CSS selectors within the HTTP response body.
Example: 80.http.get.body.css_selector:```div#login-form input[type='password']```
- ```80.http.get.body.extension```: This operator searches for web pages with a specific file extension in the HTTP response body.
Example: 80.http.get.body.extension:```pdf```
- ```80.http.get.body.sha256```: This operator searches for web pages with a specific SHA256 hash of the HTTP response body.
Example: 80.http.get.body.sha256:```cf23df2207d99a74fbe169e3eba035e633b65d94```
- ```80.http.get.body.md5```: This operator searches for web pages with a specific MD5 hash of the HTTP response body.
Example: 80.http.get.body.md5:```1b2b34c6e3e6f8c58fdd0e4f854b0f30```
- ```80.http.get.body.size```: This operator searches for web pages with a specific size (in bytes) of the HTTP response body.
Example: 80.http.get.body.size:1024
- ```80.http.get.body.magic_bytes```: This operator searches for web pages with a specific file type identified by magic bytes in the HTTP response body.
Example: 80.http.get.body.magic_bytes:```%PDF```
- ```443.https.tls.certificate.parsed.fingerprint_sha256```: This operator searches for devices using HTTPS with a certificate that has a specific SHA256 fingerprint.
Example: 443.https.tls.certificate.parsed.fingerprint_sha256:```7e5c71d598d7c40cfc1c0347f5dc9178bbd44ebd4090c233e29ecfa8d8a5070c```
- ```443.https.tls.certificate.parsed.subject.organization```: This operator searches for devices using HTTPS with a certificate that includes a specific organization in the subject.
Example: 443.https.tls.certificate.parsed.subject.organization:```Example Corp```
- ```80.http.get.body```: This operator searches for web pages with a specific keyword or phrase in the HTTP response body.
Example: 80.http.get.body:```password```
- ```autonomous_system.asn```: This operator searches for devices with a specific autonomous system number (ASN).
Example: autonomous_system.asn:16509
- ```443.https.tls.certificate.parsed.serial_number```: This operator searches for devices using HTTPS with a certificate that has a specific serial number.
Example: 443.https.tls.certificate.parsed.serial_number:```2C9E8490B8F583B0```
- ```80.http.get.headers.server```: This operator searches for web pages with a specific server software in the HTTP response headers.
Example: 80.http.get.headers.server:```Apache```
- ```443.https.tls.certificate.parsed.issuer.organization```: This operator searches for devices using HTTPS with a certificate issued by a specific organization.
Example: 443.https.tls.certificate.parsed.issuer.organization:```GlobalSign nv-sa```
- ```443.https.tls.certificate.parsed.subject.common_name```: This operator searches for devices using HTTPS with a certificate that includes a specific common name in the subject.
Example: 443.https.tls.certificate.parsed.subject.common_name:```example.com```
- ```443.https.tls.certificate.parsed.extensions.basic_constraints.is_ca```: This operator searches for devices using HTTPS with a certificate that has a specific CA flag set in the basic constraints extension.
Example: 443.https.tls.certificate.parsed.extensions.basic_constraints.is_ca:true
- ```80.http.get.title```: This operator searches for web pages with a specific title in the HTML code.
Example: 80.http.get.title:```Login Page```
- ```80.http.get.body_sha256```: This operator searches for web pages with a specific SHA256 hash of the HTTP response body.
Example: 80.http.get.body_sha256:```d21e0c3931dfb18f4ec7ed9cb9c4a4f4e4e7462f402a8b91a91fb78435229f18```
- ```autonomous_system.name```: This operator searches for devices with a specific autonomous system name (ASN).
Example: autonomous_system.name:```Amazon.com, Inc.```
- ```80.http.get.headers.content_type```: This operator searches for web pages with a specific content type in the HTTP response headers.
Example: 80.http.get.headers.content_type:```text/html```
- ```80.http.get.status_code```: This operator searches for web pages with a specific HTTP status code in the response.
Example: 80.http.get.status_code:200
- ```443.https.tls.version```: This operator searches for devices using HTTPS with a specific TLS version.
Example: 443.https.tls.version:```TLSv1.2```
- ```443.https.tls.cipher_suite.name```: This operator searches for devices using HTTPS with a specific cipher suite.
Example: 443.https.tls.cipher_suite.name:```TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384```
- ```443.https.tls.cipher_suite.handshake_protocol```: This operator searches for devices using HTTPS with a specific handshake protocol in the cipher suite.
Example: 443.https.tls.cipher_suite.handshake_protocol:```TLSv1.3```
- ```80.http.get.redirect```: This operator searches for web pages with a specific redirect in the HTTP response headers.
Example: 80.http.get.redirect:```https://example.com/login```
- ```443.https.tls.certificate.parsed.serial_number```: This operator searches for devices using HTTPS with a specific certificate serial number.
Example: 443.https.tls.certificate.parsed.serial_number:```01E4A4ED7A4A4D50E81C53FEC0A94F19```
- ```443.https.tls.certificate.parsed.validity.start```: This operator searches for devices using HTTPS with a certificate that became valid on a specific date.
Example: 443.https.tls.certificate.parsed.validity.start:```2022-01-01T00:00:00+00:00```
- ```443.https.tls.certificate.parsed.validity.end```: This operator searches for devices using HTTPS with a certificate that will expire on a specific date.
Example: 443.https.tls.certificate.parsed.validity.end:```2023-03-31T23:59:59+00:00```
- ```80.http.get.body```: This operator searches for web pages with specific text in the HTTP response body.
Example: 80.http.get.body:```password```
- ```80.http.get.headers.server```: This operator searches for web pages with a specific server in the HTTP response headers.
Example: 80.http.get.headers.server:```Apache```

