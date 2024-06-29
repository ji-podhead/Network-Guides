 | [main](https://ji-podhead.github.io/Network-Guides) | [DNS](https://ji-podhead.github.io/Network-Guides/DNS)| [Security](https://github.com/ji-podhead/Network-Guides/)|  [Repo](https://github.com/ji-podhead/Network-Guides/Websecurity) |

---

# Web & Cloud Security

 | [Attack Vectors](https://ji-podhead.github.io/Network-Guides/Security/Attack_Vectors)| [Attack Types](https://ji-podhead.github.io/Security/Attack_Types) |  [Measurements & Testing](https://ji-podhead.github.io/Network-Guides/Security/Testing) |  [Analysis & Forensic](https://ji-podhead.github.io/Network-Guides/Security/Analysis) | 

---

## Attack Types Descriptions and Tools
### Denial of Service (DoS) and Distributed Denial of Service (DDoS)
**Description**: DoS and DDoS attacks aim to render a machine or network resource unavailable to its intended users by flooding the target or its surrounding infrastructure with excessive internet traffic. 
**Types of DDoS Attacks**
1. **Volume-Based Attacks**: These attacks flood the target with high volumes of traffic, often using botnets to generate a large number of IP addresses.
2. **Protocol Attacks**: Exploiting vulnerabilities in specific protocols like ICMP (Ping Flood), UDP (UDP Flood), or TCP (SYN Flood) to overwhelm the target.
3. **Application Layer Attacks (Layer 7)**: Targeting application logic directly, using specialized protocols or pseudo-protocols to overload the server.
4. **Resource Exhaustion Attacks**: Overloading the target's resources, such as bandwidth or CPU, to degrade service quality or cause outages.
5. **Reflection Attacks**: Using compromised servers to reflect malicious traffic back at the target, amplifying the attack's impact.
**Rescources:**
[OWASP: Denial Of Service](https://owasp.org/www-community/attacks/Denial_of_Service)
[Cloudflare: What is a DDOS?](https://www.cloudflare.com/de-de/learning/ddos/what-is-a-ddos-attack/)
[OWASP: protection using dpd](https://owasp.org/www-project-dpd/)
[github tool collection](https://github.com/topics/ddos-attack-tools)
[Cloudflare: DDOS attack tools](https://www.cloudflare.com/learning/ddos/ddos-attack-tools/how-to-ddos/)
[Performance Impact of DDoS Attacks on Three Virtual Machine Hypervisors](https://www.researchgate.net/publication/313511871_Performance_Impact_of_DDoS_Attacks_on_Three_Virtual_Machine_Hypervisors)
[Video by Hacking Lecture: UDP Flood Attack](https://www.youtube.com/watch?v=dkB4lSPrKuU)
**Tools**:
- **Burp Suite**: While primarily a web application security testing tool, Burp Suite can be used to analyze and manipulate HTTP(S) traffic, which can be useful in identifying and mitigating certain types of DoS/DDoS attacks.
- **Wireshark**: Wireshark can capture and analyze network traffic, helping to identify patterns indicative of DoS/DDoS attacks, such as unusual traffic volumes or specific types of packet
---
### Cross-Site Scripting (XSS)
 XSS attacks exploit the client-side browser to execute malicious scripts. There are three main forms of XSS attacks: Stored XSS, Reflected XSS, and DOM-Based XSS.
- **Stored XSS**: Malicious code is injected into a website and stored there, executing each time a user visits the site.
- **Reflected XSS**: Malicious code is included in a request sent to a vulnerable web application, causing the code to execute when the request is processed.
- **DOM-Based XSS**: Vulnerabilities in how a webpage manipulates its Document Object Model (DOM) allow for the execution of malicious scripts.
**Resources:**
[Wiki: Cross Site Scripting](https://en.wikipedia.org/wiki/Cross-site_scripting)
[OWASP: XSS](https://owasp.org/www-community/attacks/xss/)
[Video Tutorial by David Bombai and XXS Rat's](https://www.youtube.com/watch?v=PzRQhpbYbeg)
[Hashsleuth Info: Exploiting Stored XSS in Damn Vulnerable Web Application (DVWA)](https://medium.com/@hashsleuth.info/exploiting-stored-xss-in-damn-vulnerable-web-application-dvwa-66f906dca355)
[hackxpert XSS_Playground](https://labs.hackxpert.com/XSS_Playground/)
[OWASP: Cross_Site_Scripting_Prevention_Cheat_Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
[SelfHTML: XSS Sicherheitskonzepte](https://wiki.selfhtml.org/wiki/JavaScript/Tutorials/Sicherheitskonzepte)
**Tools**:
- **OWASP ZAP**: OWASP ZAP can be used to detect XSS vulnerabilities by scanning web applications for common patterns and behaviors associated with XSS attacks.
- **Burp Suite**: Burp Suite includes tools for intercepting and manipulating HTTP(S) traffic, which can be used to test for XSS vulnerabilities.
---
### SQL Injection
 SQL Injection attacks involve inserting malicious SQL statements into input fields for execution, potentially leading to unauthorized data access or manipulation.
 **Resources:**
 [Wiki: SQL Injection](https://de.wikipedia.org/wiki/SQL-Injection)
 [OWASP: SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection)
 [invicti: SQL  Injection cheat sheet](https://www.invicti.com/blog/web-security/sql-injection-cheat-sheet/)
[hackxpert NOSQL](https://labs.hackxpert.com/NoSQLi/)
[W3Schools: sql injection](https://www.w3schools.com/sql/sql_injection.asp)
[Cloudflare: SQL Injection](https://www.cloudflare.com/de-de/learning/security/threats/sql-injection/)
[Cloudflare: How to prevent SQL Injection](https://www.cloudflare.com/learning/security/threats/how-to-prevent-sql-injection/)
**Tools**:
- **SQLMap**: SQLMap automates the detection and exploitation of SQL injection vulnerabilities, making it a valuable tool for assessing web application security against this type of attack.
- **OWASP ZAP**: OWASP ZAP can also be used to find SQL injection vulnerabilities by scanning web applications for unsafe SQL queries.
---
### CSRF Tokens and Nonces
CSRF tokens and nonces are security measures designed to prevent Cross-Site Request Forgery (CSRF) attacks. These attacks occur when an attacker tricks a victim into performing actions on a web application in which they're authenticated.
**Resources:**
- [OWASP: csrf](https://owasp.org/www-community/attacks/csrf)
- [OWASP: Cross-Site_Request_Forgery_Prevention_Cheat_Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)
- [OWASP: OAuth2_Cheat_Sheet](https://cheatsheetseries.owasp.org/cheatsheets/OAuth2_Cheat_Sheet.html)
- [Video by Web Dev Simplified about CSRF Tokens](https://www.youtube.com/watch?v=80S8h5hEwTY)
**Tools**:
- **OWASP ZAP**: OWASP ZAP can be used to test for CSRF vulnerabilities by attempting to perform actions without proper authentication mechanisms in place.
---
### Server-Side Request Forgery (SSRF)
Server-Side Request Forgery (SSRF) is a type of vulnerability where an attacker can force a server to make requests to internal systems or external sites. 
SSRF vulnerabilities arise when a web application allows untrusted input to influence the server's outbound connections. Attackers can exploit this by sending specially crafted requests that cause the server to connect to internal services or external sites, potentially bypassing firewalls and exploiting internal systems.
***Examples of SSRF Attacks***
- **Internal Network Discovery**: An attacker can use SSRF to enumerate internal networks and services.
- **Data Leakage**: Sensitive data from internal databases or services can be exposed to attackers.
- **Command Execution**: In some cases, SSRF can be used to execute commands on internal systems.
***Detection and Prevention***
	- **Input Validation**
		Ensure that all inputs to functions that make outbound connections are validated and sanitized. Avoid using user-controlled data to construct URLs or other identifiers for outbound connections.
	- **Restrict Outbound Connections**
		Limit the domains or IP addresses that the server can connect to. This can be achieved through firewall rules or configuration settings within the application.
	 -  **Use of Safe Libraries**
		When possible, use libraries or frameworks that are designed to mitigate SSRF vulnerabilities. Many modern web frameworks offer built-in protections against SSRF.
	- **Monitoring and Logging**
		Implement monitoring and logging to detect unusual outbound connections. Look for patterns that indicate SSRF attacks, such as connections to unexpected destinations or ports.
***Resources***
- [OWASP SSRF Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
- [PortSwigger Web Security Academy - SSRF Lab](https://portswigger.net/web-security/ssrf/tutorial)
- [Stack Overflow Discussion on SSRF](https://stackoverflow.com/questions/37703609/what-is-server-side-request-forgery-and-how-can-we-mitigate-it)
***Tools***
- **Wireshark**: A network protocol analyzer that can be used to monitor network traffic and identify suspicious requests.
- **OWASP ZAP**: An open-source web application security scanner that can help identify SSRF vulnerabilities.
- **Burp Suite**: A web penetration testing toolkit that includes features for intercepting and modifying HTTP(S) traffic, aiding in the identification of SSRF vulnerabilities.
---
### Session Hijacking
Session hijacking is a form of cyber attack where an attacker takes over a user's active session by intercepting and then reusing their credentials, typically in the form of session cookies. Session hijacking exploits the fact that web applications maintain stateful sessions to manage user interactions. When a user logs into a web application, a unique session identifier is generated and stored in a cookie on the user's device. The server uses this identifier to authenticate the user for subsequent requests. An attacker who intercepts this cookie can assume the identity of the user.
***Methods of Session Hijacking***
- **Sniffing**: Attacker captures session cookies via packet sniffing tools like Wireshark.
- **Sidejacking**: Also known as "session hijacking," where an attacker uses a tool like Firesheep to steal session cookies from public Wi-Fi networks.
- **Cross-Site Scripting (XSS)**: Attackers inject malicious scripts into web pages viewed by the victim, which steal session cookies.
- **Man-in-the-Middle (MitM) Attacks**: Attackers intercept communication between the user and the server, capturing session cookies.
***Detection and Prevention***
	- **Secure Cookies**
		- Use secure flags (`Secure` attribute) for cookies to ensure they are only transmitted over HTTPS.
		- Set the `HttpOnly` flag to prevent client-side scripts from accessing the cookie, reducing the risk of XSS attacks.
	-  **Regularly Rotate Session Keys**
		Change session keys periodically to limit the window of opportunity for an attacker to use a stolen key.
	- **Use Strong Authentication Mechanisms**
		Implement multi-factor authentication (MFA) to add an extra layer of security.
	- **Employ Rate Limiting**
		Limit the frequency of login attempts to prevent brute-force attacks.
	- **Monitor and Log Access**
		Regularly review logs for signs of suspicious activity, such as failed login attempts or repeated login from new locations.
***Resources***
- [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
- [Mozilla Developer Network: Secure Contexts](https://developer.mozilla.org/en-US/docs/Web/Security/Secure_Contexts)
- [OWASP ZAP Documentation](https://www.zaproxy.org/docs/)
- [Wireshark Official Website](https://www.wireshark.org/)
***Tools***
- **Wireshark**: A network protocol analyzer that can be used to capture and analyze network traffic, helping to identify session hijacking attempts.
- **OWASP ZAP**: An open-source web application security scanner that can help identify vulnerabilities that could be exploited for session hijacking.
- **Firesheep**: A Firefox extension that makes it easy to hijack sessions on public Wi-Fi networks.
- **Web Application Firewalls (WAFs)**: Can be configured to block suspicious patterns of behavior that might indicate session hijacking.
---
### Path Traversal 
Path traversal vulnerabilities occur when a web application does not properly sanitize user input, allowing attackers to access files and directories outside the intended web root directory. This can lead to unauthorized access to sensitive data, including source code, configuration files, or even executable files. 
Path traversal vulnerabilities exploit the way web applications handle file paths provided by users. Attackers can manipulate these paths to access resources beyond the web root, leveraging this to read sensitive files, upload malicious files, or execute arbitrary commands.
***Examples of Path Traversal Attacks***
- **File Disclosure**: Attackers can view the contents of files outside the web root, such as source code or configuration files.
- **Directory Listing**: Attackers can list directories and subdirectories, discovering the structure of the file system.
- **Remote Code Execution**: In some cases, attackers can execute arbitrary commands on the server by uploading a script or using command injection techniques.
***Detection and Prevention***
	- **Input Validation**
		Validate all user inputs, especially those used in file path construction, to ensure they conform to expected formats and do not contain dangerous characters.
	- **Use of Sanitization Functions**
		Sanitize user inputs to remove or escape characters that could be used to traverse the file system, such as ".." or "/".
	- **Configuration Settings**
		Configure web servers and application frameworks to restrict access to certain directories and files. For example, many web servers have options to disable directory listing.
	- **Regular Updates and Patching**
		Keep web servers, application servers, and frameworks up to date with the latest security patches to address known vulnerabilities.
	- **Monitoring and Logging**
		Implement monitoring and logging to detect unusual access patterns or attempts to access restricted areas of the file system.
***Tools***
- **OWASP ZAP**: An open-source web application security scanner that can help identify path traversal vulnerabilities by attempting to access files and directories beyond the expected scope. [OWASP ZAP](https://www.zaproxy.org/)
- **Nmap**: A network scanning tool that can be used to discover accessible files and directories on a web server. [Nmap](https://nmap.org/)
- **Burp Suite**: A web penetration testing toolkit that includes features for intercepting and modifying HTTP(S) traffic, aiding in the identification of path traversal vulnerabilities. [Burp Suite](https://portswigger.net/burp)
- **Web Application Firewalls (WAFs)**: Can be configured to block suspicious patterns of behavior that might indicate path traversal attempts. [Imperva WAF](https://www.imperva.com/products/application-firewall/waf/)
- **OWASP Top Ten 2021**: Includes path traversal as one of the top web application security risks. [OWASP Top Ten 2021](https://owasp.org/www-project-top-ten/)
***Resources***
- [OWASP Path Traversal Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Path_Traversal_Cheat_Sheet.html)
- [OWASP WebGoat Project](https://owasp.org/www-project-webgoat/) - A deliberately insecure web application maintained by OWASP for educational purposes.
- [Open Web Application Security Project (OWASP)](https://owasp.org/) - Provides extensive resources on web application security, including research papers, tools, and community forums.
- [Web Security Academy](https://portswigger.net/web-security) - Offers hands-on labs for learning about web application security, including path traversal vulnerabilities.
---
### Clickjacking 
Clickjacking, also known as UI redress attack, is a malicious technique of deception and confusion for a web user, where fraudulent clicks in a web page are tracked while the user believes they are interacting with another page or element. This can lead to unintended actions being performed, such as clicking on a button that appears to be harmless but actually performs a malicious action. 
Clickjacking exploits the way web browsers display content from multiple sources in a single page. Attackers embed malicious content over legitimate content, tricking users into performing actions they did not intend to perform.
***Examples of Clickjacking Attacks***
- **Form Submission**: Users are tricked into submitting a form they thought was inactive or unrelated.
- **Account Takeover**: Users are led to believe they are logging into a legitimate site, but instead, their credentials are captured by the attacker.
- **Malware Installation**: Users are deceived into installing malware by clicking on what appears to be a benign link or button.
***Detection and Prevention***
	- **X-Frame-Options Header**
		Use the `X-Frame-Options` HTTP response header to specify whether or not a browser should be allowed to render a page in a `<frame>`, `<iframe>`, `<embed>` or `<object>`. Setting this header to `SAMEORIGIN` prevents the page from being framed by any other domain.
	- **Content Security Policy (CSP)**
		Implement a Content Security Policy to control which domains the browser should consider to be valid sources of executable scripts. This can help prevent attackers from injecting malicious scripts into your pages.
	- **Frameguard Tool**
		Use the Frameguard tool developed by Google to check your site for clickjacking vulnerabilities. It provides recommendations for fixing issues found.
	- **Use of Secure and HttpOnly Flags for Cookies**
		Setting the `Secure` and `HttpOnly` flags for cookies can help mitigate clickjacking attacks by preventing cross-site scripting (XSS) attacks that could be used to hijack the session.
***Tools***
- **OWASP ZAP**: An open-source web application security scanner that can help identify clickjacking vulnerabilities. [OWASP ZAP](https://www.zaproxy.org/)
- **Browser Extensions**: Extensions like NoScript for Firefox and ClickJacking Defender for Chrome can help protect against clickjacking by blocking inline scripts and frames.
- **Content Security Policy (CSP) Report-Only Mode**: Use CSP report-only mode to test your site for clickjacking vulnerabilities without enforcing the policy. [CSP Report-Only](https://content-security-policy.com/report-uri/)
- **Web Application Firewalls (WAFs)**: Can be configured
***Resources***
- [OWASP Clickjacking Defense Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html)
- [Google Frameguard Tool](https://developers.google.com/speed/frameguard/)
- [Content Security Policy (CSP)](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP)
- [OWASP ZAP](https://www.zaproxy.org/)
- [Web Security Academy](https://portswigger.net/web-security/clickjacking) - Offers hands-on labs for learning about web application security, including clickjacking vulnerabilities.
---
### Man-in-the-Middle (MitM) Attacks
A Man-in-the-Middle (MitM) attack is a type of eavesdropping attack where the attacker intercepts and possibly alters the communication between two parties who believe they are directly communicating with each other. MitM attacks can compromise the confidentiality and integrity of the data being transmitted, posing a significant security risk. 
MitM attacks exploit vulnerabilities in network protocols, encryption mechanisms, or the trust relationship between parties involved in a communication. Attackers position themselves between the sender and receiver to intercept, modify, or store the data being transmitted.
***Types of MitM Attacks***
- **Passive MitM**: The attacker merely listens to the communication without altering it.
- **Active MitM**: The attacker actively modifies the communication, potentially changing the content or adding malicious elements.
- **Replay MitM**: The attacker records the communication and replays it at a later time to deceive the recipient.
***Detection and Prevention***
	- **Public Key Infrastructure (PKI)**
		Use PKI to establish secure channels for communication. Digital certificates verify the identity of the parties involved, reducing the risk of MitM attacks.
	- **Secure Communication Protocols**
		Employ secure communication protocols that include built-in protection against MitM attacks, such as TLS (Transport Layer Security) and SSL (Secure Sockets Layer).
	- **Certificate Pinning**
		Pin specific cryptographic certificates to the identities of the servers they belong to. This prevents attackers from presenting false certificates during the handshake process.
	- **Regular Updates and Patching**
		Keep all devices, software, and firmware updated to patch known vulnerabilities that could be exploited in MitM attacks.
	**Monitoring and Analysis**
		Implement continuous monitoring and analysis of network traffic to detect anomalies that could indicate a MitM attack.
***Tools***
- **Wireshark**: A network protocol analyzer that can be used to monitor network traffic and identify potential MitM attacks. [Wireshark](https://www.wireshark.org/)
- **SSL/TLS Labs**: Provides detailed reports on the security of SSL/TLS implementations, helping to identify vulnerabilities that could be exploited in MitM attacks. [SSL/TLS Labs](https://www.ssllabs.com/projects/index.html)
- **Certificate Transparency Logs**: A public log of all issued digital certificates, helping to detect unauthorized issuance of certificates that could be used in MitM attacks. [Certificate Transparency](https://www.certificate-transparency.org/)
- **OWASP ZAP**: An open-source web application security scanner that can help identify vulnerabilities that could be exploited in MitM attacks. [OWASP ZAP](https://www.zaproxy.org/)
- **Web Application Firewalls (WAFs)**: Can be configured to block suspicious patterns of behavior that might indicate MitM attempts. [Imperva WAF](https://www.imperva.com/products/application-firewall/waf/)
***Resources***
- [OWASP Testing Guide for Web Applications Chapter on SSL/TLS](https://owasp.org/www-pdf-archive/Testing_guide_v2.pdf)
- [RFC 5246 - The Transport Layer Security (TLS) Protocol Version 1.2](https://datatracker.ietf.org/doc/html/rfc5246)
- [OWASP ZAP Documentation](https://www.zaproxy.org/docs/)
- [Wireshark Official Website](https://www.wireshark.org/)
- [Web Security Academy](https://portswigger.net/web-security/mitm) - Offers hands-on labs for learning about web application security, including MitM vulnerabilities.
---
### Web Cache Poisoning 
Web cache poisoning is a specific type of attack targeting web caches, where an attacker inserts malicious content into a cache to serve false information or redirect users to malicious websites. This can lead to phishing, malware distribution, or other forms of cyberattacks. Web cache poisoning exploits vulnerabilities in web caching mechanisms, allowing attackers to corrupt cached content. This can happen through various means, such as manipulating HTTP headers or exploiting weak cache validation mechanisms.
***Examples of Web Cache Poisoning Attacks***
- **Phishing**: Users are redirected to fake login pages where their credentials are stolen.
- **Malware Distribution**: Legitimate websites are replaced with malicious ones serving malware.
- **Information Theft**: Users are directed to websites collecting personal or financial information under false pretenses.
***Detection and Prevention***
	- **Cache Validation**
		Implement cache validation mechanisms to ensure that cached content has not been tampered with. This can involve checking digital signatures or timestamps associated with cached content.
	- **Secure Headers**
		Use secure HTTP headers, such as `Cache-Control` and `ETag`, to control how and when content is cached and to validate cached content against the original.
	- **Content Hashing**
		Hash the content of web objects and store the hash value along with the object in the cache. When retrieving the object, compare the hash value with the current content to detect changes.
	- **Regular Updates and Patching**
		Keep all web servers, application servers, and frameworks up to date with the latest security patches to address known vulnerabilities.
	- **Monitoring and Analysis**
		Implement monitoring and analysis of web traffic and cache logs to detect unusual patterns that could indicate web cache poisoning attempts.
***Tools***
- **Wireshark**: A network protocol analyzer that can be used to analyze network traffic and identify web cache poisoning attempts. [Wireshark](https://www.wireshark.org/)
- **Web Application Firewalls (WAFs)**: Can be configured to block suspicious patterns of behavior that might indicate web cache poisoning attempts. [Imperva WAF](https://www.imperva.com/products/application-firewall/waf/)
- **OWASP ZAP**: An open-source web application security scanner that can help identify vulnerabilities that could be exploited in web cache poisoning attacks. [OWASP ZAP](https://www.zaproxy.org/)
- **Web Security Academy**: Offers hands-on labs for learning about web application security, including web cache poisoning vulnerabilities. [Web Security Academy](https://portswigger.net/web-security)
- **Content Delivery Networks (CDNs)**: Some CDNs offer security features to help mitigate web cache poisoning, such as content hashing and invalidation policies. [Cloudflare](https://www.cloudflare.com/learning/cdn/glossary/content-validation/)
***Resources***
- [OWASP Web Cache Poisoning Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Web_Cache_Poisoning_Cheat_Sheet.html)
- [OWASP ZAP Documentation](https://www.zaproxy.org/docs/)
- [Wireshark Official Website](https://www.wireshark.org/)
- [Web Security Academy](https://portswigger.net/web-security)
- [Cloudflare Content Validation](https://www.cloudflare.com/learning/cdn/glossary/content-validation/)
 ---
### DNS Cache Poisoning
DNS Cache Poisoning is a type of attack where an attacker corrupts a DNS resolver's cache, causing it to return incorrect IP addresses for domain names. This can lead to users being redirected to malicious websites or having their internet traffic intercepted. 
DNS Cache Poisoning exploits vulnerabilities in DNS resolver implementations, allowing attackers to inject false DNS records into a resolver's cache. Once poisoned, the cache serves incorrect IP addresses for legitimate domain names, enabling various types of attacks.
***Examples of DNS Cache Poisoning Attacks***
- **Phishing**: Users are redirected to fake login pages where their credentials are stolen.
- **Malware Distribution**: Legitimate websites are replaced with malicious ones serving malware.
- **Information Theft**: Users are directed to websites collecting personal or financial information under false pretenses.
***Detection and Prevention***
	- **DNSSEC**
		Deploy DNS Security Extensions (DNSSEC) to digitally sign DNS responses, ensuring the authenticity and integrity of DNS data. This makes it difficult for attackers to poison the cache with false data.
	- **Rate Limiting**
		Implement rate limiting on DNS queries to prevent flood-based cache poisoning attacks.
	- **Monitoring and Analysis**
		Monitor DNS query logs for unusual patterns that could indicate cache poisoning attempts, such as a sudden increase in queries for a particular domain.
	- **Use of Up-to-date DNS Resolvers**
		Ensure that DNS resolvers are kept up to date with the latest security patches and configurations to mitigate known vulnerabilities.
***Tools***
- **Wireshark**: A network protocol analyzer that can be used to analyze network traffic and identify DNS cache poisoning attempts. [Wireshark](https://www.wireshark.org/)
- **BIND**: The most widely used DNS software on the Internet, BIND supports DNSSEC and offers advanced security features. [BIND](https://www.isc.org/bind/)
- **dnspython**: A Python library for DNS operations, including DNSSEC validation. [dnspython](http://www.dnspython.org/)
- **OpenDNS**: Offers DNS security features, including filtering and monitoring, to help protect against DNS cache poisoning. [OpenDNS](https://opendns.com/)
- **OWASP ZAP**: An open-source web application security scanner that can help identify vulnerabilities that could be exploited in DNS cache poisoning attacks. [OWASP ZAP](https://www.zaproxy.org/)
- **Web Application Firewalls (WAFs)**: Can be configured to block suspicious patterns of behavior that might indicate DNS cache poisoning attempts. [Imperva WAF](https://www.imperva.com/products/application-firewall/waf/)
***Resources***
- [ISC's DNSSEC Deployment Guide](https://www.isc.org/dnssec-deployment-guide/)
- [OpenDNS Security Features](https://opendns.com/security/)
- [OWASP ZAP Documentation](https://www.zaproxy.org/docs/)
- [Wireshark Official Website](https://www.wireshark.org/)
- [Web Security Academy](https://portswigger.net/web-security) - Offers hands-on labs for learning about web application security, including DNS cache poisoning vulnerabilities.
---
### Side Channel & Timing Attacks 
Side channel attacks exploit information leaked through the implementation of a cryptosystem or physical implementation to extract data from a system. These attacks focus on the "side effects" of a computation rather than breaking the cryptographic algorithms themselves.
Side channel attacks leverage the fact that cryptographic systems often produce observable side effects that can be measured and analyzed. These side effects can include power consumption, electromagnetic radiation, timing, or even sound. By studying these side effects, attackers can gain insights into the internal state of a cryptographic system, potentially revealing secret keys or other sensitive information.
***Examples of Side Channel Attacks***
- **Power Analysis (Differential Power Analysis)**: Analyzes the power consumption of a device to recover cryptographic keys.
- **Electromagnetic Analysis (EMA)**: Uses the electromagnetic emissions of a device to extract secret information.
- **Timing Analysis**: Exploits variations in the time taken to complete cryptographic operations to infer secret values.
- **Acoustic Cryptanalysis**: Listens to the sounds produced by a device to recover secret information.
***RSA Encryption Process***
RSA is an asymmetric encryption method based on the difficulty of large integer factorization. It consists of three keys: a public key used for encrypting messages, a private key needed for decrypting them, and optionally a shared key for exchanging messages between two parties.
- **Key Generation**
	1. **Selection of Prime Numbers**: Choose two large prime numbers p and q.
	2. **Calculation of N**: N=pq is the product of the two primes.
	3. **Calculation of ϕ(N)**: ϕ(N)=(p−1)(q−1) is Euler's totient function, indicating the count of positive divisors of N.
	4. **Choice of e**: Select a public exponent e coprime to ϕ(N) ($1 < e < \phi(N)$).
	5. **Calculation of d**: The private exponent d is the multiplicative inverse of e modulo ϕ(N), i.e., ed≡1mod  ϕ(N).
 - **Encryption**
	To encrypt a message M, it is first converted into a number smaller than N. Then, the following formula is used to compute the encrypted message C:
	`` C=Memod  N``
- **Decryption**
	To decrypt the encrypted message C, the following formula is used:
	``M=Cdmod  N``
- **Security Basis**
	The security of RSA relies on the difficulty of factoring N into its factors p and q. If someone factors N, they can easily calculate the private key d by computing ϕ(N) and then finding d, which is the multiplicative inverse of e modulo ϕ(N).
- **Example**
	- Assuming p=11 and q=7, then N=77 and ϕ(N)=60. Choosing e=5, then d=23, because $5 \cdot 23 \equiv 1 \mod 60$.
	- If we want to encrypt the letter "A" (assumed as ASCII value 65), we use the formula:
	   C=655mod  77
	- After calculating C, we can decrypt the encrypted message by converting:
	 M=C23mod  77
***Timing Attack Against RSA Using the Chinese Remainder Theorem***
	A timing attack aims to gain information about the secret structure of a system by measuring the time required to perform certain operations. In the context of RSA, such an attack can enable an attacker to discover the system's private keys.
- ***Problem Statement***
	Given an RSA key pair (N,e), where N is the product of two large prime numbers p and q, and e is the public key. The private key d is defined by ed≡1mod  (p−1)(q−1). A timing attack seeks to compute d by measuring the time required to compute demod  N.
- **Attack Vector**
	The attack leverages the fact that the computation of demod  N is faster when d is smaller and slower when d is larger. By measuring the time required to compute demod  N, an attacker can recognize patterns in runtime and derive d from this.
**Use of the Chinese Remainder Theorem***
- To compute the private key d, the attacker can use the Chinese Remainder Theorem to set up an equation containing d. 
	- Assuming the attacker has k different values of d determined through measuring runtime, namely d1,d2,...,dk. 
- Then, the attacker can apply the Chinese Remainder Theorem to set up an equation:
	x≡dimod  pi
- for all i=1,2,...,k, where pi is the corresponding runtime required to compute di.
 **Solution**
	The solution to this system of equations yields the value of x, which corresponds to the private key d. Since the Chinese Remainder Theorem states that a unique solution exists if the pi are pairwise coprime, the attacker can precisely compute d.
***Tools***
-  **Wireshark**: A network protocol analyzer that can be used to analyze network traffic and identify potential side channel vulnerabilities. [Wireshark](https://www.wireshark.org/)
- **SideChannel**: A framework for conducting side channel analysis on cryptographic implementations. [SideChannel](https://github.com/sidechannel/sidechannel)
- **Gandalf**: A tool for differential power analysis (DPA) that can be used to analyze the power traces of cryptographic devices. [Gandalf](https://gandalf.gitlab.io/)
- **OWASP ZAP**: An open-source web application security scanner that can help identify vulnerabilities that could be exploited in side channel attacks. [OWASP ZAP](https://www.zaproxy.org/)
- **Web Application Firewalls (WAFs)**: Can be configured to block suspicious patterns of behavior that might indicate side channel attacks. [Imperva WAF](https://www.imperva.com/products/application-firewall/waf/)
***Resources***
- [OWASP Testing Guide for Web Applications Chapter on Side Channel Attacks](https://owasp.org/www-pdf-archive/Testing_guide_v2.pdf)
- [OWASP ZAP Documentation](https://www.zaproxy.org/docs/)
- [Wireshark Official Website](https://www.wireshark.org/)
- [Web Security Academy](https://portswigger.net/web-security) - Offers hands-on labs for learning about web application security, including side channel attack vulnerabilities.
---
### Local File Inclusion (LFI) & Remote File Inclusion (RFI)
Local File Inclusion (LFI) and Remote File Inclusion (RFI) vulnerabilities allow attackers to read files from the server's file system, potentially exposing sensitive data. 
**Examples of LFI and RFI Attacks**
- **Data Leakage**: Sensitive files like configuration files, source code, or database dumps can be accessed and disclosed.
- **Code Execution**: Attackers may execute arbitrary PHP scripts or other executable content hosted on the server.
- **Server-side Request Forgery (SSRF)**: By exploiting RFI vulnerabilities, attackers can force the server to make requests to internal services or external sites, leading to further exploitation opportunities.
**Detection and Prevention**
- **Input Validation**: Ensure that user inputs are properly sanitized to prevent path traversal vulnerabilities.
- **Configuration Settings**: Configure web servers to disallow directory listings and restrict access to sensitive directories.
- **Content Security Policy (CSP)**: Implement CSP headers to control which resources the browser is allowed to load, reducing the risk of remote code execution.
- **Regular Updates**: Keep server software and frameworks updated to patch known vulnerabilities.
**Tools**
- **OWASP ZAP**: OWASP ZAP can be used to scan for LFI and RFI vulnerabilities by attempting to access files outside the intended scope. [OWASP ZAP](https://www.zaproxy.org/)
- **ModSecurity**: An open-source, cross-platform web application firewall that can detect and prevent LFI and RFI attacks. [ModSecurity](https://www.modsecurity.org/)
- **Nmap**: While primarily a network scanning tool, Nmap can be used to identify vulnerable web applications and services. [Nmap](https://nmap.org/)
- **Burp Suite**: A popular web application security testing tool that includes functionality for detecting and exploiting LFI and RFI vulnerabilities. [Burp Suite](https://portswigger.net/burp)
**Resources**
- [OWASP Top Ten Project](https://owasp.org/www-project-top-ten/) - Provides a list of the most critical web application security risks, including LFI and RFI vulnerabilities.
- [OWASP ZAP Documentation](https://www.zaproxy.org/docs/) - Comprehensive guide on using OWASP ZAP for web application security testing.
- [Web Security Academy](https://portswigger.net/web-security) - Offers hands-on labs for learning about web application security, including LFI and RFI vulnerabilities.
By understanding and mitigating LFI and RFI vulnerabilities, organizations can significantly enhance the security posture of their web applications.
---
## Enumeration
![lock](https://m.media-amazon.com/images/G/31/apparel/rcxgs/tile._CB483369979_.gif) 
Enumeration refers to the systematic exploration of an environment to collect information that can be used for subsequent attacks. Almost any potential attack vector originates from improperly configured permissions and the absence of adequate security measures. 
It's crucial to ensure that zone forwarding is restricted to specific servers and that DNSSEC is definitely activated. Moreover, no one should be able to probe your critical infrastructure, as these directories should not even be visible to potential attackers.
***Targets***
- File Structure
- User Names
- Email Addresses
- Usernames, Groups, and Machine Names
- Routing Tables
***Methods***
- DNS Snooping and Zone Forwarding
- SQL Injection
- Path Traversal
- Brute Force (e.g., forms)
---
## API Abuse
API abuse occurs when an API is misused in ways that were not intended by its creators, often leading to security breaches, denial of service, or unauthorized access to data. ***Common types of API abuse***
- **Rate Limiting Bypass**: Exceeding the rate limits set by the API provider to perform actions faster than allowed.
- **Data Scraping**: Extracting large amounts of data from an API without permission.
- **Denial of Service (DoS)**: Overloading an API endpoint to make it unavailable to legitimate users.
- **Injection Attacks**: Injecting malicious payloads into API requests to exploit vulnerabilities.
***Detection and Prevention***
Detecting and preventing API abuse requires a combination of monitoring, logging, and implementing security controls.
	- **Monitoring and Logging**
		Implement robust logging and monitoring solutions to track API usage patterns. Look for anomalies such as:
		- Unusual request rates from a single source.
		- Requests for endpoints that are rarely accessed.
		- Requests containing unexpected parameters or payloads.
	- ***Implementing Security Controls***
		- **Rate Limiting**: Implement strict rate limiting to prevent abuse and protect against DoS attacks.
		- **Authentication and Authorization**: Ensure that only authorized users can access protected resources.
		- **Input Validation**: Validate all inputs to prevent injection attacks.
		- **Use of HTTPS**: Secure API communications to prevent man-in-the-middle attacks.
		- **Monitoring and Alerts**: Set up alerts for suspicious activity based on monitored metrics.
***Resources***
- [OWASP API Security Project](https://owasp.org/www-project-api-security/)
- [Google API Security Best Practices](https://cloud.google.com/blog/products/api-management/top-10-tips-for-writing-more-secure-apis)
- [Microsoft API Security Guide](https://docs.microsoft.com/en-us/azure/architecture/best-practices/api-design)
-  [hackxpert: Apilab](https://labs.hackxpert.com/APIs/index.html)
- [OWASP: REST Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html)
***Tools***
- **OWASP API Security Top 10**: A list of the most critical security risks to API security.
- **Postman**: A popular tool for API testing and documentation.
- **Swagger/OpenAPI**: Tools for designing, building, and documenting APIs securely.
- **Splunk**: A powerful tool for searching, monitoring, and analyzing log data.
- **AWS WAF**: Amazon Web Services' firewall for protecting APIs hosted on AWS.
---

