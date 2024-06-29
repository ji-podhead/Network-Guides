


 | [main](https://ji-podhead.github.io/Network-Guides) | [DNS](https://ji-podhead.github.io/Network-Guides/DNS)| [Security](https://github.com/ji-podhead/Network-Guides/)|  [Repo](https://github.com/ji-podhead/Network-Guides/Websecurity) |

---

# Web & Cloud Security
 | [Attack Vectors](https://ji-podhead.github.io/Network-Guides/Security/Attack_Vectors)| [Attack Types](https://ji-podhead.github.io/Security/Attack_Types) |  [Measurements & Testing](https://ji-podhead.github.io/Network-Guides/Security/Testing) |  [Analysis & Forensic](https://ji-podhead.github.io/Network-Guides/Security/Analysis) | 

## Attack Vectors
****
***Badly Configured Networks and Lack of Network Policies***: Poorly configured networks and the absence of robust network security policies leave systems vulnerable to various cyber threats. Without proper configuration, networks may expose unnecessary services, leaving them open to exploitation. Similarly, without clear security policies, there's a higher chance of misconfigurations and unsecured practices among users.
***Wiretapping***: Interception of communication traffic involves capturing and potentially analyzing private communications between parties. This can occur over various mediums like phone calls, emails, or internet traffic. Techniques used can range from simple eavesdropping to sophisticated man-in-the-middle attacks.
***IoT Devices, Printers and Other Devices***: Internet of Things (IoT) devices, printers, and other peripherals connected to a network can pose significant security risks if not properly secured. These devices often run on outdated firmware, lack strong authentication mechanisms, and may communicate over insecure channels, providing entry points for attackers.
***Open Server Ports***: Leaving server ports open without proper security measures exposes servers to potential attacks. Attackers can scan open ports to find vulnerabilities, allowing them to exploit weaknesses and gain unauthorized access to the system.
***Insecure Protocols***: Using outdated or insecure communication protocols can expose data to interception and manipulation. Secure protocols encrypt data in transit, protecting it from being read by unauthorized parties.
***Exposure of Sensitive Data***: Insecure exposure of sensitive data, such as personal information or financial details, can result from poor data handling practices. This includes storing data in plaintext, failing to encrypt sensitive information, or improperly configuring database access controls.
***Authentication Vulnerabilities***: Weaknesses in authentication mechanisms can allow attackers to impersonate legitimate users or bypass security controls. Common vulnerabilities include weak passwords, outdated authentication protocols, and insufficient multi-factor authentication (MFA).
***Outdated Components***: Keeping software and hardware components up-to-date is crucial for maintaining security. Outdated components may contain known vulnerabilities that attackers can exploit, posing a significant risk to the overall security posture.
***Inadequate Logging and Monitoring***: Without adequate logging and monitoring, detecting and responding to security incidents can be challenging. Logs provide valuable insights into network activity, while monitoring tools can alert administrators to suspicious behavior in real-time.
***Missing DNS & DHCP Protection***: DNS and DHCP services are critical for network operation but can be exploited if not properly secured. Attackers may attempt to redirect traffic to malicious sites or spoof IP addresses, compromising network integrity and user trust.
***Possible API Abuse***: APIs offer powerful interfaces for interacting with applications and services. However, they can be abused if not properly secured, leading to unauthorized data access, service disruption, or even data loss.
***Insufficient Rate Limiting***: Without sufficient rate limiting, servers can become overwhelmed by excessive requests, leading to denial-of-service (DoS) attacks or exposing the system to brute-force attempts.
***Possible Buffer Overflow***: Buffer overflow vulnerabilities occur when a program writes more data to a fixed-length block of memory than it can hold, potentially overwriting adjacent memory and executing arbitrary code.
***Unvalidated Redirects and Forwards***: Web applications that do not validate redirects and forwards can be manipulated to send users to malicious websites, leading to phishing attacks or session hijacking.
***Local File Inclusion (LFI) and Remote File Inclusion (RFI)***: LFI and RFI vulnerabilities allow attackers to include local or remote files within web pages, enabling them to read sensitive files or execute arbitrary code.
***Possible Command & SQL Injection***: Command injection vulnerabilities allow attackers to execute arbitrary commands on the host operating system, while SQL injection allows attackers to manipulate SQL queries, potentially accessing or modifying sensitive data.
***Possible Cross Site Scripting (XSS)***: XSS vulnerabilities enable attackers to inject malicious scripts into web pages viewed by other users, potentially stealing cookies, session tokens, or other sensitive information.
***No Email Scanning against Phishing and Man in The Middle Attacks***: Failing to implement email scanning for phishing and man-in-the-middle attacks leaves users vulnerable to credential theft and other forms of identity fraud.
***Session Hijacking***: Session hijacking occurs when an attacker intercepts and takes control of a user's active session, typically by stealing session identifiers or cookies.
***Bad Encryption***: Poor encryption practices can weaken the security of encrypted data, making it susceptible to decryption by attackers who possess sufficient computational resources.
***Man-in-the-Middle (MitM) Attacks***: MitM attacks involve intercepting and potentially altering the communication between two parties without their knowledge, allowing attackers to steal data or alter communications.
***SSL Snooping***: SSL snooping, also known as SSL interception, involves the interception of encrypted SSL/TLS traffic between a client and a server. By decrypting the SSL traffic, attackers can analyze the content of the communication, potentially extracting sensitive information such as usernames, passwords, or payment details. This technique requires the attacker to have access to the network path between the client and the server, often achieved through man-in-the-middle (MitM) attacks or compromised network infrastructure.
***Social Engineering***: Social engineering exploits human behavior to trick individuals into divulging confidential information or performing actions that benefit the attacker. This can take many forms, including phishing emails, pretexting, baiting, and quid pro quo. Awareness training and secure communication practices are key defenses against social engineering attacks.
***Software Supply Chain Attacks***: In these attacks, software components within the supply chain are manipulated to gain unauthorized access or embed malware. This can happen at any stage of the development process, from the initial coding phase to distribution. Ensuring the integrity and authenticity of all software components throughout the supply chain is crucial for preventing these attacks.
***Mobile Device Security***: Smartphones and tablets often serve as attack vectors due to the security flaws in apps or the underlying operating systems. Malicious apps can steal data, spy on user activities, or act as bots in DDoS attacks. Regular updates, careful app selection, and security settings adjustments are important for securing mobile devices.


---

## Cloud bases Attack Vectors

***Misconfigured Cloud Services***: Often, cloud services are not properly configured, leading to security vulnerabilities. Incorrect configurations can expose sensitive data, leave services accessible to unauthorized users, or create pathways for attackers to infiltrate the network. Proper configuration and regular audits are essential to mitigate these risks.
### Misconfigured IAM Policies
Identity and Access Management (IAM) policies play a critical role in controlling who has access to resources within a cloud environment. However, misconfigured IAM policies can inadvertently grant excessive privileges to users or services, leading to unauthorized access and potential data breaches.
***Risks Associated with Misconfigured IAM Policies***
- **Unauthorized Access**: Incorrectly configured IAM policies may allow unauthorized individuals or services to gain access to sensitive resources.
- **Privilege Escalation**: Users with elevated privileges due to misconfigurations can perform actions beyond their intended scope, potentially compromising the integrity of the system.
- **Data Leakage**: Insufficient restrictions on resource access can lead to accidental or intentional data leaks.
***Best Practices for Configuring IAM Policies***
- **Least Privilege Principle**: Grant only the necessary permissions required for a user or service to perform its function.
- **Regular Audits**: Periodically review and audit IAM policies to identify and rectify any misconfigurations.
- **Use of IAM Policies**: Leverage IAM policies to enforce fine-grained access controls at the resource level.
### Unsecured Kubernetes Secrets
Kubernetes, widely used for orchestrating containerized applications, relies heavily on secrets for managing credentials and other sensitive information. However, improperly securing these secrets can lead to significant security risks.
***Risks Associated with Unsecured Kubernetes Secrets***
- **Credential Theft**: Malicious actors can steal credentials stored in plaintext, leading to unauthorized access to systems and data.
- **Service Disruption**: Exposing secrets can enable attackers to disrupt services by impersonating legitimate services or users.
- **Data Breaches**: Sensitive data, such as API keys or database credentials, can be leaked, resulting in data breaches.
***Best Practices for Securing Kubernetes Secrets***
- **Encryption**: Always encrypt secrets at rest and in transit. Kubernetes supports encryption through various mechanisms, including the use of secret objects.
- **Secrets Management Tools**: Utilize third-party secrets management tools that integrate with Kubernetes to automate the secure handling of secrets.
- **Access Controls**: Implement strict access controls to limit who can view or modify secrets.

### Deprecated Cloud Features
Cloud providers continuously update their services, introducing new features while deprecating older ones. Using deprecated features can expose applications to vulnerabilities as support ends and security patches are no longer provided.
***Risks Associated with Using Deprecated Features***
- **Vulnerability Exposure**: Deprecated features often contain known security flaws that are not patched, making them attractive targets for attackers.
- **Loss of Support**: As support for deprecated features ends, users lose access to updates and security patches, increasing vulnerability.
- **Compatibility Issues**: Newer versions of cloud services may introduce breaking changes, requiring significant effort to migrate away from deprecated features.
***Best Practices for Managing Deprecated Features***
- **Plan for Migration**: Develop a migration plan well ahead of the deprecation date to minimize disruptions and ensure a smooth transition to supported features.
- **Automate Where Possible**: Automate the process of identifying and migrating away from deprecated features where feasible.
### Denial of Wallet Attack
**Best Practices for Preventing Denial of Wallet Attacks**
- **Use Reputable Providers**: Choose cryptocurrency wallet providers known for their security and reliability.
- **Enable Two-Factor Authentication (2FA)**: Adding an extra layer of security through 2FA can significantly reduce the risk of unauthorized access.
- **Keep Software Updated**: Regularly update the wallet software to patch any vulnerabilities that could be exploited in a DoW attack.
- **Monitor Transactions**: Set up alerts for unusual transaction activity that could indicate a breach.
- **Backup Wallets**: Store backups of your wallet offline and in a secure location to recover funds in case of a compromise.

### Misuse of Cloud Storage

**Best Practices for Preventing Misuse of Cloud Storage**
- **Implement Strong Access Controls**: Restrict access to cloud storage accounts to authorized personnel only.
- **Encrypt Sensitive Data**: Ensure that sensitive data is encrypted both at rest and in transit to protect it from unauthorized access.
- **Audit Usage Patterns**: Regularly review logs and monitor usage patterns to detect anomalies that could indicate misuse.
- **Set Up Alerts**: Configure alerts for suspicious activity, such as unexpected downloads or uploads of large volumes of data.
- **Educate Employees**: Provide training on the importance of data security and the consequences of misuse to raise awareness among employees.

### Missing Rate Limiting

**Best Practices for Implementing Rate Limiting**
- **Analyze Traffic Patterns**: Understand typical traffic patterns to set realistic rate limits that accommodate normal usage without hindering legitimate users.
- **Dynamic Adjustment**: Consider implementing dynamic rate limiting that adjusts based on current load and traffic patterns to balance security and usability.
- **Log and Monitor**: Keep logs of rate-limiting events and monitor them for signs of malicious activity or attempted attacks.
- **Fallback Strategies**: Have fallback strategies in place, such as CAPTCHA challenges or manual intervention, for cases where automated responses are not effective.
- **Documentation and Training**: Document the purpose and implementation of rate limiting and train staff on how to respond appropriately to rate-limiting errors.
---

---


## Attacks
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
### Denial of Service (DoS) and Distributed Denial of Service (DDoS)
Denial of Service (DoS) and Distributed Denial of Service (DDoS) attacks aim to make a machine or network resource unavailable to its intended users by overwhelming the target or its surrounding infrastructure with a flood of internet traffic. The reason for a DDoS can vary based on what you want to do (eg. DNS Cache Poisening)

#### Common Techniques
	- IP Address Spoofing
	- Packet Flooding
	- SYN Floods
	- Application Layer Attacks
	
## Cross-Site Scripting (XSS)
Uses client side Browser to implement malicous code.
For example  the comment section in a forum could be used to run code using`<script>` tag.
***Forms of XXS***
	- ***Stored XSS***
>	> Stored XSS involves injecting malicious code into a website that executes every time a visitor accesses it.
	- ***Reflected XSS***
>	> Reflected XSS occurs when malicious code is passed through the URL and executed upon page load.
	- ***DOM-Based XSS***
>	> DOM-Based XSS exploits vulnerabilities in how a Wegpage manipulates its Document Object Model (DOM), allowing execution of malicious code.










## SQL Injection
***Blind SQL Injection***
Blind SQL Injection involves making requests that cause the website to react without the user being aware, often by analyzing responses.
***Error-based SQL Injection***
Error-based SQL Injection leverages error messages returned by the website to gather information about the database structure.

### Nonces and CSRF Tokens
Explain how modern web applications prevent CSRF attacks using nonces and CSRF tokens.
***CSRF Token Sniffing***
Describe how an attacker might attempt to intercept CSRF tokens for malicious purposes.

### IDOR via Direct Object References
Explain how an attacker could potentially access sensitive data by exploiting direct references in URLs or other public parts of the application.


### XXE Attacks
Describe how XXE attacks work and how they can be used to exfiltrate sensitive data or compromise services.

### SSRF (Server-Side Request Forgery)
In SSRF attacks, an attacker can trick the server into making requests to internal systems or services, leading to security breaches.


### Path Traversal
Path Traversal attacks enable an attacker to navigate outside intended paths on the server, leading to file read, write, or delete operations.

### Clickjacking
Clickjacking tricks a user into clicking something while intending to click something else, resulting in unexpected actions.

### Session Hijacking
Session Hijacking attacks steal a user's authenticated status by capturing and misusing session IDs.

### Man-in-the-Middle Attacks
MitM attacks eavesdrop and manipulate the communication path between two parties, leading to data leaks or manipulation.

### Cache Poisoning
Cache Poisoning manipulates a system's cache to deliver false or counterfeit responses, causing errors or security breaches.

### Timing Attacks
Timing attacks exploit the time taken to respond to a request to gain information about the system or database.

### Local File Inclusion (LFI) / Remote File Inclusion (RFI)
These attacks allow an attacker to read or execute files by manipulating path inputs.

### Content Spoofing
Content Spoofing presents falsified content to deceive users or prompt them to perform malicious actions.

### Directory Traversal
Similar to Path Traversal, this attack enables navigation outside intended paths on the server, leading to file manipulations.

### Side Channel Attacks
Describe various types of side channel attacks, including how they are conducted and their impact on security.


 
 
 

