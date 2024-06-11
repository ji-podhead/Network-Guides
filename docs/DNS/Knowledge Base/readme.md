

 | [main](https://ji-podhead.github.io/Network-Guides) | [DNS](https://ji-podhead.github.io/Network-Guides/DNS) | [Repo](https://github.com/ji-podhead/Network-Guides/) |

---

## DNS
 | [Knowledge Base](https://ji-podhead.github.io/Network-Guides/DNS/Knowledge%20Base)| [Install](https://ji-podhead.github.io/Network-Guides/DNS/install) | [Test&Debug](https://ji-podhead.github.io/Network-Guides/DNS/testAndDebug) | [Dynamic Updates & RNDC](https://ji-podhead.github.io/Network-Guides/DNS/Dynmaic_Updates_%26_RNDC) | [Attack Vectors & Scenario](https://ji-podhead.github.io/Network-Guides/DNS/attackVectorsAndScenario) | [Protection](https://ji-podhead.github.io/Network-Guides/DNS/protection) | 


![dns](https://github.com/ji-podhead/RHEL_9_Foreman_Guide/blob/main/img/dns.png?raw=true)

- [do routers have dns?](https://superuser.com/questions/1715361/do-routers-have-a-dns-server)
... 
> - most SOHO routers have a built-in DNS server to act as a cache. It's not a mandatory "router" feature though – enterprise networks would run their DNS on a separate system instead.
> - **If this is so, then I guess that DNS server would just be another cache similar to the one in Windows...or is it a more advanced DNS server?**
> 	- It varies between products. Talking about SOHO routers, the router's own DNS server is pretty much always just a caching proxy and actual name resolution relies on forwarding requests to an upstream resolver; no root hints involved.
> 	- But in addition to that, it is also quite common for the router to be authoritative for some "local" domain (like .lan or .home or .dlink) which contains hostnames for your LAN hosts. This integrates with the router's DHCP service, collecting hostnames that devices provide in their lease requests. It may even support static entries, though in SOHO routers it's rarely anything more than a single 'A' record per name.

## DNS Resolver

A **DNS resolver** is a crucial component in the domain name system. Its primary function is to **accept queries from clients** (such as your browser) and perform **recursive queries** to locate IP addresses. Here’s how it works:

1.  When you type a domain name (e.g., `example.com`) into your browser, the DNS resolver on your machine receives this request.
2.  The resolver then **contacts other DNS servers** to find the IP address associated with the domain name.
3.  It follows a chain of delegations, starting from the **root nameservers**, down to the **top-level domain (TLD) nameservers**, and finally to the authoritative nameservers for the specific domain.
4.  Once it reaches the authoritative nameserver, it retrieves the IP address and returns it to your browser.

## DNS Server

Now, let’s talk about **DNS servers** in general. The term “DNS server” is broader and encompasses various types of servers involved in the DNS system. Here are the key distinctions:

1.  **Authoritative Nameserver**: This type of DNS server holds complete data for one or more **zones** (domains). For example, the `.com` domain has authoritative nameservers that store information about all its subdomains.
2.  **Recursive Nameserver**: A recursive DNS server starts with no data and performs queries on behalf of clients. It follows delegations and CNAME records until it finds the answer for the client query. You might use a local recursive nameserver (on your machine or provided by your ISP) or a remote one like Google Public DNS or Cloudflare DNS.
## Records

 DNS records are essential for defining how domain names are translated into IP addresses. 
 
 Some common types of DNS records include:
  
| ***Record***  | ***Description*** |
|---------------|-------------------|
|    A Record | Maps a domain name to an IPv4 address. |
|   AAAA Record | Maps a domain name to an IPv6 address. |
|    CNAME Record | Alias one name to another. |
|    MX Record  | Specifies the mail server responsible for accepting email on behalf of a domain. |
|    TXT Record | Allows you to insert arbitrary text into the DNS record. |
|    PTR Record | Used in reverse DNS lookup to associate an IP address with a hostname. |

---

## Access Control Lists (ACLs)

Access Control Lists (ACLs) in DNS are used to control who can perform certain actions on your DNS server. They allow you to specify which IP addresses or networks are allowed or denied access to various operations such as dynamic updates, zone transfers, and queries.

An ACL is defined in the DNS server's configuration file and consists of a list of IP addresses or ranges, followed by an action (permit or deny). Here's an example of an ACL definition:
>```
>...
>acl local-lan {
>  localhost;
>  192.168.1.0/24;
>  192.168.122.0/24; # Netzwork for vmbr0
>  192.168.123.0/24; # additional Networks 
>};
>  allow-query { local-lan; };
>```
> In this example, only the IP addresses within the `192.168.1.0/24`,`192.168.122.0/24` and `192.168.123.0/24` ranges are permitted to perform queries against the DNS server. 

---


## Forward Zones
Forward zones map domain names to IP addresses. They are the primary mechanism by which DNS servers respond to queries asking for the IP address associated with a given domain name.

 The main goal of forward zones is to facilitate the translation of domain names into IP addresses, allowing users to connect to web servers, email servers, and other resources identified by domain names.

Configuration: Forward zones are configured in the DNS server's configuration files, typically located in /etc/bind/named.conf.local for BIND9 servers. Each forward zone requires a zone declaration that includes the domain name and the location of the zone file containing the DNS records for that domain.

***Example Configuration:***
>```
>zone "example.com" {
>    type master;
>    file "/etc/bind/db.example.com";
>};

---

## Reverse Zones in DNS Configurations

- Reverse zones in DNS configurations are used to map IP addresses back to domain names. This is particularly useful for reverse DNS lookups, where you know an IP address and want to find the associated domain name.

- To configure reverse zones, you would typically add a zone block in your DNS server configuration file (named.conf for BIND). Here's an example of how to define a reverse zone:
>```
>zone "122.in-addr.arpa" IN {
>    type master;
>    file "/etc/bind/db.122";
>};
>```

> This configuration tells the DNS server to manage the reverse zone for the subnet 122.0.0.0/24, mapping IP addresses within this range to domain names. The file directive points to the database file that contains the PTR records for this zone.
> PTR records in the reverse zone database (db.122) would then map IP addresses back to domain names, allowing reverse DNS lookups to succeed.

---


## Differences between Reverse and Forward Zones
While both forward and reverse zones play essential roles in DNS, they serve opposite functions:

    Forward Zones: Translate domain names into IP addresses.
    Reverse Zones: Map IP addresses back to domain names, facilitating reverse DNS lookups.

In essence, forward zones are about translating names to numbers, whereas reverse zones translate numbers back to names. Both types of zones are critical for the proper functioning of the DNS system, ensuring that users can efficiently navigate the internet and internal networks.

---


## Clients in DNS Zones
 Clients in DNS zones refer to devices or networks that initiate DNS queries to a DNS server. These queries seek information about domain names, and the DNS server responds based on its configured zone files.

 The treatment of these queries can vary depending on the source network, utilizing views to serve different responses to LAN and WAN clients. 

- The `allow-query` directive specifies which clients are permitted to send queries to the DNS server. 
> - Setting allow-query { any; }; means that the DNS server accepts queries from any client, regardless of their IP address or network location.
> -  This configuration is broad and permissive but might not be suitable for all environments, especially those requiring stricter access controls for security reasons.

---

***Alternative Configuration:*** Defining Specific Clients
- Instead of using `allow-query { any; };`, you could define ***specific clients*** that are allowed to query the DNS server.
> - This approach enhances security by limiting access to trusted clients. You can achieve this by specifying IP addresses, networks, or even creating named ACLs (Access Control Lists) that group certain clients together.

Here's an example of how to define specific clients using IP addresses:

>```acl internal { 192.168.1.0/24; 10.0.0.0/8; };
>options { allow-query { internal; }; allow-transfer { none; }; };
>```
> - In this configuration, only the IP addresses within the 192.168.1.0/24 and 10.0.0.0/8 ranges are permitted to perform queries against the DNS server.
> - This method provides a more controlled environment compared to allow-query { any; };.

---

# RNCD

> - An rndc.key is a cryptographic key used by the BIND DNS server for authentication purposes, particularly in scenarios involving dynamic updates to DNS zones. This key ensures that only authorized clients can modify the DNS records within a zone, enhancing security by preventing unauthorized changes.
> - Dynamic updates allow DNS records to be modified without manually editing the zone files. This is particularly useful in environments where DNS records need to be frequently updated, such as in large networks or cloud-based services. However, dynamic updates require secure mechanisms to prevent unauthorized modifications.

Here's how rndc.key fits into the picture:

 - Authentication for Dynamic Updates: When configuring a zone for dynamic updates, you specify an allow-update clause in the zone's configuration. Within this clause, you can specify one or more keys that are allowed to perform updates. Each client attempting a dynamic update must present a valid rndc.key that matches one of these keys.
- Security through Encryption: The rndc.key itself is encrypted using a specified algorithm (such as HMAC-MD5). This means that even if someone intercepts the key, they cannot use it without knowing the encryption algorithm and the original plaintext key.
- Integration with ACLs (Access Control Lists): You can further refine who can perform dynamic updates by specifying Access Control Lists (ACLs) in conjunction with the allow-update clause. This allows you to restrict updates to specific IP addresses or networks, adding another layer of security.

Without rndc, managing dynamic updates becomes significantly more challenging. While you could theoretically manage DNS records manually or through scripts, doing so securely and efficiently would be difficult. The rndc tool provides commands like rndc freeze and rndc thaw to safely edit dynamic zones, ensuring that updates are not lost during the editing process.

---

## Zone Transfer
Zone transfer is an important mechanism to ensure that all DNS servers have the same data set. 
When changes are made to the zone files, they are synchronized via the zone transfer. 
> `AXFR` (Asynchronous Full Transfer Zone) is a method used for this purpose.
![zone_transfer](https://github.com/ji-podhead/Network-Guides/blob/main/docs/DNS/Knowledge%20Base/networkGuide_zone_transfer.png?raw=true)

> -  When a client requests a zone transfer, the source DNS server queries the zone file, sends a response to the client
> -  the target DNS server checks permissions. If permissions are granted, the zone data is transferred; otherwise, the transfer is denied.

## Response Policy Zone (RPZ)

RPZ is a mechanism designed to introduce customized policies within Domain Name System (DNS) servers. This customization enables recursive resolvers to return potentially altered results, effectively blocking access to certain hosts by modifying the returned data. RPZ operates based on DNS data feeds, known as zone transfers, received from an RPZ provider to the deploying server. Unlike traditional blocklist methods, the actual blocklist is not visible or managed by the client application. Instead, if the queried name or the resulting IP address is listed in the blocklist, the response is modified to prevent access.

***Purpose***

RPZ serves as a filtering mechanism, either preventing users from accessing certain internet domains or redirecting them to safer alternatives by manipulating DNS answers. It allows DNS recursive resolver operators to obtain reputational data from external organizations about potentially harmful domains and use this information to protect users from accessing these domains.

***Mechanism and Data***

RPZ requires data to function. Various internet security organizations and services offer RPZ data for specific domain categories or potentially dangerous domains. Additionally, recursive resolver operators can define their own domain name data (zones) to be utilized by RPZ.

***Function***

RPZ empowers a DNS recursive resolver to select specific actions for various collections of domain name data (zones). These actions can range from performing full resolution (standard behavior) to declaring that the requested domain does not exist (NXDOMAIN) or suggesting a different domain (CNAME).

---

## Understanding DNS Query Output

When querying a DNS server for domain name resolution, the response contains several sections that provide detailed information about the queried domain. 

Here's a breakdown of these sections based on the example output you provided:


| **Section Title** | **Description**                                                                                     |
|-------------------|-----------------------------------------------------------------------------------------------------|
| **Question Section** | Specifies what information is being requested.                                                     |
| **Answer Section** | Provides the actual DNS records that match the query.                                              |
| **Authority Section** | Lists the authoritative nameservers for the queried domain.                                        |
| **Additional Section** | Contains information that might be needed to resolve the query.                                 |

---

## nxdomain

- NXDOMAIN is a DNS error message indicating that the domain name queried does not exist.
  - This message is received by the client, typically a Recursive DNS server, when it attempts to resolve a domain name to an IP address but fails because the domain name is not recognized in the DNS system.
  - Essentially, NXDOMAIN signifies that the domain name specified in the DNS query does not exist in the DNS database.
  - Only an authoritative nameserver can return an NXDOMAIN response.
  -  If the domain name exists but the requested DNS record type doesn't, a NOERROR response without specific answers can still be returned.
  -  NXDOMAIN errors can occur due to typos in the domain name, incorrect configurations, or malicious activities such as NXDOMAIN attacks, where attackers flood DNS servers with requests for non-existent domain names to exhaust their resources and disrupt service


 | [Knowledge Base](https://ji-podhead.github.io/Network-Guides/DNS/Knowledge%20Base)| [Install](https://ji-podhead.github.io/Network-Guides/DNS/install) | [Test&Debug](https://ji-podhead.github.io/Network-Guides/DNS/testAndDebug) | [Dynamic Updates & RNDC](https://ji-podhead.github.io/Network-Guides/DNS/Dynmaic_Updates_%26_RNDC) | [Attack Vectors & Scenario](https://ji-podhead.github.io/Network-Guides/DNS/attackVectorsAndScenario) | [Protection](https://ji-podhead.github.io/Network-Guides/DNS/protection) | 
