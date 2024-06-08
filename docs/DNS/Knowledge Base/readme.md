

 | [Repo](https://ji-podhead.github.io/RHEL_9_Foreman_Guide/knowledge%20base)| [main](https://ji-podhead.github.io/RHEL_9_Foreman_Guide/knowledge%20base)| [DNS](https://ji-podhead.github.io/RHEL_9_Foreman_Guide/installation%20(katello%2Cdiscovery%2Cdhcp%2Ctftp)) | 

---

 | [Knowledge Base](https://ji-podhead.github.io/RHEL_9_Foreman_Guide/knowledge%20base)| [Install](https://ji-podhead.github.io/RHEL_9_Foreman_Guide/installation%20(katello%2Cdiscovery%2Cdhcp%2Ctftp)) | [Attack Vectors & Scenario](https://ji-podhead.github.io/RHEL_9_Foreman_Guide/discovery%20and%20provisioning) | [Protection](https://ji-podhead.github.io/RHEL_9_Foreman_Guide/libvirt) | 

# Knowledge Base

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
## Zone Transfer
Zone transfer is an important mechanism to ensure that all DNS servers have the same data set. 
When changes are made to the zone files, they are synchronized via the zone transfer. 
> `AXFR` (Asynchronous Full Transfer Zone) is a method used for this purpose.

```mermaid
sequenceDiagram

    participant Client as Client Request
    participant DNSMaster as Source DNS Server (Primary)
    participant DNSSlave as Target DNS Server (Secondary)
    participant ZoneFile as Zone File


    Client->>DNSMaster: Send Zone Transfer Request
    DNSMaster->>Client: Acknowledge Request
    DNSMaster->>DNSSlave: Initiate Zone Transfer
    DNSSlave->>DNSMaster: Confirm Ready to Receive
    DNSMaster->>ZoneFile: Read Zone Data
    ZoneFile-->>DNSMaster: Return Zone Data
    DNSMaster->>DNSSlave: Send Zone Data
    DNSSlave->>DNSMaster: Acknowledge Receipt of Zone Data
    DNSSlave->>ZoneFile: Write Zone Data
    ZoneFile-->>DNSSlave: Confirmation of Successful Write
    DNSSlave->>DNSMaster: Notify Completion of Zone Transfer
    DNSMaster->>Client: Notify Completion of Zone Transfer


```

> -  When a client requests a zone transfer, the source DNS server queries the zone file, sends a response to the client
> -  the target DNS server checks permissions. If permissions are granted, the zone data is transferred; otherwise, the transfer is denied.
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

