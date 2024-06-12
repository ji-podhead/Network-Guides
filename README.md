# Network-Guides


 | [Repo](https://github.com/ji-podhead/Network-Guides/) | [main](https://ji-podhead.github.io/Network-Guides/DNS) | [DNS](https://ji-podhead.github.io/Network-Guides/DNS) | 

---

 | [Knowledge Base](https://ji-podhead.github.io/Network-Guides/DNS/Knowledge%20Base)| [Install](https://ji-podhead.github.io/Network-Guides/DNS/install) | [Test&Debug](https://ji-podhead.github.io/Network-Guides/DNS/testAndDebug) | [Dynamic Updates & RNDC](https://ji-podhead.github.io/Network-Guides/DNS/Dynmaic_Updates_%26_RNDC) | [Attack Vectors & Scenario](https://ji-podhead.github.io/Network-Guides/DNS/attackVectorsAndScenario) | [Protection](https://ji-podhead.github.io/Network-Guides/DNS/protection) | 
 
***In this series i will cover different network topics like DNS, DHCP, SSL (certmanager + letsencrypt).*** 
- The content derives from my personal research, studies and work.
- this will also be available on medium as blog-posts.


## DNS 
- [***1. knowledge base:***](https://ji-podhead.github.io/Network-Guides/DNS/Knowledge%20Base)
> everything you need to know to run and protect your own DNS
- [***2. install:***](https://ji-podhead.github.io/Network-Guides/DNS/install)
>  - we will install private DNS on debian using bind9
>  - we configure the DNS to resolve our personal Dashboard Domains
- [***3. debug:***](https://ji-podhead.github.io/Network-Guides/DNS/testAndDebug)
> we learn how to debug our dns using dig, nameserver logs, etc
- [***4. Dynamic Updates & RNDC***](https://ji-podhead.github.io/Network-Guides/DNS/Dynmaic_Updates_%26_RNDC)
>  - we configure our dhcp in combination with a RNDC.key
>  - we setup bind to use `Authentication for Dynamic Updates`
- [***5. attack vectors:***](https://ji-podhead.github.io/Network-Guides/DNS/attackVectorsAndScenario)
> how to hack a dns and what are  possible attack scenarios 
- [***6 .protection:***](https://ji-podhead.github.io/Network-Guides/DNS/protection)
> - how to protect your DNS using TSIG, dnssec
> - Enhanced Security practices for kubernetes in combination with private dns
> - how to setup our firewall

----

## Storage

***1. ZFS Pool in Proxmox***
***2. ISCSI synced with Proxmox using SCST-project***

---

> ***Roadmap***
> - we learn how and why to prevent our personal data from snooping-attacks and datamining
>   - this is the basis to setup cloud9 to avoid public DNS queries and therefore a huge attack-vector
> - in the next step we configure our DNS in combination with our own private DHCP and subnets
> -ssl using certmanager and letsencrypt
> - authentication using rbac and oaut2
> - ddos protection and proxy using cloudflare
---
