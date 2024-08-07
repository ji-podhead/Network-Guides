# Network-Guides

<div align="center">
      <img src="https://github.com/ji-podhead/ji-podhead/blob/main/logo.jpg?raw=true" align="right" width="50" />
</div>
 
---


***In this series i will cover different network topics like DNS, DHCP, Web & Cloud Security and SSL.*** 
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


## Storage
- [***1. Knowledge Base***](https://ji-podhead.github.io/Network-Guides/storage/Knowledge%20Base/)
> - everything you need to knwo from sas&nas to ceph
- [***2. ZFS Pool in Proxmox***](https://ji-podhead.github.io/Network-Guides/storage/zfs&proxmox/)
> how to create a zfs ppol in promox and mount it via nfs  
- [***3. ISCSI synced with Proxmox using SCST-project***](https://ji-podhead.github.io/Network-Guides/storage/iscsi/)
> - we install SCST-Project and sync it with proxmox
---

> ***Roadmap***
> - we learn how and why to prevent our personal data from snooping-attacks and datamining
>   - this is the basis to setup cloud9 to avoid public DNS queries and therefore a huge attack-vector
> -ssl using certmanager and letsencrypt
> - authentication using rbac and oaut2
---
