

 | [main](https://ji-podhead.github.io/Network-Guides) | [DNS](https://ji-podhead.github.io/Network-Guides/DNS) | [Repo](https://github.com/ji-podhead/Network-Guides/) |

---

## DNS
 | [Knowledge Base](https://ji-podhead.github.io/Network-Guides/DNS/Knowledge%20Base)| [Install](https://ji-podhead.github.io/Network-Guides/DNS/install) | [Test&Debug](https://ji-podhead.github.io/Network-Guides/DNS/testAndDebug) | [Dynamic Updates & RNDC](https://ji-podhead.github.io/Network-Guides/DNS/Dynmaic_Updates_%26_RNDC) | [Attack Vectors & Scenario](https://ji-podhead.github.io/Network-Guides/DNS/attackVectorsAndScenario) | [Protection](https://ji-podhead.github.io/Network-Guides/DNS/protection) | 
 
# Test & Debug
- we have several options here:
> ***DNS-Host:***
> - journalctl, syslogs, cache
> 
> ***DNS-Client:***
> - wget, dig, telnet, tcdump

---

### DNS-Client debug

***wget:***

```bash
$  wget foreman.de
```

> this doesnt show us which dns is currently used, but it show us the Domain that the DNS resolved for us 

>```
>--2024-06-07 16:12:23--  http://foreman.de/
>Auflösen des Hostnamens foreman.de (foreman.de)… ::1, 192.168.122.20
>Verbindungsaufbau zu foreman.de (foreman.de)|::1|:80 … fehlgeschlagen: Verbindungsaufbau abgelehnt.
>Verbindungsaufbau zu foreman.de (foreman.de)|192.168.122.20|:80 … verbunden.
>HTTP-Anforderung gesendet, auf Antwort wird gewartet … 301 Moved Permanently
>Platz: https://foreman.de/ [folgend]
>--2024-06-07 16:12:23--  https://foreman.de/
>Verbindungsaufbau zu foreman.de (foreman.de)|192.168.122.20|:443 … verbunden.
>FEHLER: Dem Zertifikat von »foreman.de« wird nicht vertraut.
>FEHLER: Das Zertifikat von »»foreman.de«« hat keinen bekannten Austeller.
>```

---

***dig:***
```bash
 $ dig foreman.de
```
> this also tells us which DNS resolved our IP
>```
>[ji@base Dokumente]$ dig foreman.de
>
>; <<>> DiG 9.16.23-RH <<>> foreman.de
>;; global options: +cmd
>;; Got answer:
>;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 39704
>;; flags: qr aa rd; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1
>;; WARNING: recursion requested but not available
>
>;; OPT PSEUDOSECTION:
>; EDNS: version: 0, flags:; udp: 1232
>; COOKIE: 42f88eb9501cc520010000006663162e7378e4c0f794bcaf (good)
>;; QUESTION SECTION:
>;foreman.de.			IN	A
>
>;; ANSWER SECTION:
>foreman.de.		604800	IN	A	192.168.122.20
>
>;; Query time: 0 msec
>;; SERVER: 192.168.122.7#53(192.168.122.7)
>;; WHEN: Fri Jun 07 16:16:14 CEST 2024
>;; MSG SIZE  rcvd: 83
>```
> so just figured out that our DNS is `192.168.122.7` and that he found our IP is using  `A`-Record

---

***dump the tcp-logs for port 53:***
```bash
$ sudo tcpdump udp port 53 --interface virbr0 -vv
```
> - we use `virbr0` since its the network bridge the machine of our DNS-host requries, since its also running proxmox
> - is use my mobile phone here to access the internet, so the other DNS that's inside my resolv.conf will be ignored
> - a successfull query could look like this:
> 
>| **Output** | **Description** |
>|------------|------------------|
>| ```16:04:48.840074 IP (tos 0x0, ttl 64, id 23172, offset 0, flags [DF], proto UDP (17), length 56) my-proxmox.de.50724 > 192.168.122.7.domain: [bad udp cksum 0x758f -> 0x26fa!] 63196+ A? foreman.de. (28)``` | Query for A records of `foreman.de` with bad UDP checksum |
>| ```16:04:48.840088 IP (tos 0x0, ttl 64, id 23173, offset 0, flags [DF], proto UDP (17), length 56) my-proxmox.de.50724 > 192.168.122.7.domain: [bad udp cksum 0x758f -> 0xc8e3!] 21720+ AAAA? foreman.de. (28)``` | Repeated query for AAAA records of `foreman.de` with bad UDP checksum |
>| ```16:04:48.840507 IP (tos 0x0, ttl 64, id 31967, offset 0, flags [none], proto UDP (17), length 72) 192.168.122.7.domain > my-proxmox.de.50724: [bad udp cksum 0x759f -> 0x6d7f!] 63196*- q: A? foreman.de. 1/0/0 foreman.de. A 192.168.122.20 (44)``` | Response to A record query for `foreman.de` with bad UDP checksum; contains A address `192.168.122.20` |
>| ```16:04:48.840569 IP (tos 0x0, ttl 64, id 31968, offset 0, flags [none], proto UDP (17), length 84) 192.168.122.7.domain > my-proxmox.de.50724: [bad udp cksum 0x759f -> 0x6d7f!] 63196*- q: A? foreman.de. 1/0/0 foreman.de. A 192.168.122.20 (44)``` | Further response to A record query for `foreman.de` with bad UDP checksum; likely a repeated or additional response |

---

### DNS-HOST debug
***tail the logs of your nameserver:***
```bash
$ journalctl -u named.service -f
```
> ***DNS-Request via `browser`:***
>
>| ***Output*** | ***Description*** |
>|--------------|-------------------|
>| ```Jun 07 16:37:49 my-proxmox named[413848]: client @0x751f6388a168 192.168.122.1#38768 (foreman.de): query: foreman.de IN A + (192.168.122.7)``` | Initial Request for `foreman.de` (A Record) - Successful |
>| ```Jun 07 16:37:50 my-proxmox named[413848]: client @0x751f6468bd68 192.168.122.1#58656 (www.google.com): query: www.google.com IN A + (192.168.122.7)``` | Subsequent Request for `www.google.com` (A Record) - Failed due to refusal |
>| ```Jun 07 16:37:50 my-proxmox named[413848]: client @0x751f6468cb68 192.168.122.1#58656 (www.google.com): query: www.google.com IN AAAA + (192.168.122.7)``` | Additional Request for `www.google.com` (AAAA Record) - Failed due to refusal |
>| ```Jun 07 16:37:51 my-proxmox named[413848]: client @0x751f6140b968 192.168.122.1#57363 (foreman.de): query: foreman.de IN A + (192.168.122.7)``` | Final Request for `foreman.de` (A Record) - Successful |
>| ```Jun 07 16:37:51 my-proxmox named[413848]: client @0x751f61408f68 192.168.122.1#57363 (foreman.de): query: foreman.de IN AAAA + (192.168.122.7)``` | Final Request for `foreman.de` (AAAA Record) - Successful |
> 
> ***DNS-Request via `dig`-command:***
>
>| ***Output*** | ***Description*** |
>|--------------|-------------------|
>| ```Jun 07 16:44:16 my-proxmox named[413848]: client @0x751f62288d68 192.168.122.1#46572 (foreman.de): query: foreman.de IN A +E(0)K (192.168.122.7)``` | Successful DNS Lookup for `foreman.de` using `dig` command |

---

***Dump the cache:***
 - bind stores its cache in the ram, but you can dump it using 
```bash
$ rndc dumpdb > named_dump.db
```
- you can also flush it using rndc

---

 | [Knowledge Base](https://ji-podhead.github.io/Network-Guides/DNS/Knowledge%20Base)| [Install](https://ji-podhead.github.io/Network-Guides/DNS/install) | [Test&Debug](https://ji-podhead.github.io/Network-Guides/DNS/testAndDebug) | [Dynamic Updates & RNDC](https://ji-podhead.github.io/Network-Guides/DNS/Dynmaic_Updates_%26_RNDC) | [Attack Vectors & Scenario](https://ji-podhead.github.io/Network-Guides/DNS/attackVectorsAndScenario) | [Protection](https://ji-podhead.github.io/Network-Guides/DNS/protection) | 
 
