


 | [main](https://ji-podhead.github.io/Network-Guides) | [DNS](https://ji-podhead.github.io/Network-Guides/DNS) | [Repo](https://github.com/ji-podhead/Network-Guides/) |

---

## DNS
 | [Knowledge Base](https://ji-podhead.github.io/Network-Guides/DNS/Knowledge%20Base)| [Install](https://ji-podhead.github.io/Network-Guides/DNS/install) | [Test&Debug](https://ji-podhead.github.io/Network-Guides/DNS/testAndDebug) | [Dynamic Updates & RNDC](https://ji-podhead.github.io/Network-Guides/DNS/Dynmaic_Updates_%26_RNDC) | [Attack Vectors & Scenario](https://ji-podhead.github.io/Network-Guides/DNS/attackVectorsAndScenario) | [Protection](https://ji-podhead.github.io/Network-Guides/DNS/protection) | 

 
 ## Dynamic Updates & RNDC
 
 
 
 - create a rdnc key
 
  ```bash
   $  echo rndc-confgen >> /etc/bind/rndc.conf
   $  chmod 660 /etc/bind/rndc.conf
   $  chown root:bind /etc/bind/rndc.conf
  ```

---

### edit your configs accordingly:

***named.conf***

> `/etc/bind/named.conf

```yaml
include "/etc/bind/named.conf.options";
include "/etc/bind/named.conf.local";
include "/etc/bind/named.conf.default-zones";
```
---

***named.conf.local***

> `/etc/bind/named.conf.local`

```yaml
include "/etc/bind/rndc.conf";
controls {
  inet 127.0.0.1 port 953 allow {
    127.0.0.1;
    192.168.122.1;
  } keys { "rndc-key"; }; #We can now refer to the key with this variable
};

zone "foreman.de" IN {
        type master;
        file "/etc/bind/zones/foreman.de";
         allow-query { any; };  
        allow-update { key rndc-key; };
};
zone "122.168.192.in-addr.arpa" IN {
        type master;
        file "/etc/bind/zones/foreman.de.rev";
         allow-query { any; };
        allow-update { key rndc-key; };
};
```
---

***named.conf.options***

> `/etc/bind/named.conf.options`

```yaml
acl internals { 127.0.0.0/8; 192.168.122.0/24; };
controls { inet 127.0.0.1 port 953 allow { 127.0.0.1; }; };
options {
  directory "/var/cache/bind";
  forwarders { 192.168.2.1; };
  allow-query { internals; }; # only interal allowed to do queries 
  dnssec-validation auto;
  auth-nxdomain no;    # conform to RFC1035
  listen-on-v6 { none; };
  listen-on { 127.0.0.1; 192.168.122.7; };
  # recursion no;  <--- we allow recursion only for internals for security reason
  allow-recursion { internals; };
  querylog yes; # Enable for debugging
  version "not available"; # Disable for security
};
```

---


***forward-lookup-zone `foreman.de`***

> `/etc/bind/zones/foreman.de`

```yaml
; BIND data file for local loopback interface
;
$TTL    604800
@       IN      SOA     foreman.de. root.foreman.de. (
                              2         ; Serial
                         604800         ; Refresh
                          86400         ; Retry
                        2419200         ; Expire
                         604800 )       ; Negative Cache TTL
;
@       IN      NS      bindserver.foreman.de.
; A record for name server
bindserver      IN      A       192.168.122.20
@       IN      NS      localhost.
@       IN      A       192.168.122.20
@       IN      AAAA    ::1
;ns.foreman.de.    IN    A    192.168.122.7
;ns2.foreman.de.   IN    A    192.168.122.8
```

---

***reverse-lookup-zone `foreman.de.rev`***

> `/etc/bind/zones/foreman.de.rev`

```yaml
; BIND reverse data file for local loopback interface
;
$TTL    604800
@       IN      SOA     foreman.de. root.foreman.de. (
                              1         ; Serial
                         604800         ; Refresh
                          86400         ; Retry
                        2419200         ; Expire
                         604800 )       ; Negative Cache TTL
;
; Name server record
@       IN      NS     bindserver.foreman.de.
; A record for name server
bindserver      IN      A      192.168.122.20
;20.122.168.192.in-addr.arpa. IN PTR foreman.de. <<- this was allready declared in our zone, so we use the syntax below
20      IN      PTR     foreman.de.
@       IN      NS      localhost.
1.0.0   IN      PTR     localhost.
```

---

***dhcp.conf***

> `/etc/dhcp/dhcpd.conf`

```yaml
update-static-leases on;
use-host-decl-names on;
option domain-name "foreman.de.";

# Path to the key for dynamic updates
include "/etc/bind/rndc.key";

# Deactivating optimization and checking conflicts of dynamic updates
update-optimization off;
update-conflict-detection off;

# Embedding the configoration of Remote Control
include "/etc/bind/rndc.conf";

# Definition der Zone für Ihren Domainnamen
zone foreman.de. {
        primary 192.168.122.7; # DNS-Server-IP
        key rndc-key;
}

# Definition of the Reverse Lookup Zone
zone foreman.de. {
        primary 192.168.122.7; # DNS-Server-IP
        key rndc-key;
}

# Subnet-Konfiguration
subnet 192.168.122.0 netmask 255.255.255.0 {
  range 192.168.122.1 192.168.122.254;
  option subnet-mask 255.255.255.0;
  #option routers 192.168.122.20; not needed for simple dynamic update
  option broadcast-address 192.168.122.255;
  dynamic-update;
  option domain-name "foreman.de";
  option domain-name-servers 192.168.122.7;
}
```

---

***edit AppArmor*** *(if you fail to restart isc-dhcp)*

```bash
$ sudo nano /etc/apparmor.d/usr.sbin.dhcpd  
```
> add 
> ```perl
>/etc/bind/ rw,
>/etc/bind/** rw,
>```

restart AppArmor:

```bash
$ apparmor_parser -r /etc/apparmor.d/usr.sbin.dhcpd  
```

---

  ***restart/refresh DNS & DHCP***

```bash
$ named-checkzone foreman.de /etc/bind/zones/foreman.de
$ named-checkzone foreman.de /etc/bind/zones/foreman.de.rev
$ named-checkconf /etc/bind/named.conf.options
$ named-checkconf
$ sudo systemctl restart bind9
$ sudo systemctl restart isc-dhcp-server
```  
---

***check if it works***

```bash
$ nslookup 192.168.122.20 localhost
$ nslookup foreman.de 
```

---
 | [Knowledge Base](https://ji-podhead.github.io/Network-Guides/DNS/Knowledge%20Base)| [Install](https://ji-podhead.github.io/Network-Guides/DNS/install) | [Test&Debug](https://ji-podhead.github.io/Network-Guides/DNS/testAndDebug) | [Dynamic Updates & RNDC](https://ji-podhead.github.io/Network-Guides/DNS/Dynmaic_Updates_%26_RNDC) | [Attack Vectors & Scenario](https://ji-podhead.github.io/Network-Guides/DNS/attackVectorsAndScenario) | [Protection](https://ji-podhead.github.io/Network-Guides/DNS/protection) | 
