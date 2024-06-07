# DNS
> we will install our dns on Debian
> - its a stable distro for networking
> - its my proxmox-machine so i thought it would make sense not to outsource my dns and dhcp, since i use the proxmox machine for my networking and virtualisation stuff anyway.
> 

  ## Install Bind9
  ```Bash
  #  sudo apt-get install bind9 bind9utils bind9-doc
  ```
  - enable it:
  
  ```Bash
# systemctl enable bind9
# sudo systemctl enable named
```

## configure your DNS

> in our case we want to resolve  foreman.de to the ip `xxx` 
- edit the `named.conf.options` file
  
>```
>############################################################################################################
>#                                        /etc/bind/named.conf.options
>#############################################################################################################
>
>acl local-lan {
>  localhost;
>  192.168.1.0/24;
>  192.168.122.0/24; # Netzwork for vmbr0
>  192.168.123.0/24; # additional Networks 
>};
>options {
>  directory "/var/cache/bind";
>  forwarders {
>192.168.61.86;    # the DNS my phone uses
>192.168.2.1;      # the DNS of my NIC 
>  };
>  allow-query { local-lan; }; # Erlaubt Anfragen nur von den in local-lan definierten Netzwerken
>  dnssec-validation auto;
>  auth-nxdomain no;    // conform to RFC1035
>  listen-on-v6 { any; };
>  recursion no;  // we set that to no to avoid unnecessary traffic
>  querylog yes; // Enable for debugging
>  version "not available"; // Disable for security
>};
>```

---

- edit `nano /etc/bind/named.conf.local`
>```
>############################################################################################################
>#                                        /etc/bind/named.conf.local
>#############################################################################################################
>
>//include "/etc/bind/zones.rfc1918";
>zone "foreman.de" IN {
>        type master;
>        file "/etc/bind/zones/foreman.de";
>         allow-query { any; };  
>#       allow-update { any; };
>};
>zone "0.116.10.in-addr.arpa" IN {
>        type master;
>        file "/etc/bind/zones/foreman.de.rev";
>         allow-query { any; };
> #       allow-update { any; };
>};
>```

---

- create the foreward and backward files:
```Bash
 # cp /etc/bind/db.local /etc/bind/zones/foreman.de
 # cp /etc/bind/db.127 /etc/bind/zones/foreman.de.rev
```

--- 

- edit `/etc/bind/zones/foreman.de`:
>```
>############################################################################################################
>#                                        /etc/bind/zones/foreman.de
>#############################################################################################################                                                                                         
>;
>; BIND data file for local loopback interface
>;
>$TTL    604800
>@       IN      SOA     foreman.de. root.foreman.de. (
>                              2         ; Serial
>                         604800         ; Refresh
>                          86400         ; Retry
>                        2419200         ; Expire
>                         604800 )       ; Negative Cache TTL
>;
>@       IN      NS      bindserver.foreman.de.
>; A record for name server
>bindserver      IN      A       192.168.122.20
>@       IN      NS      localhost.
>@       IN      A       192.168.122.20
>@       IN      AAAA    ::1
>```



---

- edit `/etc/bind/zones/foreman.de.rev`

>```
>############################################################################################################
>#                                        /etc/bind/zones/foreman.de.rev
>#############################################################################################################                                                                                         
>;
>; BIND reverse data file for local loopback interface
>;
>$TTL    604800
>@       IN      SOA     foreman.de. root.foreman.de. (
>                              1         ; Serial
>                         604800         ; Refresh
>                          86400         ; Retry
>                        2419200         ; Expire
>                         604800 )       ; Negative Cache TTL
>;
>; Name server record
>@       IN      NS     bindserver.foreman.de.
>; A record for name server
>bindserver      IN      A      192.168.122.20
>20.122.168.192.in-addr.arpa. IN PTR foreman.de.
>@       IN      NS      localhost.
>1.0.0   IN      PTR     localhost.
>```

---

- update Bind9

```Bash
# named-checkzone foreman.de /etc/bind/zones/foreman.de
# named-checkzone foreman.de /etc/bind/zones/foreman.de.rev
# named-checkconf /etc/bind/named.conf.options
# named-checkconf
# sudo systemctl restart bind9
```
