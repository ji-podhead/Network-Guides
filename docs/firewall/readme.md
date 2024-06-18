hey im still struggeling with the route to my virtual bridge *virbr0*.
```bash
$ ifconfig
enp2s0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 192.168.1.100  netmask 255.255.255.0  broadcast 192.168.1.255
        inet6 fe80::7890:e3cf:4177:fbcb  prefixlen 64  scopeid 0x20<link>
        ether 74:d0:2b:9d:49:43  txqueuelen 1000  (Ethernet)
        RX packets 31400073  bytes 5871355543 (5.4 GiB)
        RX errors 0  dropped 29229  overruns 0  frame 0
        TX packets 738576  bytes 105241255 (100.3 MiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
https://media.discordapp.net/attachments/192269258900635648/1252638847716560987/help.png?ex=6672f256&is=6671a0d6&hm=49cca766a81eaba74db2650d20d4282356dba6855b21ccbfa68d9b8577c78225&=&format=webp&quality=lossless&width=446&height=607
virbr0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 192.168.122.1  netmask 255.255.255.0  broadcast 192.168.122.255
        ether 52:54:00:6b:4a:30  txqueuelen 1000  (Ethernet)
        RX packets 72787  bytes 16744536 (15.9 MiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 66313  bytes 59969069 (57.1 MiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
```
i created a gateway for my nic, i set up a route with destination 192.168.122.0/24 and a nat that allows any ports and sources. i also configured a firewall rule.
before i setup the nat, i tried to ping a vm using this bridge from my other my machine and it gave me *port unerachable* but it was using the right gateway (from 192.168.1.100...)
after i setup the nat it is just unreachable

 
pls help :sob:
