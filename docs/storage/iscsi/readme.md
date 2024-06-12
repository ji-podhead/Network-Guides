


 | [main](https://ji-podhead.github.io/Network-Guides) | [DNS](https://ji-podhead.github.io/Network-Guides/DNS) |[DHCP](https://ji-podhead.github.io/Network-Guides/DHCP) |[Storage](https://ji-podhead.github.io/Network-Guides/storage) | [Repo](https://github.com/ji-podhead/Network-Guides/) |

---

# Storage

 | [Knowledge Base](https://ji-podhead.github.io/Network-Guides/storage/Knowledge%20Base)| [ZFS & Proxmox](https://ji-podhead.github.io/Network-Guides/storage/zfs&proxmox) | [ISCSI & Proxmox & SCST](https://ji-podhead.github.io/Network-Guides/storage/iscsi) |

## Install
### RHEL

 ***Firewall***
>```bash
>$ sudo firewall-cmd --permanent --add-port=3260/tcp
>$ sudo firewall-cmd --reload
>```
>
>***Install targetcli and dependencies***
>
>```bash
>$ sudo dnf install git
>$ sudo dnf groupinstall "Development Tools" -y
>$ sudo dnf install openssl-devel -y
>$ sudo dnf install targetcli
>$ sudo systemctl start target
>$ sudo systemctl enable target
>```

---

### Debian

>```bash
>$ sudo apt update
>$ sudo apt install build-essential -y
>$ sudo apt install libssl-dev -y
>$ sudo apt install multipath-tools -y
>$ sudo apt install tgt
>```
> - not sure if ssh was required, but i guess so
>```bash
>$ sudo apt install openssh-server
>$ sudo systemctl enable --now ssh
>

---


### creating a iscsi target without scst-project

***create target***

```bash
sudo targetcli
/iscsi> create
```
 - or specific:
```bash
 /iscsi> create iqn.2006-04.com.example:444
```

***create a portal***

```bash
/iscsi> cd portals/
/iscsi/portals> create 192.168.1.100 3260
```

***export resources***
- now that you have a portal you can export storage resources like files, volumes, lokale SCSI-devices oder RAM-Disk
  
```bash
/iscsi> cd backstores/fileio/
/iscsi/backstores/fileio> create blockdev1 fileio /var/lib/mydata 10240
/iscsi> cd core/
/iscsi/core> create tpg1
/iscsi/core/tpg1> create acl iqn.2006-04.com.example:444
/iscsi/core/tpg1/acl> add initiator iqn.1993-08.org.debian:01:123456789abcdef
/iscsi/core/tpg1/luns> map blockdev1 1 0
```

***add portal to proxmox***
- ` Datacenter -> Storage -> Add -> iSCSI.`
- add the required information including the required iscsi-adress
> - in our example adress would be `iqn.2006-04.com.example:444`

---

### SCST Project

clone the repo:

```bash
$ git clone https://github.com/SCST-project/scst.git
$ cd scst
```
or

```bash
$ wget https://github.com/SCST-project/scst/archive/refs/tags/v3.8.tar.gz
$ tar -xzf v3.8.tar.gz
$ cd scst-3.8
```

***install***
- ***dont use  `$ sudo make install`***
- just follow the instructions (install script will take ages)

```bash
make 2release
if rpm -q glibc >/dev/null 2>&1; then
    rm -rf {,scstadmin/}rpmbuilddir
    make rpm
    sudo rpm -U $PWD/{,scstadmin/}rpmbuilddir/RPMS/*/*.rpm
elif dpkg-query -s libc-bin >/dev/null 2>&1; then
    sudo apt install build-essential debhelper devscripts gcc make lintian quilt
    sudo apt install linux-headers-$(uname -r) || sudo apt install pve-headers-$(uname -r)
    make dpkg
    sudo dpkg -i $PWD/dpkg/{scst,iscsi-scst,scstadmin}_*.deb
else
    make 2release
    BUILD_2X_MODULE=y CONFIG_SCSI_QLA_FC=y CONFIG_SCSI_QLA2XXX_TARGET=y make all
    sudo BUILD_2X_MODULE=y CONFIG_SCSI_QLA_FC=y CONFIG_SCSI_QLA2XXX_TARGET=y make -C "$PWD" install
fi
```


