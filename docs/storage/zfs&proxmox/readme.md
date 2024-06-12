


 | [main](https://ji-podhead.github.io/Network-Guides) | [DNS](https://ji-podhead.github.io/Network-Guides/DNS) |[DHCP](https://ji-podhead.github.io/Network-Guides/DHCP) |[Storage](https://ji-podhead.github.io/Network-Guides/storage) | [Repo](https://github.com/ji-podhead/Network-Guides/) |

---

## Storage

 | [Knowledge Base](https://ji-podhead.github.io/Network-Guides/DNS/Knowledge%20Base)| [ZFS & Proxmox](https://ji-podhead.github.io/Network-Guides/DNS/install) | [ISCSI & Proxmox & SCST](https://ji-podhead.github.io/Network-Guides/DNS/testAndDebug) |
 
***nice yt-video that explains the zfs tank:***

[![Thumbnail des Videos](https://img.youtube.com/vi/oSD-VoloQag/0.jpg)](https://www.youtube.com/watch?v=oSD-VoloQag&t=651s)


## proxmox ZFS tank


***add the disk’s that we need for the tank to our wm***

![add_disk](https://github.com/ji-podhead/RHEL_9_Foreman_Guide/blob/main/img/zfs1_kvm_add_disk.png?raw=true)

***create zfs called tank***

![create_tank](https://github.com/ji-podhead/RHEL_9_Foreman_Guide/blob/main/img/zfs2_creating_zfs.png?raw=true)

***create datasets for our zfs tank in proxmox shell:***

```bash
$ zfs create tank/backups
$ zfs create tank/isos
$ zfs create tank/diskstorage
```
***check it out:***
```bash
$ zfs list
$ zpool list
```
***
***create the zfs storage directories***
![create_storage](https://github.com/ji-podhead/RHEL_9_Foreman_Guide/blob/main/img/zfs3_create_storage.png?raw=true)***upload a iso (optional)***
![upload_iso](https://github.com/ji-podhead/RHEL_9_Foreman_Guide/blob/main/img/zfs4_upload_iso.png?raw=true)***move the wm storage to zfs (optional):***
![move_storage](https://github.com/ji-podhead/RHEL_9_Foreman_Guide/blob/main/img/zfs5_move_wm_storage.png?raw=true)***create a backup for our wm using our zfs_back storage directory(optional)***
![backup](https://github.com/ji-podhead/RHEL_9_Foreman_Guide/blob/main/img/zfs6_wm_backup.png?raw=true)

## nfs

***in proxmox shell:***

```bash
$ apt install nfs-common
$ apt install nfs-kernel-server
$ mkdir -p /mnt/shared_folder_on_nfs
$ chmod -R 777 /tank/diskstorage
$ chown -R nobody:nogroup /tank/diskstorage
```

***create zfs shared folder:***

```bash
$ zfs create tank/nfs_shared_folder
$ zfs set sharenfs=on tank/nfs_shared_folder
```
***edit the exports file:***

```bash
$ nano /etc/exports
```
>```yaml
>...
># /srv/nfs4/homes  gss/krb5i(rw,sync,no_subtree_check)
>#
>/proxmox.local:/tank/nfs_shared_folder *(rw,sync,no_subtree_check)
>```

***edit the wm-config:***
- this needs to be done in the machine that runs libvirt not inside proxmox
```bash
$ virsh edit <your_proxmox_wm>
```

> - add `<shareable/>` to the disk we added to create the zfs tank
> ```yaml
>      <disk type='block' device='disk'>
>      <driver name='qemu' type='raw' cache='none' io='native' discard='unmap'/>
>      <source dev='/dev/sdc'/>
>      <target dev='sdc' bus='sata'/>
>      <shareable/>
>      <address type='drive' controller='0' bus='0' target='0' unit='2'/>
>      </disk>
>```
> - this can also be done in the libvirt gui

## on the client side

***edit the fstab for pemanent mount:***

```bash
$ nano /etc/fstab
```
>```yaml
>...
>proc /proc proc defaults 0 0
>
>proxmox.local:/tank/diskstorage /mnt/shared_folder_on_nfs nfs auto 0 0
>```

***update Grub:***

```bash
$ sudo apt-get install --reinstall dracut
$ dracut -f
```

***we can mount the zfs tank thats is shared via nfs like this:***

```bash
$ mount -t nfs 192.168.122.166:/mnt/shared_folder_on_nfs <mountpoint> 
```
---
