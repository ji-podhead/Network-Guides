


```bash
# wget -O /tmp/package-signing-pubkey.asc \
https://packages.linbit.com/package-signing-pubkey.asc
# gpg --yes -o /etc/apt/trusted.gpg.d/linbit-keyring.gpg --dearmor \
/tmp/package-signing-pubkey.asc
# PVERS=8 && echo "deb [signed-by=/etc/apt/trusted.gpg.d/linbit-keyring.gpg] \
http://packages.linbit.com/public/ proxmox-$PVERS drbd-9" > /etc/apt/sources.list.d/linbit.list

apt update && apt -y install drbd-dkms drbd-utils linstor-proxmox
 apt update && apt -y install linstor-controller linstor-satellite linstor-client
