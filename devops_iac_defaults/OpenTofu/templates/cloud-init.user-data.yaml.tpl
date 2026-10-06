#cloud-config
# Cloud-init user-data template -- substitute via templatefile().
# Variables expected: hostname, ssh_authorized_keys (list), timezone

hostname: ${hostname}
manage_etc_hosts: true
preserve_hostname: false
timezone: ${timezone}

users:
  - name: peregrine
    sudo: "ALL=(ALL) NOPASSWD:ALL"
    shell: /bin/bash
    lock_passwd: true
    ssh_authorized_keys:
%{ for k in ssh_authorized_keys ~}
      - ${k}
%{ endfor ~}

package_update: true
package_upgrade: false
packages:
  - curl
  - ca-certificates

runcmd:
  - [ systemctl, enable, --now, ssh ]
