#!/bin/sh
set -e
ssh-keygen -q -t ed25519 -N "" -f /etc/ssh/ssh_host_ed25519_key
ssh-keygen -q -t ecdsa -b 256 -N "" -f /etc/ssh/ssh_host_ecdsa_key
exec /usr/sbin/sshd -D -e
