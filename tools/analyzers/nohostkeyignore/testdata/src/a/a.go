package a

import "golang.org/x/crypto/ssh"

var cb = ssh.InsecureIgnoreHostKey() // want `ssh.InsecureIgnoreHostKey is forbidden`

var ref = ssh.InsecureIgnoreHostKey // want `ssh.InsecureIgnoreHostKey is forbidden`

var ok = ssh.FixedHostKey()
