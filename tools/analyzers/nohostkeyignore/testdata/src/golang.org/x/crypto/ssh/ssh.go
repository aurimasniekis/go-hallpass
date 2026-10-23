package ssh

type HostKeyCallback func(hostname string) error

func InsecureIgnoreHostKey() HostKeyCallback { return nil }

func FixedHostKey() HostKeyCallback { return nil }
