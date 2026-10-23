package ssh

type PublicKey interface{ Type() string }

type Client struct{}

func (c *Client) NewSession() error { return nil }

func Dial(network, addr string) (*Client, error) { return nil, nil }

func FingerprintSHA256(pk PublicKey) string { return "" }
