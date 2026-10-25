// Package s3client is a small S3-compatible object storage client (AWS S3, Cloudflare R2, MinIO and others) for remote
// backups: put, get, head, list and delete, signed with AWS Signature Version 4. TLS verification is always on, there
// is no HTTP proxy and no redirect following, and private networks are refused at connect time unless allowed, like
// the OIDC client.
package s3client

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// MaxPutSize is the largest object one PUT may upload (the S3 single-request limit).
const MaxPutSize = 5 << 30

// Config describes a bucket and how to reach it.
type Config struct {
	// Endpoint is the service origin, e.g. https://s3.eu-central-1.amazonaws.com or
	// https://<account>.r2.cloudflarestorage.com. http is accepted only when AllowInsecureHTTP is set.
	Endpoint string
	Region   string
	Bucket   string
	// PathStyle addresses the bucket as <endpoint>/<bucket>/<key> instead of <bucket>.<endpoint>/<key> (MinIO).
	PathStyle       bool
	AccessKeyID     string
	SecretAccessKey string
	// CABundlePEM adds trust roots; verification is never disabled.
	CABundlePEM string
	// AllowPrivateNetwork lets the endpoint resolve to private, loopback or link-local addresses.
	AllowPrivateNetwork bool
	// AllowInsecureHTTP permits an http endpoint (development and tests only).
	AllowInsecureHTTP bool
	Timeout           time.Duration
	// Now overrides the signing clock (tests).
	Now func() time.Time
}

// Client talks to one bucket.
type Client struct {
	cfg  Config
	base *url.URL
	http *http.Client
}

// Error is an S3 error response.
type Error struct {
	Status  int
	Code    string `xml:"Code"`
	Message string `xml:"Message"`
}

func (e *Error) Error() string {
	if e.Code == "" {
		return fmt.Sprintf("object storage: HTTP %d", e.Status)
	}
	return fmt.Sprintf("object storage: %s: %s (HTTP %d)", e.Code, e.Message, e.Status)
}

// ErrNotFound is returned (wrapped) for a missing object.
var ErrNotFound = errors.New("object not found")

// New validates cfg and returns a client.
func New(cfg Config) (*Client, error) {
	u, err := url.Parse(strings.TrimRight(cfg.Endpoint, "/"))
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return nil, errors.New("endpoint must be an origin such as https://s3.example.com")
	}
	switch {
	case u.Scheme == "https":
	case u.Scheme == "http" && cfg.AllowInsecureHTTP:
	default:
		return nil, errors.New("endpoint must use https")
	}
	if !validBucket(cfg.Bucket) {
		return nil, errors.New("bucket must be 3-63 lowercase letters, digits, dots or hyphens")
	}
	if cfg.Region == "" {
		cfg.Region = "us-east-1"
	}
	if cfg.AccessKeyID == "" || cfg.SecretAccessKey == "" {
		return nil, errors.New("access key ID and secret access key are required")
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 30 * time.Second
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	roots, err := x509.SystemCertPool()
	if err != nil || roots == nil {
		roots = x509.NewCertPool()
	}
	if cfg.CABundlePEM != "" {
		if err := addPEM(roots, cfg.CABundlePEM); err != nil {
			return nil, err
		}
	}
	allowPrivate := cfg.AllowPrivateNetwork
	dialer := &net.Dialer{Timeout: cfg.Timeout, Control: func(_, address string, _ syscall.RawConn) error {
		ap, err := netip.ParseAddrPort(address)
		if err != nil {
			return err
		}
		if !allowPrivate && denyPrivate(ap.Addr()) {
			return fmt.Errorf("object storage address %s is in a private or special-purpose range (allow_private_network is off)", ap.Addr())
		}
		return nil
	}}
	tr := &http.Transport{
		Proxy:                 nil,
		DialContext:           dialer.DialContext,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots},
		TLSHandshakeTimeout:   cfg.Timeout,
		ResponseHeaderTimeout: cfg.Timeout,
		MaxIdleConnsPerHost:   4,
		IdleConnTimeout:       90 * time.Second,
		ForceAttemptHTTP2:     true,
	}
	// No overall client timeout: uploads of large snapshots take as long as they take; contexts bound them.
	hc := &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return &Client{cfg: cfg, base: u, http: hc}, nil
}

func addPEM(pool *x509.CertPool, bundle string) error {
	rest := []byte(bundle)
	n := 0
	for {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			break
		}
		if b.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			return fmt.Errorf("CA bundle: %w", err)
		}
		pool.AddCert(c)
		n++
	}
	if n == 0 {
		return errors.New("CA bundle holds no certificates")
	}
	return nil
}

func validBucket(b string) bool {
	if len(b) < 3 || len(b) > 63 {
		return false
	}
	for i := 0; i < len(b); i++ {
		c := b[i]
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '.' && c != '-' {
			return false
		}
	}
	return b[0] != '.' && b[0] != '-' && b[len(b)-1] != '.' && b[len(b)-1] != '-'
}

// denyPrivate reports addresses outside the public internet.
func denyPrivate(a netip.Addr) bool {
	a = a.Unmap()
	return !a.IsGlobalUnicast() || a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast() ||
		netip.MustParsePrefix("100.64.0.0/10").Contains(a) || netip.MustParsePrefix("fc00::/7").Contains(a)
}

// objectURL returns the request URL and the unescaped path that is signed.
func (c *Client) objectURL(key string, q url.Values) (*url.URL, string) {
	u := *c.base
	var p string
	if c.cfg.PathStyle {
		p = "/" + c.cfg.Bucket + "/" + key
	} else {
		u.Host = c.cfg.Bucket + "." + c.base.Host
		p = "/" + key
	}
	u.Path = p
	u.RawPath = uriEncode(p, true)
	u.RawQuery = canonicalQuery(q)
	return &u, p
}

func (c *Client) do(ctx context.Context, method, key string, q url.Values, body io.Reader, size int64, payloadHash string) (*http.Response, error) {
	u, raw := c.objectURL(key, q)
	req, err := http.NewRequestWithContext(ctx, method, u.String(), body)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.ContentLength = size
	}
	sign(req, raw, payloadHash, c.cfg.AccessKeyID, c.cfg.SecretAccessKey, c.cfg.Region, c.cfg.Now())
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 300 {
		defer resp.Body.Close()
		e := &Error{Status: resp.StatusCode}
		if b, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10)); len(b) > 0 {
			_ = xml.Unmarshal(b, e)
		}
		if resp.StatusCode == http.StatusNotFound && (e.Code == "" || e.Code == "NoSuchKey") {
			return nil, fmt.Errorf("%w: %s", ErrNotFound, key)
		}
		return nil, e
	}
	return resp, nil
}

// Put uploads size bytes from body as key. payloadHash is the hex SHA-256 of the body, which S3 verifies.
func (c *Client) Put(ctx context.Context, key string, body io.Reader, size int64, payloadHash string) error {
	if size > MaxPutSize {
		return fmt.Errorf("object %s is %d bytes, more than the %d-byte single upload limit", key, size, int64(MaxPutSize))
	}
	resp, err := c.do(ctx, http.MethodPut, key, nil, body, size, payloadHash)
	if err != nil {
		return err
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.Body.Close()
}

// Get opens key for reading; the caller closes the body.
func (c *Client) Get(ctx context.Context, key string) (io.ReadCloser, int64, error) {
	resp, err := c.do(ctx, http.MethodGet, key, nil, nil, 0, EmptySHA256)
	if err != nil {
		return nil, 0, err
	}
	return resp.Body, resp.ContentLength, nil
}

// Head returns the size of key, or ErrNotFound.
func (c *Client) Head(ctx context.Context, key string) (int64, error) {
	resp, err := c.do(ctx, http.MethodHead, key, nil, nil, 0, EmptySHA256)
	if err != nil {
		var e *Error
		if errors.As(err, &e) && e.Status == http.StatusNotFound {
			return 0, fmt.Errorf("%w: %s", ErrNotFound, key)
		}
		return 0, err
	}
	_ = resp.Body.Close()
	return resp.ContentLength, nil
}

// Delete removes key. Deleting a missing key succeeds (S3 semantics).
func (c *Client) Delete(ctx context.Context, key string) error {
	resp, err := c.do(ctx, http.MethodDelete, key, nil, nil, 0, EmptySHA256)
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.Body.Close()
}

// Object is one listed object.
type Object struct {
	Key          string    `xml:"Key"`
	Size         int64     `xml:"Size"`
	LastModified time.Time `xml:"LastModified"`
}

type listResult struct {
	Contents              []Object `xml:"Contents"`
	IsTruncated           bool     `xml:"IsTruncated"`
	NextContinuationToken string   `xml:"NextContinuationToken"`
}

// List returns every object whose key starts with prefix (ListObjectsV2, following continuation tokens).
func (c *Client) List(ctx context.Context, prefix string) ([]Object, error) {
	var out []Object
	token := ""
	for page := 0; ; page++ {
		if page > 100000 {
			return nil, errors.New("object listing did not terminate")
		}
		q := url.Values{"list-type": {"2"}, "prefix": {prefix}, "max-keys": {strconv.Itoa(1000)}}
		if token != "" {
			q.Set("continuation-token", token)
		}
		resp, err := c.listRequest(ctx, q)
		if err != nil {
			return nil, err
		}
		out = append(out, resp.Contents...)
		if !resp.IsTruncated || resp.NextContinuationToken == "" {
			return out, nil
		}
		token = resp.NextContinuationToken
	}
}

func (c *Client) listRequest(ctx context.Context, q url.Values) (*listResult, error) {
	u := *c.base
	raw := "/"
	if c.cfg.PathStyle {
		raw = "/" + c.cfg.Bucket
	} else {
		u.Host = c.cfg.Bucket + "." + c.base.Host
	}
	u.Path, u.RawPath, u.RawQuery = raw, uriEncode(raw, true), canonicalQuery(q)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	sign(req, raw, EmptySHA256, c.cfg.AccessKeyID, c.cfg.SecretAccessKey, c.cfg.Region, c.cfg.Now())
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 300 {
		e := &Error{Status: resp.StatusCode}
		_ = xml.Unmarshal(b, e)
		return nil, e
	}
	var lr listResult
	if err := xml.Unmarshal(b, &lr); err != nil {
		return nil, fmt.Errorf("object listing: %w", err)
	}
	return &lr, nil
}
