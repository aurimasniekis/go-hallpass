// Command hallpass-collector is the reference destination-side audit collector for HallPass (WP25, HP-REC-012).
//
// It runs on a destination host, reads Linux audit (auditd) and sshd log lines, assembles exec records for logins
// made by HallPass, signs them with its own Ed25519 key and posts them to HallPass. HallPass labels everything it
// receives as destination-reported: a root user on the destination can forge or suppress these records.
//
//	hallpass-collector keygen -key /etc/hallpass-collector/key
//	hallpass-collector pubkey -key /etc/hallpass-collector/key
//	tail -F -n0 /var/log/audit/audit.log /var/log/auth.log | hallpass-collector run \
//	    -url https://hallpass.example.com -collector-id dac_… -key /etc/hallpass-collector/key \
//	    -state /var/lib/hallpass-collector/seq
//
// See docs/destination/audit-collector.md.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/aurimasniekis/go-hallpass/internal/buildinfo"
	"github.com/aurimasniekis/go-hallpass/internal/destaudit/collector"
	"github.com/aurimasniekis/go-hallpass/internal/destaudit/wire"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := run(ctx, os.Args[1:], os.Stdin, os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}

const usage = `usage: hallpass-collector <command> [flags]

commands:
  keygen   create a new collector key (prints the public key to enroll in HallPass)
  pubkey   print the public key of an existing collector key
  run      read audit/sshd log lines (files or stdin) and ship exec records to HallPass
  version  print the version
`

func run(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	var err error
	switch args[0] {
	case "keygen":
		err = cmdKeygen(args[1:], stdout, stderr)
	case "pubkey":
		err = cmdPubkey(args[1:], stdout, stderr)
	case "run":
		err = cmdRun(ctx, args[1:], stdin, stdout, stderr)
	case "version":
		fmt.Fprintln(stdout, "hallpass-collector", buildinfo.Version)
	case "help", "-h", "--help":
		fmt.Fprint(stdout, usage)
	default:
		fmt.Fprint(stderr, usage)
		return 2
	}
	if errors.Is(err, flag.ErrHelp) {
		return 0
	}
	if err != nil {
		fmt.Fprintf(stderr, "hallpass-collector: %v\n", err)
		return 1
	}
	return 0
}

func cmdKeygen(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("keygen", flag.ContinueOnError)
	fs.SetOutput(stderr)
	key := fs.String("key", "", "path of the new private key (must not exist)")
	comment := fs.String("comment", defaultComment(), "public key comment")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *key == "" {
		return errors.New("-key is required")
	}
	line, err := collector.GenerateKeyFile(*key, *comment)
	if err != nil {
		return err
	}
	fmt.Fprintln(stdout, line)
	return nil
}

func defaultComment() string {
	h, err := os.Hostname()
	if err != nil || h == "" {
		return "hallpass-collector"
	}
	return "hallpass-collector@" + h
}

func cmdPubkey(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("pubkey", flag.ContinueOnError)
	fs.SetOutput(stderr)
	key := fs.String("key", "", "private key path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	priv, err := collector.LoadKeyFile(*key)
	if err != nil {
		return err
	}
	line, err := collector.PublicLine(priv.Public().(ed25519.PublicKey), "")
	if err != nil {
		return err
	}
	fmt.Fprintln(stdout, line)
	return nil
}

type listFlag []string

func (l *listFlag) String() string     { return strings.Join(*l, ",") }
func (l *listFlag) Set(v string) error { *l = append(*l, v); return nil }

type runConfig struct {
	baseURL, collectorID, keyPath, statePath, caFile string
	allowHTTP, dryRun                                bool
	flushEvery                                       time.Duration
	accounts, fingerprints                           listFlag
	inputs                                           []string
}

func cmdRun(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	var c runConfig
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&c.baseURL, "url", "", "HallPass base URL (https://…); records are posted to <url>/hooks/destaudit/<collector-id>")
	fs.StringVar(&c.collectorID, "collector-id", "", "collector ID assigned by HallPass at enrollment (dac_…)")
	fs.StringVar(&c.keyPath, "key", "", "collector private key (created by keygen)")
	fs.StringVar(&c.statePath, "state", "", "file that persists the last accepted batch sequence number")
	fs.StringVar(&c.caFile, "ca-file", "", "PEM CA bundle to verify HallPass's TLS certificate (default: system roots)")
	fs.BoolVar(&c.allowHTTP, "allow-insecure-http", false, "allow a plain http:// URL (testing only: exec arguments would cross the network unencrypted)")
	fs.BoolVar(&c.dryRun, "dry-run", false, "print records as JSON lines instead of sending them (no key or URL needed)")
	fs.DurationVar(&c.flushEvery, "flush-interval", 5*time.Second, "how often to ship assembled records")
	fs.Var(&c.accounts, "account", "also ship managed-key logins of this destination account (repeatable)")
	fs.Var(&c.fingerprints, "fingerprint", "also ship logins with this SHA256 key fingerprint (repeatable; HallPass managed login keys)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	c.inputs = fs.Args()

	filter := collector.Filter{Fingerprints: map[string]bool{}, Accounts: map[string]bool{}}
	for _, f := range c.fingerprints {
		filter.Fingerprints[f] = true
	}
	for _, a := range c.accounts {
		filter.Accounts[a] = true
	}
	asm := collector.NewAssembler(filter)

	sink, err := c.sink(stdout, stderr)
	if err != nil {
		return err
	}
	in, closeIn, err := openInputs(c.inputs, stdin)
	if err != nil {
		return err
	}
	defer closeIn()
	onErr := func(err error) { fmt.Fprintf(stderr, "hallpass-collector: ship: %v\n", err) }
	err = collector.Run(ctx, in, asm, sink, c.flushEvery, onErr)
	st := asm.Stats
	fmt.Fprintf(stderr, "hallpass-collector: lines=%d exec_events=%d shipped=%d not_shipped=%d ignored_lines=%d\n",
		st.Lines, st.Execs, st.Shipped, st.NotShipped, st.Ignored)
	return err
}

func (c *runConfig) sink(stdout, stderr io.Writer) (collector.Sink, error) {
	if c.dryRun {
		enc := json.NewEncoder(stdout)
		return func(_ context.Context, recs []wire.Record) error {
			for i := range recs {
				if err := enc.Encode(&recs[i]); err != nil {
					return err
				}
			}
			return nil
		}, nil
	}
	if c.baseURL == "" || c.collectorID == "" || c.keyPath == "" {
		return nil, errors.New("-url, -collector-id and -key are required (or use -dry-run)")
	}
	target, err := ingestURL(c.baseURL, c.collectorID, c.allowHTTP)
	if err != nil {
		return nil, err
	}
	key, err := collector.LoadKeyFile(c.keyPath)
	if err != nil {
		return nil, err
	}
	client, err := httpClient(c.caFile)
	if err != nil {
		return nil, err
	}
	sh := &collector.Shipper{URL: target, CollectorID: c.collectorID, Key: key, Client: client, StatePath: c.statePath}
	if err := sh.LoadState(); err != nil {
		return nil, err
	}
	return func(ctx context.Context, recs []wire.Record) error {
		res, err := sh.Send(ctx, recs)
		if res != nil {
			for _, r := range res.Rejections {
				fmt.Fprintf(stderr, "hallpass-collector: record %s not attached: %s\n", r.RecordID, r.Reason)
			}
		}
		return err
	}, nil
}

// ingestURL builds <base>/hooks/destaudit/<id>, requiring https unless explicitly allowed.
func ingestURL(base, id string, allowHTTP bool) (string, error) {
	u, err := url.Parse(base)
	if err != nil || u.Host == "" {
		return "", fmt.Errorf("invalid -url %q", base)
	}
	switch u.Scheme {
	case "https":
	case "http":
		if !allowHTTP {
			return "", errors.New("-url must use https (use -allow-insecure-http only for testing)")
		}
	default:
		return "", fmt.Errorf("invalid -url scheme %q", u.Scheme)
	}
	if !strings.HasPrefix(id, "dac_") || strings.ContainsAny(id, "/?#") {
		return "", fmt.Errorf("invalid -collector-id %q", id)
	}
	return u.JoinPath("hooks", "destaudit", id).String(), nil
}

func httpClient(caFile string) (*http.Client, error) {
	tc := &tls.Config{MinVersion: tls.VersionTLS12}
	if caFile != "" {
		pem, err := os.ReadFile(caFile) //nolint:gosec // operator-chosen CA path
		if err != nil {
			return nil, err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("no certificates in %s", caFile)
		}
		tc.RootCAs = pool
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = tc
	return &http.Client{Timeout: 30 * time.Second, Transport: tr}, nil
}

// openInputs concatenates the named files ("-" is stdin); no names means stdin.
func openInputs(names []string, stdin io.Reader) (io.Reader, func(), error) {
	if len(names) == 0 {
		return stdin, func() {}, nil
	}
	var readers []io.Reader
	var files []*os.File
	closeAll := func() {
		for _, f := range files {
			_ = f.Close()
		}
	}
	for _, n := range names {
		if n == "-" {
			readers = append(readers, stdin)
			continue
		}
		f, err := os.Open(n) //nolint:gosec // operator-chosen log path
		if err != nil {
			closeAll()
			return nil, nil, err
		}
		files = append(files, f)
		// Each file ends with a newline boundary so lines of consecutive files never merge.
		readers = append(readers, f, strings.NewReader("\n"))
	}
	return io.MultiReader(readers...), closeAll, nil
}
