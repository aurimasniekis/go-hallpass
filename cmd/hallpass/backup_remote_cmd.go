package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"text/tabwriter"

	"github.com/aurimasniekis/go-hallpass/internal/backup"
	"github.com/aurimasniekis/go-hallpass/internal/keyring"
	"github.com/aurimasniekis/go-hallpass/internal/s3client"
)

// Remote backups are made by the server (System → Backups); these commands find and download them on any host,
// typically a fresh one being restored. The bucket is named with flags; the access key comes from the environment
// (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY) so it never appears in a process listing.

type s3Flags struct {
	endpoint, region, bucket, prefix, caFile *string
	pathStyle, allowPrivate                  *bool
}

func addS3Flags(fs *flag.FlagSet) s3Flags {
	return s3Flags{
		endpoint:     fs.String("s3-endpoint", "", "object storage endpoint, e.g. https://s3.eu-central-1.amazonaws.com"),
		region:       fs.String("s3-region", "us-east-1", "region (auto for Cloudflare R2)"),
		bucket:       fs.String("s3-bucket", "", "bucket"),
		prefix:       fs.String("s3-prefix", "", "key prefix the server uses (empty or ending with /)"),
		caFile:       fs.String("s3-ca-file", "", "extra trust roots (PEM) for the endpoint"),
		pathStyle:    fs.Bool("s3-path-style", false, "address the bucket as endpoint/bucket (MinIO)"),
		allowPrivate: fs.Bool("s3-allow-private-network", false, "allow an endpoint on a private network"),
	}
}

func (f s3Flags) client() (*s3client.Client, error) {
	if *f.endpoint == "" || *f.bucket == "" {
		return nil, &exitError{code: 2, err: errors.New("--s3-endpoint and --s3-bucket are required")}
	}
	if err := backup.ValidatePrefix(*f.prefix); err != nil {
		return nil, &exitError{code: 2, err: err}
	}
	ca := ""
	if *f.caFile != "" {
		b, err := os.ReadFile(*f.caFile)
		if err != nil {
			return nil, &exitError{code: 1, err: err}
		}
		ca = string(b)
	}
	c, err := s3client.New(s3client.Config{Endpoint: *f.endpoint, Region: *f.region, Bucket: *f.bucket, PathStyle: *f.pathStyle,
		AccessKeyID: os.Getenv("AWS_ACCESS_KEY_ID"), SecretAccessKey: os.Getenv("AWS_SECRET_ACCESS_KEY"), CABundlePEM: ca,
		AllowPrivateNetwork: *f.allowPrivate})
	if err != nil {
		return nil, &exitError{code: 1, err: fmt.Errorf("%w (set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY)", err)}
	}
	return c, nil
}

func runBackupRemoteList(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fs := newFlagSet("backup remote-list", stderr)
	s3 := addS3Flags(fs)
	asJSON := fs.Bool("json", false, "print JSON")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	c, err := s3.client()
	if err != nil {
		return err
	}
	list, err := backup.ListRemote(ctx, c, *s3.prefix)
	if err != nil {
		return &exitError{code: 1, err: err}
	}
	if *asJSON {
		return json.NewEncoder(stdout).Encode(list)
	}
	if len(list) == 0 {
		fmt.Fprintln(stdout, "no backups found")
		return nil
	}
	tw := tabwriter.NewWriter(stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "BACKUP\tCREATED\tSIZE\tSTATE")
	for _, b := range list {
		state, created := "complete", b.CreatedAt.Format("2006-01-02T15:04:05Z07:00")
		if !b.Complete {
			state, created = "incomplete (not restorable)", "-"
		}
		fmt.Fprintf(tw, "%s\t%s\t%d\t%s\n", b.ID, created, b.Bytes, state)
	}
	return tw.Flush()
}

func runBackupRemoteDownload(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fs := newFlagSet("backup remote-download", stderr)
	path := configFlag(fs)
	s3 := addS3Flags(fs)
	id := fs.String("backup", "", "backup ID to download (see hallpass backup remote-list); default: the newest complete one")
	out := fs.String("out", "", "new directory to write the backup to (must not exist)")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if *out == "" {
		return &exitError{code: 2, err: errors.New("--out is required")}
	}
	cfg, err := loadConfig(*path)
	if err != nil {
		return &exitError{code: 1, err: err}
	}
	if cfg.KEK.Source != "env" && cfg.KEK.File == "" {
		return &exitError{code: 1, err: errors.New("the remote backup is sealed under the KEK: set kek.file (or kek.source=env with HALLPASS_KEK)")}
	}
	kek, err := keyring.LoadKEK(keyring.Source{Kind: cfg.KEK.Source, File: cfg.KEK.File, Production: true, Environ: os.Environ()})
	if err != nil {
		return &exitError{code: 1, err: err}
	}
	c, err := s3.client()
	if err != nil {
		return err
	}
	if *id == "" {
		list, err := backup.ListRemote(ctx, c, *s3.prefix)
		if err != nil {
			return &exitError{code: 1, err: err}
		}
		for _, b := range list {
			if b.Complete {
				*id = b.ID
				break
			}
		}
		if *id == "" {
			return &exitError{code: 1, err: errors.New("no complete backup found below the prefix")}
		}
	}
	m, err := backup.DownloadRemote(ctx, c, kek, *s3.prefix, *id, *out)
	if err != nil {
		code := 1
		if errors.Is(err, backup.ErrInvalid) || errors.Is(err, backup.ErrSealed) {
			code = 3
		}
		return &exitError{code: code, err: err}
	}
	fmt.Fprintf(stdout, "downloaded backup %s (created %s, schema %d, %d files) to %s\n", *id,
		m.CreatedAt.Format("2006-01-02T15:04:05Z07:00"), m.SchemaVersion, len(m.Files), *out)
	fmt.Fprintf(stdout, "next: hallpass backup verify %s; then hallpass restore%s %s\n", *out, configArg(*path), *out)
	return nil
}
