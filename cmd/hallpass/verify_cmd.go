package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/aurimasniekis/go-hallpass/internal/audit"
	"github.com/aurimasniekis/go-hallpass/internal/recording"
)

func verifyCommand() *command {
	return &command{name: "verify", summary: "verify recording segments and the integrity chain (offline; takes the data-directory lock)", run: runVerify}
}

func runVerify(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fs := newFlagSet("verify", stderr)
	path := configFlag(fs)
	session := fs.String("session", "", "verify only this access session")
	asJSON := fs.Bool("json", false, "print JSON")
	adopt := fs.Bool("adopt-chain-head", false, "after checking every chain link and MAC, record the current last entry as the "+
		"authenticated chain head (for chains recorded before schema 19, or after investigating a reported head mismatch "+
		"against exported anchors); audited")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	a, err := openApp(ctx, *path)
	if err != nil {
		return &exitError{code: 1, err: err}
	}
	defer a.Close()
	if *adopt {
		seq, hash, err := a.Recording.AdoptChainHead(ctx, audit.Actor{Type: audit.ActorCLI, ID: "hallpass verify --adopt-chain-head"})
		if err != nil {
			return &exitError{code: 3, err: err}
		}
		fmt.Fprintf(stderr, "adopted integrity chain head %d %x; compare it with your latest exported anchor\n", seq, hash)
	}
	res, err := a.Recording.Verify(ctx, *session)
	if err != nil {
		return err
	}
	seq, head, err := a.Recording.ChainHead(ctx)
	if err != nil {
		return err
	}
	if *asJSON {
		out := struct {
			*recording.VerifyResult
			ChainHeadSeq  int64  `json:"chain_head_seq"`
			ChainHeadHash string `json:"chain_head_hash"`
		}{res, seq, hex.EncodeToString(head)}
		if err := json.NewEncoder(stdout).Encode(out); err != nil {
			return err
		}
	} else {
		counts := map[string]int{}
		for _, s := range res.Segments {
			counts[s.Status]++
			if s.Status != "ok" && s.Status != "skipped" {
				fmt.Fprintf(stdout, "%-11s %s session=%s %s\n", s.Status, s.SegmentID, s.SessionID, s.Problem)
			}
		}
		fmt.Fprintf(stdout, "segments: %d ok, %d interrupted, %d corrupt, %d missing, %d skipped\n",
			counts["ok"], counts["interrupted"], counts["corrupt"], counts["missing"], counts["skipped"])
		if res.ChainOK {
			fmt.Fprintf(stdout, "integrity chain: ok (%d entries, head %d %x)\n", res.ChainLen, seq, head)
		} else {
			fmt.Fprintf(stdout, "integrity chain: FAILED: %s\n", res.Problem)
		}
	}
	if !res.OK {
		return &exitError{code: 3, err: errors.New("verification found problems")}
	}
	return nil
}
