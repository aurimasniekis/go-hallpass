package collector

import (
	"bufio"
	"context"
	"io"
	"time"

	"github.com/aurimasniekis/go-hallpass/internal/destaudit/wire"
)

// MaxLineBytes bounds one input line.
const MaxLineBytes = 1 << 20

// Sink receives ready records (Shipper.Send, or a dry-run printer).
type Sink func(ctx context.Context, recs []wire.Record) error

// Run reads lines from r until EOF or ctx ends, flushing ready records to sink every flushEvery (default 5s) and
// once more at the end. When onError is nil the first sink error stops Run; otherwise onError receives it and Run
// continues (the records of that flush are dropped and the drop is reported).
func Run(ctx context.Context, r io.Reader, a *Assembler, sink Sink, flushEvery time.Duration, onError func(error)) error {
	if flushEvery <= 0 {
		flushEvery = 5 * time.Second
	}
	lines := make(chan string, 1024)
	readErr := make(chan error, 1)
	go func() {
		sc := bufio.NewScanner(r)
		sc.Buffer(make([]byte, 64<<10), MaxLineBytes)
		for sc.Scan() {
			select {
			case lines <- sc.Text():
			case <-ctx.Done():
				readErr <- ctx.Err()
				return
			}
		}
		readErr <- sc.Err()
		close(lines)
	}()
	tick := time.NewTicker(flushEvery)
	defer tick.Stop()
	flush := func(final bool) error {
		recs := a.Drain(time.Now(), final)
		if len(recs) == 0 {
			return nil
		}
		if err := sink(ctx, recs); err != nil {
			if onError == nil {
				return err
			}
			onError(err)
		}
		return nil
	}
	for {
		select {
		case line, ok := <-lines:
			if !ok {
				if err := flush(true); err != nil {
					return err
				}
				return <-readErr
			}
			a.Add(line, time.Now())
		case <-tick.C:
			if err := flush(false); err != nil {
				return err
			}
		case <-ctx.Done():
			// Ship what is complete; use a fresh context so the final batch is not canceled with the input.
			sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
			defer cancel()
			recs := a.Drain(time.Now(), true)
			if len(recs) > 0 {
				if err := sink(sctx, recs); err != nil && onError != nil {
					onError(err)
				}
			}
			return nil
		}
	}
}
