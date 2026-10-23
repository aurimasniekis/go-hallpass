package recording

import (
	"errors"
	"testing"
	"time"

	"github.com/aurimasniekis/go-hallpass/internal/access"
	"github.com/aurimasniekis/go-hallpass/internal/obs/metrics"
	"github.com/aurimasniekis/go-hallpass/internal/obs/metrics/metricstest"
	"github.com/aurimasniekis/go-hallpass/internal/sshproxy"
)

// HP-OBS-004: records, bytes, queue depth, finalize latency and failures are exported.
func TestRecorderMetrics(t *testing.T) {
	f := newFx(t)
	m := metrics.New()
	svc := f.service(Options{Metrics: m, Durability: "strict"})
	reg := f.channel(access.KindExec)
	rec, err := svc.Open(f.ctx, reg, access.KindExec, false)
	must(t, err)
	must(t, rec.ExecRequested("uptime"))
	must(t, rec.Output(sshproxy.StreamStdout, []byte("0123456789")))
	must(t, rec.Finalize("exit_status"))
	val := func(name string, labels ...string) float64 { return metricstest.Value(t, m, name, labels...) }
	if v := val("hallpass_recording_records_total"); v != 2 {
		t.Errorf("records = %v", v)
	}
	if v := val("hallpass_recording_bytes_total"); v != 16 {
		t.Errorf("bytes = %v", v)
	}
	if v := val("hallpass_recording_queue_depth"); v != 0 {
		t.Errorf("queue depth = %v", v)
	}
	if v := val("hallpass_recording_segment_finalize_seconds"); v != 1 {
		t.Errorf("finalize samples = %v", v)
	}
	if v := val("hallpass_recording_segments_total", "result", "finalized"); v != 1 {
		t.Errorf("finalized = %v", v)
	}

	// Stall: queue timeout counted once, the failed segment once.
	svc2 := f.service(Options{Metrics: m, QueueBytes: 1024, QueueRecords: 1, BlockTimeout: 50 * time.Millisecond})
	reg2 := f.channel(access.KindExec)
	r2, err := svc2.Open(f.ctx, reg2, access.KindExec, false)
	must(t, err)
	cr := r2.(*channelRecorder)
	for range cap(cr.bytes) {
		cr.bytes <- struct{}{}
	}
	if err := cr.Output(sshproxy.StreamStdout, []byte("blocked")); err == nil {
		t.Fatal("expected stall")
	}
	_ = cr.Output(sshproxy.StreamStdout, []byte("again")) // already failed: not counted again
	for range cap(cr.bytes) {
		<-cr.bytes
	}
	cr.Abort(errors.New("stalled"))
	if v := val("hallpass_recording_failures_total", "stage", "queue_timeout"); v != 1 {
		t.Errorf("queue timeouts = %v", v)
	}
	if v := val("hallpass_recording_segments_total", "result", "failed"); v != 1 {
		t.Errorf("failed segments = %v", v)
	}
}
