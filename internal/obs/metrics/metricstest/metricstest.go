// Package metricstest reads metric values from a metrics.Metrics registry in tests.
package metricstest

import (
	"testing"

	dto "github.com/prometheus/client_model/go"

	"github.com/aurimasniekis/go-hallpass/internal/obs/metrics"
)

// Value sums the series of family name whose labels include every pair in labels ("key", "value", …). Counters
// and gauges contribute their value, histograms their sample count. A missing family is 0.
func Value(t testing.TB, m *metrics.Metrics, name string, labels ...string) float64 {
	t.Helper()
	if len(labels)%2 != 0 {
		t.Fatalf("metricstest.Value: odd label list %v", labels)
	}
	fams, err := m.Registry().Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	var sum float64
	for _, f := range fams {
		if f.GetName() != name {
			continue
		}
		for _, mt := range f.GetMetric() {
			if !matches(mt, labels) {
				continue
			}
			switch {
			case mt.Counter != nil:
				sum += mt.GetCounter().GetValue()
			case mt.Gauge != nil:
				sum += mt.GetGauge().GetValue()
			case mt.Histogram != nil:
				sum += float64(mt.GetHistogram().GetSampleCount())
			}
		}
	}
	return sum
}

func matches(mt *dto.Metric, labels []string) bool {
	for i := 0; i < len(labels); i += 2 {
		found := false
		for _, l := range mt.GetLabel() {
			if l.GetName() == labels[i] && l.GetValue() == labels[i+1] {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}
