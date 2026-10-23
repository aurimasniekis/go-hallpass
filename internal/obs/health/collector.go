package health

import "github.com/prometheus/client_golang/prometheus"

var allStatuses = []Status{StatusStarting, StatusReady, StatusDegraded, StatusFailed, StatusStopping}

// Collector exports the last readiness evaluation (it never runs checks itself; use Run to keep it fresh):
//
//	hallpass_readiness_state{state}  1 for the current state, 0 for the others
//	hallpass_readiness_check_ok{check} 1 when the check passed, 0 when degraded or failed
//
// Check names come from Register (validated, code-defined), so the label set is bounded.
func (c *Checker) Collector() prometheus.Collector { return &collector{c: c} }

var (
	descState = prometheus.NewDesc("hallpass_readiness_state", "Readiness state (1 for the current state).", []string{"state"}, nil)
	descCheck = prometheus.NewDesc("hallpass_readiness_check_ok", "Readiness check result from the last evaluation (1 ok, 0 degraded or failed).", []string{"check"}, nil)
)

type collector struct{ c *Checker }

func (col *collector) Describe(ch chan<- *prometheus.Desc) {
	ch <- descState
	ch <- descCheck
}

func (col *collector) Collect(ch chan<- prometheus.Metric) {
	rep, ok := col.c.Last()
	cur := rep.Status
	if !ok {
		cur = StatusStarting // serving but never evaluated: report not ready rather than guess
	}
	for _, s := range allStatuses {
		v := 0.0
		if s == cur {
			v = 1
		}
		ch <- prometheus.MustNewConstMetric(descState, prometheus.GaugeValue, v, string(s))
	}
	for _, r := range rep.Checks {
		v := 0.0
		if r.Status == CheckOK {
			v = 1
		}
		ch <- prometheus.MustNewConstMetric(descCheck, prometheus.GaugeValue, v, r.Name)
	}
}
