package fsstat

import (
	"errors"
	"path/filepath"
	"testing"
)

func TestStat(t *testing.T) {
	u, err := Stat(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if u.Total == 0 || u.Avail > u.Total {
		t.Errorf("implausible usage %+v", u)
	}
	if p := u.UsedPercent(); p < 0 || p > 100 {
		t.Errorf("used %% = %v", p)
	}
	if _, err := Stat(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Error("missing path must fail")
	}
}

func TestReserve(t *testing.T) {
	u := Usage{Total: 100 << 30, Avail: 3 << 30}
	if r := u.Reserve(2<<30, 5); r != 5<<30 { // 5% of 100 GiB beats 2 GiB
		t.Errorf("reserve = %d", r)
	}
	if !u.BelowReserve(2<<30, 5) {
		t.Error("3 GiB free is below a 5 GiB reserve")
	}
	if u.BelowReserve(2<<30, 0) || u.BelowReserve(0, 0) || u.BelowReserve(-1, -1) {
		t.Error("reserve must ignore non-positive thresholds")
	}
	if r := (Usage{Total: 10 << 30}).Reserve(2<<30, 5); r != 2<<30 {
		t.Errorf("small disk reserve = %d", r)
	}
	if (Usage{}).UsedPercent() != 0 || (Usage{Total: 10, Avail: 20}).UsedPercent() != 0 {
		t.Error("degenerate used percent")
	}
	if p := (Usage{Total: 100, Avail: 20}).UsedPercent(); p != 80 {
		t.Errorf("used = %v", p)
	}
}

func TestReserveCheck(t *testing.T) {
	dir := t.TempDir()
	if err := ReserveCheck(dir, 0, 0)(); err != nil {
		t.Errorf("no reserve: %v", err)
	}
	if err := ReserveCheck(dir, 1<<62, 0)(); !errors.Is(err, ErrBelowReserve) {
		t.Errorf("huge reserve: %v", err)
	}
	if err := ReserveCheck(filepath.Join(dir, "missing"), 0, 5)(); err == nil {
		t.Error("stat failure must fail closed")
	}
}
