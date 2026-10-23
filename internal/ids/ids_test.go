package ids

import (
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestFormatAndParse(t *testing.T) {
	id := New(Request)
	if len(id) != len("req_")+26 {
		t.Fatalf("bad length %q", id)
	}
	if !Valid(Request, id) || Valid(Grant, id) {
		t.Fatalf("validation wrong for %q", id)
	}
	for _, bad := range []string{"", "req_", "req_short", "req_" + "u" + id[5:], "req-" + id[4:], "req_" + "z0000000000000000000000000"} {
		if Valid(Request, bad) {
			t.Errorf("accepted %q", bad)
		}
	}
	upper := "req_" + strings.ToUpper(id[4:])
	if c, err := Parse(Request, upper); err != nil || c != id {
		t.Fatalf("parse canonical: %v %q", err, c)
	}
}

func TestMonotonicWithinMillisecond(t *testing.T) {
	fixed := time.UnixMilli(1_800_000_000_000)
	g := NewGenerator(func() time.Time { return fixed })
	prev := ""
	for range 10000 {
		id := g.New(Event)
		if id <= prev {
			t.Fatalf("not monotonic: %q after %q", id, prev)
		}
		prev = id
	}
}

func TestTimeRoundTrip(t *testing.T) {
	at := time.UnixMilli(1_790_000_123_456)
	g := NewGenerator(func() time.Time { return at })
	got, err := Time(g.New(Agent))
	if err != nil || !got.Equal(at) {
		t.Fatalf("got %v %v want %v", got, err, at)
	}
}

func TestUniqueConcurrent(t *testing.T) {
	var mu sync.Mutex
	seen := map[string]bool{}
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			local := make([]string, 0, 2000)
			for range 2000 {
				local = append(local, New(Channel))
			}
			mu.Lock()
			defer mu.Unlock()
			for _, id := range local {
				if seen[id] {
					t.Errorf("duplicate %s", id)
				}
				seen[id] = true
			}
		})
	}
	wg.Wait()
}

func TestSortedByTime(t *testing.T) {
	var list []string
	base := time.UnixMilli(1_800_000_000_000)
	for i := range 100 {
		g := NewGenerator(func() time.Time { return base.Add(time.Duration(i) * time.Millisecond) })
		list = append(list, g.New(Request))
	}
	if !sort.StringsAreSorted(list) {
		t.Fatal("ids not time-sortable")
	}
}
