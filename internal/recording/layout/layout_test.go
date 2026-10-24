package layout

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aurimasniekis/go-hallpass/internal/ids"
)

// SR-16: segment locations come only from canonical IDs and always stay under the recordings directory.
func TestPath(t *testing.T) {
	ses, seg := ids.New(ids.Session), ids.New(ids.Segment)
	p, err := Path("/data/recordings", ses, seg)
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join("/data/recordings", ses[len(ses)-2:], ses, seg+Ext); p != want {
		t.Fatalf("path %s, want %s", p, want)
	}
	for _, c := range [][2]string{
		{"..", seg}, {ses, ".."}, {"ses_../../x", seg}, {ses, "seg_" + strings.Repeat(".", 26)}, {strings.ToUpper(ses[:4]) + ses[4:], seg},
		{ses, strings.Replace(seg, "seg_", "ses_", 1)}, {"", seg}, {ses, ""}, {ses, "/etc/passwd"}, {ses, seg[:len(seg)-1] + "/"},
	} {
		if _, err := Path("/data/recordings", c[0], c[1]); !errors.Is(err, ErrInvalidID) {
			t.Errorf("Path(%q, %q) accepted", c[0], c[1])
		}
	}
}

func TestMatches(t *testing.T) {
	ses, seg := ids.New(ids.Session), ids.New(ids.Segment)
	good, _ := Path("/srv/hallpass/recordings", ses, seg)
	moved, _ := Path("/mnt/new/recordings", ses, seg)
	for _, p := range []string{good, moved} {
		if !Matches(p, ses, seg) {
			t.Errorf("%s does not match", p)
		}
	}
	other, _ := Path("/srv/hallpass/recordings", ses, ids.New(ids.Segment))
	for _, p := range []string{"", "/etc/hallpass/kek", other, "recordings/" + ses[len(ses)-2:] + "/" + ses + "/" + seg + Ext,
		"/srv/hallpass/recordings/../" + strings.TrimPrefix(good, "/srv/hallpass/"), "/srv/x" + strings.TrimPrefix(good, "/srv/hallpass/recordings")} {
		if Matches(p, ses, seg) {
			t.Errorf("%q matches", p)
		}
	}
	if Matches(good, "..", seg) {
		t.Error("invalid id matches")
	}
}
