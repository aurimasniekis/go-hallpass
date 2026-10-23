//go:build oidcinterop

package oidcinterop

import (
	"context"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strings"
	"testing"
)

// browser is a minimal browser: a cookie jar, manual redirect following and HTML form submission. It stops as soon
// as a redirect leaves the IdP for a Hallpass page that is not part of the SSO flow (the "landing" page).
type browser struct {
	t        *testing.T
	hc       *http.Client
	hallpass *url.URL
	csrf     string
	// hops lists every URL requested since the last resetHops, in order.
	hops []*url.URL
}

// page is the result of a navigation.
type page struct {
	URL     *url.URL
	Status  int
	Body    string
	Landing string // Hallpass path+query the flow ended on ("" when the navigation ended on a rendered page)
}

func newBrowser(t *testing.T, hallpassBase string) *browser {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(hallpassBase)
	if err != nil {
		t.Fatal(err)
	}
	return &browser{t: t, hallpass: u, hc: &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}}
}

func (b *browser) isLanding(u *url.URL) bool {
	return u.Host == b.hallpass.Host && !strings.HasPrefix(u.Path, "/auth/") && !strings.HasPrefix(u.Path, "/api/")
}

// navigate performs a GET (form == nil) or a form POST and follows redirects.
func (b *browser) navigate(method, raw string, form url.Values) *page {
	b.t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		b.t.Fatalf("parse %q: %v", raw, err)
	}
	if !u.IsAbs() {
		u = b.hallpass.ResolveReference(u)
	}
	for range 25 {
		b.hops = append(b.hops, u)
		var body io.Reader
		if form != nil {
			body = strings.NewReader(form.Encode())
		}
		req, err := http.NewRequestWithContext(context.Background(), method, u.String(), body)
		if err != nil {
			b.t.Fatal(err)
		}
		if form != nil {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
		req.Header.Set("Accept", "text/html,application/xhtml+xml")
		req.Header.Set("User-Agent", "hallpass-oidcinterop/1")
		res, err := b.hc.Do(req)
		if err != nil {
			b.t.Fatalf("%s %s: %v", method, u.Redacted(), err)
		}
		data, _ := io.ReadAll(io.LimitReader(res.Body, 4<<20))
		_ = res.Body.Close()
		if res.StatusCode >= 300 && res.StatusCode < 400 {
			loc, err := u.Parse(res.Header.Get("Location"))
			if err != nil || res.Header.Get("Location") == "" {
				b.t.Fatalf("%s %s: redirect without a usable Location %q", method, u.Redacted(), res.Header.Get("Location"))
			}
			if b.isLanding(loc) {
				return &page{URL: loc, Status: res.StatusCode, Landing: loc.RequestURI()}
			}
			u, method, form = loc, http.MethodGet, nil
			continue
		}
		return &page{URL: u, Status: res.StatusCode, Body: string(data)}
	}
	b.t.Fatalf("too many redirects starting at %s", raw)
	return nil
}

func (b *browser) resetHops() { b.hops = nil }

// hop returns the first requested URL whose prefix matches.
func (b *browser) hop(prefix string) *url.URL {
	b.t.Helper()
	for _, h := range b.hops {
		if strings.HasPrefix(h.String(), prefix) {
			return h
		}
	}
	b.t.Fatalf("no request to %s; hops %v", prefix, b.hops)
	return nil
}

// apiJSON calls the Hallpass API like the web UI does (same-origin Origin and CSRF header on mutations).
func (b *browser) api(method, path string) (int, []byte) {
	b.t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), method, b.hallpass.ResolveReference(&url.URL{Path: path}).String(), nil)
	if err != nil {
		b.t.Fatal(err)
	}
	if method != http.MethodGet {
		req.Header.Set("Origin", b.hallpass.Scheme+"://"+b.hallpass.Host)
		req.Header.Set("X-CSRF-Token", b.csrf)
	}
	res, err := b.hc.Do(req)
	if err != nil {
		b.t.Fatal(err)
	}
	defer res.Body.Close()
	data, _ := io.ReadAll(res.Body)
	return res.StatusCode, data
}

// cookie returns a cookie value the jar would send to the Hallpass origin.
func (b *browser) cookie(name string) string {
	for _, c := range b.hc.Jar.Cookies(b.hallpass) {
		if c.Name == name {
			return c.Value
		}
	}
	return ""
}

// ---- HTML forms (regular expressions are enough for the server-rendered IdP pages; no new dependencies)

var (
	formRE  = regexp.MustCompile(`(?is)<form\b([^>]*)>(.*?)</form>`)
	inputRE = regexp.MustCompile(`(?is)<(input|button)\b([^>]*)>`)
	attrRE  = regexp.MustCompile(`(?s)([a-zA-Z_:][-a-zA-Z0-9_:.]*)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'>]+)))?`)
)

type htmlForm struct {
	Action   string
	Method   string
	Values   url.Values
	Password bool // the form has a password field
}

func attrs(s string) map[string]string {
	out := map[string]string{}
	for _, m := range attrRE.FindAllStringSubmatch(s, -1) {
		name := strings.ToLower(m[1])
		if _, dup := out[name]; dup {
			continue
		}
		out[name] = html.UnescapeString(m[2] + m[3] + m[4])
	}
	return out
}

func parseForms(body string) []htmlForm {
	var forms []htmlForm
	for _, fm := range formRE.FindAllStringSubmatch(body, -1) {
		fa := attrs(fm[1])
		f := htmlForm{Action: fa["action"], Method: strings.ToUpper(fa["method"]), Values: url.Values{}}
		if f.Method == "" {
			f.Method = http.MethodGet
		}
		submitted := false
		for _, im := range inputRE.FindAllStringSubmatch(fm[2], -1) {
			a := attrs(im[2])
			typ := strings.ToLower(a["type"])
			switch {
			case typ == "" && strings.EqualFold(im[1], "button"):
				typ = "submit"
			case typ == "":
				typ = "text"
			}
			name, hasValue := a["name"], true
			switch typ {
			case "password":
				f.Password = true
			case "checkbox", "radio":
				_, hasValue = a["checked"]
			case "submit", "image":
				hasValue = !submitted
				submitted = submitted || name != ""
			}
			if name != "" && hasValue && !f.Values.Has(name) {
				f.Values.Set(name, a["value"])
			}
		}
		forms = append(forms, f)
	}
	return forms
}

// loginForm returns the page's username/password form.
func (p *page) loginForm() (*htmlForm, bool) {
	for _, f := range parseForms(p.Body) {
		if f.Password {
			return &f, true
		}
	}
	return nil, false
}

// submit posts a form found on page p with extra values.
func (b *browser) submit(p *page, f *htmlForm, set map[string]string) *page {
	b.t.Helper()
	action, err := p.URL.Parse(f.Action)
	if err != nil {
		b.t.Fatalf("form action %q: %v", f.Action, err)
	}
	for k, v := range set {
		f.Values.Set(k, v)
	}
	if f.Method == http.MethodGet {
		action.RawQuery = f.Values.Encode()
		return b.navigate(http.MethodGet, action.String(), nil)
	}
	return b.navigate(http.MethodPost, action.String(), f.Values)
}

// snippet shortens a page body for failure messages.
func snippet(s string) string {
	s = regexp.MustCompile(`(?s)<script.*?</script>|<style.*?</style>`).ReplaceAllString(s, "")
	s = regexp.MustCompile(`(?s)<[^>]+>`).ReplaceAllString(s, " ")
	s = strings.Join(strings.Fields(html.UnescapeString(s)), " ")
	if len(s) > 600 {
		s = s[:600] + "…"
	}
	return fmt.Sprintf("%q", s)
}
