package apirules

import (
	"slices"
	"testing"
)

func mustCompile(t *testing.T, rules []Rule) *Policy {
	t.Helper()
	p, err := Compile(rules)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func req(t *testing.T, method, host, path string) Request {
	t.Helper()
	segs, err := SplitPath(path)
	if err != nil {
		t.Fatal(path, err)
	}
	return Request{Method: method, Host: host, Segments: segs}
}

func TestSplitPath(t *testing.T) {
	for _, c := range []struct {
		in   string
		want []string
		bad  bool
	}{
		{in: "/", want: []string{""}},
		{in: "/repos/acme/api", want: []string{"repos", "acme", "api"}},
		{in: "/repos/acme/api/branches/feature%2Fx", want: []string{"repos", "acme", "api", "branches", "feature/x"}},
		{in: "/a/../b", bad: true},
		{in: "/a/%2e%2E/b", bad: true},
		{in: "/a/./b", bad: true},
		{in: "/a/%5c", bad: true},
		{in: "/a/%zz", bad: true},
		{in: "relative", bad: true},
	} {
		got, err := SplitPath(c.in)
		if c.bad != (err != nil) || (!c.bad && !slices.Equal(got, c.want)) {
			t.Errorf("SplitPath(%q) = %q, %v", c.in, got, err)
		}
	}
}

func TestHosts(t *testing.T) {
	for h, ok := range map[string]bool{
		"api.github.com": true, "*.googleapis.com": true, "*.com": false, "com": false, "10.0.0.1": false,
		"api.github.com.": false, "-a.example.com": false, "a_b.example.com": false, "*.*.example.com": false, "": false,
	} {
		if ValidHost(h) != ok {
			t.Errorf("ValidHost(%q) = %v", h, !ok)
		}
	}
	if !HostMatches("*.googleapis.com", "storage.googleapis.com") || HostMatches("*.googleapis.com", "googleapis.com") ||
		HostMatches("*.googleapis.com", "evilgoogleapis.com") || !HostMatches("api.github.com", "api.github.com") {
		t.Fatal("HostMatches")
	}
}

func TestDecide(t *testing.T) {
	p := mustCompile(t, []Rule{
		{Effect: Allow, Methods: []string{"get", "HEAD"}},
		{Effect: Allow, Methods: []string{"POST", "PATCH"}, Paths: []string{"/repos/acme/{api,web}/issues/**", "/repos/acme/*/pulls"}},
		{Effect: Deny, Paths: []string{"/repos/acme/secret/**", "/user/keys"}},
		{Effect: Allow, Methods: []string{"DELETE"}, Hosts: []string{"uploads.github.com"}, Paths: []string{"/repos/*/*/releases/assets/*"}},
		{Effect: Allow, Methods: []string{"PUT"}, Paths: []string{"/repos/acme/web-*/contents/**"}},
	})
	for _, c := range []struct {
		method, host, path string
		allowed            bool
	}{
		{"GET", "api.github.com", "/repos/acme/api", true},
		{"HEAD", "api.github.com", "/", true},
		{"GET", "api.github.com", "/repos/acme/secret/contents/x", false},
		{"GET", "api.github.com", "/repos/ACME/Secret/contents/x", false}, // case-insensitive
		{"GET", "api.github.com", "/user/keys", false},
		{"POST", "api.github.com", "/repos/acme/api/issues/1/comments", true},
		{"POST", "api.github.com", "/repos/acme/api/issues", true}, // ** matches zero segments
		{"POST", "api.github.com", "/repos/acme/other/issues/1", false},
		{"POST", "api.github.com", "/repos/acme/x/pulls", true},
		{"POST", "api.github.com", "/repos/acme/x/pulls/1", false},
		{"POST", "api.github.com", "/repos/acme%2Fapi/x/pulls", false}, // an encoded slash stays inside one segment
		{"DELETE", "api.github.com", "/repos/acme/api/releases/assets/1", false},
		{"DELETE", "uploads.github.com", "/repos/acme/api/releases/assets/1", true},
		{"PUT", "api.github.com", "/repos/acme/web-site/contents/a/b.txt", true},
		{"PUT", "api.github.com", "/repos/acme/api/contents/a.txt", false},
	} {
		d := p.Decide(req(t, c.method, c.host, c.path))
		if d.Allowed != c.allowed {
			t.Errorf("%s %s%s: allowed=%v rule=%d", c.method, c.host, c.path, d.Allowed, d.Rule)
		}
	}
	if d := mustCompile(t, nil).Decide(req(t, "GET", "a.example.com", "/")); d.Allowed || d.Rule != -1 {
		t.Fatal("empty policy must deny")
	}
}

func TestDecideGraphQL(t *testing.T) {
	p := mustCompile(t, []Rule{
		{Effect: Allow, Methods: []string{"GET"}},
		{Effect: Allow, Methods: []string{"POST"}, Paths: []string{"/graphql"}, GraphQL: []string{"query"}},
	})
	r := req(t, "POST", "api.github.com", "/graphql")
	if !p.NeedsGraphQL(r) || p.NeedsGraphQL(req(t, "POST", "api.github.com", "/repos")) {
		t.Fatal("NeedsGraphQL")
	}
	for body, allowed := range map[string]bool{
		`{"query":"query { viewer { login } }"}`:                          true,
		`{"query":"{ viewer { login } }","variables":{}}`:                 true,
		`{"query":"mutation { addStar(input:{}) { clientMutationId } }"}`: false,
		`{"query":"query A { a } mutation B { b }","operationName":"A"}`:  false,
		`[{"query":"query { a }"},{"query":"mutation { b }"}]`:            false,
		`[{"query":"query { a }"},{"query":"{ b }"}]`:                     true,
		`{"extensions":{"persistedQuery":{"sha256Hash":"abc"}}}`:          false,
		`not json`: false,
		`{"query":"query ($a: In = {x: \"}\"}) { a(x: $a) { b } } fragment F on T { c }"}`: true,
		`{"query":"type Query { a: Int }"}`:                                                false,
		`{"query":"# mutation\nquery { a }"}`:                                              true,
		`{"query":"query { a(s: \"\"\"mutation { } \"\"\") }"}`:                            true,
		`{"query":"query { a "}`:                                                           false,
	} {
		r.GraphQL = ClassifyBody([]byte(body))
		if d := p.Decide(r); d.Allowed != allowed {
			t.Errorf("%s: allowed=%v ops=%v", body, d.Allowed, r.GraphQL.Names())
		}
	}

	deny := mustCompile(t, []Rule{
		{Effect: Allow, Methods: []string{"POST"}},
		{Effect: Deny, Paths: []string{"/graphql"}, GraphQL: []string{"mutation"}},
	})
	r.GraphQL = ClassifyBody([]byte(`{"query":"query { a }"}`))
	if !deny.Decide(r).Allowed {
		t.Fatal("query denied by a mutation deny rule")
	}
	for _, body := range []string{`{"query":"mutation { a }"}`, `{"id":"persisted"}`} {
		r.GraphQL = ClassifyBody([]byte(body))
		if deny.Decide(r).Allowed {
			t.Fatalf("%s allowed despite the mutation deny rule", body)
		}
	}
}

func TestCompileErrors(t *testing.T) {
	for _, r := range []Rule{
		{Effect: "maybe"},
		{Effect: Allow, Methods: []string{"TRACE"}},
		{Effect: Allow, Hosts: []string{"*.com"}},
		{Effect: Allow, Paths: []string{"repos"}},
		{Effect: Allow, Paths: []string{"/a/../b"}},
		{Effect: Allow, Paths: []string{"/a/b**"}},
		{Effect: Allow, Paths: []string{"/a/{b"}},
		{Effect: Allow, Paths: []string{"/a/{b,{c}}"}},
		{Effect: Allow, Paths: []string{"/{a,b,c,d}/{a,b,c,d}/{a,b,c,d}/{a,b,c,d}/{a,b,c,d}"}},
		{Effect: Allow, GraphQL: []string{"fragment"}},
	} {
		if _, err := Compile([]Rule{r}); err == nil {
			t.Errorf("%+v compiled", r)
		}
	}
}

func FuzzClassifyDocument(f *testing.F) {
	for _, s := range []string{"query { a }", "mutation M($x: I = {a: 1}) { b }", `{ a(s: """x""") }`, "#c\n{a}", "fragment F on T { a }"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, doc string) {
		_ = ClassifyDocument(doc)
	})
}

func FuzzDecide(f *testing.F) {
	p, err := Compile([]Rule{{Effect: Allow, Methods: []string{"GET"}, Paths: []string{"/repos/acme/**", "/a/*b*/c"}}, {Effect: Deny, Paths: []string{"/repos/acme/secret/**"}}})
	if err != nil {
		f.Fatal(err)
	}
	f.Add("/repos/acme/x")
	f.Add("/a/xbx/c")
	f.Fuzz(func(t *testing.T, path string) {
		segs, err := SplitPath(path)
		if err != nil {
			return
		}
		d := p.Decide(Request{Method: "GET", Host: "api.github.com", Segments: segs})
		if d.Allowed && len(segs) >= 3 && segs[0] == "repos" && segs[1] == "acme" && segs[2] == "secret" {
			t.Fatalf("%q allowed", path)
		}
	})
}
