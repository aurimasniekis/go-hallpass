package grammar

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"
)

// A small JSON Schema (draft 2020-12) checker for the keyword subset used in api/ssh-schemas. Unknown keywords fail
// the test so the checker never silently ignores a constraint. In strict mode every instance property must be
// declared, which keeps the Go structs and the published schemas in sync (the schemas themselves stay open for
// additive /v1 changes).

const schemaDir = "../../../api/ssh-schemas"

var knownKeywords = map[string]bool{
	"$schema": true, "$id": true, "title": true, "description": true, "$defs": true, "$ref": true,
	"type": true, "properties": true, "required": true, "items": true, "enum": true, "const": true,
	"pattern": true, "format": true, "minimum": true, "maximum": true, "minLength": true, "anyOf": true,
}

type checker struct {
	root   map[string]any
	strict bool
	errs   []string
}

func loadSchema(t *testing.T, id string) map[string]any {
	t.Helper()
	// "hallpass.list/v1" → "hallpass.list.v1.json"
	name := strings.Replace(id, "/", ".", 1) + ".json"
	b, err := os.ReadFile(filepath.Join(schemaDir, name))
	if err != nil {
		t.Fatalf("schema %s: %v", id, err)
	}
	var s map[string]any
	if err := json.Unmarshal(b, &s); err != nil {
		t.Fatalf("schema %s: %v", id, err)
	}
	if s["$schema"] != "https://json-schema.org/draft/2020-12/schema" || s["title"] != id {
		t.Fatalf("schema %s: wrong $schema or title", id)
	}
	return s
}

func decodeInstance(b []byte) (any, error) {
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	var v any
	if err := d.Decode(&v); err != nil {
		return nil, err
	}
	if d.More() {
		return nil, fmt.Errorf("trailing data")
	}
	return v, nil
}

func (c *checker) fail(path, format string, args ...any) {
	c.errs = append(c.errs, path+": "+fmt.Sprintf(format, args...))
}

func typeOf(v any) string {
	switch v := v.(type) {
	case nil:
		return "null"
	case bool:
		return "boolean"
	case string:
		return "string"
	case json.Number:
		if !strings.ContainsAny(v.String(), ".eE") {
			return "integer"
		}
		return "number"
	case []any:
		return "array"
	case map[string]any:
		return "object"
	}
	return "unknown"
}

func typeMatches(want, got string) bool { return want == got || (want == "number" && got == "integer") }

func jsonEqual(a, b any) bool {
	ja, _ := json.Marshal(a)
	jb, _ := json.Marshal(b)
	return bytes.Equal(ja, jb)
}

func num(v any) (float64, bool) {
	switch v := v.(type) {
	case json.Number:
		f, err := v.Float64()
		return f, err == nil
	case float64:
		return v, true
	}
	return 0, false
}

func (c *checker) validate(path string, s map[string]any, v any) {
	for k := range s {
		if !knownKeywords[k] {
			c.fail(path, "schema uses unsupported keyword %q", k)
		}
	}
	if ref, ok := s["$ref"].(string); ok {
		name, found := strings.CutPrefix(ref, "#/$defs/")
		defs, _ := c.root["$defs"].(map[string]any)
		target, ok := defs[name].(map[string]any)
		if !found || !ok {
			c.fail(path, "unresolvable $ref %q", ref)
			return
		}
		c.validate(path, target, v)
	}
	if anyOf, ok := s["anyOf"].([]any); ok {
		matched := false
		for _, alt := range anyOf {
			sub := &checker{root: c.root, strict: c.strict}
			sub.validate(path, alt.(map[string]any), v)
			if len(sub.errs) == 0 {
				matched = true
				break
			}
		}
		if !matched {
			c.fail(path, "matches no anyOf alternative")
		}
	}
	got := typeOf(v)
	switch tv := s["type"].(type) {
	case string:
		if !typeMatches(tv, got) {
			c.fail(path, "type %s, want %s", got, tv)
			return
		}
	case []any:
		ok := false
		for _, x := range tv {
			ok = ok || typeMatches(x.(string), got)
		}
		if !ok {
			c.fail(path, "type %s, want one of %v", got, tv)
			return
		}
	}
	if cv, ok := s["const"]; ok && !jsonEqual(cv, v) {
		c.fail(path, "value %v, want const %v", v, cv)
	}
	if ev, ok := s["enum"].([]any); ok && !slices.ContainsFunc(ev, func(e any) bool { return jsonEqual(e, v) }) {
		c.fail(path, "value %v not in enum %v", v, ev)
	}
	if str, ok := v.(string); ok {
		if p, ok := s["pattern"].(string); ok && !regexp.MustCompile(p).MatchString(str) {
			c.fail(path, "%q does not match %s", str, p)
		}
		if n, ok := num(s["minLength"]); ok && float64(len([]rune(str))) < n {
			c.fail(path, "shorter than %v", n)
		}
		if f, ok := s["format"].(string); ok {
			if f != "date-time" {
				c.fail(path, "unsupported format %q", f)
			} else if _, err := time.Parse(time.RFC3339, str); err != nil {
				c.fail(path, "not RFC 3339: %v", err)
			}
		}
	}
	if f, ok := num(v); ok {
		if m, ok := num(s["minimum"]); ok && f < m {
			c.fail(path, "%v < minimum %v", f, m)
		}
		if m, ok := num(s["maximum"]); ok && f > m {
			c.fail(path, "%v > maximum %v", f, m)
		}
	}
	if obj, ok := v.(map[string]any); ok {
		props, _ := s["properties"].(map[string]any)
		if req, ok := s["required"].([]any); ok {
			for _, r := range req {
				if _, ok := obj[r.(string)]; !ok {
					c.fail(path, "missing required property %q", r)
				}
			}
		}
		keys := make([]string, 0, len(obj))
		for k := range obj {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			ps, declared := props[k].(map[string]any)
			if !declared {
				if c.strict && props != nil {
					c.fail(path, "undeclared property %q", k)
				}
				continue
			}
			c.validate(path+"."+k, ps, obj[k])
		}
	}
	if arr, ok := v.([]any); ok {
		if items, ok := s["items"].(map[string]any); ok {
			for i, x := range arr {
				c.validate(fmt.Sprintf("%s[%d]", path, i), items, x)
			}
		}
	}
}

// validateDoc validates one JSON document against the schema named by its "schema" field, strictly.
func validateDoc(t *testing.T, b []byte) []string {
	t.Helper()
	v, err := decodeInstance(b)
	if err != nil {
		return []string{err.Error()}
	}
	obj, ok := v.(map[string]any)
	if !ok {
		return []string{"document is not an object"}
	}
	id, _ := obj["schema"].(string)
	if !slices.Contains(Schemas(), id) {
		return []string{fmt.Sprintf("unknown schema %q", id)}
	}
	c := &checker{root: loadSchema(t, id), strict: true}
	c.validate("$", c.root, v)
	return c.errs
}

// Schema files: one per published schema, every object property required, no unknown keywords.
func TestSchemaFiles(t *testing.T) {
	entries, err := os.ReadDir(schemaDir)
	if err != nil {
		t.Fatal(err)
	}
	var files []string
	for _, e := range entries {
		files = append(files, e.Name())
	}
	var want []string
	for _, id := range Schemas() {
		want = append(want, strings.Replace(id, "/", ".", 1)+".json")
	}
	sort.Strings(want)
	if !slices.Equal(files, want) {
		t.Errorf("schema files %v, want %v", files, want)
	}
	for _, id := range Schemas() {
		s := loadSchema(t, id)
		var walk func(path string, n map[string]any)
		walk = func(path string, n map[string]any) {
			for k, v := range n {
				if !knownKeywords[k] {
					t.Errorf("%s %s: unknown keyword %q", id, path, k)
				}
				switch k {
				case "properties", "$defs":
					props := v.(map[string]any)
					for pk, pv := range props {
						walk(path+"/"+k+"/"+pk, pv.(map[string]any))
					}
					if k == "properties" {
						req, _ := n["required"].([]any)
						if len(req) != len(props) {
							t.Errorf("%s %s: every property must be required (nullable instead of optional)", id, path)
						}
					}
				case "items":
					walk(path+"/items", v.(map[string]any))
				case "anyOf":
					for i, alt := range v.([]any) {
						walk(fmt.Sprintf("%s/anyOf/%d", path, i), alt.(map[string]any))
					}
				case "pattern":
					if _, err := regexp.Compile(v.(string)); err != nil {
						t.Errorf("%s %s: bad pattern: %v", id, path, err)
					}
				}
			}
		}
		walk("#", s)
		props := s["properties"].(map[string]any)
		if c, _ := props["schema"].(map[string]any)["const"].(string); c != id {
			t.Errorf("%s: schema const = %q", id, c)
		}
	}
}

// The checker itself must reject non-conforming documents.
func TestCheckerRejects(t *testing.T) {
	good := string(mustMarshal(t, NewErrorDoc(NotFoundOrForbidden())))
	if errs := validateDoc(t, []byte(good)); len(errs) != 0 {
		t.Fatalf("good document rejected: %v", errs)
	}
	bad := map[string]string{
		"missing property": strings.Replace(good, `,"request_id":null`, "", 1),
		"extra property":   strings.Replace(good, `"request_id":null`, `"request_id":null,"x":1`, 1),
		"wrong const":      strings.Replace(good, `"source":"gateway"`, `"source":"agent"`, 1),
		"wrong enum":       strings.Replace(good, `"not_found_or_forbidden"`, `"nope"`, 1),
		"wrong type":       strings.Replace(good, `"exit_code":82`, `"exit_code":"82"`, 1),
		"not integer":      strings.Replace(good, `"exit_code":82`, `"exit_code":82.5`, 1),
		"below minimum":    strings.Replace(good, `"exit_code":82`, `"exit_code":0`, 1),
		"above maximum":    strings.Replace(good, `"exit_code":82`, `"exit_code":91`, 1),
		"anyOf mismatch":   strings.Replace(good, `"request_id":null`, `"request_id":"req_1"`, 1),
		"min length":       strings.Replace(good, `"message":"server or role not found or not permitted"`, `"message":""`, 1),
		"unknown schema":   strings.Replace(good, `hallpass.error/v1`, `hallpass.nope/v1`, 1),
		"not object":       `[]`,
		"trailing":         good + "{}",
	}
	for name, doc := range bad {
		if errs := validateDoc(t, []byte(doc)); len(errs) == 0 {
			t.Errorf("%s: accepted %s", name, doc)
		}
	}
	// Time format and array items.
	l := NewListDoc(time.Unix(0, 0), []ListServer{{Alias: "web1", Roles: []ListRole{{Alias: "r1", Level: "bogus"}}}})
	if errs := validateDoc(t, mustMarshal(t, l)); len(errs) == 0 {
		t.Error("bad nested enum accepted")
	}
	st := string(mustMarshal(t, NewStatusDoc(time.Unix(0, 0), StatusInfo{ID: rid, Server: "web1", Role: "r1", State: "pending", CreatedAt: Time(time.Unix(0, 0))})))
	st = strings.Replace(st, `"created_at":"1970-01-01T00:00:00Z"`, `"created_at":"1970-01-01 00:00:00"`, 1)
	if errs := validateDoc(t, []byte(st)); len(errs) == 0 {
		t.Error("bad timestamp accepted")
	}
}

func mustMarshal(t *testing.T, doc any) []byte {
	t.Helper()
	b, err := Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
