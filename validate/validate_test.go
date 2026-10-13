package validate

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/grokify/ocsf-schema-go/schema"
)

func newValidator(t *testing.T, opts ...Option) *Validator {
	t.Helper()
	s, err := schema.Load(filepath.Join("..", "schema", "testdata", "minischema"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	c, err := s.Compile()
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	return New(c, opts...)
}

func hasIssue(r *Result, code Code, pathContains string) bool {
	for _, i := range r.Issues {
		if i.Code == code && strings.Contains(i.Path, pathContains) {
			return true
		}
	}
	return false
}

const validAuth = `{
	"activity_id": 1,
	"category_uid": 3,
	"class_uid": 3002,
	"time": 1757894400000,
	"user": {"name": "jdoe", "type_id": 1, "labels": ["a", "b"], "is_disabled": false}
}`

func TestValidateEventValid(t *testing.T) {
	v := newValidator(t)
	r := v.ValidateEvent([]byte(validAuth))
	if !r.Valid() {
		t.Fatalf("expected valid, got issues: %v", r.Issues)
	}
	if r.Class != "authentication" || r.ClassUID != 3002 {
		t.Errorf("Class/ClassUID = %s/%d, want authentication/3002", r.Class, r.ClassUID)
	}
}

func TestValidateEventIssues(t *testing.T) {
	v := newValidator(t)

	tests := []struct {
		name  string
		json  string
		code  Code
		path  string
		valid bool
	}{
		{"invalid json", `{`, CodeInvalidJSON, "", false},
		{"missing class_uid", `{"time": 1}`, CodeMissingClassUID, "class_uid", false},
		{"unknown class", `{"class_uid": 999999}`, CodeUnknownClass, "class_uid", false},
		{"missing required user", `{"activity_id": 1, "category_uid": 3, "class_uid": 3002, "time": 1}`,
			CodeMissingRequired, "user", false},
		{"bad activity enum", `{"activity_id": 5, "category_uid": 3, "class_uid": 3002, "time": 1, "user": {"name": "x"}}`,
			CodeInvalidEnumValue, "activity_id", false},
		{"wrong type time", `{"activity_id": 1, "category_uid": 3, "class_uid": 3002, "time": "later", "user": {"name": "x"}}`,
			CodeWrongType, "time", false},
		{"nested enum", `{"activity_id": 1, "category_uid": 3, "class_uid": 3002, "time": 1, "user": {"name": "x", "type_id": 42}}`,
			CodeInvalidEnumValue, "user.type_id", false},
		{"nested constraint", `{"activity_id": 1, "category_uid": 3, "class_uid": 3002, "time": 1, "user": {"type_id": 1}}`,
			CodeConstraintViolation, "user", false},
		{"array type", `{"activity_id": 1, "category_uid": 3, "class_uid": 3002, "time": 1, "user": {"name": "x", "labels": "a"}}`,
			CodeWrongType, "user.labels", false},
		{"array elem type", `{"activity_id": 1, "category_uid": 3, "class_uid": 3002, "time": 1, "user": {"name": "x", "labels": [1]}}`,
			CodeWrongType, "user.labels[0]", false},
		{"bool type", `{"activity_id": 1, "category_uid": 3, "class_uid": 3002, "time": 1, "user": {"name": "x", "is_disabled": "yes"}}`,
			CodeWrongType, "user.is_disabled", false},
		{"category mismatch", `{"activity_id": 1, "category_uid": 9, "class_uid": 3002, "time": 1, "user": {"name": "x"}}`,
			CodeInconsistentUID, "category_uid", false},
		{"type_uid mismatch", `{"activity_id": 2, "category_uid": 3, "class_uid": 3002, "type_uid": 300201, "time": 1, "user": {"name": "x"}}`,
			CodeInconsistentUID, "type_uid", false},
		{"unknown attribute warns", `{"activity_id": 1, "category_uid": 3, "class_uid": 3002, "time": 1, "user": {"name": "x"}, "bogus": 1}`,
			CodeUnknownAttribute, "bogus", true},
		{"null optional ok, null required missing", `{"activity_id": 1, "category_uid": 3, "class_uid": 3002, "time": 1, "user": null}`,
			CodeMissingRequired, "user", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := v.ValidateEvent([]byte(tt.json))
			if !hasIssue(r, tt.code, tt.path) {
				t.Errorf("want issue %s at %q, got %v", tt.code, tt.path, r.Issues)
			}
			if r.Valid() != tt.valid {
				t.Errorf("Valid() = %v, want %v (issues %v)", r.Valid(), tt.valid, r.Issues)
			}
		})
	}
}

func TestUnknownAttributeModes(t *testing.T) {
	payload := []byte(`{"activity_id": 1, "category_uid": 3, "class_uid": 3002, "time": 1, "user": {"name": "x"}, "bogus": 1}`)

	if r := newValidator(t, WithUnknownAttributes(UnknownError)).ValidateEvent(payload); r.Valid() {
		t.Error("UnknownError mode should fail validation")
	}
	if r := newValidator(t, WithUnknownAttributes(UnknownIgnore)).ValidateEvent(payload); len(r.Issues) != 0 {
		t.Errorf("UnknownIgnore mode should report nothing, got %v", r.Issues)
	}
}

// TestProfileRequiredAttributes: the fixture cloud profile marks "region"
// required, but that only applies when the event activates the profile via
// metadata.profiles.
func TestProfileRequiredAttributes(t *testing.T) {
	v := newValidator(t, WithUnknownAttributes(UnknownIgnore))

	// Profile inactive: region not required.
	r := v.ValidateEvent([]byte(validAuth))
	if hasIssue(r, CodeMissingRequired, "region") {
		t.Errorf("region required without active profile: %v", r.Issues)
	}

	// Profile active: region required.
	withProfile := `{
		"activity_id": 1, "category_uid": 3, "class_uid": 3002, "time": 1,
		"user": {"name": "x"},
		"metadata": {"profiles": ["cloud"]}
	}`
	r = v.ValidateEvent([]byte(withProfile))
	if !hasIssue(r, CodeMissingRequired, "region") {
		t.Errorf("region should be required with cloud profile active: %v", r.Issues)
	}
}

func TestValidateObject(t *testing.T) {
	v := newValidator(t)

	r, err := v.ValidateObject("user", []byte(`{"name": "jdoe", "type_id": 2}`))
	if err != nil {
		t.Fatal(err)
	}
	if !r.Valid() {
		t.Errorf("expected valid user, got %v", r.Issues)
	}

	r, err = v.ValidateObject("user", []byte(`{"type_id": 77}`))
	if err != nil {
		t.Fatal(err)
	}
	if !hasIssue(r, CodeInvalidEnumValue, "type_id") || !hasIssue(r, CodeConstraintViolation, "") {
		t.Errorf("want enum + constraint issues, got %v", r.Issues)
	}

	if _, err := v.ValidateObject("nope", []byte(`{}`)); err == nil {
		t.Error("expected error for unknown object name")
	}
}

func TestValidateEventClass(t *testing.T) {
	v := newValidator(t)
	r, err := v.ValidateEventClass("authentication", []byte(validAuth))
	if err != nil {
		t.Fatal(err)
	}
	if !r.Valid() {
		t.Errorf("expected valid, got %v", r.Issues)
	}
	if _, err := v.ValidateEventClass("nope", []byte(`{}`)); err == nil {
		t.Error("expected error for unknown class name")
	}
}

// TestValidateFullSchema validates realistic events against a real
// ocsf/ocsf-schema checkout when OCSF_SCHEMA_DIR is set.
func TestValidateFullSchema(t *testing.T) {
	dir := os.Getenv("OCSF_SCHEMA_DIR")
	if dir == "" {
		t.Skip("OCSF_SCHEMA_DIR not set")
	}
	s, err := schema.LoadWithExtensions(dir, "all")
	if err != nil {
		t.Fatal(err)
	}
	c, err := s.Compile()
	if err != nil {
		t.Fatal(err)
	}
	v := New(c)

	auth := `{
		"activity_id": 1,
		"category_uid": 3,
		"class_uid": 3002,
		"severity_id": 1,
		"time": 1757894400000,
		"type_uid": 300201,
		"metadata": {"version": "1.10.0", "product": {"name": "idp", "vendor_name": "Example"}},
		"user": {"name": "jdoe", "type_id": 1},
		"dst_endpoint": {"hostname": "auth.example.com"},
		"status_id": 1
	}`
	r := v.ValidateEvent([]byte(auth))
	if !r.Valid() {
		t.Errorf("real-schema authentication should validate, got %v", r.Issues)
	}

	bad := strings.Replace(auth, `"severity_id": 1`, `"severity_id": 42`, 1)
	if r := v.ValidateEvent([]byte(bad)); !hasIssue(r, CodeInvalidEnumValue, "severity_id") {
		t.Errorf("severity_id 42 should be invalid, got %v", r.Issues)
	}

	winReg := `{
		"activity_id": 1,
		"category_uid": 1,
		"class_uid": 201001,
		"severity_id": 1,
		"time": 1757894400000,
		"metadata": {"version": "1.10.0", "product": {"name": "sysmon"}},
		"reg_key": {"path": "HKLM\\Software\\Test"}
	}`
	r = v.ValidateEvent([]byte(winReg))
	if r.Class != "registry_key_activity" {
		t.Errorf("class_uid 201001 resolved to %q, want registry_key_activity", r.Class)
	}
	for _, i := range r.Errors() {
		// The event intentionally omits several recommended/required attrs
		// of the win extension class; only unexpected errors should fail.
		if i.Code != CodeMissingRequired {
			t.Errorf("unexpected error validating extension event: %v", i)
		}
	}
}
