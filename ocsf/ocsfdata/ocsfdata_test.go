package ocsfdata_test

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/grokify/ocsf-schema-go/ocsf/events"
	"github.com/grokify/ocsf-schema-go/ocsf/objects"
	"github.com/grokify/ocsf-schema-go/ocsf/ocsfdata"
	"github.com/grokify/ocsf-schema-go/validate"
)

func TestSchema(t *testing.T) {
	c, err := ocsfdata.Schema()
	if err != nil {
		t.Fatalf("Schema: %v", err)
	}
	if c.Version != events.SchemaVersion {
		t.Errorf("embedded schema version %q != generated SchemaVersion %q", c.Version, events.SchemaVersion)
	}
	if len(c.Objects) < 150 || len(c.Classes) < 80 {
		t.Errorf("embedded schema looks truncated: %d objects, %d classes", len(c.Objects), len(c.Classes))
	}
	auth, ok := c.Classes["authentication"]
	if !ok || auth.ClassUID != 3002 {
		t.Fatalf("authentication class = %+v, want ClassUID 3002", auth)
	}

	// Profile provenance must survive the embed round-trip; the validate
	// package depends on it to scope profile-required attributes.
	cloud := auth.Attributes["cloud"]
	if cloud == nil || cloud.Source != "profile:cloud" {
		t.Errorf("authentication.cloud source = %+v, want profile:cloud", cloud)
	}
}

// TestValidateWithEmbeddedSchema is the wiring ocsf-lake will use: a
// runtime validator with no OCSF checkout on disk.
func TestValidateWithEmbeddedSchema(t *testing.T) {
	v := validate.New(ocsfdata.MustSchema())

	good := `{
		"activity_id": 1,
		"category_uid": 3,
		"class_uid": 3002,
		"severity_id": 1,
		"time": 1757894400000,
		"type_uid": 300201,
		"metadata": {"version": "1.10.0", "product": {"name": "idp"}},
		"user": {"name": "jdoe", "type_id": 1},
		"dst_endpoint": {"hostname": "auth.example.com"}
	}`
	if r := v.ValidateEvent([]byte(good)); !r.Valid() {
		t.Errorf("expected valid event, got %v", r.Issues)
	}

	missing := `{"class_uid": 3002, "category_uid": 3}`
	r := v.ValidateEvent([]byte(missing))
	if r.Valid() {
		t.Error("event missing required attributes should be invalid")
	}
	if r.Class != "authentication" {
		t.Errorf("Class = %q, want authentication", r.Class)
	}

	// Extension classes are included in the embedded schema.
	if _, ok := v.Class(201001); !ok {
		t.Error("embedded schema missing win extension class 201001 (registry_key_activity)")
	}
}

// strictIssues validates data with unknown attributes reported as errors and
// returns every issue, warnings included.
func strictIssues(t *testing.T, data []byte) []validate.Issue {
	t.Helper()
	v := validate.New(ocsfdata.MustSchema(), validate.WithUnknownAttributes(validate.UnknownError))
	return v.ValidateEvent(data).Issues
}

// TestGeneratedEventOmitsUnusedProfiles marshals a generated struct with no
// profile in use: profile attributes such as cloud and osint must be left
// out rather than written as null, and the result must validate strictly.
func TestGeneratedEventOmitsUnusedProfiles(t *testing.T) {
	evt := events.Authentication{
		ActivityID:  events.AuthenticationActivityIDLogon,
		CategoryUID: events.CategoryUIDIAM,
		ClassUID:    events.ClassUIDAuthentication,
		SeverityID:  events.AuthenticationSeverityIDInformational,
		Time:        1757894400000,
		TypeUID:     int64(events.ClassUIDAuthentication)*100 + events.AuthenticationActivityIDLogon,
		Metadata:    &objects.Metadata{Version: events.SchemaVersion, Product: &objects.Product{Name: "idp", VendorName: "Example"}},
		User:        &objects.User{UID: "u-1"},
		DstEndpoint: &objects.NetworkEndpoint{Hostname: "auth.example.com"},
	}
	data, err := json.Marshal(evt)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	for _, key := range []string{"cloud", "osint"} {
		if _, ok := m[key]; ok {
			t.Errorf("%s written without its profile: %s", key, data)
		}
	}
	if issues := strictIssues(t, data); len(issues) > 0 {
		t.Errorf("generated event issues: %v", issues)
	}
}

// TestInheritedEnumValues checks that a class keeps the dictionary's Unknown
// (0) and Other (99) beside its own values, for class attributes and object
// attributes alike, as the OCSF schema server presents them.
func TestInheritedEnumValues(t *testing.T) {
	c := ocsfdata.MustSchema()
	auth := c.Classes["authentication"]
	for attr, want := range map[string][]string{
		"activity_id": {"0", "1", "7", "99"},
		"status_id":   {"0", "1", "2", "99"},
	} {
		for _, k := range want {
			if _, ok := auth.Attributes[attr].Enum[k]; !ok {
				t.Errorf("authentication.%s enum lacks %s", attr, k)
			}
		}
	}
	for _, k := range []string{"0", "1", "99"} {
		if _, ok := c.Objects["managed_entity"].Attributes["type_id"].Enum[k]; !ok {
			t.Errorf("managed_entity.type_id enum lacks %s", k)
		}
	}

	for _, ids := range [][2]int{{0, 0}, {99, 99}} {
		evt := fmt.Sprintf(`{"activity_id": %d, "status_id": %d, "category_uid": 3, "class_uid": 3002,
			"severity_id": 1, "time": 1757894400000, "type_uid": %d,
			"metadata": {"version": "1.10.0", "product": {"name": "idp"}}, "user": {"uid": "u-1"},
			"dst_endpoint": {"hostname": "auth.example.com"}}`,
			ids[0], ids[1], 300200+ids[0])
		if issues := strictIssues(t, []byte(evt)); len(issues) > 0 {
			t.Errorf("activity_id %d, status_id %d: %v", ids[0], ids[1], issues)
		}
	}
}

// TestUnmappedHoldsAnyKeys checks that the generic object attributes, such
// as unmapped, accept any keys even when unknown attributes are errors,
// and still must be JSON objects.
func TestUnmappedHoldsAnyKeys(t *testing.T) {
	const base = `{"activity_id": 1, "category_uid": 3, "class_uid": 3002,
		"severity_id": 1, "time": 1757894400000, "type_uid": 300201,
		"metadata": {"version": "1.10.0", "product": {"name": "idp"}}, "user": {"uid": "u-1"},
		"dst_endpoint": {"hostname": "auth.example.com"}, `
	if issues := strictIssues(t, []byte(base+`"unmapped": {"source_field": "x", "nested": {"n": 1}}}`)); len(issues) > 0 {
		t.Errorf("unmapped keys reported: %v", issues)
	}
	issues := strictIssues(t, []byte(base+`"unmapped": "not an object"}`))
	if len(issues) != 1 || issues[0].Code != validate.CodeWrongType {
		t.Errorf("unmapped string: issues %v, want one wrong-type issue", issues)
	}
}

// TestBaseEvent checks that Base Event, class_uid 0, is a concrete class: it
// is registered, and events dispatch to it by class_uid.
func TestBaseEvent(t *testing.T) {
	if name := events.ClassNames[events.ClassUIDBaseEvent]; name != "base_event" {
		t.Errorf("ClassNames[0] = %q, want base_event", name)
	}
	evt := `{"activity_id": 99, "category_uid": 0, "class_uid": 0, "severity_id": 1,
		"time": 1757894400000, "type_uid": 99, "message": "other",
		"metadata": {"version": "1.10.0", "product": {"name": "idp"}}}`
	v := validate.New(ocsfdata.MustSchema(), validate.WithUnknownAttributes(validate.UnknownError))
	r := v.ValidateEvent([]byte(evt))
	if r.Class != "base_event" || !r.Valid() || len(r.Issues) > 0 {
		t.Errorf("base event: class %q, issues %v", r.Class, r.Issues)
	}
	if bad := v.ValidateEvent([]byte(`{"class_uid": 0, "category_uid": 0}`)); bad.Valid() {
		t.Error("base event missing required attributes should be invalid")
	}
}
