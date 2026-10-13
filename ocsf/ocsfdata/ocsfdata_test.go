package ocsfdata_test

import (
	"testing"

	"github.com/grokify/ocsf-schema-go/ocsf/events"
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
