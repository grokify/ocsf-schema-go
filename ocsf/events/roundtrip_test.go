package events_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/grokify/ocsf-schema-go/ocsf/events"
	"github.com/grokify/ocsf-schema-go/ocsf/objects"
)

// TestAuthenticationMarshal builds an OCSF Authentication event and checks
// the wire format: snake_case names, required fields always present,
// omitted optional fields absent.
func TestAuthenticationMarshal(t *testing.T) {
	mfa := true
	evt := events.Authentication{
		ActivityID:  events.AuthenticationActivityIDLogon,
		CategoryUID: events.CategoryUIDIAM,
		ClassUID:    events.ClassUIDAuthentication,
		SeverityID:  events.AuthenticationSeverityIDInformational,
		Time:        1757894400000,
		TypeUID:     int64(events.ClassUIDAuthentication)*100 + events.AuthenticationActivityIDLogon,
		IsMFA:       &mfa,
		Message:     "User jdoe logged in from 10.0.0.1.",
		Metadata: &objects.Metadata{
			Version: events.SchemaVersion,
			Product: &objects.Product{Name: "example", VendorName: "Example Corp"},
		},
		User: &objects.User{
			Name:   "jdoe",
			TypeID: objects.UserTypeIDUser,
		},
		SrcEndpoint: &objects.NetworkEndpoint{IP: "10.0.0.1"},
	}

	data, err := json.Marshal(evt)
	if err != nil {
		t.Fatal(err)
	}
	got := string(data)

	for _, want := range []string{
		`"activity_id":1`,
		`"category_uid":3`,
		`"class_uid":3002`,
		`"severity_id":1`,
		`"type_uid":300201`,
		`"is_mfa":true`,
		`"user":{`,
		`"name":"jdoe"`,
		`"type_id":1`,
		`"src_endpoint":{"ip":"10.0.0.1"}`,
		`"vendor_name":"Example Corp"`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("marshaled event missing %s\nfull: %s", want, got)
		}
	}
	for _, absent := range []string{
		`"status_id"`,   // optional int, zero -> omitted
		`"raw_data"`,    // optional string, empty -> omitted
		`"enrichments"`, // optional array, nil -> omitted
	} {
		if strings.Contains(got, absent) {
			t.Errorf("marshaled event should omit %s\nfull: %s", absent, got)
		}
	}
}

// TestAuthenticationUnmarshal parses a hand-written OCSF event sample.
func TestAuthenticationUnmarshal(t *testing.T) {
	sample := `{
		"activity_id": 2,
		"activity_name": "Logoff",
		"category_uid": 3,
		"class_uid": 3002,
		"severity_id": 1,
		"time": 1757894400000,
		"type_uid": 300202,
		"metadata": {"version": "1.10.0-dev", "product": {"name": "idp"}},
		"user": {"name": "jdoe", "type_id": 1, "groups": [{"name": "admins"}]},
		"is_remote": false,
		"auth_protocol_id": 5,
		"observables": [{"name": "user.name", "type_id": 4, "value": "jdoe"}]
	}`

	var evt events.Authentication
	if err := json.Unmarshal([]byte(sample), &evt); err != nil {
		t.Fatal(err)
	}
	if evt.ActivityID != events.AuthenticationActivityIDLogoff {
		t.Errorf("ActivityID = %d, want Logoff (2)", evt.ActivityID)
	}
	if evt.ClassUID != events.ClassUIDAuthentication {
		t.Errorf("ClassUID = %d, want %d", evt.ClassUID, events.ClassUIDAuthentication)
	}
	if evt.User == nil || evt.User.Name != "jdoe" {
		t.Fatalf("User = %+v, want name jdoe", evt.User)
	}
	if len(evt.User.Groups) != 1 || evt.User.Groups[0].Name != "admins" {
		t.Errorf("User.Groups = %+v, want [admins]", evt.User.Groups)
	}
	if evt.IsRemote == nil || *evt.IsRemote {
		t.Errorf("IsRemote = %v, want explicit false preserved", evt.IsRemote)
	}
	if len(evt.Observables) != 1 || evt.Observables[0].Value != "jdoe" {
		t.Errorf("Observables = %+v", evt.Observables)
	}
	if evt.Metadata == nil || evt.Metadata.Product == nil || evt.Metadata.Product.Name != "idp" {
		t.Errorf("Metadata = %+v", evt.Metadata)
	}

	// Round-trip: explicit false booleans survive re-marshaling.
	data, err := json.Marshal(evt)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"is_remote":false`) {
		t.Errorf("re-marshaled event lost is_remote=false: %s", data)
	}
}

// TestUnmarshalEvent exercises the class-UID registry dispatcher.
func TestUnmarshalEvent(t *testing.T) {
	evt, err := events.UnmarshalEvent([]byte(`{
		"class_uid": 3002, "category_uid": 3, "activity_id": 1, "time": 5,
		"user": {"name": "jdoe"}
	}`))
	if err != nil {
		t.Fatal(err)
	}
	auth, ok := evt.(*events.Authentication)
	if !ok {
		t.Fatalf("UnmarshalEvent returned %T, want *events.Authentication", evt)
	}
	if auth.User == nil || auth.User.Name != "jdoe" {
		t.Errorf("auth.User = %+v", auth.User)
	}

	// Extension class dispatch (win extension, class_uid 201001).
	evt, err = events.UnmarshalEvent([]byte(`{"class_uid": 201001, "time": 5}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := evt.(*events.RegistryKeyActivity); !ok {
		t.Errorf("UnmarshalEvent(201001) returned %T, want *events.RegistryKeyActivity", evt)
	}

	if _, err := events.UnmarshalEvent([]byte(`{"time": 5}`)); err == nil {
		t.Error("expected error for event without class_uid")
	}
	if _, err := events.UnmarshalEvent([]byte(`{"class_uid": 999999}`)); err == nil {
		t.Error("expected error for unknown class_uid")
	}
}

// TestRegistryMaps spot-checks the generated lookup maps and shared enums.
func TestRegistryMaps(t *testing.T) {
	if got := events.ClassNames[3002]; got != "authentication" {
		t.Errorf("ClassNames[3002] = %q, want authentication", got)
	}
	if got := events.ClassCaptions[3002]; got != "Authentication" {
		t.Errorf("ClassCaptions[3002] = %q, want Authentication", got)
	}
	if got := events.CategoryCaptions[events.CategoryUIDIAM]; got != "Identity & Access Management" {
		t.Errorf("CategoryCaptions[3] = %q", got)
	}
	if events.SeverityIDInformational != 1 || events.SeverityIDCaptions[1] != "Informational" {
		t.Error("shared SeverityID constants/captions incorrect")
	}
	if got := events.AuthenticationActivityIDCaptions[events.AuthenticationActivityIDLogon]; got != "Logon" {
		t.Errorf("AuthenticationActivityIDCaptions[Logon] = %q", got)
	}
}

// TestClassUIDConstants spot-checks generated classification constants
// against published OCSF values.
func TestClassUIDConstants(t *testing.T) {
	for name, got := range map[string]struct{ got, want int }{
		"FileActivity":    {events.ClassUIDFileActivity, 1001},
		"SecurityFinding": {events.ClassUIDSecurityFinding, 2001},
		"Authentication":  {events.ClassUIDAuthentication, 3002},
		"DNSActivity":     {events.ClassUIDDNSActivity, 4003},
		"CategorySystem":  {events.CategoryUIDSystem, 1},
		"CategoryIAM":     {events.CategoryUIDIAM, 3},
	} {
		if got.got != got.want {
			t.Errorf("%s = %d, want %d", name, got.got, got.want)
		}
	}
}
