package schema

import (
	"os"
	"path/filepath"
	"testing"
)

func loadMini(t *testing.T) *Schema {
	t.Helper()
	s, err := Load(filepath.Join("testdata", "minischema"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return s
}

func compileMini(t *testing.T) *CompiledSchema {
	t.Helper()
	c, err := loadMini(t).Compile()
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	return c
}

func TestLoad(t *testing.T) {
	s := loadMini(t)

	if s.Version.Version != "1.10.0-test" {
		t.Errorf("version = %q, want 1.10.0-test", s.Version.Version)
	}
	if got := len(s.Objects); got != 2 {
		t.Errorf("len(Objects) = %d, want 2", got)
	}
	if got := len(s.Events); got != 3 {
		t.Errorf("len(Events) = %d, want 3", got)
	}
	if _, ok := s.Profiles["profiles/cloud.json"]; !ok {
		t.Errorf("profile not keyed by repo-relative path: %v", s.Profiles)
	}
	if got := s.Events["base_event"].Attributes.Includes; len(got) != 1 || got[0] != "profiles/cloud.json" {
		t.Errorf("base_event $include = %v, want [profiles/cloud.json]", got)
	}
	if s.Events["authentication"].UID == nil || *s.Events["authentication"].UID != 2 {
		t.Errorf("authentication uid = %v, want 2", s.Events["authentication"].UID)
	}
	if s.Events["iam"].UID != nil {
		t.Errorf("iam uid = %v, want nil (abstract)", s.Events["iam"].UID)
	}
	if got := len(s.Dictionary.Types.Attributes); got != 6 {
		t.Errorf("len(Dictionary.Types) = %d, want 6", got)
	}
}

func TestCompileObjects(t *testing.T) {
	c := compileMini(t)

	entity, ok := c.Objects["_entity"]
	if !ok {
		t.Fatal("_entity not compiled")
	}
	if !entity.Hidden {
		t.Error("_entity should be Hidden")
	}

	user, ok := c.Objects["user"]
	if !ok {
		t.Fatal("user not compiled")
	}
	if user.Hidden {
		t.Error("user should not be Hidden")
	}
	if len(user.Ancestors) != 1 || user.Ancestors[0] != "_entity" {
		t.Errorf("user.Ancestors = %v, want [_entity]", user.Ancestors)
	}

	// Inherited from _entity, description overridden locally.
	name := user.Attributes["name"]
	if name == nil {
		t.Fatal("user.name missing (extends not flattened)")
	}
	if name.Type != "string_t" {
		t.Errorf("user.name type = %q, want string_t (dictionary join)", name.Type)
	}
	if name.Description != "The username." {
		t.Errorf("user.name description = %q, want local override", name.Description)
	}
	if name.Requirement != RequirementRecommended {
		t.Errorf("user.name requirement = %q, want inherited recommended", name.Requirement)
	}

	if got := user.Attributes["labels"]; got == nil || !got.IsArray || got.Type != "string_t" {
		t.Errorf("user.labels = %+v, want string_t array", got)
	}

	// Local enum replaces the dictionary enum wholesale.
	typeID := user.Attributes["type_id"]
	if typeID == nil {
		t.Fatal("user.type_id missing")
	}
	if len(typeID.Enum) != 4 {
		t.Errorf("user.type_id enum size = %d, want 4", len(typeID.Enum))
	}
	if typeID.Enum["2"].Caption != "Admin" {
		t.Errorf("user.type_id enum[2] = %+v, want Admin", typeID.Enum["2"])
	}
	if typeID.Sibling != "type_name" {
		t.Errorf("user.type_id sibling = %q, want type_name (from dictionary)", typeID.Sibling)
	}

	// Constraints inherited from _entity.
	if user.Constraints == nil || len(user.Constraints.AtLeastOne) != 1 {
		t.Errorf("user.Constraints = %+v, want at_least_one from _entity", user.Constraints)
	}
}

func TestCompileClasses(t *testing.T) {
	c := compileMini(t)

	base := c.Classes["base_event"]
	if base == nil || !base.Abstract || base.ClassUID != 0 {
		t.Errorf("base_event = %+v, want abstract with ClassUID 0", base)
	}

	auth := c.Classes["authentication"]
	if auth == nil {
		t.Fatal("authentication not compiled")
	}
	if auth.Abstract {
		t.Error("authentication should be concrete")
	}
	if auth.ClassUID != 3002 {
		t.Errorf("authentication.ClassUID = %d, want 3002", auth.ClassUID)
	}
	if auth.CategoryUID != 3 {
		t.Errorf("authentication.CategoryUID = %d, want 3", auth.CategoryUID)
	}
	if auth.Category != "iam" {
		t.Errorf("authentication.Category = %q, want iam (inherited from iam base)", auth.Category)
	}
	if want := []string{"base_event", "iam"}; len(auth.Ancestors) != 2 || auth.Ancestors[0] != want[0] || auth.Ancestors[1] != want[1] {
		t.Errorf("authentication.Ancestors = %v, want %v", auth.Ancestors, want)
	}

	// Enum refinement: authentication's {1,2} are merged into base_event's
	// {0,99}, as the OCSF schema server presents the class.
	activity := auth.Attributes["activity_id"]
	if activity == nil {
		t.Fatal("authentication.activity_id missing")
	}
	if len(activity.Enum) != 4 || activity.Enum["0"].Caption != "Unknown" ||
		activity.Enum["1"].Caption != "Logon" || activity.Enum["2"].Caption != "Logoff" || activity.Enum["99"].Caption != "Other" {
		t.Errorf("authentication.activity_id enum = %+v, want {0:Unknown, 1:Logon, 2:Logoff, 99:Other}", activity.Enum)
	}
	// The merge builds a new map: base_event keeps only its own members.
	if got := base.Attributes["activity_id"].Enum; len(got) != 2 {
		t.Errorf("base_event.activity_id enum = %+v, want {0, 99} only", got)
	}
	if activity.Requirement != RequirementRequired {
		t.Errorf("activity_id requirement = %q, want required (inherited)", activity.Requirement)
	}

	// Profile mixin flows down from base_event's $include.
	region := auth.Attributes["region"]
	if region == nil {
		t.Fatal("authentication.region missing ($include not resolved)")
	}
	if region.Source != "profile:cloud" {
		t.Errorf("region.Source = %q, want profile:cloud", region.Source)
	}

	// Requirement override on inherited profile-free attribute.
	if got := auth.Attributes["user"]; got == nil || got.Requirement != RequirementRequired {
		t.Errorf("authentication.user = %+v, want required (local override)", got)
	}
	if got := auth.Attributes["user"]; got == nil || got.Type != "user" {
		t.Errorf("authentication.user type = %+v, want object type user", got)
	}

	// time comes straight from base_event + dictionary.
	if got := auth.Attributes["time"]; got == nil || got.Type != "timestamp_t" || got.Source != "base_event" {
		t.Errorf("authentication.time = %+v, want timestamp_t from base_event", got)
	}
}

func TestRootScalarType(t *testing.T) {
	c := compileMini(t)
	for in, want := range map[string]string{
		"ip_t":        "string_t",
		"timestamp_t": "long_t",
		"string_t":    "string_t",
		"user":        "user", // not a scalar
	} {
		if got := c.RootScalarType(in); got != want {
			t.Errorf("RootScalarType(%s) = %q, want %q", in, got, want)
		}
	}
}

func TestLoadWithExtensions(t *testing.T) {
	s, err := LoadWithExtensions(filepath.Join("testdata", "minischema"), "all")
	if err != nil {
		t.Fatalf("LoadWithExtensions: %v", err)
	}
	c, err := s.Compile()
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}

	ext, ok := c.Extensions["tex"]
	if !ok || ext.UID != 2 {
		t.Fatalf("Extensions = %+v, want tex with uid 2", c.Extensions)
	}

	// New extension object with its own dictionary type and observable.
	widget, ok := c.Objects["widget"]
	if !ok {
		t.Fatal("widget object not loaded from extension")
	}
	if widget.Extension != "tex" || widget.Observable != 90 {
		t.Errorf("widget = ext %q observable %d, want tex/90", widget.Extension, widget.Observable)
	}
	if got := widget.Attributes["path"]; got == nil || got.Type != "widget_path_t" {
		t.Errorf("widget.path = %+v, want widget_path_t (extension dictionary type)", got)
	}
	if got := c.RootScalarType("widget_path_t"); got != "string_t" {
		t.Errorf("RootScalarType(widget_path_t) = %q, want string_t", got)
	}

	// Extension event class: class_uid = ext_uid*100000 + category_uid*1000 + uid.
	wa, ok := c.Classes["widget_activity"]
	if !ok {
		t.Fatal("widget_activity class not loaded from extension")
	}
	if wa.ClassUID != 203001 {
		t.Errorf("widget_activity.ClassUID = %d, want 203001", wa.ClassUID)
	}
	if wa.Extension != "tex" || wa.Category != "iam" {
		t.Errorf("widget_activity ext/category = %q/%q, want tex/iam", wa.Extension, wa.Category)
	}

	// Patch: user gains kernel_flag plus the extension profile's attributes,
	// with provenance recorded.
	user := c.Objects["user"]
	kf := user.Attributes["kernel_flag"]
	if kf == nil || kf.Type != "boolean_t" {
		t.Fatalf("user.kernel_flag = %+v, want patched boolean_t", kf)
	}
	if kf.Source != "extension:tex" {
		t.Errorf("user.kernel_flag.Source = %q, want extension:tex", kf.Source)
	}
	if got := user.Attributes["labels"]; got == nil {
		t.Error("user.labels missing: extension-relative $include not resolved")
	}

	// Core-only Load stays untouched by extension patches.
	core := compileMini(t)
	if _, ok := core.Objects["user"].Attributes["kernel_flag"]; ok {
		t.Error("core Load leaked extension patch attribute kernel_flag")
	}
	if _, ok := core.Objects["widget"]; ok {
		t.Error("core Load leaked extension object widget")
	}
}

func TestLoadWithExtensionDirs(t *testing.T) {
	s, err := LoadWithOptions(filepath.Join("testdata", "minischema"), LoadOptions{
		ExtensionDirs: []string{filepath.Join("testdata", "extdir", "patchext")},
	})
	if err != nil {
		t.Fatalf("LoadWithOptions: %v", err)
	}
	c, err := s.Compile()
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if _, ok := c.Extensions["patchext"]; !ok {
		t.Fatalf("external extension not registered: %v", c.Extensions)
	}
	attr := c.Objects["user"].Attributes["external_flag"]
	if attr == nil || attr.Type != "boolean_t" {
		t.Fatalf("user.external_flag = %+v, want patched boolean_t", attr)
	}
	if attr.Source != "extension:patchext" {
		t.Errorf("user.external_flag.Source = %q, want extension:patchext", attr.Source)
	}
}

func TestLoadWithExtensionsUnknownName(t *testing.T) {
	if _, err := LoadWithExtensions(filepath.Join("testdata", "minischema"), "nope"); err == nil {
		t.Fatal("expected error for unknown extension name")
	}
}

// TestCompileFullSchema compiles a real ocsf/ocsf-schema checkout when
// OCSF_SCHEMA_DIR is set (e.g. OCSF_SCHEMA_DIR=~/go/src/github.com/ocsf/ocsf-schema).
func TestCompileFullSchema(t *testing.T) {
	dir := os.Getenv("OCSF_SCHEMA_DIR")
	if dir == "" {
		t.Skip("OCSF_SCHEMA_DIR not set")
	}
	s, err := Load(dir)
	if err != nil {
		t.Fatalf("Load(%s): %v", dir, err)
	}
	c, err := s.Compile()
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if len(c.Objects) < 100 {
		t.Errorf("len(Objects) = %d, want >= 100", len(c.Objects))
	}
	if len(c.Classes) < 50 {
		t.Errorf("len(Classes) = %d, want >= 50", len(c.Classes))
	}
	for _, w := range c.Warnings {
		t.Logf("warning: %s", w)
	}
	// Every non-warned attribute must have a resolvable type.
	for _, obj := range c.Objects {
		for name, attr := range obj.Attributes {
			if attr.Type == "" {
				continue // warned: not in dictionary
			}
			if _, scalar := c.ScalarType(attr.Type); scalar {
				continue
			}
			if attr.Type == "object" {
				continue
			}
			if _, isObj := c.Objects[attr.Type]; !isObj {
				t.Errorf("object %s attribute %s: unresolvable type %q", obj.Name, name, attr.Type)
			}
		}
	}
}
