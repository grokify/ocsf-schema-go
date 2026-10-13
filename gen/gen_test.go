package gen

import (
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"
	"testing"

	"github.com/grokify/ocsf-schema-go/schema"
)

func TestGoName(t *testing.T) {
	for in, want := range map[string]string{
		"account":                     "Account",
		"type_id":                     "TypeID",
		"class_uid":                   "ClassUID",
		"http_activity":               "HTTPActivity",
		"src_endpoint":                "SrcEndpoint",
		"is_on_premises_sync_enabled": "IsOnPremisesSyncEnabled",
		"cvss":                        "CVSS",
		"d3f_tactic":                  "D3FTactic",
		"_entity":                     "Entity",
		"_resource":                   "Resource",
		"ja4_fingerprint":             "JA4Fingerprint",
		"os":                          "OS",
		"tls":                         "TLS",
		"url":                         "URL",
		"ai_agent":                    "AIAgent",
	} {
		if got := GoName(in); got != want {
			t.Errorf("GoName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestEnumIdent(t *testing.T) {
	for in, want := range map[string]string{
		"Unknown":        "Unknown",
		"LDAP Account":   "LDAPAccount",
		"In-Progress":    "InProgress",
		"TCP/IP":         "TCPIP",
		"Other":          "Other",
		"IPv4 (RFC 791)": "IPv4RFC791",
	} {
		if got := EnumIdent(in); got != want {
			t.Errorf("EnumIdent(%q) = %q, want %q", in, got, want)
		}
	}
}

func compiled(t *testing.T) *schema.CompiledSchema {
	t.Helper()
	s, err := schema.Load(filepath.Join("..", "schema", "testdata", "minischema"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	c, err := s.Compile()
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	return c
}

func TestGenerate(t *testing.T) {
	files, err := Generate(compiled(t), Options{})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	for _, want := range []string{
		"objects/objects.go", "objects/doc.go", "objects/observables.go",
		"events/base.go", "events/iam.go", "events/constants.go", "events/registry.go", "events/doc.go",
		"ocsfdata/ocsfdata.go", "ocsfdata/schema.json",
	} {
		if _, ok := files[want]; !ok {
			t.Errorf("missing output file %s (got %v)", want, keys(files))
		}
	}

	// Every generated Go file must parse as valid Go.
	fset := token.NewFileSet()
	for name, src := range files {
		if !strings.HasSuffix(name, ".go") {
			continue
		}
		if _, err := parser.ParseFile(fset, name, src, parser.ParseComments); err != nil {
			t.Errorf("%s does not parse: %v", name, err)
		}
	}

	// gofmt column-aligns fields and const blocks; normalize runs of spaces
	// so assertions can use single-space spelling.
	norm := func(src []byte) string {
		return strings.Join(strings.Fields(string(src)), " ")
	}

	objects := norm(files["objects/objects.go"])
	for _, want := range []string{
		"type User struct {",
		"Name string `json:\"name,omitempty\"`",
		"IsDisabled *bool `json:\"is_disabled,omitempty\"`",
		"Labels []string `json:\"labels,omitempty\"`",
		"UserTypeIDAdmin = 2",
		"UserTypeIDOther = 99",
	} {
		if !strings.Contains(objects, want) {
			t.Errorf("objects.go missing %q", want)
		}
	}
	if strings.Contains(objects, "type Entity struct") {
		t.Error("objects.go contains hidden object _entity")
	}

	iam := norm(files["events/iam.go"])
	for _, want := range []string{
		"type Authentication struct {",
		"User *objects.User `json:\"user\"`", // required: no omitempty
		"SrcIP string `json:\"src_ip,omitempty\"`",
		"Time int64 `json:\"time\"`",
		"AuthenticationActivityIDLogon = 1",
		"AuthenticationActivityIDLogoff = 2",
	} {
		if !strings.Contains(iam, want) {
			t.Errorf("events/iam.go missing %q", want)
		}
	}
	// class_uid enums are covered by ClassUID constants, not per-struct enums.
	if strings.Contains(iam, "AuthenticationClassUID") {
		t.Error("events/iam.go should not emit per-struct class_uid enum constants")
	}

	constants := norm(files["events/constants.go"])
	for _, want := range []string{
		`const SchemaVersion = "1.10.0-test"`,
		"CategoryUIDIAM = 3",
		"ClassUIDAuthentication = 3002",
		"SeverityIDInformational = 1", // shared severity constants from base_event
		"var SeverityIDCaptions = map[int]string{",
	} {
		if !strings.Contains(constants, want) {
			t.Errorf("events/constants.go missing %q", want)
		}
	}
	if strings.Contains(constants, "ClassUIDIAM") {
		t.Error("constants.go should not include abstract classes")
	}

	registry := norm(files["events/registry.go"])
	for _, want := range []string{
		"func NewEventByClassUID(classUID int) (any, bool) {",
		"case ClassUIDAuthentication: return &Authentication{}, true",
		"func UnmarshalEvent(data []byte) (any, error) {",
		`ClassUIDAuthentication: "authentication",`,
		`ClassUIDAuthentication: "Authentication",`,
		`CategoryUIDIAM: "Identity & Access Management",`,
	} {
		if !strings.Contains(registry, want) {
			t.Errorf("events/registry.go missing %q", want)
		}
	}

	// Enum caption maps accompany constants.
	if want := "var UserTypeIDCaptions = map[int]string{"; !strings.Contains(objects, want) {
		t.Errorf("objects.go missing %q", want)
	}
}

func TestGenerateWithExtensions(t *testing.T) {
	s, err := schema.LoadWithExtensions(filepath.Join("..", "schema", "testdata", "minischema"), "all")
	if err != nil {
		t.Fatalf("LoadWithExtensions: %v", err)
	}
	c, err := s.Compile()
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	files, err := Generate(c, Options{})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	norm := func(src []byte) string {
		return strings.Join(strings.Fields(string(src)), " ")
	}

	objects := norm(files["objects/objects.go"])
	for _, want := range []string{
		"type Widget struct {",
		"KernelFlag *bool `json:\"kernel_flag,omitempty\"`", // patched onto user
	} {
		if !strings.Contains(objects, want) {
			t.Errorf("objects.go missing %q", want)
		}
	}
	if want := `"widget": 90,`; !strings.Contains(norm(files["objects/observables.go"]), want) {
		t.Errorf("observables.go missing object observable %q", want)
	}

	constants := norm(files["events/constants.go"])
	if !strings.Contains(constants, "ClassUIDWidgetActivity = 203001") {
		t.Error("constants.go missing extension class UID 203001")
	}
}

func TestCleanText(t *testing.T) {
	in := "The name.<br>See <code>account_type_id</code> &gt; 0.\n  More."
	want := "The name. See account_type_id > 0. More."
	if got := cleanText(in); got != want {
		t.Errorf("cleanText = %q, want %q", got, want)
	}
}

func keys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
