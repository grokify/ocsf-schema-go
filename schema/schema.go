// Package schema loads and compiles OCSF schema source trees
// (https://github.com/ocsf/ocsf-schema).
//
// The OCSF schema is authored in OCSF's own metaschema format, not standard
// JSON Schema: event classes and objects declare partial attribute maps whose
// types live in a shared dictionary, inherit from parents via "extends", and
// mix in profile attributes via "$include". Load reads the raw source tree;
// Compile resolves all of that into flattened, self-contained definitions.
package schema

import "encoding/json"

// Requirement levels used by OCSF attribute definitions.
const (
	RequirementRequired    = "required"
	RequirementRecommended = "recommended"
	RequirementOptional    = "optional"
)

// Version is the content of version.json.
type Version struct {
	Version string `json:"version"`
}

// Category is one entry in categories.json#/attributes.
type Category struct {
	Name        string `json:"-"`
	UID         int    `json:"uid"`
	Caption     string `json:"caption"`
	Description string `json:"description"`
}

// Categories is the content of categories.json.
type Categories struct {
	Caption     string              `json:"caption"`
	Description string              `json:"description"`
	Name        string              `json:"name"`
	Attributes  map[string]Category `json:"attributes"`
}

// EnumMember is one value of an attribute enum, keyed by its (stringified
// integer) value in the enclosing enum map.
type EnumMember struct {
	Caption     string       `json:"caption"`
	Description string       `json:"description,omitempty"`
	Deprecated  *Deprecation `json:"@deprecated,omitempty"`
}

// Deprecation is the @deprecated annotation on attributes and enum members.
type Deprecation struct {
	Message      string   `json:"message"`
	Since        string   `json:"since"`
	SupersededBy []string `json:"superseded_by,omitempty"`
}

// Attribute is a single attribute definition. In dictionary.json entries the
// Type field is populated; in object/event/profile files most fields are
// omitted and only override what the dictionary supplies.
type Attribute struct {
	Caption     string                `json:"caption,omitempty"`
	Description string                `json:"description,omitempty"`
	Type        string                `json:"type,omitempty"`
	IsArray     bool                  `json:"is_array,omitempty"`
	Requirement string                `json:"requirement,omitempty"`
	Group       string                `json:"group,omitempty"`
	Observable  int                   `json:"observable,omitempty"`
	Sibling     string                `json:"sibling,omitempty"`
	Enum        map[string]EnumMember `json:"enum,omitempty"`
	Profile     *string               `json:"profile,omitempty"`
	Deprecated  *Deprecation          `json:"@deprecated,omitempty"`

	// Source records where the attribute entered a compiled definition:
	// "" (declared directly), the ancestor class/object name (inherited),
	// "profile:<name>" (mixed in via $include), or "extension:<name>"
	// (added by a platform extension patch). The _source key never occurs
	// in OCSF source files; it exists so compiled schemas serialize
	// losslessly (see the generated ocsfdata package).
	Source string `json:"_source,omitempty"`
}

// AttributeMap is an OCSF attribute map. It captures the "$include" key,
// which shares the map with regular attribute names, separately.
type AttributeMap struct {
	Includes   []string
	Attributes map[string]*Attribute
}

// UnmarshalJSON lifts "$include" out of the attribute map before decoding the
// remaining entries as Attribute values.
func (m *AttributeMap) UnmarshalJSON(data []byte) error {
	raw := map[string]json.RawMessage{}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	m.Attributes = make(map[string]*Attribute, len(raw))
	for name, msg := range raw {
		if name == "$include" {
			// The only shape used in the OCSF repo is a list of paths, but a
			// single string is tolerated by upstream tooling.
			var list []string
			if err := json.Unmarshal(msg, &list); err != nil {
				var one string
				if err2 := json.Unmarshal(msg, &one); err2 != nil {
					return err
				}
				list = []string{one}
			}
			m.Includes = list
			continue
		}
		attr := &Attribute{}
		if err := json.Unmarshal(msg, attr); err != nil {
			return err
		}
		m.Attributes[name] = attr
	}
	return nil
}

// DictionaryType is one scalar type from dictionary.json#/types/attributes,
// e.g. string_t, integer_t, ip_t.
type DictionaryType struct {
	Caption     string          `json:"caption"`
	Description string          `json:"description,omitempty"`
	Type        string          `json:"type,omitempty"` // base type for subtypes, e.g. ip_t -> string_t
	MaxLen      int             `json:"max_len,omitempty"`
	Range       []float64       `json:"range,omitempty"`
	Regex       string          `json:"regex,omitempty"`
	Values      json.RawMessage `json:"values,omitempty"`
	TypeName    string          `json:"type_name,omitempty"`
	Observable  int             `json:"observable,omitempty"`
}

// Dictionary is the content of dictionary.json.
type Dictionary struct {
	Caption     string                `json:"caption"`
	Description string                `json:"description"`
	Name        string                `json:"name"`
	Attributes  map[string]*Attribute `json:"attributes"`
	Types       struct {
		Caption     string                    `json:"caption"`
		Description string                    `json:"description"`
		Attributes  map[string]DictionaryType `json:"attributes"`
	} `json:"types"`
}

// Definition is a raw object, event class, or profile definition file.
// A file with an "extends" but no "name" is a patch: it amends the extended
// definition instead of declaring a new one (used by platform extensions).
type Definition struct {
	Caption     string       `json:"caption"`
	Description string       `json:"description"`
	Name        string       `json:"name"`
	Extends     string       `json:"extends,omitempty"`
	Category    string       `json:"category,omitempty"` // events only
	UID         *int         `json:"uid,omitempty"`      // events only; nil = abstract class
	Meta        string       `json:"meta,omitempty"`     // "profile" for profiles
	Observable  int          `json:"observable,omitempty"`
	Profiles    []string     `json:"profiles,omitempty"`
	Attributes  AttributeMap `json:"attributes"`
	Constraints *Constraints `json:"constraints,omitempty"`
	Deprecated  *Deprecation `json:"@deprecated,omitempty"`

	// SourcePath is the path of the file this definition was loaded from,
	// relative to the schema root.
	SourcePath string `json:"-"`
	// Extension and ExtensionUID identify the platform extension a
	// definition came from ("" / 0 for core schema definitions).
	Extension    string `json:"-"`
	ExtensionUID int    `json:"-"`
}

// Extension is the content of an extensions/<dir>/extension.json file.
type Extension struct {
	UID         int    `json:"uid"`
	Caption     string `json:"caption"`
	Description string `json:"description,omitempty"`
	Name        string `json:"name"`
	Version     string `json:"version,omitempty"`
}

// Constraints holds OCSF definition-level constraints.
type Constraints struct {
	AtLeastOne []string `json:"at_least_one,omitempty"`
	JustOne    []string `json:"just_one,omitempty"`
}

// Schema is a loaded (but not yet compiled) OCSF schema source tree.
type Schema struct {
	Version    Version
	Categories Categories
	Dictionary Dictionary
	Objects    map[string]*Definition // keyed by definition name (e.g. "_entity", "account")
	Events     map[string]*Definition // keyed by definition name (e.g. "base_event", "authentication")
	Profiles   map[string]*Definition // keyed by repo-relative path (e.g. "profiles/cloud.json")
	Extensions map[string]*Extension  // keyed by extension name (e.g. "win"); empty unless loaded
}
