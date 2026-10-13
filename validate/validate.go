// Package validate checks OCSF event and object JSON against a compiled OCSF
// schema (see the schema package). It is a semantic validator driven directly
// by the schema's requirement levels, dictionary types, enums, and
// constraints — no JSON Schema files are involved.
//
// Typical use with the embedded schema shipped in this module:
//
//	v := validate.New(ocsfdata.MustSchema())
//	result := v.ValidateEvent(eventJSON)
//	if !result.Valid() { ... }
package validate

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/grokify/ocsf-schema-go/schema"
)

// Code identifies a category of validation issue.
type Code string

// Validation issue codes.
const (
	CodeInvalidJSON         Code = "invalid_json"
	CodeMissingClassUID     Code = "missing_class_uid"
	CodeUnknownClass        Code = "unknown_class"
	CodeMissingRequired     Code = "missing_required"
	CodeUnknownAttribute    Code = "unknown_attribute"
	CodeWrongType           Code = "wrong_type"
	CodeInvalidEnumValue    Code = "invalid_enum_value"
	CodeConstraintViolation Code = "constraint_violation"
	CodeInconsistentUID     Code = "inconsistent_uid"
	CodeDeprecatedAttribute Code = "deprecated_attribute"
)

// Issue is a single validation finding.
type Issue struct {
	Code    Code   `json:"code"`
	Path    string `json:"path,omitempty"` // dotted attribute path, e.g. "user.name" or "observables[2].type_id"
	Message string `json:"message"`
	Warning bool   `json:"warning,omitempty"` // true for advisory findings that do not fail validation
}

func (i Issue) String() string {
	kind := "error"
	if i.Warning {
		kind = "warning"
	}
	if i.Path == "" {
		return fmt.Sprintf("%s [%s]: %s", kind, i.Code, i.Message)
	}
	return fmt.Sprintf("%s [%s] %s: %s", kind, i.Code, i.Path, i.Message)
}

// Result is the outcome of validating one event or object.
type Result struct {
	// Class is the event class name the payload was validated against
	// (empty for object validation).
	Class    string  `json:"class,omitempty"`
	ClassUID int     `json:"class_uid,omitempty"`
	Issues   []Issue `json:"issues,omitempty"`
}

// Valid reports whether validation found no error-level issues. Warnings
// (e.g. unknown or deprecated attributes under the default options) do not
// make a result invalid.
func (r *Result) Valid() bool {
	for _, i := range r.Issues {
		if !i.Warning {
			return false
		}
	}
	return true
}

// Errors returns only the error-level issues.
func (r *Result) Errors() []Issue {
	var out []Issue
	for _, i := range r.Issues {
		if !i.Warning {
			out = append(out, i)
		}
	}
	return out
}

// UnknownMode controls how attributes absent from the schema are reported.
type UnknownMode int

// Unknown-attribute handling modes.
const (
	UnknownWarn   UnknownMode = iota // report as warning (default)
	UnknownIgnore                    // do not report
	UnknownError                     // report as error
)

// Options configures a Validator.
type Options struct {
	// UnknownAttributes controls reporting of attributes not defined by the
	// schema. OCSF reserves the "unmapped" attribute for such data, so the
	// default is to warn.
	UnknownAttributes UnknownMode
	// DeprecatedWarnings, when true (default), reports usage of deprecated
	// attributes as warnings.
	DeprecatedWarnings bool
}

// Option mutates Options.
type Option func(*Options)

// WithUnknownAttributes sets the unknown-attribute handling mode.
func WithUnknownAttributes(m UnknownMode) Option {
	return func(o *Options) { o.UnknownAttributes = m }
}

// WithDeprecatedWarnings enables or disables deprecation warnings.
func WithDeprecatedWarnings(on bool) Option {
	return func(o *Options) { o.DeprecatedWarnings = on }
}

// Validator validates OCSF payloads against a compiled schema. It is safe
// for concurrent use.
type Validator struct {
	c     *schema.CompiledSchema
	byUID map[int]*schema.CompiledClass
	opts  Options
}

// New creates a Validator for the compiled schema.
func New(c *schema.CompiledSchema, opts ...Option) *Validator {
	o := Options{UnknownAttributes: UnknownWarn, DeprecatedWarnings: true}
	for _, opt := range opts {
		opt(&o)
	}
	v := &Validator{c: c, byUID: map[int]*schema.CompiledClass{}, opts: o}
	for _, cls := range c.Classes {
		if !cls.Abstract {
			v.byUID[cls.ClassUID] = cls
		}
	}
	return v
}

// Class returns the compiled event class registered for a class_uid.
func (v *Validator) Class(classUID int) (*schema.CompiledClass, bool) {
	cls, ok := v.byUID[classUID]
	return cls, ok
}

// ValidateEvent validates OCSF event JSON, dispatching on its class_uid.
// All problems, including malformed JSON, are reported as issues on the
// Result rather than as Go errors.
func (v *Validator) ValidateEvent(data []byte) *Result {
	r := &Result{}
	payload, ok := decodeObject(data, r)
	if !ok {
		return r
	}

	classUID, ok := intField(payload, "class_uid")
	if !ok {
		r.add(Issue{Code: CodeMissingClassUID, Path: "class_uid",
			Message: "event has no integer class_uid attribute"})
		return r
	}
	r.ClassUID = classUID
	cls, ok := v.byUID[classUID]
	if !ok {
		r.add(Issue{Code: CodeUnknownClass, Path: "class_uid",
			Message: fmt.Sprintf("no event class with class_uid %d in schema %s", classUID, v.c.Version)})
		return r
	}
	r.Class = cls.Name

	v.validateAttributes("", cls.Attributes, cls.Constraints, payload, activeProfiles(payload), r)
	v.checkClassificationConsistency(cls, payload, r)
	return r
}

// ValidateEventClass validates event JSON against a specific class by name,
// ignoring the payload's own class_uid for dispatch.
func (v *Validator) ValidateEventClass(className string, data []byte) (*Result, error) {
	cls, ok := v.c.Classes[className]
	if !ok {
		return nil, fmt.Errorf("validate: unknown event class %q", className)
	}
	r := &Result{Class: cls.Name, ClassUID: cls.ClassUID}
	payload, ok2 := decodeObject(data, r)
	if !ok2 {
		return r, nil
	}
	v.validateAttributes("", cls.Attributes, cls.Constraints, payload, activeProfiles(payload), r)
	if !cls.Abstract {
		v.checkClassificationConsistency(cls, payload, r)
	}
	return r, nil
}

// ValidateObject validates object JSON against a named OCSF object
// definition (e.g. "user").
func (v *Validator) ValidateObject(objectName string, data []byte) (*Result, error) {
	obj, ok := v.c.Objects[objectName]
	if !ok {
		return nil, fmt.Errorf("validate: unknown object %q", objectName)
	}
	r := &Result{}
	payload, ok2 := decodeObject(data, r)
	if !ok2 {
		return r, nil
	}
	v.validateAttributes("", obj.Attributes, obj.Constraints, payload, nil, r)
	return r, nil
}

func (r *Result) add(i Issue) { r.Issues = append(r.Issues, i) }

func decodeObject(data []byte, r *Result) (map[string]any, bool) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var payload map[string]any
	if err := dec.Decode(&payload); err != nil {
		r.add(Issue{Code: CodeInvalidJSON, Message: err.Error()})
		return nil, false
	}
	return payload, true
}

// activeProfiles extracts metadata.profiles from an event payload. Both the
// full profile reference (e.g. "linux/linux_users") and its last path
// segment are included, matching how profile provenance is recorded during
// schema compilation.
func activeProfiles(payload map[string]any) map[string]bool {
	active := map[string]bool{}
	meta, ok := payload["metadata"].(map[string]any)
	if !ok {
		return active
	}
	list, ok := meta["profiles"].([]any)
	if !ok {
		return active
	}
	for _, p := range list {
		s, ok := p.(string)
		if !ok {
			continue
		}
		active[s] = true
		if i := strings.LastIndex(s, "/"); i >= 0 {
			active[s[i+1:]] = true
		}
	}
	return active
}

// validateAttributes checks one attribute map (event class or object level)
// against a JSON object value.
func (v *Validator) validateAttributes(path string, attrs map[string]*schema.Attribute, constraints *schema.Constraints, value map[string]any, profiles map[string]bool, r *Result) {
	// Missing required attributes. Attributes contributed by a profile are
	// required only when the event declares that profile active.
	names := make([]string, 0, len(attrs))
	for name := range attrs {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		attr := attrs[name]
		if attr.Requirement != schema.RequirementRequired {
			continue
		}
		if profile, ok := strings.CutPrefix(attr.Source, "profile:"); ok && !profiles[profile] {
			continue
		}
		if val, present := value[name]; !present || val == nil {
			r.add(Issue{Code: CodeMissingRequired, Path: joinPath(path, name),
				Message: fmt.Sprintf("required attribute %q is missing", name)})
		}
	}

	// Present attributes: unknown, deprecated, then type/enum checks.
	keys := make([]string, 0, len(value))
	for key := range value {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		val := value[key]
		attr, known := attrs[key]
		if !known {
			if v.opts.UnknownAttributes == UnknownIgnore {
				continue
			}
			r.add(Issue{Code: CodeUnknownAttribute, Path: joinPath(path, key),
				Message: fmt.Sprintf("attribute %q is not defined for this type; consider the unmapped attribute", key),
				Warning: v.opts.UnknownAttributes == UnknownWarn})
			continue
		}
		if val == nil {
			continue // treated as absent
		}
		if attr.Deprecated != nil && v.opts.DeprecatedWarnings {
			r.add(Issue{Code: CodeDeprecatedAttribute, Path: joinPath(path, key),
				Message: fmt.Sprintf("attribute %q is deprecated since %s", key, attr.Deprecated.Since),
				Warning: true})
		}
		v.checkValue(joinPath(path, key), key, attr, val, profiles, r)
	}

	if constraints != nil {
		v.checkConstraints(path, constraints, value, r)
	}
}

// checkValue validates one attribute value (possibly an array).
func (v *Validator) checkValue(path, name string, attr *schema.Attribute, val any, profiles map[string]bool, r *Result) {
	if attr.IsArray {
		arr, ok := val.([]any)
		if !ok {
			r.add(Issue{Code: CodeWrongType, Path: path,
				Message: fmt.Sprintf("expected an array of %s", attr.Type)})
			return
		}
		for i, elem := range arr {
			if elem == nil {
				continue
			}
			v.checkElement(fmt.Sprintf("%s[%d]", path, i), name, attr, elem, profiles, r)
		}
		return
	}
	v.checkElement(path, name, attr, val, profiles, r)
}

// classificationAttrs have their enums checked structurally (class lookup,
// category and type_uid consistency) rather than by enum membership, because
// source schema definitions only enumerate the base class values.
var classificationAttrs = map[string]bool{"class_uid": true, "category_uid": true, "type_uid": true}

// checkElement validates a single non-array JSON value against an attribute.
func (v *Validator) checkElement(path, name string, attr *schema.Attribute, val any, profiles map[string]bool, r *Result) {
	// Object-typed attribute: recurse.
	if obj, ok := v.c.Objects[attr.Type]; ok {
		m, ok2 := val.(map[string]any)
		if !ok2 {
			r.add(Issue{Code: CodeWrongType, Path: path,
				Message: fmt.Sprintf("expected a %s object", attr.Type)})
			return
		}
		v.validateAttributes(path, obj.Attributes, obj.Constraints, m, profiles, r)
		return
	}
	if attr.Type == "object" || attr.Type == "" {
		if _, ok := val.(map[string]any); !ok && attr.Type == "object" {
			r.add(Issue{Code: CodeWrongType, Path: path, Message: "expected a JSON object"})
		}
		return
	}

	switch root := v.c.RootScalarType(attr.Type); root {
	case "string_t":
		s, ok := val.(string)
		if !ok {
			r.add(Issue{Code: CodeWrongType, Path: path,
				Message: fmt.Sprintf("expected a string (%s)", attr.Type)})
			return
		}
		v.checkEnum(path, name, attr, s, r)
	case "integer_t", "long_t":
		n, ok := val.(json.Number)
		if !ok {
			r.add(Issue{Code: CodeWrongType, Path: path,
				Message: fmt.Sprintf("expected an integer (%s)", attr.Type)})
			return
		}
		i, err := strconv.ParseInt(n.String(), 10, 64)
		if err != nil {
			r.add(Issue{Code: CodeWrongType, Path: path,
				Message: fmt.Sprintf("expected an integer (%s), got %s", attr.Type, n)})
			return
		}
		if !classificationAttrs[name] {
			v.checkEnum(path, name, attr, strconv.FormatInt(i, 10), r)
		}
	case "float_t":
		if _, ok := val.(json.Number); !ok {
			r.add(Issue{Code: CodeWrongType, Path: path, Message: "expected a number"})
		}
	case "boolean_t":
		if _, ok := val.(bool); !ok {
			r.add(Issue{Code: CodeWrongType, Path: path, Message: "expected a boolean"})
		}
	case "json_t":
		// Any JSON value is legal.
	default:
		// Unknown scalar type: schema irregularity, not a payload problem.
	}
}

// checkEnum reports values outside an attribute's enum. key is the enum map
// key form of the value (stringified integer or the string itself).
func (v *Validator) checkEnum(path, name string, attr *schema.Attribute, key string, r *Result) {
	if len(attr.Enum) == 0 || classificationAttrs[name] {
		return
	}
	if _, ok := attr.Enum[key]; !ok {
		r.add(Issue{Code: CodeInvalidEnumValue, Path: path,
			Message: fmt.Sprintf("value %s is not a defined enum value for %q", key, name)})
	}
}

// checkConstraints enforces at_least_one and just_one definition constraints.
func (v *Validator) checkConstraints(path string, c *schema.Constraints, value map[string]any, r *Result) {
	count := func(names []string) int {
		n := 0
		for _, name := range names {
			if val, ok := value[name]; ok && val != nil {
				n++
			}
		}
		return n
	}
	if len(c.AtLeastOne) > 0 && count(c.AtLeastOne) == 0 {
		r.add(Issue{Code: CodeConstraintViolation, Path: path,
			Message: fmt.Sprintf("at least one of [%s] must be present", strings.Join(c.AtLeastOne, ", "))})
	}
	if len(c.JustOne) > 0 && count(c.JustOne) != 1 {
		r.add(Issue{Code: CodeConstraintViolation, Path: path,
			Message: fmt.Sprintf("exactly one of [%s] must be present", strings.Join(c.JustOne, ", "))})
	}
}

// checkClassificationConsistency verifies category_uid and type_uid agree
// with the event class identified by class_uid.
func (v *Validator) checkClassificationConsistency(cls *schema.CompiledClass, payload map[string]any, r *Result) {
	if catUID, ok := intField(payload, "category_uid"); ok && catUID != cls.CategoryUID {
		r.add(Issue{Code: CodeInconsistentUID, Path: "category_uid",
			Message: fmt.Sprintf("category_uid %d does not match class %s (expected %d)", catUID, cls.Name, cls.CategoryUID)})
	}
	typeUID, hasType := intField(payload, "type_uid")
	activityID, hasActivity := intField(payload, "activity_id")
	if hasType && hasActivity {
		if want := cls.ClassUID*100 + activityID; typeUID != want {
			r.add(Issue{Code: CodeInconsistentUID, Path: "type_uid",
				Message: fmt.Sprintf("type_uid %d != class_uid*100 + activity_id (%d)", typeUID, want)})
		}
	}
}

func intField(payload map[string]any, name string) (int, bool) {
	n, ok := payload[name].(json.Number)
	if !ok {
		return 0, false
	}
	i, err := strconv.ParseInt(n.String(), 10, 64)
	if err != nil {
		return 0, false
	}
	return int(i), true
}

func joinPath(base, name string) string {
	if base == "" {
		return name
	}
	return base + "." + name
}
