package schema

import (
	"fmt"
	"maps"
	"sort"
	"strconv"
)

// CompiledSchema is a Schema with all indirection resolved: every object and
// event class carries its complete attribute set with types joined from the
// dictionary, extends chains flattened, and $include profiles mixed in.
type CompiledSchema struct {
	Version    string
	Categories map[string]Category
	Objects    map[string]*CompiledObject
	Classes    map[string]*CompiledClass
	Dictionary Dictionary
	Extensions map[string]*Extension

	// Warnings lists non-fatal irregularities found during compilation,
	// e.g. attributes that are absent from the dictionary.
	Warnings []string
}

// CompiledObject is a fully resolved OCSF object definition.
type CompiledObject struct {
	Name        string
	Caption     string
	Description string
	// Hidden marks abstract base objects (names starting with "_") that
	// exist only to be extended and are not part of the wire format.
	Hidden bool
	// Observable is the observable type_id assigned to this object, 0 if none.
	Observable int
	// Extension names the platform extension the object came from, "" for core.
	Extension   string
	Ancestors   []string // extends chain, root first, excluding "object"
	Attributes  map[string]*Attribute
	Constraints *Constraints
	Deprecated  *Deprecation
}

// CompiledClass is a fully resolved OCSF event class.
type CompiledClass struct {
	Name        string
	Caption     string
	Description string
	Category    string
	CategoryUID int
	// ClassUID is category_uid*1000 + uid for concrete core classes and
	// extension_uid*100000 + category_uid*1000 + uid for extension classes;
	// 0 for abstract classes (base_event and category base classes).
	ClassUID int
	Abstract bool
	// Extension names the platform extension the class came from, "" for core.
	Extension   string
	Ancestors   []string // extends chain, root first
	Attributes  map[string]*Attribute
	Constraints *Constraints
	Deprecated  *Deprecation
}

// ScalarType reports whether name is a scalar type defined in
// dictionary.json#/types (e.g. string_t, integer_t, ip_t).
func (c *CompiledSchema) ScalarType(name string) (DictionaryType, bool) {
	t, ok := c.Dictionary.Types.Attributes[name]
	return t, ok
}

// RootScalarType follows subtype chains (ip_t -> string_t) to the base scalar
// type name. It returns name unchanged if it is not a known scalar type.
func (c *CompiledSchema) RootScalarType(name string) string {
	seen := map[string]bool{}
	for {
		t, ok := c.Dictionary.Types.Attributes[name]
		if !ok || t.Type == "" || t.Type == name || seen[name] {
			return name
		}
		seen[name] = true
		name = t.Type
	}
}

// Compile resolves the loaded schema into flattened definitions.
func (s *Schema) Compile() (*CompiledSchema, error) {
	c := &CompiledSchema{
		Version:    s.Version.Version,
		Categories: s.Categories.Attributes,
		Objects:    map[string]*CompiledObject{},
		Classes:    map[string]*CompiledClass{},
		Dictionary: s.Dictionary,
		Extensions: s.Extensions,
	}

	for name, def := range s.Objects {
		chain, err := extendsChain(def, s.Objects, "object")
		if err != nil {
			return nil, fmt.Errorf("schema: object %s: %w", name, err)
		}
		attrs, err := s.flattenAttributes(c, chain)
		if err != nil {
			return nil, fmt.Errorf("schema: object %s: %w", name, err)
		}
		c.Objects[name] = &CompiledObject{
			Name:        name,
			Caption:     def.Caption,
			Description: def.Description,
			Hidden:      len(name) > 0 && name[0] == '_',
			Observable:  def.Observable,
			Extension:   def.Extension,
			Ancestors:   chainNames(chain[:len(chain)-1]),
			Attributes:  attrs,
			Constraints: inheritedConstraints(chain),
			Deprecated:  def.Deprecated,
		}
	}

	for name, def := range s.Events {
		chain, err := extendsChain(def, s.Events, "")
		if err != nil {
			return nil, fmt.Errorf("schema: event class %s: %w", name, err)
		}
		attrs, err := s.flattenAttributes(c, chain)
		if err != nil {
			return nil, fmt.Errorf("schema: event class %s: %w", name, err)
		}
		cls := &CompiledClass{
			Name:        name,
			Caption:     def.Caption,
			Description: def.Description,
			Category:    def.Category,
			Abstract:    def.UID == nil,
			Extension:   def.Extension,
			Ancestors:   chainNames(chain[:len(chain)-1]),
			Attributes:  attrs,
			Constraints: inheritedConstraints(chain),
			Deprecated:  def.Deprecated,
		}
		// Category may only be set on an ancestor (subclasses inherit it).
		for i := len(chain) - 1; i >= 0 && cls.Category == ""; i-- {
			cls.Category = chain[i].Category
		}
		if cat, ok := s.Categories.Attributes[cls.Category]; ok {
			cls.CategoryUID = cat.UID
			if def.UID != nil {
				cls.ClassUID = cat.UID*1000 + *def.UID
				if def.ExtensionUID > 0 {
					cls.ClassUID += def.ExtensionUID * 100000
				}
			}
		} else if def.UID != nil {
			c.Warnings = append(c.Warnings,
				fmt.Sprintf("event class %s: unknown category %q; class_uid not computed", name, cls.Category))
		}
		c.Classes[name] = cls
	}

	c.synthesizeObservableEnum()
	sort.Strings(c.Warnings)
	return c, nil
}

// synthesizeObservableEnum rebuilds the observable object's type_id enum
// from the observable annotations scattered across the schema (dictionary
// types, dictionary attributes, objects, and object/class attributes). The
// source schema only declares the 0/Unknown and 99/Other members; the full
// enum is derived, mirroring the OCSF server's behavior.
func (c *CompiledSchema) synthesizeObservableEnum() {
	observable, ok := c.Objects["observable"]
	if !ok {
		return
	}
	typeID, ok := observable.Attributes["type_id"]
	if !ok {
		return
	}
	enum := make(map[string]EnumMember, len(typeID.Enum))
	maps.Copy(enum, typeID.Enum)
	add := func(uid int, caption string) {
		key := strconv.Itoa(uid)
		if _, exists := enum[key]; !exists && uid != 0 {
			enum[key] = EnumMember{Caption: caption}
		}
	}

	// Priority order mirrors caption quality: scalar types first, then
	// dictionary attributes, whole objects, and finally per-attribute
	// annotations qualified by their owning definition's caption.
	for _, name := range sortedKeys(c.Dictionary.Types.Attributes) {
		if t := c.Dictionary.Types.Attributes[name]; t.Observable != 0 {
			add(t.Observable, t.Caption)
		}
	}
	for _, name := range sortedKeys(c.Dictionary.Attributes) {
		if a := c.Dictionary.Attributes[name]; a != nil && a.Observable != 0 {
			add(a.Observable, a.Caption)
		}
	}
	for _, name := range sortedKeys(c.Objects) {
		obj := c.Objects[name]
		if obj.Observable != 0 {
			add(obj.Observable, obj.Caption)
		}
	}
	for _, name := range sortedKeys(c.Objects) {
		obj := c.Objects[name]
		for _, attrName := range sortedKeys(obj.Attributes) {
			if a := obj.Attributes[attrName]; a.Observable != 0 {
				add(a.Observable, obj.Caption+" "+a.Caption)
			}
		}
	}
	for _, name := range sortedKeys(c.Classes) {
		cls := c.Classes[name]
		for _, attrName := range sortedKeys(cls.Attributes) {
			if a := cls.Attributes[attrName]; a.Observable != 0 {
				add(a.Observable, cls.Caption+" "+a.Caption)
			}
		}
	}
	typeID.Enum = enum
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// extendsChain returns the definition's inheritance chain, root ancestor
// first. implicitRoot names an extends target that terminates the chain
// without a backing definition (the empty "object" root for objects).
func extendsChain(def *Definition, all map[string]*Definition, implicitRoot string) ([]*Definition, error) {
	var chain []*Definition
	seen := map[string]bool{}
	for d := def; ; {
		if seen[d.Name] {
			return nil, fmt.Errorf("extends cycle through %q", d.Name)
		}
		seen[d.Name] = true
		chain = append([]*Definition{d}, chain...)
		if d.Extends == "" || d.Extends == implicitRoot {
			return chain, nil
		}
		parent, ok := all[d.Extends]
		if !ok {
			return nil, fmt.Errorf("extends unknown definition %q", d.Extends)
		}
		d = parent
	}
}

func chainNames(chain []*Definition) []string {
	names := make([]string, len(chain))
	for i, d := range chain {
		names[i] = d.Name
	}
	return names
}

// inheritedConstraints returns the constraints of the most-derived definition
// in the chain that declares any; OCSF subclasses replace rather than merge
// parent constraints.
func inheritedConstraints(chain []*Definition) *Constraints {
	for i := len(chain) - 1; i >= 0; i-- {
		if chain[i].Constraints != nil {
			return chain[i].Constraints
		}
	}
	return nil
}

// flattenAttributes merges the attribute maps of an inheritance chain (root
// first, so subclasses override) including $include profile mixins, then
// joins every attribute against the dictionary for type information.
func (s *Schema) flattenAttributes(c *CompiledSchema, chain []*Definition) (map[string]*Attribute, error) {
	merged := map[string]*Attribute{}
	for _, def := range chain {
		source := ""
		if def != chain[len(chain)-1] {
			source = def.Name
		}
		for _, includePath := range def.Attributes.Includes {
			profile, ok := s.Profiles[includePath]
			if !ok {
				return nil, fmt.Errorf("%s: $include references unknown profile %q", def.SourcePath, includePath)
			}
			for name, attr := range profile.Attributes.Attributes {
				mergeAttribute(merged, name, attr, "profile:"+profile.Name)
			}
		}
		for name, attr := range def.Attributes.Attributes {
			mergeAttribute(merged, name, attr, source)
		}
	}

	for name, attr := range merged {
		dict, ok := s.Dictionary.Attributes[name]
		if !ok {
			c.Warnings = append(c.Warnings,
				fmt.Sprintf("%s: attribute %q not found in dictionary", chain[len(chain)-1].Name, name))
			continue
		}
		if attr.Type == "" {
			attr.Type = dict.Type
		}
		if dict.IsArray {
			attr.IsArray = true
		}
		if attr.Caption == "" {
			attr.Caption = dict.Caption
		}
		if attr.Description == "" {
			attr.Description = dict.Description
		}
		if attr.Enum == nil {
			attr.Enum = dict.Enum
		}
		if attr.Sibling == "" {
			attr.Sibling = dict.Sibling
		}
		if attr.Deprecated == nil {
			attr.Deprecated = dict.Deprecated
		}
	}
	return merged, nil
}

// mergeAttribute overlays src onto dst[name] property-by-property: non-zero
// src fields win, and a src enum replaces the existing enum wholesale.
func mergeAttribute(dst map[string]*Attribute, name string, src *Attribute, source string) {
	// An attribute that already carries provenance (an extension patch
	// stamped onto a raw definition) keeps it through flattening.
	if src.Source != "" {
		source = src.Source
	}
	cur, ok := dst[name]
	if !ok {
		cp := *src
		cp.Source = source
		dst[name] = &cp
		return
	}
	if src.Caption != "" {
		cur.Caption = src.Caption
	}
	if src.Description != "" {
		cur.Description = src.Description
	}
	if src.Type != "" {
		cur.Type = src.Type
	}
	if src.IsArray {
		cur.IsArray = true
	}
	if src.Requirement != "" {
		cur.Requirement = src.Requirement
	}
	if src.Group != "" {
		cur.Group = src.Group
	}
	if src.Observable != 0 {
		cur.Observable = src.Observable
	}
	if src.Sibling != "" {
		cur.Sibling = src.Sibling
	}
	if src.Enum != nil {
		cur.Enum = src.Enum
	}
	if src.Profile != nil {
		cur.Profile = src.Profile
	}
	if src.Deprecated != nil {
		cur.Deprecated = src.Deprecated
	}
	// A direct redeclaration takes over ownership of the attribute.
	cur.Source = source
}
