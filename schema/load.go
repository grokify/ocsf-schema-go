package schema

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// LoadOptions configures Load behavior.
type LoadOptions struct {
	// Extensions selects platform extensions under <dir>/extensions by
	// directory or declared name (e.g. "win", "windows"); the special name
	// "all" selects every extension found. Empty means none.
	Extensions []string
	// ExtensionDirs lists paths to additional extension roots located
	// outside the schema tree (each directory contains its own
	// extension.json, and optionally dictionary.json, objects/, events/,
	// and profiles/). These are always loaded.
	ExtensionDirs []string
}

// Load reads an OCSF schema source tree (a checkout of ocsf/ocsf-schema) from
// dir, without platform extensions. It parses version.json, categories.json,
// dictionary.json, and every definition file under objects/, events/, and
// profiles/.
func Load(dir string) (*Schema, error) {
	return LoadWithOptions(dir, LoadOptions{})
}

// LoadWithExtensions is Load plus the named platform extensions from the
// extensions/ directory. See LoadOptions.Extensions.
func LoadWithExtensions(dir string, extensions ...string) (*Schema, error) {
	return LoadWithOptions(dir, LoadOptions{Extensions: extensions})
}

// LoadWithOptions is Load plus platform extensions selected by opts.
//
// Extensions contribute new dictionary attributes/types, new objects and
// event classes (whose class_uid is extension_uid*100000 + category_uid*1000
// + uid), and patches: definition files with "extends" but no "name" that
// amend an existing core definition in place.
func LoadWithOptions(dir string, opts LoadOptions) (*Schema, error) {
	s := &Schema{
		Objects:    map[string]*Definition{},
		Events:     map[string]*Definition{},
		Profiles:   map[string]*Definition{},
		Extensions: map[string]*Extension{},
	}

	if err := readJSON(filepath.Join(dir, "version.json"), &s.Version); err != nil {
		return nil, fmt.Errorf("schema: reading version.json: %w", err)
	}
	if err := readJSON(filepath.Join(dir, "categories.json"), &s.Categories); err != nil {
		return nil, fmt.Errorf("schema: reading categories.json: %w", err)
	}
	for name, cat := range s.Categories.Attributes {
		cat.Name = name
		s.Categories.Attributes[name] = cat
	}
	if err := readJSON(filepath.Join(dir, "dictionary.json"), &s.Dictionary); err != nil {
		return nil, fmt.Errorf("schema: reading dictionary.json: %w", err)
	}

	var patches []*Definition
	if err := s.loadTree(dir, "", nil, &patches); err != nil {
		return nil, err
	}
	if len(patches) > 0 {
		return nil, fmt.Errorf("schema: core schema contains %d patch definitions (missing name); patches are only valid in extensions", len(patches))
	}

	var extPatches []*Definition
	if len(opts.Extensions) > 0 {
		if err := s.loadExtensions(dir, opts.Extensions, &extPatches); err != nil {
			return nil, err
		}
	}
	for _, extDir := range opts.ExtensionDirs {
		abs, err := filepath.Abs(extDir)
		if err != nil {
			return nil, fmt.Errorf("schema: resolving extension dir %s: %w", extDir, err)
		}
		// Use the parent as the tree root so SourcePaths and $include keys
		// are namespaced by the extension directory name.
		if err := s.loadExtensionRoot(filepath.Dir(abs), filepath.Base(abs), &extPatches); err != nil {
			return nil, err
		}
	}
	for _, patch := range extPatches {
		if err := s.applyPatch(patch); err != nil {
			return nil, err
		}
	}

	return s, nil
}

// loadTree loads objects/, events/, and profiles/ under root+sub, tagging
// definitions with ext when loading an extension tree. Nameless patch
// definitions are appended to patches.
func (s *Schema) loadTree(root, sub string, ext *Extension, patches *[]*Definition) error {
	base := root
	if sub != "" {
		base = filepath.Join(root, sub)
	}

	add := func(target map[string]*Definition, kind string) func(*Definition) error {
		return func(def *Definition) error {
			if ext != nil {
				def.Extension = ext.Name
				def.ExtensionUID = ext.UID
				rewriteIncludes(def, root, sub)
			}
			if def.Name == "" {
				if def.Extends == "" {
					return fmt.Errorf("schema: %s: definition has neither name nor extends", def.SourcePath)
				}
				*patches = append(*patches, def)
				return nil
			}
			if other, ok := target[def.Name]; ok {
				return fmt.Errorf("schema: duplicate %s name %q in %s and %s", kind, def.Name, other.SourcePath, def.SourcePath)
			}
			target[def.Name] = def
			return nil
		}
	}

	if err := loadDefinitions(root, base, "objects", add(s.Objects, "object")); err != nil {
		return err
	}
	if err := loadDefinitions(root, base, "events", add(s.Events, "event class")); err != nil {
		return err
	}
	// Profiles are keyed by repo-relative path because that is how $include
	// directives reference them.
	return loadDefinitions(root, base, "profiles", func(def *Definition) error {
		if ext != nil {
			def.Extension = ext.Name
			def.ExtensionUID = ext.UID
			rewriteIncludes(def, root, sub)
		}
		s.Profiles[def.SourcePath] = def
		return nil
	})
}

// rewriteIncludes qualifies $include paths written relative to an extension
// root (e.g. "profiles/linux_users.json" inside extensions/linux/) to their
// repo-relative form, leaving references to core profiles untouched.
func rewriteIncludes(def *Definition, root, sub string) {
	for i, inc := range def.Attributes.Includes {
		qualified := filepath.ToSlash(filepath.Join(sub, inc))
		if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(qualified))); err == nil {
			def.Attributes.Includes[i] = qualified
		}
	}
}

// loadExtensions loads the selected platform extensions from
// <dir>/extensions, collecting their patch definitions into patches.
func (s *Schema) loadExtensions(dir string, names []string, patches *[]*Definition) error {
	all := false
	selected := map[string]bool{}
	for _, n := range names {
		if n == "all" {
			all = true
			continue
		}
		selected[n] = true
	}

	extRoot := filepath.Join(dir, "extensions")
	entries, err := os.ReadDir(extRoot)
	if err != nil {
		if os.IsNotExist(err) && !all && len(selected) == 0 {
			return nil
		}
		return fmt.Errorf("schema: reading extensions directory: %w", err)
	}

	found := map[string]bool{}
	// Sort for deterministic patch application order.
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		extFile := filepath.Join(extRoot, e.Name(), "extension.json")
		if _, err := os.Stat(extFile); os.IsNotExist(err) {
			continue
		}
		if !all && !selected[e.Name()] {
			// Peek at the declared name before skipping.
			ext := &Extension{}
			if err := readJSON(extFile, ext); err != nil {
				return fmt.Errorf("schema: reading %s: %w", extFile, err)
			}
			if !selected[ext.Name] {
				continue
			}
		}
		if err := s.loadExtensionRoot(dir, filepath.Join("extensions", e.Name()), patches); err != nil {
			return err
		}
		found[e.Name()] = true
	}

	for name := range selected {
		if found[name] {
			continue
		}
		if _, ok := s.Extensions[name]; !ok {
			return fmt.Errorf("schema: extension %q not found under %s", name, extRoot)
		}
	}
	return nil
}

// loadExtensionRoot loads one extension tree rooted at <root>/<sub>
// (containing extension.json), merging its dictionary and definitions.
func (s *Schema) loadExtensionRoot(root, sub string, patches *[]*Definition) error {
	base := filepath.Join(root, sub)
	ext := &Extension{}
	if err := readJSON(filepath.Join(base, "extension.json"), ext); err != nil {
		return fmt.Errorf("schema: reading %s: %w", filepath.Join(base, "extension.json"), err)
	}
	if other, ok := s.Extensions[ext.Name]; ok && other.UID != ext.UID {
		return fmt.Errorf("schema: duplicate extension name %q with different uids (%d and %d)", ext.Name, other.UID, ext.UID)
	}
	if err := s.mergeExtensionDictionary(filepath.Join(base, "dictionary.json"), ext); err != nil {
		return err
	}
	if err := s.loadTree(root, sub, ext, patches); err != nil {
		return err
	}
	s.Extensions[ext.Name] = ext
	return nil
}

// mergeExtensionDictionary merges an extension's dictionary.json (if any)
// into the core dictionary. Extensions may only add attributes and types;
// redefining a core entry is an error.
func (s *Schema) mergeExtensionDictionary(path string, ext *Extension) error {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil
	}
	extDict := Dictionary{}
	if err := readJSON(path, &extDict); err != nil {
		return fmt.Errorf("schema: reading %s: %w", path, err)
	}
	for name, attr := range extDict.Attributes {
		if _, ok := s.Dictionary.Attributes[name]; ok {
			return fmt.Errorf("schema: extension %s redefines dictionary attribute %q", ext.Name, name)
		}
		s.Dictionary.Attributes[name] = attr
	}
	for name, typ := range extDict.Types.Attributes {
		if _, ok := s.Dictionary.Types.Attributes[name]; ok {
			return fmt.Errorf("schema: extension %s redefines dictionary type %q", ext.Name, name)
		}
		if s.Dictionary.Types.Attributes == nil {
			s.Dictionary.Types.Attributes = map[string]DictionaryType{}
		}
		s.Dictionary.Types.Attributes[name] = typ
	}
	return nil
}

// applyPatch amends the definition named by patch.Extends: attributes are
// overlaid property-by-property, $include lists are appended, and constraints
// are replaced when the patch declares any.
func (s *Schema) applyPatch(patch *Definition) error {
	target, ok := s.Objects[patch.Extends]
	if !ok {
		if target, ok = s.Events[patch.Extends]; !ok {
			return fmt.Errorf("schema: %s: patch extends unknown definition %q", patch.SourcePath, patch.Extends)
		}
	}
	if target.Attributes.Attributes == nil {
		target.Attributes.Attributes = map[string]*Attribute{}
	}
	source := "extension:" + patch.Extension
	for name, attr := range patch.Attributes.Attributes {
		mergeAttribute(target.Attributes.Attributes, name, attr, source)
	}
	target.Attributes.Includes = append(target.Attributes.Includes, patch.Attributes.Includes...)
	if patch.Constraints != nil {
		target.Constraints = patch.Constraints
	}
	if patch.Observable != 0 {
		target.Observable = patch.Observable
	}
	return nil
}

func loadDefinitions(root, base, sub string, add func(*Definition) error) error {
	start := filepath.Join(base, sub)
	if _, err := os.Stat(start); os.IsNotExist(err) {
		return nil
	}
	return filepath.WalkDir(start, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(d.Name(), ".json") {
			return nil
		}
		def := &Definition{}
		if err := readJSON(path, def); err != nil {
			return fmt.Errorf("schema: reading %s: %w", path, err)
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		def.SourcePath = filepath.ToSlash(rel)
		return add(def)
	})
}

func readJSON(path string, v any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(data, v); err != nil {
		return fmt.Errorf("%s: %w", filepath.Base(path), err)
	}
	return nil
}
