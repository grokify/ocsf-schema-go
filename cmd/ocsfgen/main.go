// Command ocsfgen generates Go bindings from an OCSF schema source tree
// (a checkout of https://github.com/ocsf/ocsf-schema).
package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/grokify/ocsf-schema-go/gen"
	"github.com/grokify/ocsf-schema-go/schema"
)

func main() {
	if err := rootCmd().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "ocsfgen:", err)
		os.Exit(1)
	}
}

func rootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:           "ocsfgen",
		Short:         "Generate Go bindings from an OCSF schema source tree",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.AddCommand(generateCmd())
	return root
}

func generateCmd() *cobra.Command {
	var schemaDir, outDir, objectsImportPath string
	var extensions, extensionDirs []string

	cmd := &cobra.Command{
		Use:   "generate",
		Short: "Compile the schema and write generated Go packages",
		RunE: func(cmd *cobra.Command, args []string) error {
			opts := schema.LoadOptions{}
			for _, n := range extensions {
				if n != "" {
					opts.Extensions = append(opts.Extensions, n)
				}
			}
			for _, d := range extensionDirs {
				if d != "" {
					opts.ExtensionDirs = append(opts.ExtensionDirs, d)
				}
			}
			s, err := schema.LoadWithOptions(schemaDir, opts)
			if err != nil {
				return err
			}
			c, err := s.Compile()
			if err != nil {
				return err
			}
			for _, w := range c.Warnings {
				cmd.PrintErrln("warning:", w)
			}

			files, err := gen.Generate(c, gen.Options{ObjectsImportPath: objectsImportPath})
			if err != nil {
				return err
			}

			paths := make([]string, 0, len(files))
			for rel := range files {
				paths = append(paths, rel)
			}
			for _, rel := range paths {
				path := filepath.Join(outDir, filepath.FromSlash(rel))
				if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
					return err
				}
				if err := os.WriteFile(path, files[rel], 0o644); err != nil {
					return err
				}
				cmd.Println("wrote", path)
			}
			cmd.Printf("generated %d files from OCSF schema v%s\n", len(files), c.Version)
			return nil
		},
	}

	cmd.Flags().StringVar(&schemaDir, "schema-dir", "", "path to an ocsf/ocsf-schema checkout (required)")
	cmd.Flags().StringSliceVar(&extensions, "extensions", []string{"all"},
		`platform extensions to include ("all", extension names like "win", or empty for none)`)
	cmd.Flags().StringSliceVar(&extensionDirs, "extension-dirs", nil,
		"paths to additional extension roots outside the schema tree (each containing extension.json)")
	cmd.Flags().StringVar(&outDir, "out", "ocsf", "output directory for the generated objects/ and events/ packages")
	cmd.Flags().StringVar(&objectsImportPath, "objects-import-path",
		"github.com/grokify/ocsf-schema-go/ocsf/objects",
		"import path the generated events package uses to reference the objects package")
	if err := cmd.MarkFlagRequired("schema-dir"); err != nil {
		panic(err) // programming error: flag name must exist
	}
	return cmd
}
