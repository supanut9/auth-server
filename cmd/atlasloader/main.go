package main

import (
	"fmt"
	"io"
	"os"

	"ariga.io/atlas-provider-gorm/gormschema"
	"github.com/supanut9/auth-server/internal/adapter/out/persistence/schema"
)

func main() {
	stmts, err := gormschema.New("postgres").Load(schema.Models...)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to load gorm schema: %v\n", err)
		os.Exit(1)
	}

	if _, err := io.WriteString(os.Stdout, stmts); err != nil {
		fmt.Fprintf(os.Stderr, "failed to write gorm schema: %v\n", err)
		os.Exit(1)
	}
}
