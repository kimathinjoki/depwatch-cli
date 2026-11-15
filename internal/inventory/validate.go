package inventory

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sync"

	"github.com/kimathinjoki/watchdep-cli/schema"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

var (
	compiled    *jsonschema.Schema
	compileErr  error
	compileOnce sync.Once
)

func compiledSchema() (*jsonschema.Schema, error) {
	compileOnce.Do(func() {
		doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(schema.Inventory))
		if err != nil {
			compileErr = err
			return
		}
		c := jsonschema.NewCompiler()
		c.AssertFormat()
		if err := c.AddResource("inventory.schema.json", doc); err != nil {
			compileErr = err
			return
		}
		compiled, compileErr = c.Compile("inventory.schema.json")
	})
	return compiled, compileErr
}

// Validate checks the inventory against the committed schema.
func (inv *Inventory) Validate() error {
	s, err := compiledSchema()
	if err != nil {
		return fmt.Errorf("compiling inventory schema: %w", err)
	}
	var buf bytes.Buffer
	if err := inv.Write(&buf); err != nil {
		return err
	}
	doc, err := jsonschema.UnmarshalJSON(&buf)
	if err != nil {
		return err
	}
	return s.Validate(doc)
}

// ValidateJSON checks raw JSON against the committed schema.
func ValidateJSON(raw []byte) error {
	s, err := compiledSchema()
	if err != nil {
		return err
	}
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return err
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		return err
	}
	return s.Validate(doc)
}
