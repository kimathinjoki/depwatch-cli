// Package schema embeds the committed JSON schemas, so the CLI validates against exactly the files
// the server and the docs read.
package schema

import _ "embed"

// Inventory is schema/inventory.schema.json.
//
//go:embed inventory.schema.json
var Inventory []byte

// Config is schema/watchdep.schema.json.
//
//go:embed watchdep.schema.json
var Config []byte
