// SPDX-License-Identifier: http://www.apache.org/licenses/LICENSE-2.0
/*
 *
 * Copyright (C) 2026 , Inc.
 *
 * Authors:
 *
 */

// Package spf provides small helpers for file I/O used by the LSDB.
package spf

import (
	"encoding/json"
	"os"
	"path/filepath"
)

// SaveJSON writes the JSON encoding of v to the named file, creating
// parent directories if they don't exist.
func SaveJSON(filename string, v interface{}) error {
	dir := filepath.Dir(filename)
	if dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return err
		}
	}
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filename, b, 0644)
}

// LoadJSON reads the JSON-encoded file and decodes it into v.
func LoadJSON(filename string, v interface{}) error {
	b, err := os.ReadFile(filename)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}
