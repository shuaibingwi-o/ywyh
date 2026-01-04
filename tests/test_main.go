// Small test runner used during development to exercise packages in this
// repository. This file is a convenience helper and not part of the core API.
package main

import (
	"flag"
	"fmt"
)

func main() {
	mode := flag.String("mode", "run", "mode: run|version")
	flag.Parse()

	if *mode == "version" {
		fmt.Println("ywyh PCE version 0.1.0")
		return
	}

	fmt.Println("Starting ywyh PCE (from tests/test_main.go)...")
	fmt.Println("No PCE implementation present; this is a placeholder main.")
}
