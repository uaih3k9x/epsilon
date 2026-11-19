//go:build !windows

package main

import (
	"fmt"
	"os"
)

func runLimited(limitedOpts) int {
	fmt.Fprintln(os.Stderr, "limited: Windows only")
	return 2
}
