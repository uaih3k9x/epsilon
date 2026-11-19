//go:build windows

package jobbox

import (
	"syscall"
	"testing"
)

func TestEscapeArgMatchesSyscall(t *testing.T) {
	for _, s := range []string{"", `a`, `a b`, `a"b`, `a b\`, `C:\x y\z\`, `{"k":"v w"}`, "t\tx", `\\"`} {
		if escapeArg(s) != syscall.EscapeArg(s) {
			t.Fatalf("%q: %s != %s", s, escapeArg(s), syscall.EscapeArg(s))
		}
	}
}
