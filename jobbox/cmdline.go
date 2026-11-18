package jobbox

import (
	"fmt"
	"strings"
	"unicode/utf16"

	"epsilon/jobrun"
)

// MaxCmdLine 是 CreateProcessWithLogonW 的 lpCommandLine 上限（MSDN：最多 1024 个字符），留一个给结尾的 NUL。
const MaxCmdLine = 1023

// CmdLine 按 Windows 的规则拼命令行（转义和 syscall.EscapeArg 一样）。纯函数：Mac 上也能测长度。
func CmdLine(path string, args []string) string {
	parts := []string{escapeArg(path)}
	for _, a := range args {
		parts = append(parts, escapeArg(a))
	}
	return strings.Join(parts, " ")
}

// cmdLen 按 UTF-16 算长度（Windows 的"字符"）。
func cmdLen(s string) int { return len(utf16.Encode([]rune(s))) }

// escapeArg 是 syscall.EscapeArg（只在 Windows 构建里有）的照抄。
func escapeArg(s string) string {
	if s == "" {
		return `""`
	}
	needsBackslash, hasSpace := false, false
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '"', '\\':
			needsBackslash = true
		case ' ', '\t':
			hasSpace = true
		}
	}
	if !needsBackslash && !hasSpace {
		return s
	}
	if !needsBackslash {
		return `"` + s + `"`
	}
	var b []byte
	if hasSpace {
		b = append(b, '"')
	}
	slashes := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch c {
		default:
			slashes = 0
		case '\\':
			slashes++
		case '"':
			for ; slashes > 0; slashes-- {
				b = append(b, '\\')
			}
			b = append(b, '\\')
		}
		b = append(b, c)
	}
	if hasSpace {
		for ; slashes > 0; slashes-- {
			b = append(b, '\\')
		}
		b = append(b, '"')
	}
	return string(b)
}

// checkCmdLine：超长的命令行是这个任务（入口参数太多）的问题，不交给系统。
func checkCmdLine(l jobrun.Launch) error {
	if n := cmdLen(CmdLine(l.Path, l.Args)); n > MaxCmdLine {
		return fmt.Errorf("命令行 %d 个字符，超过 CreateProcessWithLogonW 的上限 %d", n, MaxCmdLine)
	}
	return nil
}

// limitStarter 在交给系统之前查命令行长度。
type limitStarter struct{ p Platform }

func (s limitStarter) Start(l jobrun.Launch) (jobrun.Proc, error) {
	if err := checkCmdLine(l); err != nil {
		return nil, err
	}
	return s.p.Start(l)
}
