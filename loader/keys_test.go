package loader

import (
	"go/ast"
	"go/parser"
	"go/token"
	"reflect"
	"strconv"
	"testing"
)

// listIn 从源码里取名为 name 的 []string 变量的字面值。
func listIn(t *testing.T, path, name string) []string {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	found := false
	ast.Inspect(f, func(n ast.Node) bool {
		vs, ok := n.(*ast.ValueSpec)
		if !ok || len(vs.Names) != 1 || vs.Names[0].Name != name || len(vs.Values) != 1 {
			return true
		}
		found = true
		for _, el := range vs.Values[0].(*ast.CompositeLit).Elts {
			s, err := strconv.Unquote(el.(*ast.BasicLit).Value)
			if err != nil {
				t.Fatal(err)
			}
			out = append(out, s)
		}
		return false
	})
	if !found {
		t.Fatalf("%s 里没有 %s", path, name)
	}
	return out
}

// 公钥有两份（boot 的 main 包没法 import）：两边必须一样，防止只改一边。
func TestKeysMatchBoot(t *testing.T) {
	bootKeys := listIn(t, "../cmd/epsilon-boot/keys.go", "publicKeys")
	ours := listIn(t, "keys.go", "PublicKeys")
	if len(ours) == 0 || !reflect.DeepEqual(bootKeys, ours) {
		t.Fatalf("公钥两份不一致:\nboot   %q\nloader %q", bootKeys, ours)
	}
	if !reflect.DeepEqual(ours, PublicKeys) {
		t.Fatal("解析源码和运行时不一致")
	}
	keys, err := ParseKeys(PublicKeys)
	if err != nil || len(keys) != len(PublicKeys) {
		t.Fatalf("ParseKeys: %v", err)
	}
}

func TestParseKeysBad(t *testing.T) {
	if _, err := ParseKeys([]string{"不是 base64"}); err == nil {
		t.Fatal("坏公钥应该报错")
	}
	if _, err := ParseKeys([]string{"AAAA"}); err == nil {
		t.Fatal("长度不对应该报错")
	}
}
