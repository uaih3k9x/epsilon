package jobsign

import (
	"encoding/json"
	"strings"
	"testing"
)

func decl(t *testing.T, s string) map[string]json.RawMessage {
	t.Helper()
	var m map[string]json.RawMessage
	if err := json.Unmarshal([]byte(s), &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestFillParamsOK(t *testing.T) {
	d := decl(t, `{
		"lr": {"type": "number", "min": 1e-5, "max": 1.0, "default": 0.1},
		"epochs": "int",
		"subset": {"type": "string", "enum": ["tiny", "full"], "default": "full"},
		"fast": "bool",
		"seed": {"type": "int", "min": 0, "max": 999}
	}`)
	got, err := FillParams(d, decl(t, `{"epochs": 3, "seed": 7, "fast": true}`))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(got)
	want := `{"epochs":3,"fast":true,"lr":0.1,"seed":7,"subset":"full"}`
	if string(b) != want {
		t.Fatalf("got %s want %s", b, want)
	}
	// 再过一遍不变（探针拿主控填好的再核一次）
	again, err := FillParams(d, got)
	if err != nil {
		t.Fatal(err)
	}
	if b2, _ := json.Marshal(again); string(b2) != want {
		t.Fatalf("不是幂等的: %s", b2)
	}
}

func TestFillParamsRejects(t *testing.T) {
	d := decl(t, `{
		"lr": {"type": "number", "min": 0, "max": 1},
		"epochs": "int",
		"subset": {"type": "string", "enum": ["tiny", "full"]},
		"fast": "bool"
	}`)
	cases := map[string]string{
		"不认识的参数":    `{"cmd": "rm -rf"}`,
		"int 给小数":   `{"epochs": 1.5}`,
		"int 给字符串":  `{"epochs": "3"}`,
		"number 越界": `{"lr": 2}`,
		"number 低于": `{"lr": -0.1}`,
		"不在 enum":   `{"subset": "huge"}`,
		"bool 给数字":  `{"fast": 1}`,
		"string 给数": `{"subset": 3}`,
		"null":      `{"epochs": null}`,
	}
	for name, v := range cases {
		if _, err := FillParams(d, decl(t, v)); err == nil {
			t.Errorf("%s: 应该拒", name)
		}
	}
}

func TestFillParamsBadDecl(t *testing.T) {
	for _, s := range []string{`{"x": "float"}`, `{"x": {"type": "list"}}`, `{"x": 3}`,
		`{"x": {"type": "int", "default": "a"}}`, `{"x": {"type": "string", "enum": [1]}}`} {
		if _, err := FillParams(decl(t, s), nil); err == nil {
			t.Errorf("%s: 声明不合法应该报错", s)
		}
	}
}

func TestFillParamsNoDecl(t *testing.T) {
	got, err := FillParams(nil, nil)
	if err != nil || len(got) != 0 {
		t.Fatalf("没声明没填应该是空: %v %v", got, err)
	}
	if _, err := FillParams(nil, decl(t, `{"a": 1}`)); err == nil || !strings.Contains(err.Error(), "a") {
		t.Fatalf("没声明却填了要拒: %v", err)
	}
}
