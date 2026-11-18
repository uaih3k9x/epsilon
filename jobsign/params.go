package jobsign

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"strconv"
)

// paramSpec 是 job.json params 里一项的声明（手册 5.4）：简写 "int"，或 {"type","min","max","enum","default"}。
type paramSpec struct {
	Type    string            `json:"type"`
	Min     *float64          `json:"min,omitempty"`
	Max     *float64          `json:"max,omitempty"`
	Enum    []json.RawMessage `json:"enum,omitempty"`
	Default json.RawMessage   `json:"default,omitempty"`
}

var paramTypes = map[string]bool{"int": true, "number": true, "string": true, "bool": true}

func parseSpec(name string, raw json.RawMessage) (paramSpec, error) {
	var s paramSpec
	var short string
	if json.Unmarshal(raw, &short) == nil {
		s.Type = short
	} else if err := json.Unmarshal(raw, &s); err != nil {
		return s, fmt.Errorf("参数 %s 的声明看不懂", name)
	}
	if !paramTypes[s.Type] {
		return s, fmt.Errorf("参数 %s 的类型 %q 不认识（只有 int / number / string / bool）", name, s.Type)
	}
	for _, e := range s.Enum {
		if _, err := s.check(name, e); err != nil {
			return s, fmt.Errorf("参数 %s 的 enum 不合法: %v", name, err)
		}
	}
	if len(s.Default) > 0 {
		if _, err := s.check(name, s.Default); err != nil {
			return s, fmt.Errorf("参数 %s 的 default 不合法: %v", name, err)
		}
	}
	return s, nil
}

// check 校验一个值，返回规范化后的 JSON。不查 enum（enum 本身也要过 check）。
func (s paramSpec) check(name string, v json.RawMessage) (json.RawMessage, error) {
	v = bytes.TrimSpace(v)
	switch s.Type {
	case "string":
		var x string
		if err := json.Unmarshal(v, &x); err != nil || v[0] != '"' {
			return nil, fmt.Errorf("参数 %s 要是字符串", name)
		}
		b, _ := json.Marshal(x)
		return b, nil
	case "bool":
		var x bool
		if err := json.Unmarshal(v, &x); err != nil || v[0] == '"' {
			return nil, fmt.Errorf("参数 %s 要是 true / false", name)
		}
		return json.RawMessage(strconv.FormatBool(x)), nil
	}
	if len(v) == 0 || !(v[0] == '-' || v[0] >= '0' && v[0] <= '9') { // 只认 JSON 数字，"3"、null 都不行
		return nil, fmt.Errorf("参数 %s 要是数字", name)
	}
	f, err := strconv.ParseFloat(string(v), 64)
	if err != nil || math.IsInf(f, 0) || math.IsNaN(f) {
		return nil, fmt.Errorf("参数 %s 要是数字", name)
	}
	if s.Type == "int" && (f != math.Trunc(f) || math.Abs(f) > 1<<53) {
		return nil, fmt.Errorf("参数 %s 要是整数", name)
	}
	if s.Min != nil && f < *s.Min || s.Max != nil && f > *s.Max {
		return nil, fmt.Errorf("参数 %s = %v 超出声明的范围", name, f)
	}
	if s.Type == "int" {
		return json.RawMessage(strconv.FormatInt(int64(f), 10)), nil
	}
	return json.RawMessage(strconv.FormatFloat(f, 'g', -1, 64)), nil
}

// FillParams 按任务包里的 params 声明校验主控填的参数值、补上声明了 default 的，返回规范化后的值（写成 params.json）。
// 不认识的参数、类型不对、越界、不在 enum 里都拒。主控提交时调一次；探针不信主控，拿到后再调一次（幂等）。
// 没填又没 default 的参数不出现在结果里，由脚本自己按默认处理。
func FillParams(decl, values map[string]json.RawMessage) (map[string]json.RawMessage, error) {
	specs := map[string]paramSpec{}
	for name, raw := range decl {
		s, err := parseSpec(name, raw)
		if err != nil {
			return nil, err
		}
		specs[name] = s
	}
	out := map[string]json.RawMessage{}
	for name, v := range values {
		s, ok := specs[name]
		if !ok {
			return nil, fmt.Errorf("任务包没有声明参数 %s", name)
		}
		c, err := s.check(name, v)
		if err != nil {
			return nil, err
		}
		if len(s.Enum) > 0 {
			in := false
			for _, e := range s.Enum {
				ce, _ := s.check(name, e)
				in = in || bytes.Equal(ce, c)
			}
			if !in {
				return nil, fmt.Errorf("参数 %s = %s 不在声明的 enum 里", name, c)
			}
		}
		out[name] = c
	}
	for name, s := range specs {
		if _, ok := out[name]; !ok && len(s.Default) > 0 {
			c, _ := s.check(name, s.Default)
			out[name] = c
		}
	}
	return out, nil
}
