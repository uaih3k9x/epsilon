package jobbox

import (
	"sort"
	"strings"
	"testing"
)

func envMap(env []string) map[string]string {
	m := map[string]string{}
	for _, kv := range env {
		k, v, _ := strings.Cut(kv, "=")
		m[k] = v
	}
	return m
}

var probeEnv = []string{
	`SystemRoot=C:\Windows`, `windir=C:\Windows`, "NUMBER_OF_PROCESSORS=16", "PROCESSOR_ARCHITECTURE=AMD64",
	"PROCESSOR_IDENTIFIER=Intel64", "OS=Windows_NT", "PATHEXT=.COM;.EXE",
	`USERPROFILE=C:\Users\Administrator`, `APPDATA=C:\Users\Administrator\AppData\Roaming`,
	`PATH=C:\Windows\system32;C:\Program Files\Git\cmd`, "EPS_KEY=sk-secret", `PYTHONPATH=C:\evil`,
	"COMPUTERNAME=PC-01", `TEMP=C:\Users\ADMINI~1\AppData\Local\Temp`,
}

func TestJobEnvStartsFromScratch(t *testing.T) {
	env := envMap(JobEnv(`D:\epsilon\jobs\demo-1`, `D:\epsilon\envs\smoke@2`, probeEnv))
	for _, k := range []string{"EPS_KEY", "PYTHONPATH", "COMPUTERNAME"} {
		if _, ok := env[k]; ok {
			t.Fatalf("%s 不能从探针的环境带过去", k)
		}
	}
	for _, k := range []string{"SystemRoot", "windir", "NUMBER_OF_PROCESSORS", "PROCESSOR_ARCHITECTURE", "PROCESSOR_IDENTIFIER", "OS", "PATHEXT"} {
		if env[k] == "" {
			t.Fatalf("系统变量 %s 要带上: %v", k, env)
		}
	}
}

func TestJobEnvPointsEverythingIntoTmp(t *testing.T) {
	dir := `D:\epsilon\jobs\demo-1`
	env := envMap(JobEnv(dir, `D:\epsilon\envs\smoke@2`, probeEnv))
	tmp := dir + `\tmp`
	want := map[string]string{
		"TMP": tmp, "TEMP": tmp, "TMPDIR": tmp,
		"USERPROFILE": tmp + `\home`, "APPDATA": tmp + `\home\AppData\Roaming`, "LOCALAPPDATA": tmp + `\home\AppData\Local`,
		"XDG_CACHE_HOME": tmp + `\cache`, "CUDA_CACHE_PATH": tmp + `\cache\nv`, "TORCH_HOME": tmp + `\cache\torch`,
		"HF_HOME": tmp + `\cache\hf`, "MPLCONFIGDIR": tmp + `\cache\mpl`,
		"HF_HUB_OFFLINE": "1", "TRANSFORMERS_OFFLINE": "1",
		"EPSILON_JOB_DIR": dir,
		"PATH":            `D:\epsilon\envs\smoke@2;C:\Windows\System32`,
	}
	for k, v := range want {
		if env[k] != v {
			t.Fatalf("%s = %q，要的是 %q", k, env[k], v)
		}
	}
}

func TestJobEnvIsSortedAndCaseInsensitive(t *testing.T) {
	// 探针的环境里变量名大小写可能不一样（Windows 不分）
	env := JobEnv(`D:\j`, `D:\e`, []string{`SYSTEMROOT=C:\Win`, "Path=x"})
	m := envMap(env)
	if m["SystemRoot"] != `C:\Win` || m["PATH"] != `D:\e;C:\Win\System32` {
		t.Fatalf("%v", m)
	}
	keys := make([]string, len(env))
	for i, kv := range env {
		keys[i], _, _ = strings.Cut(kv, "=")
	}
	if !sort.SliceIsSorted(keys, func(i, j int) bool { return strings.ToUpper(keys[i]) < strings.ToUpper(keys[j]) }) {
		t.Fatalf("环境块要按名字排序（不分大小写）: %v", keys)
	}
	seen := map[string]bool{}
	for _, k := range keys {
		if seen[strings.ToUpper(k)] {
			t.Fatalf("重复的 %s", k)
		}
		seen[strings.ToUpper(k)] = true
	}
}

func TestJobEnvDefaultsSystemRoot(t *testing.T) {
	m := envMap(JobEnv(`D:\j`, `D:\e`, nil))
	if m["SystemRoot"] != `C:\Windows` || !strings.HasSuffix(m["PATH"], `;C:\Windows\System32`) {
		t.Fatalf("%v", m)
	}
}

func TestHomeDirsUnderTmp(t *testing.T) {
	for _, d := range HomeDirs {
		if strings.Contains(d, "..") || strings.HasPrefix(d, `\`) {
			t.Fatal(d)
		}
	}
}
