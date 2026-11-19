package jobbox

import (
	"sort"
	"strings"
)

// sysVars 是从探针环境里原样带给任务的系统变量（名字不分大小写），其余一概不带。
var sysVars = []string{"SystemRoot", "windir", "NUMBER_OF_PROCESSORS", "OS", "PATHEXT",
	"PROCESSOR_ARCHITECTURE", "PROCESSOR_IDENTIFIER", "PROCESSOR_LEVEL", "PROCESSOR_REVISION"}

// HomeDirs 是 tmp\ 下要先建好的目录（USERPROFILE、APPDATA、LOCALAPPDATA 和缓存）。
var HomeDirs = []string{`home\AppData\Roaming`, `home\AppData\Local`, `cache`}

func winJoin(a, b string) string { return strings.TrimRight(a, `\/`) + `\` + b }

// JobEnv 从零拼任务进程的环境块，不继承探针的（探针的环境里有 EPS_KEY、管理员的 PATH 和 APPDATA）。
// sys 是探针自己的环境，只从里面取 sysVars。结果按名字排序（不分大小写），CreateProcess 要求这样。
func JobEnv(jobDir, envDir string, sys []string) []string {
	got := map[string]string{}
	for _, kv := range sys {
		k, v, ok := strings.Cut(kv, "=")
		if !ok {
			continue
		}
		for _, name := range sysVars {
			if strings.EqualFold(k, name) {
				got[name] = v
			}
		}
	}
	if got["SystemRoot"] == "" {
		got["SystemRoot"] = `C:\Windows`
	}
	if got["windir"] == "" {
		got["windir"] = got["SystemRoot"]
	}
	tmp := winJoin(jobDir, "tmp")
	home := winJoin(tmp, "home")
	cache := winJoin(tmp, "cache")
	for k, v := range map[string]string{
		"PATH": envDir + ";" + winJoin(got["SystemRoot"], "System32"),
		"TMP":  tmp, "TEMP": tmp, "TMPDIR": tmp,
		"USERPROFILE": home, "APPDATA": winJoin(home, `AppData\Roaming`), "LOCALAPPDATA": winJoin(home, `AppData\Local`),
		"XDG_CACHE_HOME": cache, "CUDA_CACHE_PATH": winJoin(cache, "nv"), "TORCH_HOME": winJoin(cache, "torch"),
		"HF_HOME": winJoin(cache, "hf"), "MPLCONFIGDIR": winJoin(cache, "mpl"),
		"HF_HUB_OFFLINE": "1", "TRANSFORMERS_OFFLINE": "1", "PYTHONDONTWRITEBYTECODE": "1",
		"EPSILON_JOB_DIR": jobDir,
	} {
		got[k] = v
	}
	keys := make([]string, 0, len(got))
	for k := range got {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return strings.ToUpper(keys[i]) < strings.ToUpper(keys[j]) })
	env := make([]string, len(keys))
	for i, k := range keys {
		env[i] = k + "=" + got[k]
	}
	return env
}
