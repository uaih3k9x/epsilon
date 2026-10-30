package probe

import (
	"encoding/json"
	"reflect"
	"testing"
)

// 模拟 Windows WDDM 下的 nvidia-smi：桌面进程（C+G）、浏览器、真计算程序、自己的 llama-server。
const wddmApps = "100, C:\\Windows\\explorer.exe, [N/A]\n" +
	"101, C:\\Windows\\System32\\dwm.exe, [N/A]\n" +
	"102, C:\\Windows\\SystemApps\\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\\SearchHost.exe, [N/A]\n" +
	"103, C:\\Windows\\SystemApps\\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\\StartMenuExperienceHost.exe, [N/A]\n" +
	"104, C:\\Windows\\SystemApps\\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\\TextInputHost.exe, [N/A]\n" +
	"105, C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\MSEDGE.EXE, [N/A]\n" +
	"200, C:\\Users\\学生\\miniconda3\\python.exe, [N/A]\n" +
	"201, C:\\Program Files\\Blender Foundation\\Blender 4.2\\blender.exe, 1500\n" +
	"1234, C:\\epsilon\\llama-server.exe, [N/A]\n"

func TestForeignAppsIgnoresDesktopAndBrowsers(t *testing.T) {
	got := ForeignApps(wddmApps, 1234)
	if want := []string{"python.exe", "blender.exe"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

func TestForeignAppsExtraIgnore(t *testing.T) {
	got := ForeignApps(wddmApps, 1234, "Blender.EXE")
	if want := []string{"python.exe"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

func TestConfigGPUIgnore(t *testing.T) {
	var c Config
	if err := json.Unmarshal([]byte(`{"gpu_ignore":["obs64.exe"]}`), &c); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(c.GPUIgnore, []string{"obs64.exe"}) {
		t.Fatalf("got %v", c.GPUIgnore)
	}
}
