package jobbox

import (
	"strings"
	"testing"
	"unicode/utf16"
)

func TestParseSecret(t *testing.T) {
	ok := `{"version":1,"user":"epsilon-job","sid":"S-1-5-21-1-2-3-1001","password_dpapi":"AQID"}`
	s, blob, err := ParseSecret([]byte(ok))
	if err != nil || s.SID != "S-1-5-21-1-2-3-1001" || string(blob) != "\x01\x02\x03" {
		t.Fatalf("%+v %v %v", s, blob, err)
	}
	// PowerShell 5.1 的 UTF8 带 BOM
	if _, _, err := ParseSecret(append([]byte("\xef\xbb\xbf"), ok...)); err != nil {
		t.Fatal(err)
	}
	for name, bad := range map[string]string{
		"版本":   strings.Replace(ok, `"version":1`, `"version":2`, 1),
		"账户名":  strings.Replace(ok, `"epsilon-job"`, `"Administrator"`, 1),
		"SID":  strings.Replace(ok, `S-1-5-21-1-2-3-1001`, `S-1-5-21-1)(A;;FA;;;WD`, 1),
		"密文":   strings.Replace(ok, `"AQID"`, `"!!"`, 1),
		"空密文":  strings.Replace(ok, `"AQID"`, `""`, 1),
		"不是对象": `[]`,
	} {
		if _, _, err := ParseSecret([]byte(bad)); err == nil {
			t.Errorf("%s 不对要报错", name)
		}
	}
}

func TestPipeAndDesktopSDs(t *testing.T) {
	p := PipeSD(probeSID, jobSID)
	// 任务账户读写，但没有 FILE_CREATE_PIPE_INSTANCE（0x4）：抢注不了实例；Low 标签让 Low IL 进程能写
	if p != "D:P(A;;0x12019b;;;"+jobSID+")(A;;FA;;;SY)(A;;FA;;;"+probeSID+")S:(ML;;NW;;;LW)" {
		t.Fatal(p)
	}
	if 0x12019b&0x4 != 0 {
		t.Fatal("不能给建实例的权限")
	}
	// 窗口站、桌面：任务账户能用，但不能改它们的 DACL、所有者（不然能把探针排除在外、给别人开门）
	for _, d := range []string{WinstaSD(probeSID, jobSID), DesktopSD(probeSID, jobSID)} {
		if !strings.HasSuffix(d, "S:(ML;;NW;;;LW)") || !strings.HasPrefix(d, "D:P") || strings.Contains(d, "GA;;;"+jobSID) {
			t.Fatal(d)
		}
		for _, a := range aces(t, d) {
			if a.sid == jobSID && a.mask&(0x40000|0x80000|0x10000000|0x10000) != 0 { // WRITE_DAC WRITE_OWNER GENERIC_ALL DELETE
				t.Fatalf("任务账户的权限太大: 0x%x %s", a.mask, d)
			}
		}
	}
	if !strings.Contains(WinstaSD(probeSID, jobSID), "(A;;0x2037f;;;"+jobSID+")") || !strings.Contains(DesktopSD(probeSID, jobSID), "(A;;0x201ff;;;"+jobSID+")") {
		t.Fatal("窗口站给 WINSTA_ALL 的具体权限 + READ_CONTROL；桌面给 DESKTOP_* 全部具体权限 + READ_CONTROL")
	}
}

func TestOnlyUsersGroupAllowed(t *testing.T) {
	if err := groupsOK([]string{"S-1-5-32-545"}); err != nil {
		t.Fatal(err)
	}
	for _, g := range [][]string{{"S-1-5-32-545", "S-1-5-32-544"}, {"S-1-5-32-545", "S-1-5-32-551"}, {}, {"S-1-5-32-546"}} {
		if err := groupsOK(g); err == nil {
			t.Fatalf("只许在 Users 里（Backup Operators 的 SeBackup 绕过所有 DACL）: %v", g)
		}
	}
}

func TestLogonCodes(t *testing.T) {
	for _, c := range []uint32{1326, 1385, 1058, 1331, 1909, 1330, 1907, 1327} {
		if !isLogonCode(c) {
			t.Errorf("%d 是本机账户配置问题", c)
		}
	}
	for _, c := range []uint32{2, 5, 193, 1450} {
		if isLogonCode(c) {
			t.Errorf("%d 不是", c)
		}
	}
}

func TestEnvBlock(t *testing.T) {
	b := envBlock([]string{"A=1", "B=x"})
	want := utf16.Encode([]rune("A=1\x00B=x\x00\x00"))
	if len(b) != len(want) {
		t.Fatalf("%v", b)
	}
	for i := range b {
		if b[i] != want[i] {
			t.Fatalf("%v", b)
		}
	}
	if b := envBlock(nil); len(b) != 2 || b[0] != 0 || b[1] != 0 {
		t.Fatalf("空环境块是两个 NUL: %v", b)
	}
	if b := envBlock([]string{"A=\x00x"}); b != nil {
		t.Fatal("带 NUL 的变量要拒")
	}
}

func TestStartErrorClassification(t *testing.T) {
	// 找不到解释器、工作目录不对、不是 exe：这个任务（环境层）的问题；其余（5、1314、资源不足……）是本机的问题
	for _, c := range []uint32{2, 3, 123, 193, 206, 267} {
		if _, machine := startError(c, "x").(*MachineError); machine {
			t.Errorf("%d 是任务的问题", c)
		}
	}
	for _, c := range []uint32{5, 1314, 1450, 8} {
		if _, machine := startError(c, "x").(*MachineError); !machine {
			t.Errorf("%d 是本机的问题", c)
		}
	}
	if _, logon := startError(1326, "x").(*LogonError); !logon {
		t.Error("1326 是登录错误")
	}
}
