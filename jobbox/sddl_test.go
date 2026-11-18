package jobbox

import (
	"strings"
	"testing"
)

const (
	probeSID = "S-1-5-21-1-2-3-500"
	jobSID   = "S-1-5-21-1-2-3-1001"
)

func sdFor(t *testing.T, sds []PathSD, rel string) PathSD {
	t.Helper()
	for _, s := range sds {
		if s.Rel == rel {
			return s
		}
	}
	t.Fatalf("没有 %q 的安全描述符: %+v", rel, sds)
	return PathSD{}
}

func TestJobDirRootIsProtectedReadOnlyForJob(t *testing.T) {
	sds := JobDirSDs(probeSID, jobSID)
	if sds[0].Rel != "" {
		t.Fatalf("根要先设（子目录的追加 ACE 要在根换完之后）: %+v", sds)
	}
	root := sds[0].SDDL
	want := "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;" + probeSID + ")(A;OICI;FR;;;" + jobSID + ")(A;OICI;0x20000;;;OW)"
	if root != want {
		t.Fatalf("根:\n got %s\nwant %s", root, want)
	}
	// 不继承 D:\epsilon 上 Users 的修改权；任务账户只读
	if !strings.HasPrefix(root, "D:P") || strings.Contains(root, ";;;BU)") || strings.Contains(root, ";;;AU)") {
		t.Fatal("根必须是受保护 DACL，不能有 Users / Authenticated Users")
	}
}

func TestOwnerRightsAceLimitsOwnerToReadControl(t *testing.T) {
	// 任务在 output\ 里新建的文件，所有者是任务账户；没有 OW 那条，所有者天生有 WRITE_DAC，能删掉拒绝执行
	for _, sds := range [][]PathSD{JobDirSDs(probeSID, jobSID), RevokedSDs(probeSID)} {
		if !strings.Contains(sds[0].SDDL, "(A;OICI;0x20000;;;OW)") {
			t.Fatalf("根上要有可继承的 OWNER RIGHTS = READ_CONTROL: %s", sds[0].SDDL)
		}
	}
}

func TestWritableDirsDenyExecuteAsHexOnFilesOnly(t *testing.T) {
	sds := JobDirSDs(probeSID, jobSID)
	for _, rel := range []string{"output", "tmp"} {
		s := sdFor(t, sds, rel).SDDL
		want := "D:(D;OIIO;0x20;;;" + jobSID + ")(A;OICI;0x13019f;;;" + jobSID + ")S:(ML;OICI;NW;;;LW)"
		if s != want {
			t.Fatalf("%s:\n got %s\nwant %s", rel, s, want)
		}
		// FX 是 FILE_GENERIC_EXECUTE，连 SYNCHRONIZE 和 READ_CONTROL 一起拒，读文件就坏了
		if strings.Contains(s, ";FX;") || strings.Contains(s, ";GX;") {
			t.Fatalf("%s: 拒绝执行必须写成 0x20", rel)
		}
		if strings.HasPrefix(s, "D:P") {
			t.Fatalf("%s: 不能受保护，要继承根上的 SY/BA/探针/OW", rel)
		}
	}
}

func TestJobWriteMaskHasNoExecuteNorDacNorOwner(t *testing.T) {
	const (
		fileExecute = 0x20
		deleteChild = 0x40
		writeDAC    = 0x40000
		writeOwner  = 0x80000
	)
	if MaskJobWrite&(fileExecute|writeDAC|writeOwner|deleteChild) != 0 {
		t.Fatalf("0x%x 不能含执行、WRITE_DAC、WRITE_OWNER、DELETE_CHILD", MaskJobWrite)
	}
	// 修改权（0x1301bf）去掉 FILE_EXECUTE
	if MaskJobWrite != 0x1301bf&^fileExecute {
		t.Fatalf("0x%x 应该是修改权去掉执行", MaskJobWrite)
	}
}

func TestCodeAndParamsHaveNoExplicitEntry(t *testing.T) {
	// code\ params.json job.log 都继承根上的只读：不单独给执行权限
	for _, s := range JobDirSDs(probeSID, jobSID) {
		if s.Rel != "" && s.Rel != "output" && s.Rel != "tmp" {
			t.Fatalf("多出来的条目 %q", s.Rel)
		}
	}
}

func TestRevokedHasNoJobAceAndResetsWritableTrees(t *testing.T) {
	sds := RevokedSDs(probeSID)
	if sds[0].Rel != "" || !strings.HasPrefix(sds[0].SDDL, "D:P") {
		t.Fatalf("收回时根先设、仍然受保护: %+v", sds)
	}
	for _, s := range sds {
		if strings.Contains(s.SDDL, jobSID) || strings.Contains(s.SDDL, "S-1-5-21-1-2-3-1001") {
			t.Fatalf("收回后不能还有任务账户的 ACE: %+v", s)
		}
	}
	for _, rel := range []string{"output", "tmp"} {
		s := sdFor(t, sds, rel)
		if s.SDDL != "D:" || !s.Reset {
			t.Fatalf("%s 要清空显式 ACE、整棵重置成只继承（任务建文件时可以自带 DACL）: %+v", rel, s)
		}
	}
}

func TestSIDsAreValidated(t *testing.T) {
	for _, bad := range []string{"", "S-1-5-21-1)(A;;FA;;;WD", "WD", "S-1-5-21-x"} {
		if ValidSID(bad) {
			t.Fatalf("%q 不能当 SID 拼进 SDDL", bad)
		}
	}
	if !ValidSID(jobSID) {
		t.Fatal(jobSID)
	}
}
