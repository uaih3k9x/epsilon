package jobbox

import (
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// ace 是 SDDL 里的一条 ACE（只认这里用到的写法）。
type ace struct {
	typ, flags string
	mask       uint32
	sid        string
}

var aceRe = regexp.MustCompile(`\(([AD]);([A-Z]*);([^;]+);;;([^)]+)\)`)

// aces 按位解码 DACL 里的 ACE（FA/FR/GA 按文件对象展开），不比字面量：比字面量看不出缺了哪一位。
func aces(t *testing.T, sddl string) []ace {
	t.Helper()
	dacl, _, _ := strings.Cut(sddl, "S:")
	var out []ace
	for _, m := range aceRe.FindAllStringSubmatch(dacl, -1) {
		var mask uint32
		switch m[3] {
		case "FA":
			mask = 0x1f01ff
		case "FR":
			mask = 0x120089
		case "GA":
			mask = 0x10000000
		default:
			v, err := strconv.ParseUint(m[3], 0, 32)
			if err != nil {
				t.Fatalf("掩码 %q", m[3])
			}
			mask = uint32(v)
		}
		out = append(out, ace{m[1], m[2], mask, m[4]})
	}
	return out
}

// effective 是 sid 在"目录本身"（containers=true）或"目录里的文件"上的允许位减去拒绝位（不算继承来的）。
func effective(t *testing.T, sddl, sid string, containers bool) uint32 {
	var allow, deny uint32
	for _, a := range aces(t, sddl) {
		if a.sid != sid {
			continue
		}
		applies := !strings.Contains(a.flags, "IO") // 这一级目录本身
		if !containers {
			applies = strings.Contains(a.flags, "OI") // 里面的文件
		}
		if !applies {
			continue
		}
		if a.typ == "A" {
			allow |= a.mask
		} else {
			deny |= a.mask
		}
	}
	return allow &^ deny
}

const fileTraverse, fileExecute = 0x20, 0x20

func TestJobDirsAreTraversableButFilesNotExecutable(t *testing.T) {
	// SetCurrentDirectory（lpCurrentDirectory、os.chdir）以 FILE_TRAVERSE 打开目标目录本身，SeChangeNotify 只免中间各级
	sds := JobDirSDs(probeSID, jobSID)
	for _, rel := range []string{"", "output", "tmp"} {
		sd := sdFor(t, sds, rel).SDDL
		if rel != "" {
			sd = sdFor(t, sds, "").SDDL + sd // 子目录继承根上的
		}
		if effective(t, sd, jobSID, true)&fileTraverse == 0 {
			t.Fatalf("%q: 目录上要有 FILE_TRAVERSE: %s", rel, sd)
		}
		if effective(t, sd, jobSID, false)&fileExecute != 0 {
			t.Fatalf("%q: 文件上不能有 FILE_EXECUTE: %s", rel, sd)
		}
	}
}

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
	want := "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;" + probeSID + ")(A;OICI;FR;;;" + jobSID + ")(A;CI;0x20;;;" + jobSID + ")(A;OICI;0x20000;;;OW)"
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
