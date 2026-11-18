package jobbox

import "regexp"

// 访问掩码（docs/jobs-sandbox.md 第 3 节）。
const (
	// MaskJobWrite 是任务账户在 output\ tmp\ 上的权限：修改权（0x1301bf）去掉 FILE_EXECUTE；不含 WRITE_DAC、WRITE_OWNER。
	MaskJobWrite = 0x13019f
	// maskExecute 只拒 FILE_EXECUTE。不能写成 FX：FX 是 FILE_GENERIC_EXECUTE，连 SYNCHRONIZE、READ_CONTROL 一起拒，读文件就坏了。
	maskExecute = "0x20"
	// maskReadControl 是 OWNER RIGHTS 那条：所有者的隐含权限只剩 READ_CONTROL，改不了自己文件的 DACL。
	maskReadControl = "0x20000"
)

// PathSD 是任务目录里一处要设的安全描述符（SDDL）。按切片顺序设：根在最前。
// Reset 为真时把这棵子树里所有显式 ACE 清掉、只留继承（任务建文件时可以自带 DACL）。
type PathSD struct {
	Rel   string // 相对任务目录；"" 是根
	SDDL  string
	Reset bool
}

// Writable 是任务账户能写的子目录；其余（code\ data\ params.json job.log canary.out）继承根上的只读。
var Writable = []string{"output", "tmp"}

func rootSD(probeSID, jobSID string) string {
	s := "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;" + probeSID + ")"
	if jobSID != "" {
		s += "(A;OICI;FR;;;" + jobSID + ")"
	}
	return s + "(A;OICI;" + maskReadControl + ";;;OW)"
}

// JobDirSDs 是任务开始前设的：根受保护（不继承 D:\epsilon 上 Users 的修改权），任务账户只读、没有执行权限；
// output\ tmp\ 追加"可写不可执行"（拒绝只作用在文件上，OIIO，不碍目录遍历），标签 Low。
func JobDirSDs(probeSID, jobSID string) []PathSD {
	sds := []PathSD{{Rel: "", SDDL: rootSD(probeSID, jobSID)}}
	for _, d := range Writable {
		sds = append(sds, PathSD{Rel: d, SDDL: "D:(D;OIIO;" + maskExecute + ";;;" + jobSID + ")(A;OICI;0x13019f;;;" + jobSID + ")S:(ML;OICI;NW;;;LW)"})
	}
	return sds
}

// RevokedSDs 是任务结束后收回：所有任务共用一个账户，不收回下一个任务就能读这一份输出。OW 那条留着。
func RevokedSDs(probeSID string) []PathSD {
	sds := []PathSD{{Rel: "", SDDL: rootSD(probeSID, "")}}
	for _, d := range Writable {
		sds = append(sds, PathSD{Rel: d, SDDL: "D:", Reset: true})
	}
	return sds
}

var sidPattern = regexp.MustCompile(`^S-1-[0-9]+(-[0-9]+){1,14}$`)

// ValidSID 判断字符串是不是 S-1-... 形式的 SID（拼进 SDDL 之前查，免得拼出别的 ACE）。
func ValidSID(s string) bool { return sidPattern.MatchString(s) }
