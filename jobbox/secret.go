package jobbox

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"unicode/utf16"
)

// 任务账户和它的密码文件（install.ps1 以 SYSTEM 生成，docs/jobs-sandbox.md 第 2 节）。
const (
	JobUser       = "epsilon-job"
	SecretFile    = "epsilon-job.json" // <artifact_root>\secrets\ 下
	SecretEntropy = "epsilon-job/v1"   // DPAPI（LocalMachine 作用域）的附加熵
)

// Secret 是 secrets\epsilon-job.json。
type Secret struct {
	Version       int    `json:"version"`
	User          string `json:"user"`
	SID           string `json:"sid"`
	PasswordDPAPI string `json:"password_dpapi"`
}

// ParseSecret 解析并核对密码文件，返回 DPAPI 密文。
func ParseSecret(b []byte) (Secret, []byte, error) {
	var s Secret
	if err := json.Unmarshal(bytes.TrimPrefix(b, []byte("\xef\xbb\xbf")), &s); err != nil {
		return s, nil, fmt.Errorf("密码文件坏了: %v", err)
	}
	if s.Version != 1 {
		return s, nil, fmt.Errorf("密码文件版本 %d 不认识", s.Version)
	}
	if s.User != JobUser {
		return s, nil, fmt.Errorf("密码文件里的账户是 %q，不是 %s", s.User, JobUser)
	}
	if !ValidSID(s.SID) {
		return s, nil, fmt.Errorf("密码文件里的 SID %q 不对", s.SID)
	}
	blob, err := base64.StdEncoding.DecodeString(s.PasswordDPAPI)
	if err != nil || len(blob) == 0 {
		return s, nil, errors.New("密码文件里的密文不是 base64")
	}
	return s, blob, nil
}

// PipeSD 是审计管道：任务账户读写（0x12019b = 读写去掉 FILE_CREATE_PIPE_INSTANCE），抢注不了实例；标签 Low。
func PipeSD(probeSID, jobSID string) string {
	return "D:P(A;;0x12019b;;;" + jobSID + ")(A;;FA;;;SY)(A;;FA;;;" + probeSID + ")S:(ML;;NW;;;LW)"
}

// DesktopSD 是窗口站 epsilon-job 和桌面 Default：任务账户能用；没有 Low 标签的话，Low IL 进程初始化 user32 会失败。
func DesktopSD(probeSID, jobSID string) string {
	return "D:P(A;;GA;;;SY)(A;;GA;;;" + probeSID + ")(A;;GA;;;" + jobSID + ")S:(ML;;NW;;;LW)"
}

// isLogonCode：CreateProcessWithLogonW 的这些错误说明本机账户配置坏了（停接任务），不是这个任务的问题。
func isLogonCode(c uint32) bool {
	switch c {
	case 1326, // ERROR_LOGON_FAILURE：密码不对
		1385, // ERROR_LOGON_TYPE_NOT_GRANTED：没有本地交互登录权限
		1058, // ERROR_SERVICE_DISABLED：seclogon 被禁用
		1327, // ERROR_ACCOUNT_RESTRICTION
		1330, // ERROR_PASSWORD_EXPIRED
		1331, // ERROR_ACCOUNT_DISABLED
		1907, // ERROR_PASSWORD_MUST_CHANGE
		1909: // ERROR_ACCOUNT_LOCKED_OUT
		return true
	}
	return false
}

// envBlock 是 CREATE_UNICODE_ENVIRONMENT 要的 UTF-16 环境块："K=V\0...\0\0"。变量里带 NUL 返回 nil。
func envBlock(env []string) []uint16 {
	var b []uint16
	for _, kv := range env {
		if strings.IndexByte(kv, 0) >= 0 {
			return nil
		}
		b = append(b, utf16.Encode([]rune(kv))...)
		b = append(b, 0)
	}
	if len(b) == 0 {
		b = append(b, 0)
	}
	return append(b, 0)
}
