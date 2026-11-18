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

// 窗口站和桌面上任务账户的权限：全部具体权限 + READ_CONTROL，没有 WRITE_DAC、WRITE_OWNER、DELETE
// （不然任务能改它们的 DACL，把探针排除在外或者给别人开门）。真机上 user32 初始化够不够见文档第 7 节。
const (
	winstaJobMask  = "0x2037f" // WINSTA_ENUMDESKTOPS…WINSTA_READSCREEN（0x37f）| READ_CONTROL
	desktopJobMask = "0x201ff" // DESKTOP_READOBJECTS…DESKTOP_SWITCHDESKTOP（0x1ff）| READ_CONTROL
)

// WinstaSD 是窗口站 epsilon-job；DesktopSD 是它下面的桌面 Default。没有 Low 标签的话，Low IL 进程初始化 user32 会失败。
func WinstaSD(probeSID, jobSID string) string {
	return "D:P(A;;GA;;;SY)(A;;GA;;;" + probeSID + ")(A;;" + winstaJobMask + ";;;" + jobSID + ")S:(ML;;NW;;;LW)"
}

func DesktopSD(probeSID, jobSID string) string {
	return "D:P(A;;GA;;;SY)(A;;GA;;;" + probeSID + ")(A;;" + desktopJobMask + ";;;" + jobSID + ")S:(ML;;NW;;;LW)"
}

// UsersSID 是 BUILTIN\Users。任务账户的本地组必须恰好是它：Administrators 不用说，
// Backup Operators（S-1-5-32-551）的 SeBackup 能绕过所有 DACL，别的组也不该有。
const UsersSID = "S-1-5-32-545"

func groupsOK(sids []string) error {
	if len(sids) == 1 && sids[0] == UsersSID {
		return nil
	}
	return fmt.Errorf("账户 %s 的本地组是 %v，只许是 Users（%s）", JobUser, sids, UsersSID)
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

// startError 把 CreateProcessWithLogonW 的错误码分成三类：登录（本机账户配置，LogonError）、
// 这个任务的（解释器、工作目录、路径不对）、其余都算本机的（MachineError：停接任务，主控换一台）。
func startError(code uint32, msg string) error {
	if isLogonCode(code) {
		return &LogonError{Code: code, Msg: msg}
	}
	err := fmt.Errorf("CreateProcessWithLogonW: %s（%d）", msg, code)
	switch code {
	case 2, 3, 123, 193, 206, 267: // FILE_NOT_FOUND PATH_NOT_FOUND INVALID_NAME BAD_EXE_FORMAT FILENAME_EXCED_RANGE DIRECTORY
		return err
	}
	return &MachineError{Err: err}
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
