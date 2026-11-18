//go:build windows

package jobbox

// Windows 一侧的沙箱（docs/jobs-sandbox.md 第 2–4 节）。只用标准库，advapi32/crypt32/user32/wtsapi32/netapi32 走 LazyProc。
// 这一份在 Mac 上只保证能编译（GOOS=windows go build/vet），没有在真机上跑过；要验证的单子见文档第 7 节。

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"epsilon/jobrun"
	"epsilon/winproc"
)

var (
	advapi32 = syscall.NewLazyDLL("advapi32.dll")
	crypt32  = syscall.NewLazyDLL("crypt32.dll")
	kernel32 = syscall.NewLazyDLL("kernel32.dll")
	user32   = syscall.NewLazyDLL("user32.dll")
	wtsapi32 = syscall.NewLazyDLL("wtsapi32.dll")
	netapi32 = syscall.NewLazyDLL("netapi32.dll")

	procCreateProcessWithLogonW = advapi32.NewProc("CreateProcessWithLogonW")
	procConvertSDDLToSD         = advapi32.NewProc("ConvertStringSecurityDescriptorToSecurityDescriptorW")
	procGetSDDacl               = advapi32.NewProc("GetSecurityDescriptorDacl")
	procGetSDSacl               = advapi32.NewProc("GetSecurityDescriptorSacl")
	procGetSDControl            = advapi32.NewProc("GetSecurityDescriptorControl")
	procSetNamedSecurityInfoW   = advapi32.NewProc("SetNamedSecurityInfoW")
	procTreeResetNamedSecInfoW  = advapi32.NewProc("TreeResetNamedSecurityInfoW")
	procEqualSid                = advapi32.NewProc("EqualSid")
	procCryptUnprotectData      = crypt32.NewProc("CryptUnprotectData")
	procLocalFree               = kernel32.NewProc("LocalFree")
	procCreateNamedPipeW        = kernel32.NewProc("CreateNamedPipeW")
	procConnectNamedPipe        = kernel32.NewProc("ConnectNamedPipe")
	procDisconnectNamedPipe     = kernel32.NewProc("DisconnectNamedPipe")
	procCancelIoEx              = kernel32.NewProc("CancelIoEx")
	procCreateWindowStationW    = user32.NewProc("CreateWindowStationW")
	procCreateDesktopW          = user32.NewProc("CreateDesktopW")
	procGetProcessWindowStation = user32.NewProc("GetProcessWindowStation")
	procSetProcessWindowStation = user32.NewProc("SetProcessWindowStation")
	procCloseWindowStation      = user32.NewProc("CloseWindowStation")
	procWTSEnumerateProcessesEx = wtsapi32.NewProc("WTSEnumerateProcessesExW")
	procWTSFreeMemoryEx         = wtsapi32.NewProc("WTSFreeMemoryExW")
	procNetUserGetLocalGroups   = netapi32.NewProc("NetUserGetLocalGroups")
	procNetApiBufferFree        = netapi32.NewProc("NetApiBufferFree")
)

const (
	seFileObject              = 1
	daclSecurityInformation   = 0x4
	labelSecurityInformation  = 0x10
	protectedDaclSecurityInfo = 0x80000000
	unprotectedDaclSecurity   = 0x20000000
	seDaclProtected           = 0x1000
	progressInvokeNever       = 1

	createSuspended          = 0x00000004
	createUnicodeEnvironment = 0x00000400
	startfUseShowWindow      = 0x00000001
	startfUseStdHandles      = 0x00000100

	pipeAccessInbound         = 0x00000001
	fileFlagFirstPipeInstance = 0x00080000
	pipeRejectRemoteClients   = 0x00000008
	pipeUnlimitedInstances    = 255
	errorPipeConnected        = 535

	winstaAllAccess = 0x37f | 0xf0000
	cwfCreateOnly   = 0x1 // 同名窗口站已经存在就失败，不打开别人的（和它的 DACL）
	genericAll      = 0x10000000
	genericWrite    = 0x40000000

	cryptProtectUIForbidden = 0x1
	wtsAnySession           = 0xfffffffe
	wtsTypeProcessInfoL1    = 1
	processTerminate        = 0x0001
	lgIncludeIndirect       = 0x1
	maxPreferredLength      = 0xffffffff
	errorNoneMapped         = 1332 // LookupAccountName：没有这个账户
)

type winPlatform struct {
	cfg      Config
	probeSID string

	mu       sync.Mutex
	jobSID   string
	jobSIDp  *syscall.SID
	password string
	winsta   uintptr
	desktop  uintptr
}

func newPlatform(c Config) (Platform, error) {
	tok, err := syscall.OpenCurrentProcessToken()
	if err != nil {
		return nil, fmt.Errorf("打开探针令牌: %v", err)
	}
	defer tok.Close()
	u, err := tok.GetTokenUser()
	if err != nil {
		return nil, fmt.Errorf("读探针令牌用户: %v", err)
	}
	s, err := u.User.Sid.String()
	if err != nil || !ValidSID(s) {
		return nil, fmt.Errorf("探针令牌用户 SID: %v", err)
	}
	return &winPlatform{cfg: c, probeSID: s}, nil
}

// wstr 读一个以 NUL 结尾的 UTF-16 串（系统分配的）。
func wstr(p *uint16) string {
	if p == nil {
		return ""
	}
	var s []uint16
	for ptr := unsafe.Pointer(p); ; ptr = unsafe.Add(ptr, 2) {
		c := *(*uint16)(ptr)
		if c == 0 {
			return syscall.UTF16ToString(s)
		}
		s = append(s, c)
	}
}

func utf16p(s string) *uint16 {
	p, err := syscall.UTF16PtrFromString(s)
	if err != nil {
		return nil
	}
	return p
}

// securityDescriptor 把 SDDL 转成自相对安全描述符；用完 LocalFree。
func securityDescriptor(sddl string) (uintptr, error) {
	var sd uintptr
	r, _, err := procConvertSDDLToSD.Call(uintptr(unsafe.Pointer(utf16p(sddl))), 1, uintptr(unsafe.Pointer(&sd)), 0)
	if r == 0 {
		return 0, fmt.Errorf("SDDL %q: %v", sddl, err)
	}
	return sd, nil
}

// setSD 按 SDDL 设一处的 DACL（和标签）。SetNamedSecurityInfo 会把可继承的变化传到子项；
// reset 时用 TreeResetNamedSecurityInfo 把子树里的显式 ACE 也清掉（任务建文件时可以自带 DACL）。
func setSD(path, sddl string, reset bool) error {
	sd, err := securityDescriptor(sddl)
	if err != nil {
		return err
	}
	defer procLocalFree.Call(sd)
	var present, defaulted int32
	var dacl, sacl uintptr
	if r, _, err := procGetSDDacl.Call(sd, uintptr(unsafe.Pointer(&present)), uintptr(unsafe.Pointer(&dacl)), uintptr(unsafe.Pointer(&defaulted))); r == 0 {
		return err
	}
	var saclPresent int32
	if r, _, err := procGetSDSacl.Call(sd, uintptr(unsafe.Pointer(&saclPresent)), uintptr(unsafe.Pointer(&sacl)), uintptr(unsafe.Pointer(&defaulted))); r == 0 {
		return err
	}
	var control uint16
	var rev uint32
	if r, _, err := procGetSDControl.Call(sd, uintptr(unsafe.Pointer(&control)), uintptr(unsafe.Pointer(&rev))); r == 0 {
		return err
	}
	info := uint32(daclSecurityInformation)
	if control&seDaclProtected != 0 {
		info |= protectedDaclSecurityInfo
	} else {
		info |= unprotectedDaclSecurity
	}
	if saclPresent != 0 {
		info |= labelSecurityInformation
	}
	p := uintptr(unsafe.Pointer(utf16p(path)))
	var rc uintptr
	if reset {
		rc, _, _ = procTreeResetNamedSecInfoW.Call(p, seFileObject, uintptr(info), 0, 0, dacl, sacl, 0, 0, progressInvokeNever, 0)
	} else {
		rc, _, _ = procSetNamedSecurityInfoW.Call(p, seFileObject, uintptr(info), 0, 0, dacl, sacl)
	}
	if rc != 0 {
		return syscall.Errno(rc)
	}
	return nil
}

func applySDs(dir string, sds []PathSD) error {
	for _, s := range sds {
		path := dir
		if s.Rel != "" {
			path = filepath.Join(dir, s.Rel)
		}
		if err := setSD(path, s.SDDL, s.Reset); err != nil {
			return fmt.Errorf("%s: %v", path, err)
		}
	}
	return nil
}

func (p *winPlatform) job() (sid string, sidp *syscall.SID, password string, err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.jobSID == "" {
		return "", nil, "", errors.New("任务账户还没通过健康检查")
	}
	return p.jobSID, p.jobSIDp, p.password, nil
}

func (p *winPlatform) Grant(dir string) error {
	sid, _, _, err := p.job()
	if err != nil {
		return err
	}
	return applySDs(dir, JobDirSDs(p.probeSID, sid))
}

func (p *winPlatform) Revoke(dir string) error { return applySDs(dir, RevokedSDs(p.probeSID)) }

type dataBlob struct {
	size uint32
	data *byte
}

func unprotect(blob, entropy []byte) ([]byte, error) {
	in := dataBlob{uint32(len(blob)), &blob[0]}
	ent := dataBlob{uint32(len(entropy)), &entropy[0]}
	var out dataBlob
	r, _, err := procCryptUnprotectData.Call(uintptr(unsafe.Pointer(&in)), 0, uintptr(unsafe.Pointer(&ent)), 0, 0,
		cryptProtectUIForbidden, uintptr(unsafe.Pointer(&out)))
	if r == 0 {
		return nil, err
	}
	defer procLocalFree.Call(uintptr(unsafe.Pointer(out.data)))
	return append([]byte(nil), unsafe.Slice(out.data, out.size)...), nil
}

// localGroups 是账户（含间接）所在本地组的 SID。按 SID 比，不按组名（组名是本地化的）；查不了 SID 的组算错误。
func localGroups(user string) ([]string, error) {
	var buf unsafe.Pointer
	var read, total uint32
	rc, _, _ := procNetUserGetLocalGroups.Call(0, uintptr(unsafe.Pointer(utf16p(user))), 0, lgIncludeIndirect,
		uintptr(unsafe.Pointer(&buf)), maxPreferredLength, uintptr(unsafe.Pointer(&read)), uintptr(unsafe.Pointer(&total)))
	if rc != 0 {
		return nil, fmt.Errorf("NetUserGetLocalGroups: %v", syscall.Errno(rc))
	}
	defer procNetApiBufferFree.Call(uintptr(buf))
	var sids []string
	for _, name := range unsafe.Slice((**uint16)(buf), read) {
		sid, _, _, err := syscall.LookupSID("", wstr(name))
		if err != nil {
			return nil, fmt.Errorf("本地组 %s 的 SID: %v", wstr(name), err)
		}
		s, _ := sid.String()
		sids = append(sids, s)
	}
	return sids, nil
}

// Health 是健康检查（docs/jobs-sandbox.md 第 6 节）。通过后记下 SID 和密码，建好窗口站。
func (p *winPlatform) Health() error {
	b, err := os.ReadFile(filepath.Join(p.cfg.Root, "secrets", SecretFile))
	if err != nil {
		return fmt.Errorf("读密码文件: %v", err)
	}
	sec, blob, err := ParseSecret(b)
	if err != nil {
		return err
	}
	pw, err := unprotect(blob, []byte(SecretEntropy))
	if err != nil {
		return fmt.Errorf("密码文件解不开（C: 还原后主密钥变了？）: %v", err)
	}
	sid, _, _, err := syscall.LookupSID("", JobUser)
	if err != nil {
		return fmt.Errorf("找不到账户 %s（C: 被还原了？）: %v", JobUser, err)
	}
	if s, _ := sid.String(); s != sec.SID {
		return fmt.Errorf("账户 %s 的 SID 是 %s，密码文件里记的是 %s", JobUser, s, sec.SID)
	}
	groups, err := localGroups(JobUser)
	if err != nil {
		return err
	}
	if err := groupsOK(groups); err != nil {
		return err
	}
	p.mu.Lock()
	p.jobSID, p.jobSIDp, p.password = sec.SID, sid, string(pw)
	p.mu.Unlock()
	return p.ensureDesktop(sec.SID)
}

// ensureDesktop 建一次窗口站 epsilon-job 和桌面 Default，句柄攥到探针退出。
// CWF_CREATE_ONLY：同名窗口站已经存在（有人抢先建了，或者上一个探针的残留进程还攥着）就失败，不用别人的。
// CreateDesktop 建在进程当前的窗口站上，所以要先 SetProcessWindowStation（整个进程生效），建完马上切回。
func (p *winPlatform) ensureDesktop(jobSID string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.desktop != 0 {
		return nil
	}
	attrs := func(sddl string) (*syscall.SecurityAttributes, func(), error) {
		sd, err := securityDescriptor(sddl)
		if err != nil {
			return nil, nil, err
		}
		return &syscall.SecurityAttributes{Length: uint32(unsafe.Sizeof(syscall.SecurityAttributes{})), SecurityDescriptor: sd},
			func() { procLocalFree.Call(sd) }, nil
	}
	wsa, free1, err := attrs(WinstaSD(p.probeSID, jobSID))
	if err != nil {
		return err
	}
	defer free1()
	dsa, free2, err := attrs(DesktopSD(p.probeSID, jobSID))
	if err != nil {
		return err
	}
	defer free2()
	name, desk, _ := strings.Cut(Desktop, `\`)
	ws, _, err := procCreateWindowStationW.Call(uintptr(unsafe.Pointer(utf16p(name))), cwfCreateOnly, winstaAllAccess, uintptr(unsafe.Pointer(wsa)))
	if ws == 0 {
		return fmt.Errorf("建窗口站 %s（已经存在也算失败）: %v", name, err)
	}
	orig, _, _ := procGetProcessWindowStation.Call()
	if r, _, err := procSetProcessWindowStation.Call(ws); r == 0 {
		procCloseWindowStation.Call(ws)
		return fmt.Errorf("切到窗口站 %s: %v", name, err)
	}
	d, _, derr := procCreateDesktopW.Call(uintptr(unsafe.Pointer(utf16p(desk))), 0, 0, 0, genericAll, uintptr(unsafe.Pointer(dsa)))
	procSetProcessWindowStation.Call(orig)
	if d == 0 {
		procCloseWindowStation.Call(ws)
		return fmt.Errorf("建桌面 %s: %v", Desktop, derr)
	}
	p.winsta, p.desktop = ws, d
	return nil
}

type winProc struct {
	h    syscall.Handle
	pid  int
	tree *winproc.Tree
	once sync.Once
}

func (w *winProc) Pid() int { return w.pid }
func (w *winProc) Wait() (int, error) {
	if _, err := syscall.WaitForSingleObject(w.h, syscall.INFINITE); err != nil {
		return -1, err
	}
	var code uint32
	if err := syscall.GetExitCodeProcess(w.h, &code); err != nil {
		return -1, err
	}
	return int(code), nil
}
func (w *winProc) Kill() { w.tree.Kill() }
func (w *winProc) Close() {
	w.once.Do(func() {
		w.tree.Close()
		syscall.CloseHandle(w.h)
	})
}

// Start 用 CreateProcessWithLogonW（走 seclogon，不需要探针有特权）以任务账户、独立桌面挂起起进程，
// 放进作业对象再恢复。stdout/stderr 接到 l.Log 的句柄（seclogon 复制给新进程，所以先复制一份可继承的）。
func (p *winPlatform) Start(l jobrun.Launch) (jobrun.Proc, error) {
	_, _, password, err := p.job()
	if err != nil {
		return nil, &MachineError{Err: err}
	}
	p.mu.Lock()
	haveDesktop := p.desktop != 0
	p.mu.Unlock()
	if !haveDesktop {
		return nil, &MachineError{Err: errors.New("独立桌面没建好")}
	}
	env := envBlock(l.Env)
	if env == nil {
		return nil, errors.New("环境变量里有 NUL")
	}
	cur, _ := syscall.GetCurrentProcess()
	var logh syscall.Handle
	if err := syscall.DuplicateHandle(cur, syscall.Handle(l.Log.Fd()), cur, &logh, 0, true, syscall.DUPLICATE_SAME_ACCESS); err != nil {
		return nil, &MachineError{Err: fmt.Errorf("复制日志句柄: %v", err)}
	}
	defer syscall.CloseHandle(logh)
	cmd, err := syscall.UTF16FromString(CmdLine(l.Path, l.Args)) // lpCommandLine 必须可写；长度 Box 已经查过
	if err != nil {
		return nil, err
	}
	si := syscall.StartupInfo{Desktop: utf16p(Desktop), Flags: startfUseStdHandles | startfUseShowWindow,
		ShowWindow: 0, StdOutput: logh, StdErr: logh} // SW_HIDE；CREATE_NO_WINDOW 不在这个函数允许的标志里
	si.Cb = uint32(unsafe.Sizeof(si))
	var pi syscall.ProcessInformation
	r, _, cerr := procCreateProcessWithLogonW.Call(
		uintptr(unsafe.Pointer(utf16p(JobUser))), uintptr(unsafe.Pointer(utf16p("."))), uintptr(unsafe.Pointer(utf16p(password))),
		0, // 不加载用户配置文件（LOGON_WITH_PROFILE 要真机验证后再说）
		uintptr(unsafe.Pointer(utf16p(l.Path))), uintptr(unsafe.Pointer(&cmd[0])),
		createSuspended|createUnicodeEnvironment, uintptr(unsafe.Pointer(&env[0])), uintptr(unsafe.Pointer(utf16p(l.Dir))),
		uintptr(unsafe.Pointer(&si)), uintptr(unsafe.Pointer(&pi)))
	if r == 0 {
		if errno, ok := cerr.(syscall.Errno); ok {
			return nil, startError(uint32(errno), errno.Error())
		}
		return nil, &MachineError{Err: fmt.Errorf("CreateProcessWithLogonW: %v", cerr)}
	}
	tree, err := winproc.AdoptSuspended(pi.Process, pi.Thread, winproc.SandboxLimits)
	syscall.CloseHandle(pi.Thread)
	if err != nil { // 进程已经被 seclogon 放进别的作业之类：本机的问题
		syscall.CloseHandle(pi.Process)
		return nil, &MachineError{Err: err}
	}
	return &winProc{h: pi.Process, pid: int(pi.ProcessId), tree: tree}, nil
}

// ---- 审计管道 ----

type pipeServer struct {
	sd     uintptr
	mu     sync.Mutex
	next   syscall.Handle
	closed bool
}

func createPipe(sd uintptr, first bool) (syscall.Handle, error) {
	sa := syscall.SecurityAttributes{Length: uint32(unsafe.Sizeof(syscall.SecurityAttributes{})), SecurityDescriptor: sd}
	mode := uint32(pipeAccessInbound)
	if first {
		mode |= fileFlagFirstPipeInstance // 有人先建了同名管道就建不出来：不跑
	}
	h, _, err := procCreateNamedPipeW.Call(uintptr(unsafe.Pointer(utf16p(AuditPipe))), uintptr(mode), pipeRejectRemoteClients,
		pipeUnlimitedInstances, 0, 64<<10, 0, uintptr(unsafe.Pointer(&sa)))
	if syscall.Handle(h) == syscall.InvalidHandle {
		return 0, fmt.Errorf("建审计管道: %v", err)
	}
	return syscall.Handle(h), nil
}

func (p *winPlatform) Audit() (AuditServer, error) {
	sid, _, _, err := p.job()
	if err != nil {
		return nil, err
	}
	sd, err := securityDescriptor(PipeSD(p.probeSID, sid))
	if err != nil {
		return nil, err
	}
	h, err := createPipe(sd, true)
	if err != nil {
		procLocalFree.Call(sd)
		return nil, err
	}
	return &pipeServer{sd: sd, next: h}, nil
}

type pipeConn struct {
	*os.File
	h    syscall.Handle
	once sync.Once
}

// Close 先断开客户端、取消挂着的 ReadFile，再关句柄（逃出作业的进程攥着连接时也能关掉）。
func (c *pipeConn) Close() error {
	c.once.Do(func() {
		procDisconnectNamedPipe.Call(uintptr(c.h))
		procCancelIoEx.Call(uintptr(c.h), 0)
	})
	return c.File.Close()
}

func (s *pipeServer) Accept() (io.ReadCloser, error) {
	s.mu.Lock()
	h, closed := s.next, s.closed
	s.mu.Unlock()
	if closed || h == 0 {
		return nil, errors.New("审计管道已关")
	}
	r, _, err := procConnectNamedPipe.Call(uintptr(h), 0)
	if r == 0 && err != syscall.Errno(errorPipeConnected) {
		s.mu.Lock()
		s.next = 0
		s.mu.Unlock()
		syscall.CloseHandle(h)
		return nil, fmt.Errorf("ConnectNamedPipe: %v", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed { // Close 自己连上来叫醒的
		s.next = 0
		syscall.CloseHandle(h)
		return nil, errors.New("审计管道已关")
	}
	next, err := createPipe(s.sd, false) // 先建好下一个实例，子进程连得上
	if err != nil {
		s.next = 0
	} else {
		s.next = next
	}
	return &pipeConn{File: os.NewFile(uintptr(h), "audit"), h: h}, nil
}

func (s *pipeServer) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	s.mu.Unlock()
	// ConnectNamedPipe 阻塞着：自己当客户端连一下把它叫醒
	for i := 0; i < 5; i++ {
		c, err := syscall.CreateFile(utf16p(AuditPipe), genericWrite, 0, nil, syscall.OPEN_EXISTING, 0, 0)
		if err == nil {
			syscall.CloseHandle(c)
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	go func() { // 等 Accept 收尾再释放安全描述符
		time.Sleep(time.Second)
		procLocalFree.Call(s.sd)
	}()
	return nil
}

// ---- 清场 ----

// wtsProcessInfoEx 是 WTS_PROCESS_INFO_EXW（amd64 布局）。
type wtsProcessInfoEx struct {
	SessionID, ProcessID uint32
	ProcessName          *uint16
	UserSid              *syscall.SID
	Threads, Handles     uint32
	PagefileUsage        uint32
	PeakPagefileUsage    uint32
	WorkingSetSize       uint32
	PeakWorkingSetSize   uint32
	UserTime, KernelTime int64
}

// jobSIDForSweep 是清场用的任务账户 SID：健康检查过了用记下的；还没过（启动时先清场）就自己查，不需要密码文件。
// 账户不存在（C: 被还原）返回 nil：也就不可能有它的进程。
func (p *winPlatform) jobSIDForSweep() (*syscall.SID, error) {
	p.mu.Lock()
	sid := p.jobSIDp
	p.mu.Unlock()
	if sid != nil {
		return sid, nil
	}
	sid, _, _, err := syscall.LookupSID("", JobUser)
	if errno, ok := err.(syscall.Errno); ok && errno == errorNoneMapped {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("查账户 %s: %v", JobUser, err)
	}
	return sid, nil
}

// jobProcs 用 WTSEnumerateProcessesExW 列所有会话里任务账户的进程。
// 查不了 SID 的进程（pUserSid 为空）跳过：探针看不看得见任务账户的进程由 Box.mustSee 每个任务核对一次。
func (p *winPlatform) jobProcs() ([]uint32, error) {
	sid, err := p.jobSIDForSweep()
	if err != nil || sid == nil {
		return nil, err
	}
	level := uint32(1)
	var info unsafe.Pointer
	var count uint32
	if r, _, err := procWTSEnumerateProcessesEx.Call(0, uintptr(unsafe.Pointer(&level)), wtsAnySession,
		uintptr(unsafe.Pointer(&info)), uintptr(unsafe.Pointer(&count))); r == 0 {
		return nil, fmt.Errorf("WTSEnumerateProcessesExW: %v", err)
	}
	defer procWTSFreeMemoryEx.Call(wtsTypeProcessInfoL1, uintptr(info), uintptr(count))
	var pids []uint32
	for _, pr := range unsafe.Slice((*wtsProcessInfoEx)(info), count) {
		if pr.UserSid == nil {
			continue
		}
		if eq, _, _ := procEqualSid.Call(uintptr(unsafe.Pointer(pr.UserSid)), uintptr(unsafe.Pointer(sid))); eq != 0 {
			pids = append(pids, pr.ProcessID)
		}
	}
	return pids, nil
}

func (p *winPlatform) Procs() ([]int, error) {
	pids, err := p.jobProcs()
	out := make([]int, len(pids))
	for i, pid := range pids {
		out[i] = int(pid)
	}
	return out, err
}

// Sweep 结束任务账户还活着的进程（TerminateProcess），返回找到几个。
func (p *winPlatform) Sweep() (int, error) {
	pids, err := p.jobProcs()
	if err != nil {
		return 0, err
	}
	var failed []string
	for _, pid := range pids {
		h, err := syscall.OpenProcess(processTerminate, false, pid)
		if err == nil {
			err = syscall.TerminateProcess(h, 1)
			syscall.CloseHandle(h)
		}
		if err != nil {
			failed = append(failed, fmt.Sprintf("%d: %v", pid, err))
		}
	}
	if len(failed) > 0 {
		return len(pids), fmt.Errorf("结束不了: %s", strings.Join(failed, "；"))
	}
	return len(pids), nil
}
