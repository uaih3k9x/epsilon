package probe

// 批任务执行（能力 32，默认关）和任务钥匙环（能力 33，默认开）。契约见 docs/jobs.md，设计书 22.2–22.4。
//
// 主控不可信：它发来的任务包原文、参数、钥匙环、清单，这里全部自己再核一遍。
// 时钟：过期判断用"本机时间、主控回包的 Date、钥匙环签发时间"里最晚的那个，只会多拒、不会多放。
//
// 上线前必须做（issue #1 第 4 步，这一版没有）：
//   - 任务进程现在以探针的账户运行（教室机自动登录的是 Administrator），要换成专用低权限账户 epsilon-job；
//   - code\ 只读、output\ tmp\ 可写不可执行（NTFS ACL），环境层审计钩子；
//   - 出站防火墙：只许连主控和同教室，钥匙 network: true 才放开。

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"epsilon/envlayer"
	"epsilon/joboutput"
	"epsilon/jobrun"
	"epsilon/jobsign"
	"epsilon/proto"
)

const (
	keyringVersionFile = "job-keyring.version"
	keyringRefresh     = 10 * time.Minute
	jobLogKeep         = 1 << 20 // job.log 末尾多少随输出回传
)

var jobIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._@-]{0,127}$`)

// jobState 是 Agent 上和批任务有关的东西，嵌在 Agent 里。
type jobState struct {
	// JobRoots 是验钥匙环的根公钥（main 里填 loader.PublicKeys）；为空时一个任务都不跑。
	JobRoots []ed25519.PublicKey

	jobInterp       func(envDir string) string // 解释器路径；nil = 环境层里的 python.exe。测试里换成替身
	jobEnv          []string                   // 追加给任务进程的环境变量（测试用）
	jobCheckEvery   time.Duration              // 多久查一次任务写盘；0 = 10 秒
	jobUploadRetry  time.Duration              // 回传失败后多久再试
	jobFetchTimeout time.Duration              // 拉环境层和代码包最多多久；0 = 2 小时
	clock           func() time.Time           // 本机时钟；nil = time.Now

	jmu    sync.Mutex
	jobCur *jobRun

	krMu    sync.Mutex // 拉钥匙环、读写版本号一次一个
	krAt    time.Time  // 上次后台刷新（只在 Step 里碰）
	krBusy  atomic.Bool
	skewMu  sync.Mutex
	ctlSkew time.Duration // 主控 Date 比本机快多少（只记正的）
}

type jobRun struct {
	assign  proto.JobAssign
	cancel  context.CancelFunc
	done    chan struct{}
	status  proto.JobStatus // 受 Agent.jmu 保护
	started time.Time       // 进程起来的时间，算已跑多久
}

// rejectErr 是"一行代码都没跑就拒了"：验签、钥匙环、过期、权限、哈希、参数。
type rejectErr struct{ msg string }

func (e rejectErr) Error() string { return e.msg }

func reject(format string, args ...any) error { return rejectErr{fmt.Sprintf(format, args...)} }

func (a *Agent) localNow() time.Time {
	if a.clock != nil {
		return a.clock()
	}
	return time.Now()
}

// strictNow 取本机时间和主控时间里晚的那个：本机时钟慢了也不会把过期钥匙当有效。
func (a *Agent) strictNow() time.Time {
	a.skewMu.Lock()
	defer a.skewMu.Unlock()
	return a.localNow().Add(a.ctlSkew)
}

// noteDate 记下主控回包的 Date。主控可以撒谎，但只能让探针更早判过期，不能让它放过过期的。
func (a *Agent) noteDate(h string) {
	t, err := http.ParseTime(h)
	if err != nil {
		return
	}
	skew := t.Sub(a.localNow())
	if skew < 0 {
		skew = 0
	}
	a.skewMu.Lock()
	a.ctlSkew = skew
	a.skewMu.Unlock()
}

func (a *Agent) keyringEnabled() bool { return a.cfg.JobKeyring == nil || *a.cfg.JobKeyring }

// readKeyringVersion 读本机见过的最高钥匙环版本；没有 = 0。文件坏了报错（宁可一个都不跑，也不当成 0 让旧钥匙环回来）。
func readKeyringVersion(path string) (int, error) {
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	v, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil || v < 0 {
		return 0, fmt.Errorf("%s 坏了（%q），修好或确认后删掉", filepath.Base(path), b)
	}
	return v, nil
}

// writeKeyringVersion 原子写：写临时文件、Sync、改名。
func writeKeyringVersion(path string, v int) error {
	tmp := path + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(f, "%d\n", v)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp, path)
	}
	if err != nil {
		os.Remove(tmp)
	}
	return err
}

// keyring 从主控拉钥匙环、用根公钥验、版本不许比见过的旧，验过后把更高的版本号持久化。
func (a *Agent) keyring(ctx context.Context) (jobsign.Keyring, error) {
	raw, err := a.getRaw(ctx, "/v1/job-keyring", 4<<20)
	if err != nil {
		return jobsign.Keyring{}, fmt.Errorf("拉钥匙环: %w", err)
	}
	var s jobsign.SignedKeyring
	if err := json.Unmarshal(raw, &s); err != nil {
		return jobsign.Keyring{}, reject("钥匙环格式坏了: %v", err)
	}
	if len(a.JobRoots) == 0 {
		return jobsign.Keyring{}, reject("本机没有根公钥")
	}
	a.krMu.Lock()
	defer a.krMu.Unlock()
	path := filepath.Join(a.cfg.ArtifactRoot, keyringVersionFile)
	seen, err := readKeyringVersion(path)
	if err != nil {
		return jobsign.Keyring{}, reject("%v", err)
	}
	kr, err := jobsign.VerifyKeyring(s, a.JobRoots, seen, a.strictNow())
	if err != nil {
		return kr, reject("%v", err)
	}
	if kr.Version > seen {
		if err := writeKeyringVersion(path, kr.Version); err != nil {
			return kr, reject("钥匙环版本号存不下来，不敢用: %v", err)
		}
		log.Printf("任务钥匙环升到版本 %d（之前 %d）", kr.Version, seen)
		a.sendEvent(proto.Event{Kind: "keyring", Detail: fmt.Sprintf("版本 %d → %d", seen, kr.Version)})
	}
	return kr, nil
}

// refreshKeyring 是能力 33：后台定时拉一次，好让本机尽早记住新版本号（防回滚）。
func (a *Agent) refreshKeyring(now time.Time) {
	if !a.keyringEnabled() || now.Sub(a.krAt) < keyringRefresh || !a.krBusy.CompareAndSwap(false, true) {
		return
	}
	a.krAt = now
	go func() {
		defer a.krBusy.Store(false)
		ctx, cancel := context.WithTimeout(a.fetchCtx, time.Minute)
		defer cancel()
		if _, err := a.keyring(ctx); err != nil {
			log.Printf("任务钥匙环: %v", err)
		}
	}()
}

func (a *Agent) getRaw(ctx context.Context, path string, max int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.cfg.Controller+path, nil)
	if err != nil {
		return nil, err
	}
	a.auth(req)
	r, err := a.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer r.Body.Close()
	if r.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: HTTP %d", path, r.StatusCode)
	}
	return io.ReadAll(io.LimitReader(r.Body, max))
}

// stepJob 每个 Step 调：期望状态换了任务（或没了）就撤销手上的；手上空了、期望里有就开始。
// 返回 true 表示这台机器现在归批任务，不起推理。
func (a *Agent) stepJob(now time.Time) bool {
	a.refreshKeyring(now)
	want := a.desired.Job
	a.jmu.Lock()
	cur := a.jobCur
	a.jmu.Unlock()
	if cur != nil && (want == nil || want.ID != cur.assign.ID || want.Attempt != cur.assign.Attempt) {
		cur.cancel() // 已经结束的话什么都不做
		select {
		case <-cur.done:
			a.jmu.Lock()
			a.jobCur = nil
			a.jmu.Unlock()
			cur = nil
		default:
		}
	}
	if cur == nil && want != nil {
		a.startJob(*want)
		return true
	}
	return cur != nil || want != nil
}

func (a *Agent) startJob(as proto.JobAssign) {
	ctx, cancel := context.WithCancel(a.fetchCtx)
	j := &jobRun{assign: as, cancel: cancel, done: make(chan struct{}),
		status: proto.JobStatus{ID: as.ID, Attempt: as.Attempt, State: proto.JobFetching}}
	a.jmu.Lock()
	a.jobCur = j
	a.jmu.Unlock()
	go func() {
		defer close(j.done)
		defer cancel()
		st := a.runJob(ctx, j)
		a.jmu.Lock()
		j.status.State, j.status.Detail, j.status.ExitCode = st.State, st.Detail, st.ExitCode
		if !j.started.IsZero() {
			j.status.Seconds = st.Seconds
		}
		a.jmu.Unlock()
		log.Printf("任务 %s 第 %d 次: %s %s", as.ID, as.Attempt, st.State, st.Detail)
		a.sendEvent(proto.Event{Kind: "job", Detail: fmt.Sprintf("结束 %s#%d %s %s", as.ID, as.Attempt, st.State, st.Detail)})
	}()
}

// jobStatus 是随心跳上报的状态（复制一份）。
func (a *Agent) jobStatus() *proto.JobStatus {
	a.jmu.Lock()
	defer a.jmu.Unlock()
	if a.jobCur == nil {
		return nil
	}
	s := a.jobCur.status
	if s.State == proto.JobRunning && !a.jobCur.started.IsZero() {
		s.Seconds = time.Since(a.jobCur.started).Seconds()
	}
	return &s
}

func (a *Agent) setJob(j *jobRun, f func(s *proto.JobStatus)) {
	a.jmu.Lock()
	f(&j.status)
	a.jmu.Unlock()
}

// runJob 跑完一次任务，返回结束状态。
func (a *Agent) runJob(ctx context.Context, j *jobRun) proto.JobStatus {
	fail := func(err error) proto.JobStatus {
		var rj rejectErr
		if errors.As(err, &rj) {
			return proto.JobStatus{State: proto.JobRejected, Detail: rj.msg}
		}
		if ctx.Err() != nil {
			return proto.JobStatus{State: proto.JobKilled, Detail: "撤销"}
		}
		return proto.JobStatus{State: proto.JobFailed, Detail: err.Error()}
	}
	as := j.assign
	if !a.cfg.Jobs {
		return fail(reject("本机没开批任务（probe.json \"jobs\": true，能力 32）"))
	}
	if !a.keyringEnabled() {
		return fail(reject("本机关了任务钥匙环（能力 33），验不了任务包"))
	}
	if !jobIDPattern.MatchString(as.ID) {
		return fail(reject("任务号不合法: %q", as.ID))
	}
	kr, err := a.keyring(ctx)
	if err != nil {
		return fail(err)
	}
	var signed jobsign.SignedJob
	if err := json.Unmarshal([]byte(as.Signed), &signed); err != nil {
		return fail(reject("任务包格式坏了: %v", err))
	}
	// 签发时间也算进"现在"：钥匙环是 issued 之后才签的，本机时钟比它还早肯定是慢了
	now := a.strictNow()
	if issued, err := time.Parse(time.RFC3339, kr.Issued); err == nil && issued.After(now) {
		now = issued
	}
	job, key, err := jobsign.VerifyJob(signed, kr, now)
	if err != nil {
		return fail(reject("%v", err))
	}
	digest := jobsign.JobDigest(signed)
	a.setJob(j, func(s *proto.JobStatus) { s.Signer, s.Digest = key.Name, digest })
	if len(job.Data) > 0 {
		return fail(reject("数据集还没做：带 data 的任务包这一版不跑"))
	}
	params, err := jobsign.FillParams(job.Params, as.Params)
	if err != nil {
		return fail(reject("参数: %v", err))
	}
	paramsJSON, _ := json.MarshalIndent(params, "", "  ")
	a.sendEvent(proto.Event{Kind: "job", Detail: fmt.Sprintf("开始 %s#%d %s@%s 签名 %s 摘要 %s 参数 %s",
		as.ID, as.Attempt, job.Name, job.Version, key.Name, digest[:12], compactJSON(params))})
	if job.Network {
		log.Printf("任务 %s 声明要联网；出站防火墙还没做（issue #1 第 4 步）", as.ID)
	}

	fetchTimeout := a.jobFetchTimeout
	if fetchTimeout <= 0 {
		fetchTimeout = 2 * time.Hour // 环境层 5–8 GB，教室内 P2P 够了；拉不下来就别一直占着机器
	}
	fctx, fcancel := context.WithTimeout(ctx, fetchTimeout)
	envDir, err := a.prepareEnv(fctx, kr, job.Env)
	var codeZip string
	if err == nil {
		codeZip, err = a.prepareCode(fctx, job.CodeSHA256)
	}
	timedOut := fctx.Err() == context.DeadlineExceeded
	fcancel()
	if err != nil && timedOut && ctx.Err() == nil {
		return proto.JobStatus{State: proto.JobFailed, Detail: fmt.Sprintf("%s 内没拉齐环境层和代码包: %v", fetchTimeout, err)}
	}
	if err != nil {
		return fail(err)
	}
	dir := filepath.Join(a.cfg.ArtifactRoot, "jobs", as.ID)
	if err := jobrun.Prepare(dir, codeZip, paramsJSON); err != nil {
		return fail(reject("展开任务目录: %v", err))
	}
	interp := filepath.Join(envDir, envlayer.Interpreter)
	if a.jobInterp != nil {
		interp = a.jobInterp(envDir)
	}
	a.setJob(j, func(s *proto.JobStatus) { s.State = proto.JobRunning })
	a.jmu.Lock()
	j.started = time.Now()
	a.jmu.Unlock()
	res, err := jobrun.Run(ctx, jobrun.Spec{Dir: dir, Interp: interp, Entry: job.Entry,
		Timeout: time.Duration(job.MaxHours * float64(time.Hour)), DiskMaxMB: job.DiskMaxMB, Env: a.jobEnv, CheckEvery: a.jobCheckEvery})
	if err != nil {
		return fail(err)
	}
	end := proto.JobStatus{Seconds: res.Seconds}
	switch res.Killed {
	case "cancelled":
		return proto.JobStatus{State: proto.JobKilled, Detail: "撤销", Seconds: res.Seconds} // 主控不要了，不回传
	case "timeout":
		end.State, end.Detail = proto.JobKilled, fmt.Sprintf("超时（max_hours %g）", job.MaxHours)
	case "disk":
		end.State, end.Detail = proto.JobKilled, fmt.Sprintf("写盘超过 disk_max_mb %d", job.DiskMaxMB)
	default:
		code := res.ExitCode
		end.ExitCode = &code
		end.State = proto.JobSucceeded
		if code != 0 {
			end.State, end.Detail = proto.JobFailed, fmt.Sprintf("退出码 %d", code)
		}
	}
	if n := jobrun.OutputBytes(dir); n > int64(job.OutputMaxMB)<<20 {
		return proto.JobStatus{State: proto.JobFailed, Detail: fmt.Sprintf("output 有 %d MB，超过 output_max_mb %d，不回传", n>>20, job.OutputMaxMB),
			ExitCode: end.ExitCode, Seconds: res.Seconds}
	}
	a.writeSummary(dir, as, job, key.Name, digest, params, res)
	a.setJob(j, func(s *proto.JobStatus) { s.State = proto.JobUploading })
	if err := a.uploadOutput(ctx, as, filepath.Join(dir, "output")); err != nil {
		if ctx.Err() != nil {
			return proto.JobStatus{State: proto.JobKilled, Detail: "撤销", Seconds: res.Seconds}
		}
		return proto.JobStatus{State: proto.JobFailed, Detail: "回传失败: " + err.Error(), ExitCode: end.ExitCode, Seconds: res.Seconds}
	}
	return end
}

func compactJSON(v any) string { b, _ := json.Marshal(v); return string(b) }

// prepareEnv 备好环境层：钥匙环里的摘要核对清单 → 拉块 → 拼 zip → 解压。已经装好就直接用。
func (a *Agent) prepareEnv(ctx context.Context, kr jobsign.Keyring, name string) (string, error) {
	digest, ok := kr.EnvLayerDigest(name)
	if !ok {
		return "", reject("环境层 %s 不在钥匙环里", name)
	}
	dir := envlayer.Dir(a.cfg.ArtifactRoot, name)
	if envlayer.Ready(dir, digest) {
		return dir, nil
	}
	raw, err := a.getRaw(ctx, "/v1/manifests/"+url.PathEscape(name), 16<<20)
	if err != nil {
		return "", fmt.Errorf("取环境层清单: %w", err)
	}
	m, err := envlayer.Parse(raw, name, digest)
	if err != nil {
		return "", reject("%v", err)
	}
	if err := a.fetchManifest(ctx, m); err != nil {
		return "", err
	}
	z := filepath.Join(a.cfg.ArtifactRoot, filepath.FromSlash(m.Files[0].Path))
	if _, err := envlayer.Expand(z, dir, digest); err != nil {
		return "", reject("解压环境层: %v", err)
	}
	os.Remove(z)
	os.Remove(z + ".epsilon-ok")
	return dir, nil
}

// CodePath 是代码包在 artifact_root 下的位置；代码包清单 code-<sha> 里只能有这一个文件。
func CodePath(sha string) string { return "jobcode/" + sha + ".zip" }

// prepareCode 拉代码包，返回 zip 路径。清单的整文件哈希先和签过名的 code_sha256 对；
// 拼好以后（或本地已有）再整个重算一遍——这是 code_sha256 的二次核对，不信清单、不信校验戳。
func (a *Agent) prepareCode(ctx context.Context, sha string) (string, error) {
	id := "code-" + sha
	raw, err := a.getRaw(ctx, "/v1/manifests/"+id, 16<<20)
	if err != nil {
		return "", fmt.Errorf("取代码包清单: %w", err)
	}
	var m proto.Manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return "", reject("代码包清单格式坏了: %v", err)
	}
	if err := checkManifest(m, id); err != nil {
		return "", reject("%v", err)
	}
	if len(m.Files) != 1 || m.Files[0].Path != CodePath(sha) || m.Files[0].SHA256 != sha {
		return "", reject("代码包清单和签过名的 code_sha256 对不上")
	}
	if err := a.fetchManifest(ctx, m); err != nil {
		return "", err
	}
	p := filepath.Join(a.cfg.ArtifactRoot, filepath.FromSlash(CodePath(sha)))
	got, err := fileSHA256(p)
	if err != nil {
		return "", err
	}
	if got != sha {
		os.Remove(p)
		os.Remove(p + ".epsilon-ok")
		return "", reject("代码包哈希是 %s，签过名的是 %s", got[:12], sha[:12])
	}
	return p, nil
}

// fetchManifest 拉齐块、拼成文件（复用制品分发：P2P、限速、拉黑都一样）。
func (a *Agent) fetchManifest(ctx context.Context, m proto.Manifest) error {
	if a.Chunks == nil || a.Ready == nil || a.Assemble == nil {
		return errors.New("没有接块缓存")
	}
	if a.Ready(m, a.cfg.ArtifactRoot) {
		return nil
	}
	if err := a.pull(ctx, m); err != nil {
		return fmt.Errorf("拉 %s: %w", m.ID, err)
	}
	if err := a.Assemble(m, a.cfg.ArtifactRoot); err != nil {
		return reject("拼 %s: %v", m.ID, err)
	}
	return nil
}

func fileSHA256(p string) (string, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// writeSummary 写 output/_runner/：运行摘要和 job.log 末尾，随输出回传（失败时也能看到原因）。
func (a *Agent) writeSummary(dir string, as proto.JobAssign, job jobsign.Job, signer, digest string, params map[string]json.RawMessage, res jobrun.Result) {
	rd := filepath.Join(dir, "output", jobrun.Runner)
	os.MkdirAll(rd, 0o755)
	sum := map[string]any{"id": as.ID, "attempt": as.Attempt, "node": a.cfg.Node, "package": job.Name + "@" + job.Version,
		"signer": signer, "digest": digest, "params": params, "exit_code": res.ExitCode, "killed": res.Killed,
		"seconds": res.Seconds, "probe": a.version}
	b, _ := json.MarshalIndent(sum, "", "  ")
	os.WriteFile(filepath.Join(rd, "summary.json"), b, 0o644)
	os.WriteFile(filepath.Join(rd, "job.log"), []byte(tailFile(filepath.Join(dir, "job.log"), jobLogKeep)), 0o644)
}

// jobTransport 给回传请求带上节点名和第几次：主控只收当前派到的那台、那一次。
type jobTransport struct {
	node    string
	attempt int
}

func (t jobTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("X-Epsilon-Node", t.node)
	r.Header.Set("X-Epsilon-Attempt", strconv.Itoa(t.attempt))
	return http.DefaultTransport.RoundTrip(r)
}

// uploadOutput 用 joboutput 回传；失败了隔一会儿再续传，最多 5 轮。
func (a *Agent) uploadOutput(ctx context.Context, as proto.JobAssign, out string) error {
	hc := &http.Client{Timeout: 10 * time.Minute, Transport: jobTransport{node: a.cfg.Node, attempt: as.Attempt}}
	wait := a.jobUploadRetry
	if wait <= 0 {
		wait = 30 * time.Second
	}
	var err error
	for i := 0; i < 5; i++ {
		if _, err = joboutput.Upload(ctx, hc, a.cfg.Controller, a.cfg.Token, as.ID, out, 0); err == nil {
			return nil
		}
		log.Printf("任务 %s 输出回传失败（%s 后续传）: %v", as.ID, wait, err)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(wait):
		}
	}
	return err
}

// stopJob 退出时撤销手上的任务并等它收尾（最多 15 秒）。
func (a *Agent) stopJob() {
	a.jmu.Lock()
	cur := a.jobCur
	a.jmu.Unlock()
	if cur == nil {
		return
	}
	cur.cancel()
	select {
	case <-cur.done:
	case <-time.After(15 * time.Second):
	}
}
