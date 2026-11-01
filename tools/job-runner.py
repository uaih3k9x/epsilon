"""一次性任务运行器：执行器做出来之前，用来在真机上按手册布局跑一个任务单元（随签名发布下发）。

用层里的解释器跑: python -E -B job-runner.py --job-dir ... --code-zip ... --code-sha256 ... --params ... --script train.py
核对 code.zip 哈希 → 展开成 code/ params.json output/ tmp/ → 跑脚本并采显存 → 汇总写 runner-done.json 并打印。
跑过就不再跑；给了 --job-id 就把 output/ 传回主控。打印完默认挂着不退出，免得探针把它当崩溃反复拉起。
"""
import argparse
import hashlib
import json
import shutil
import subprocess
import sys
import threading
import time
import zipfile
from pathlib import Path

DONE = "runner-done.json"


class RunnerError(Exception):
    pass


def parse_mem(text):
    try:
        return int(text.strip().splitlines()[0])
    except (ValueError, IndexError):
        return None


def nvidia_smi_used():
    try:
        out = subprocess.run(["nvidia-smi", "--query-gpu=memory.used", "--format=csv,noheader,nounits", "-i", "0"],
                             capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.SubprocessError):
        return None
    return parse_mem(out.stdout) if out.returncode == 0 else None


def parse_apps(text):
    """nvidia-smi --query-compute-apps=pid,process_name,used_memory 的输出 -> {pid: (名字, MB 或 None)}。WDDM 下显存常是 [N/A]。"""
    apps = {}
    for line in text.splitlines():
        parts = line.rsplit(",", 1)
        head = parts[0].split(",", 1)
        if len(parts) != 2 or len(head) != 2 or not head[0].strip().isdigit():
            continue
        mem = parts[1].strip()
        apps[int(head[0])] = (head[1].strip(), int(mem) if mem.isdigit() else None)
    return apps


def nvidia_smi_apps():
    try:
        out = subprocess.run(["nvidia-smi", "--query-compute-apps=pid,process_name,used_memory", "--format=csv,noheader,nounits", "-i", "0"],
                             capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.SubprocessError):
        return None
    return parse_apps(out.stdout) if out.returncode == 0 else None


def read_result(path):
    try:
        v = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return v


def run_job(job, code_zip, code_sha256, params, script, gpu_sampler=nvidia_smi_used, apps_sampler=nvidia_smi_apps, sample_seconds=1.0):
    job, code_zip, params = Path(job), Path(code_zip), Path(params)
    got = hashlib.sha256(code_zip.read_bytes()).hexdigest()
    if got != code_sha256:
        raise RunnerError(f"code.zip 的 SHA-256 是 {got}，要的是 {code_sha256}")
    done = job / DONE
    if done.exists():
        return json.loads(done.read_text(encoding="utf-8"))
    if job.exists():  # 上次没跑完：从头来
        shutil.rmtree(job)
    (job / "code").mkdir(parents=True)
    (job / "output").mkdir()
    (job / "tmp").mkdir()
    with zipfile.ZipFile(code_zip) as z:
        z.extractall(job / "code")
    shutil.copyfile(params, job / "params.json")

    baseline = gpu_sampler()
    base_apps = apps_sampler()
    samples = [] if baseline is None else [baseline]
    notes = set()
    if baseline is None:
        notes.add("基线缺失")
    if base_apps is None:
        notes.add("拿不到 GPU 进程列表")
    gpu_failures = [0]
    job_mem = []
    stop = threading.Event()
    start = time.perf_counter()
    proc = subprocess.Popen([sys.executable, "-E", "-B", str(job / "code" / script)], cwd=job / "code")

    def sample():
        while not stop.is_set():
            v = gpu_sampler()
            if v is None:
                gpu_failures[0] += 1
            else:
                samples.append(v)
            apps = apps_sampler()
            if apps is None:
                notes.add("拿不到 GPU 进程列表")
            else:
                me = apps.pop(proc.pid, None)
                if me and me[1] is not None:
                    job_mem.append(me[1])
                if base_apps is not None:
                    for pid in apps.keys() - base_apps.keys():
                        notes.add(f"运行中出现别的 GPU 进程: {apps[pid][0]} (pid {pid})")
                    for pid in base_apps.keys() - apps.keys():
                        notes.add(f"运行中退出了 GPU 进程: {base_apps[pid][0]} (pid {pid})")
            stop.wait(sample_seconds)

    sampler = threading.Thread(target=sample, daemon=True)
    sampler.start()
    rc = proc.wait()
    seconds = time.perf_counter() - start
    stop.set()
    sampler.join()
    if gpu_failures[0]:
        notes.add(f"nvidia-smi 采样失败 {gpu_failures[0]} 次")

    result = read_result(job / "output" / "RESULT.json")
    summary = {
        "returncode": rc,
        "seconds": seconds,
        "code_sha256": got,
        "vram_baseline_mb": baseline,
        "vram_peak_mb": max(samples) if samples else None,
        "vram_delta_mb": max(samples) - baseline if samples and baseline is not None else None,
        "vram_job_process_mb": max(job_mem) if job_mem else None,
        "vram_allocator_peak_mb": result.get("gpu_peak_allocated_mb") if isinstance(result, dict) else None,
        "vram_reliable": not notes,
        "vram_notes": sorted(notes),
        "output_bytes": sum(p.stat().st_size for p in (job / "output").rglob("*") if p.is_file()),
        "output_files": sorted(p.relative_to(job / "output").as_posix() for p in (job / "output").rglob("*") if p.is_file()),
        "result": result,
    }
    done.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    return summary


def publish_summary(job, summary):
    """摘要放进 output/_runner/ 跟输出一起回传，审核人用它校对 gpu_mem_mb。它不算任务自己的输出。"""
    d = Path(job) / "output" / "_runner"
    d.mkdir(parents=True, exist_ok=True)
    (d / "summary.json").write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")


def upload_cmd(exe, job_id, job_dir, config):
    return [exe, "upload", "-id", job_id, "-dir", str(Path(job_dir) / "output"), "-config", config]


def upload_until_ok(cmd, run=lambda c: subprocess.run(c).returncode, sleep=time.sleep, tries=120, delay=60):
    """回传失败只重传，不重跑任务；重传是续传，主控已有的块不再发。"""
    for i in range(tries):
        if run(cmd) == 0:
            return True
        if i + 1 < tries:
            sleep(delay)
    return False


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--job-dir", required=True)
    ap.add_argument("--code-zip", required=True)
    ap.add_argument("--code-sha256", required=True)
    ap.add_argument("--params", required=True)
    ap.add_argument("--script", required=True)
    ap.add_argument("--no-wait", action="store_true")
    ap.add_argument("--job-id", help="给了就在跑完后回传 output/")
    ap.add_argument("--upload-exe")
    ap.add_argument("--probe-config")
    a = ap.parse_args()
    summary = run_job(a.job_dir, a.code_zip, a.code_sha256, a.params, a.script)
    print("JOB_DONE " + json.dumps(summary), flush=True)
    if a.job_id:
        publish_summary(a.job_dir, summary)
        ok = upload_until_ok(upload_cmd(a.upload_exe, a.job_id, a.job_dir, a.probe_config))
        print("UPLOAD_DONE" if ok else "UPLOAD_FAILED", flush=True)
    while not a.no_wait:
        time.sleep(3600)


if __name__ == "__main__":
    main()
