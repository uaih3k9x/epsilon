"""一次性任务运行器：执行器做出来之前，用来在真机上按手册布局跑一个任务单元（随签名发布下发）。

用层里的解释器跑: python -E -B job-runner.py --job-dir ... --code-zip ... --code-sha256 ... --params ... --script train.py
核对 code.zip 哈希 → 展开成 code/ params.json output/ tmp/ → 跑脚本并采显存 → 汇总写 runner-done.json 并打印。
跑过就不再跑；打印完默认挂着不退出，免得探针把它当崩溃反复拉起。
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


def run_job(job, code_zip, code_sha256, params, script, gpu_sampler=nvidia_smi_used, sample_seconds=1.0):
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
    samples = [] if baseline is None else [baseline]
    stop = threading.Event()

    def sample():
        while not stop.is_set():
            v = gpu_sampler()
            if v is not None:
                samples.append(v)
            stop.wait(sample_seconds)

    sampler = threading.Thread(target=sample, daemon=True)
    sampler.start()
    start = time.perf_counter()
    rc = subprocess.run([sys.executable, "-E", "-B", str(job / "code" / script)], cwd=job / "code").returncode
    seconds = time.perf_counter() - start
    stop.set()
    sampler.join()

    result_file = job / "output" / "RESULT.json"
    summary = {
        "returncode": rc,
        "seconds": seconds,
        "code_sha256": got,
        "vram_baseline_mb": baseline,
        "vram_peak_mb": max(samples) if samples else None,
        "vram_delta_mb": max(samples) - baseline if samples else None,
        "output_bytes": sum(p.stat().st_size for p in (job / "output").rglob("*") if p.is_file()),
        "output_files": sorted(p.relative_to(job / "output").as_posix() for p in (job / "output").rglob("*") if p.is_file()),
        "result": json.loads(result_file.read_text(encoding="utf-8")) if result_file.exists() else None,
    }
    done.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    return summary


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--job-dir", required=True)
    ap.add_argument("--code-zip", required=True)
    ap.add_argument("--code-sha256", required=True)
    ap.add_argument("--params", required=True)
    ap.add_argument("--script", required=True)
    ap.add_argument("--no-wait", action="store_true")
    a = ap.parse_args()
    summary = run_job(a.job_dir, a.code_zip, a.code_sha256, a.params, a.script)
    print("JOB_DONE " + json.dumps(summary), flush=True)
    while not a.no_wait:
        time.sleep(3600)


if __name__ == "__main__":
    main()
