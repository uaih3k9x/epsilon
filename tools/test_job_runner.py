"""job-runner 的测试。运行: python3 -m pytest tools/test_job_runner.py"""

import hashlib
import importlib.util
import json
import os
import zipfile

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
_spec = importlib.util.spec_from_file_location("job_runner", os.path.join(HERE, "job-runner.py"))
jr = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(jr)

TRAIN = """
import json, sys
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
import helper
p = json.loads((ROOT / "params.json").read_text(encoding="utf-8"))
print("EPSILON-PROGRESS 1.000", flush=True)
(ROOT / "output").mkdir(exist_ok=True)
(ROOT / "output" / "RESULT.json").write_text(json.dumps({"ok": p["trial"] == 0, "cwd_flag_B": sys.dont_write_bytecode}), encoding="utf-8")
sys.exit(0 if p["trial"] == 0 else 3)
"""


@pytest.fixture
def pkg(tmp_path):
    z = tmp_path / "code.zip"
    with zipfile.ZipFile(z, "w") as f:
        f.writestr("train.py", TRAIN)
        f.writestr("helper.py", "X = 1\n")
    params = tmp_path / "params.json"
    params.write_text('{"trial": 0}', encoding="utf-8")
    return z, params, hashlib.sha256(z.read_bytes()).hexdigest(), tmp_path / "jobs" / "t0"


def run(z, params, sha, job):
    return jr.run_job(job, z, sha, params, "train.py", gpu_sampler=lambda: None)


def test_runs_with_manual_layout_and_records_result(pkg):
    z, params, sha, job = pkg
    s = run(z, params, sha, job)
    assert s["returncode"] == 0 and s["result"]["ok"] is True
    assert s["result"]["cwd_flag_B"] is True  # 带 -B 跑
    assert (job / "code" / "train.py").exists() and (job / "params.json").exists() and (job / "tmp").is_dir()
    assert s["output_bytes"] > 0
    assert json.loads((job / "runner-done.json").read_text(encoding="utf-8"))["returncode"] == 0


def test_refuses_wrong_code_hash_before_touching_disk(pkg):
    z, params, _, job = pkg
    with pytest.raises(jr.RunnerError):
        run(z, params, "0" * 64, job)
    assert not job.exists()


def test_failure_is_recorded_not_raised(pkg):
    z, params, sha, job = pkg
    params.write_text('{"trial": 1}', encoding="utf-8")
    s = run(z, params, sha, job)
    assert s["returncode"] == 3 and s["result"]["ok"] is False


def test_does_not_run_twice(pkg):
    # 探针会把退出的工作负载拉起来; 跑过一次就只报告, 不重复占 GPU
    z, params, sha, job = pkg
    first = run(z, params, sha, job)
    (job / "output" / "RESULT.json").write_text('{"ok": "changed"}', encoding="utf-8")
    assert run(z, params, sha, job) == first


def test_restart_after_interrupted_run_starts_clean(pkg):
    z, params, sha, job = pkg
    (job / "output").mkdir(parents=True)
    (job / "output" / "stale.bin").write_text("old", encoding="utf-8")
    run(z, params, sha, job)
    assert not (job / "output" / "stale.bin").exists()


def test_gpu_peak_is_measured_against_baseline(pkg):
    z, params, sha, job = pkg
    readings = iter([339, 400, 1200, 800])
    s = jr.run_job(job, z, sha, params, "train.py", gpu_sampler=lambda: next(readings, 800), sample_seconds=0.001)
    assert s["vram_baseline_mb"] == 339
    assert s["vram_peak_mb"] >= 400 and s["vram_delta_mb"] == s["vram_peak_mb"] - 339


def test_parse_nvidia_smi():
    assert jr.parse_mem("339\n") == 339
    assert jr.parse_mem("N/A\n") is None
    assert jr.parse_mem("") is None


def test_upload_retries_until_success():
    calls = []

    def fake(cmd):
        calls.append(cmd)
        return 0 if len(calls) == 3 else 1

    assert jr.upload_until_ok(["epsilon-env", "upload"], run=fake, sleep=lambda s: None) is True
    assert len(calls) == 3


def test_upload_gives_up_after_limit():
    assert jr.upload_until_ok(["x"], run=lambda c: 1, sleep=lambda s: None, tries=2) is False


def test_upload_command_passes_job_and_output_dir():
    cmd = jr.upload_cmd("E:/epsilon-env.exe", "exp029-t0", "D:/jobs/exp029-t0", "D:/probe.json")
    assert cmd[:2] == ["E:/epsilon-env.exe", "upload"]
    assert cmd[cmd.index("-id") + 1] == "exp029-t0"
    assert cmd[cmd.index("-dir") + 1].replace("\\", "/").endswith("exp029-t0/output")
    assert cmd[cmd.index("-config") + 1] == "D:/probe.json"


# --- 显存实测 (#5) ---

BASE_APPS = {7: ("Microsoft.Photos.exe", None), 9: ("[Insufficient Permissions]", None)}


def measure(pkg, gpu=lambda: 500, apps=lambda: dict(BASE_APPS)):
    z, params, sha, job = pkg
    return jr.run_job(job, z, sha, params, "train.py", gpu_sampler=gpu, apps_sampler=apps, sample_seconds=0.001)


def test_clean_run_is_reliable(pkg):
    s = measure(pkg)
    assert s["vram_reliable"] is True and s["vram_notes"] == []


def test_missing_baseline_is_unreliable(pkg):
    readings = iter([None])
    s = measure(pkg, gpu=lambda: next(readings, 800))
    assert s["vram_reliable"] is False
    assert s["vram_baseline_mb"] is None and s["vram_delta_mb"] is None
    assert any("基线" in n for n in s["vram_notes"])


def test_nvidia_smi_failure_midway_is_unreliable(pkg):
    readings = iter([500, None])
    s = measure(pkg, gpu=lambda: next(readings, 800))
    assert s["vram_reliable"] is False
    assert s["vram_baseline_mb"] == 500
    assert any("采样失败" in n for n in s["vram_notes"])


def test_process_list_unavailable_is_unreliable(pkg):
    s = measure(pkg, apps=lambda: None)
    assert s["vram_reliable"] is False
    assert any("进程" in n for n in s["vram_notes"])


def test_foreign_process_appearing_midway_is_flagged(pkg):
    readings = iter([dict(BASE_APPS)])
    s = measure(pkg, apps=lambda: next(readings, {**BASE_APPS, 42: ("game.exe", 3000)}))
    assert s["vram_reliable"] is False
    assert any("game.exe" in n and "42" in n for n in s["vram_notes"])


def test_foreign_process_leaving_midway_is_flagged(pkg):
    # 基线里的进程退出会把差值压低, 同样不可靠
    readings = iter([dict(BASE_APPS)])
    s = measure(pkg, apps=lambda: next(readings, {9: BASE_APPS[9]}))
    assert s["vram_reliable"] is False
    assert any("Microsoft.Photos.exe" in n for n in s["vram_notes"])


def test_job_process_itself_is_not_foreign_and_reports_its_memory(pkg, monkeypatch):
    z, params, sha, job = pkg
    seen = {}
    real_popen = jr.subprocess.Popen

    def popen(*a, **k):
        p = real_popen(*a, **k)
        seen["pid"] = p.pid
        return p

    monkeypatch.setattr(jr.subprocess, "Popen", popen)

    def apps():
        return {**BASE_APPS, seen["pid"]: ("python.exe", 1234)} if "pid" in seen else dict(BASE_APPS)

    s = jr.run_job(job, z, sha, params, "train.py", gpu_sampler=lambda: 500, apps_sampler=apps, sample_seconds=0.001)
    assert s["vram_reliable"] is True, s["vram_notes"]
    # 脚本可能快到采不到; 采到了就必须是任务进程自己的值
    assert s["vram_job_process_mb"] in (None, 1234)


def test_job_process_memory_comes_from_samples(monkeypatch, pkg):
    z, params, sha, job = pkg
    slow = pkg[0].parent / "slow.zip"
    with jr.zipfile.ZipFile(slow, "w") as f:
        f.writestr("train.py", "import time; time.sleep(0.5)\n")
    sha = jr.hashlib.sha256(slow.read_bytes()).hexdigest()
    pids = {}
    real_popen = jr.subprocess.Popen

    def popen(*a, **k):
        p = real_popen(*a, **k)
        pids["job"] = p.pid
        return p

    monkeypatch.setattr(jr.subprocess, "Popen", popen)
    apps = lambda: {pids["job"]: ("python.exe", 1234)} if "job" in pids else {}
    s = jr.run_job(job, slow, sha, params, "train.py", gpu_sampler=lambda: 500, apps_sampler=apps, sample_seconds=0.01)
    assert s["vram_job_process_mb"] == 1234
    assert s["vram_reliable"] is True, s["vram_notes"]


def test_allocator_peak_comes_from_result(tmp_path, pkg):
    z, params, sha, job = pkg
    code = tmp_path / "a.zip"
    with jr.zipfile.ZipFile(code, "w") as f:
        f.writestr("train.py", """
from pathlib import Path
Path(__file__).resolve().parent.parent.joinpath("output", "RESULT.json").write_text('{"gpu_peak_allocated_mb": 812.5}')
""")
    sha = jr.hashlib.sha256(code.read_bytes()).hexdigest()
    s = jr.run_job(job, code, sha, params, "train.py", gpu_sampler=lambda: 500, apps_sampler=lambda: {}, sample_seconds=0.001)
    assert s["vram_allocator_peak_mb"] == 812.5


def test_broken_result_json_does_not_crash_the_runner(tmp_path, pkg):
    # 崩了探针会拉起, 整个任务重跑; RESULT.json 坏了要记下来, 不能重跑
    z, params, sha, job = pkg
    code = tmp_path / "b.zip"
    with jr.zipfile.ZipFile(code, "w") as f:
        f.writestr("train.py", """
from pathlib import Path
Path(__file__).resolve().parent.parent.joinpath("output", "RESULT.json").write_text('[1, 2')
""")
    sha = jr.hashlib.sha256(code.read_bytes()).hexdigest()
    s = jr.run_job(job, code, sha, params, "train.py", gpu_sampler=lambda: None, apps_sampler=lambda: {}, sample_seconds=0.001)
    assert s["result"] is None and s["returncode"] == 0
    assert s["vram_allocator_peak_mb"] is None


def test_parse_compute_apps_windows_output():
    text = "1234, C:\\x\\python.exe, [N/A]\n7, Microsoft.Photos.exe, 300\nbad line\n"
    assert jr.parse_apps(text) == {1234: ("C:\\x\\python.exe", None), 7: ("Microsoft.Photos.exe", 300)}
    assert jr.parse_apps("") == {}


def test_summary_goes_back_with_the_output(pkg):
    z, params, sha, job = pkg
    s = measure(pkg)
    jr.publish_summary(job, s)
    got = json.loads((job / "output" / "_runner" / "summary.json").read_text(encoding="utf-8"))
    assert got["vram_reliable"] is True
    # 不算进任务自己的输出
    assert not any(f.startswith("_runner") for f in got["output_files"])
