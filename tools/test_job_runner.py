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
