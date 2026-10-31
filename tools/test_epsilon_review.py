"""epsilon-review 的测试. 运行: python3 -m pytest tools/test_epsilon_review.py

样本分三类:
  坏样本 —— 每条规则至少一个, 重点是绕过写法, 断言被抓到且级别对;
  干净样本 —— 一个完整任务包, 必须 0 拒签 0 需解释;
  误报控制 —— 看着像但其实没问题的写法, 不许报拒签.
"""

import hashlib
import importlib.util
import io
import json
import os
import zipfile

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
_spec = importlib.util.spec_from_file_location("epsilon_review", os.path.join(HERE, "epsilon-review.py"))
er = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(er)

REJECT, EXPLAIN, INFO = er.REJECT, er.EXPLAIN, er.INFO


def scan_py(src, name="train.py"):
    return er.scan_files({name: src.encode("utf-8")})


def rules(findings, level=None):
    return {f.rule for f in findings if level is None or f.level == level}


def levels_of(findings, rule):
    return {f.level for f in findings if f.rule == rule}


# ======================================================================== 代码层: 拒签

@pytest.mark.parametrize("src", [
    "eval('1+1')",
    "exec(code)",
    "compile(src, 'x', 'exec')",
    "import builtins\nbuiltins.eval('1')",
    "from builtins import eval as e\ne('1')",
    "e = eval\ne('1')",
    "f = exec; f(s)",
    "__builtins__.exec(s)",
    "x = (eval)\nx('1')",
])
def test_exec_family_rejected(src):
    assert "exec-call" in rules(scan_py(src), REJECT)


def test_getattr_builtins_concat_eval_is_caught():
    fs = scan_py('getattr(__builtins__, "ev" + "al")("1")')
    assert "reflect-nonliteral" in rules(fs) and "dunder-access" in rules(fs)
    assert er.verdict(fs) in (REJECT, EXPLAIN)


def test_dunder_import_concat_os_system():
    fs = scan_py('__import__("o" + "s").system("whoami")')
    assert "reflect-nonliteral" in rules(fs, EXPLAIN)
    # .system 调用本身 (对着动态模块) 也要被标出来
    assert "process-call" in rules(fs, REJECT)


@pytest.mark.parametrize("src,rule", [
    ("import pickle\npickle.load(f)", "pickle-use"),
    ("import cPickle", "pickle-use"),
    ("import dill", "pickle-use"),
    ("from joblib import load", "pickle-use"),
    ("import shelve", "pickle-use"),
    ("import marshal", "pickle-use"),
    ("import pandas as pd\npd.read_pickle('x')", "pickle-use"),
    ("import torch\ntorch.load('w.pt')", "unsafe-load"),
    ("import torch\ntorch.load('w.pt', weights_only=False)", "unsafe-load"),
    ("import numpy as np\nnp.load('a.npy', allow_pickle=True)", "unsafe-load"),
    ("import yaml\nyaml.load(f)", "unsafe-load"),
    ("import yaml\nyaml.load(f, Loader=yaml.Loader)", "unsafe-load"),
    ("import yaml\nyaml.unsafe_load(f)", "unsafe-load"),
])
def test_deserialization_rejected(src, rule):
    assert rule in rules(scan_py(src), REJECT)


@pytest.mark.parametrize("src", [
    "import subprocess\nsubprocess.run(['ls'])",
    "from subprocess import Popen",
    "import os\nos.system('x')",
    "import os\nos.popen('x')",
    "import os\nos.execv('/bin/sh', [])",
    "import os\nos.spawnl(os.P_WAIT, 'x')",
    "import os\nos.startfile('x.exe')",
    "import pty",
    "from os import system as s\ns('x')",
])
def test_process_rejected(src):
    assert "process-call" in rules(scan_py(src), REJECT)


@pytest.mark.parametrize("src", ["import ctypes", "from ctypes import windll", "import cffi", "import winreg",
                                 "import win32api", "import _winapi", "import msvcrt"])
def test_native_rejected(src):
    assert "native-api" in rules(scan_py(src), REJECT)


@pytest.mark.parametrize("src", ["import socket", "import requests", "from urllib.request import urlopen",
                                 "import urllib", "import http.client", "import ftplib", "import smtplib",
                                 "import paramiko", "import aiohttp", "import httpx"])
def test_network_rejected(src):
    assert "network" in rules(scan_py(src), REJECT)


def test_write_py_then_import_rejected():
    src = (
        "from pathlib import Path\n"
        "p = Path('tmp') / 'mod.py'\n"
        "with open('tmp/mod.py', 'w') as f:\n"
        "    f.write(payload)\n"
        "import importlib.util\n"
        "spec = importlib.util.spec_from_file_location('mod', 'tmp/mod.py')\n"
    )
    assert "write-then-import" in rules(scan_py(src), REJECT)


def test_write_py_with_runpy_rejected():
    src = "open('x.py','w').write(s)\nimport runpy\nrunpy.run_path('x.py')"
    assert "write-then-import" in rules(scan_py(src), REJECT)


def test_addaudithook_rejected():
    assert "audit-hook" in rules(scan_py("import sys\nsys.addaudithook(lambda *a: None)"), REJECT)


# ======================================================================== 代码层: 需解释

@pytest.mark.parametrize("src", [
    "getattr(models, name)()",
    "setattr(obj, key, 1)",
    "delattr(obj, k)",
    "hasattr(obj, k)",
    "__import__(mod)",
    "import importlib\nimportlib.import_module(f'pkg.{name}')",
])
def test_nonliteral_reflection_needs_explanation(src):
    assert levels_of(scan_py(src), "reflect-nonliteral") == {EXPLAIN}


def test_literal_reflection_is_only_info():
    fs = scan_py("getattr(obj, 'weight')")
    assert levels_of(fs, "reflect-literal") == {INFO}
    assert "reflect-nonliteral" not in rules(fs)


@pytest.mark.parametrize("src", ["globals()[name]()", "locals()['x']", "vars(mod)[k]", "f(globals())"])
def test_namespace_access(src):
    assert "namespace-access" in rules(scan_py(src), EXPLAIN)


@pytest.mark.parametrize("src", ["x.__dict__", "f.__code__", "f.__globals__", "object.__subclasses__()",
                                 "().__class__.__bases__[0]", "t.__reduce__", "type(x).__mro__"])
def test_dunder_access(src):
    assert "dunder-access" in rules(scan_py(src), EXPLAIN)


@pytest.mark.parametrize("src", ["import sys\nsys.path.insert(0, 'x')", "import sys\nsys.path.append(p)",
                                 "import sys\nsys.modules['x'] = m", "import sys\nsys.meta_path.append(f)",
                                 "import os\nos.environ['PATH'] = p"])
def test_import_machinery_changes(src):
    assert "import-machinery" in rules(scan_py(src), EXPLAIN)


@pytest.mark.parametrize("src", [
    "import base64\nbase64.b64decode(s)",
    "import base64\nbase64.urlsafe_b64decode(s)",
    "import binascii\nbinascii.unhexlify(s)",
    "import codecs\ncodecs.decode(s, 'rot13')",
    "bytes.fromhex('6576616c')",
    "import zlib\nzlib.decompress(b)",
    "import lzma\nlzma.decompress(b)",
    "import bz2\nbz2.decompress(b)",
    "s = chr(101)+chr(118)+chr(97)+chr(108)+chr(40)+chr(41)+chr(32)+chr(32)",
])
def test_string_decoding(src):
    assert "string-decode" in rules(scan_py(src), EXPLAIN)


def test_base64_then_exec_is_rejected_overall():
    src = "import base64\nexec(base64.b64decode('cHJpbnQoMSk='))"
    fs = scan_py(src)
    assert er.verdict(fs) == REJECT and "string-decode" in rules(fs)


def test_long_and_high_entropy_literals():
    long_s = "a" * 250
    noisy = "Zm9yIGkgaW4gcmFuZ2UoMTApOiBwcmludChpKQo9PT0hQCMkJV4mKigpXytYeXo1Njc4OQ=="
    assert "suspicious-literal" in rules(scan_py(f"x = '{long_s}'"), EXPLAIN)
    assert "suspicious-literal" in rules(scan_py(f"x = '{noisy}'"), EXPLAIN)


def test_docstring_is_not_suspicious_literal():
    doc = "这是一段很长的中文说明。" * 30
    fs = scan_py(f'"""{doc}"""\ndef f():\n    """{doc}"""\n    return 1\n')
    assert "suspicious-literal" not in rules(fs)


def test_writes_outside_task_dir():
    for p in ("C:\\\\Users\\\\x.txt", "/etc/passwd", "~/x", "%TEMP%/a", "C:/AppData/x"):
        fs = scan_py(f"open('{p}', 'w')")
        assert "write-outside" in rules(fs, EXPLAIN), p


def test_download_functions():
    fs = scan_py("from transformers import AutoModel\nAutoModel.from_pretrained('bert-base-uncased')")
    assert "download" in rules(fs, EXPLAIN)
    fs = scan_py("from transformers import AutoModel\nAutoModel.from_pretrained(DATA / 'bert')")
    assert levels_of(fs, "download") <= {INFO, EXPLAIN}
    fs = scan_py("import torch\ntorch.hub.load('pytorch/vision', 'resnet18')")
    assert "download" in rules(fs, EXPLAIN)


# ======================================================================== 误报控制

@pytest.mark.parametrize("src", [
    "import torch\nsd = torch.load(p, weights_only=True)",
    "import yaml\ncfg = yaml.safe_load(f)",
    "import yaml\ncfg = yaml.load(f, Loader=yaml.SafeLoader)",
    "import numpy as np\na = np.load('a.npy')",
    "import numpy as np\na = np.load('a.npy', allow_pickle=False)",
    "import gzip\nwith gzip.open(p, 'rt', encoding='utf-8') as f:\n    rows = f.read()",
    "getattr(obj, 'weight')",
    "import json\nP = json.load(open('params.json', encoding='utf-8'))",
    "from torch.utils.data import DataLoader\nDataLoader(ds, num_workers=2)",
    "import multiprocessing as mp\nmp.set_start_method('spawn')",
    "with open(OUT / 'RESULT.json', 'w', encoding='utf-8') as f:\n    f.write(s)",
    "def evaluate(model):\n    model.eval()\n    return 1",
    "x.compile_model()",
])
def test_no_false_reject(src):
    fs = scan_py(src)
    assert not rules(fs, REJECT), [f.message for f in fs if f.level == REJECT]


def test_method_named_eval_is_fine():
    # model.eval() 是 PyTorch 的常规用法, 不是 builtins.eval
    assert "exec-call" not in rules(scan_py("model.eval()\nnet.train()"))


# ======================================================================== 文件层

def test_extension_whitelist_and_magic():
    fs = er.scan_files({"run.bat": b"@echo off", "weights.pkl": b"\x80\x04K\x01.", "a.py": b"x=1"})
    assert {"file-type"} <= rules(fs, REJECT)
    assert {f.file for f in fs if f.rule == "file-type"} == {"run.bat", "weights.pkl"}


@pytest.mark.parametrize("name,data", [
    ("config.json", b"MZ\x90\x00" + b"\x00" * 60),          # PE 改名
    ("notes.txt", b"\x7fELF\x02\x01\x01"),                    # ELF
    ("data.csv", b"\x80\x04\x95\x10\x00\x00"),                # pickle 协议头
    ("readme.md", b"PK\x03\x04" + b"\x00" * 20),              # zip
    ("x.yaml", b"7z\xbc\xaf\x27\x1c"),                        # 7z
    ("y.toml", b"Rar!\x1a\x07\x00"),                          # rar
    ("z.txt", b"\x1f\x8b\x08\x00"),                           # gzip
    ("m.py", b"\x61\x0d\x0d\x0a" + b"\x00" * 12),             # .pyc 魔数 (3.12)
])
def test_magic_bytes_beat_extension(name, data):
    assert "file-magic" in rules(er.scan_files({name: data}), REJECT)


@pytest.mark.parametrize("name", ["../evil.py", "/abs.py", "C:/x.py", "a/b:stream.py", "CON.py", "sub/nul.txt",
                                  "trail.py.", "space.py ", "com1.json"])
def test_bad_paths(name):
    assert "bad-path" in rules(er.scan_files({name: b"x=1"}), REJECT)


def test_case_conflict():
    assert "bad-path" in rules(er.scan_files({"Data.py": b"x=1", "data.py": b"y=2"}), REJECT)


def test_big_and_non_utf8_text():
    fs = er.scan_files({"big.csv": b"a,b\n" * 400000, "gbk.txt": "中文".encode("gbk")})
    assert "big-text" in rules(fs, EXPLAIN) and "encoding" in rules(fs, EXPLAIN)


def test_junk_files_info():
    fs = er.scan_files({"__pycache__/a.cpython-311.pyc": b"x", ".DS_Store": b"x", "a.py": b"x=1"})
    assert "junk" in rules(fs, INFO)


def test_nested_archive_in_zip(tmp_path):
    inner = io.BytesIO()
    with zipfile.ZipFile(inner, "w") as z:
        z.writestr("x.py", "print(1)")
    outer = tmp_path / "code.zip"
    with zipfile.ZipFile(outer, "w") as z:
        z.writestr("a.py", "x = 1")
        z.writestr("inner.zip", inner.getvalue())
    fs = er.scan_package(str(outer))
    assert "file-magic" in rules(fs, REJECT) or "file-type" in rules(fs, REJECT)


def test_symlink_in_zip_rejected(tmp_path):
    p = tmp_path / "code.zip"
    with zipfile.ZipFile(p, "w") as z:
        info = zipfile.ZipInfo("link.py")
        info.external_attr = (0o120777 << 16)
        z.writestr(info, "/etc/passwd")
    assert "bad-path" in rules(er.scan_package(str(p)), REJECT)


# ======================================================================== job.json

def _pkg(tmp_path, job, files):
    code = tmp_path / "code"
    code.mkdir()
    for n, s in files.items():
        (code / n).write_text(s, encoding="utf-8")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for n, s in sorted(files.items()):
            z.writestr(n, s)
    (tmp_path / "code.zip").write_bytes(buf.getvalue())
    job.setdefault("code_sha256", hashlib.sha256(buf.getvalue()).hexdigest())
    (tmp_path / "job.json").write_text(json.dumps(job, ensure_ascii=False), encoding="utf-8")
    return str(tmp_path)


GOOD_JOB = {
    "schema": 1, "name": "cifar10-hpsearch", "version": "1.0.0", "description": "网格搜索",
    "owner": "zhangsan", "entry": ["python", "train.py"], "env": "py311-torch2.5-cu124@3",
    "data": ["cifar10@1"],
    "params": {"trial": {"type": "int", "min": 0, "max": 23}, "subset": {"type": "string", "enum": ["tiny", "full"]}},
    "gpu_mem_mb": 3500, "max_hours": 2, "disk_max_mb": 1024, "output_max_mb": 100, "network": False, "gpu": True,
}

CLEAN_TRAIN = '''"""CIFAR-10 上 ResNet-18 的一个 trial."""
import json
import os
import random
from pathlib import Path

CODE = Path(__file__).resolve().parent
ROOT = CODE.parent
DATA, OUT, TMP = ROOT / "data" / "cifar10@1", ROOT / "output", ROOT / "tmp"
LRS = [0.2, 0.1, 0.05, 0.02]
MODELS = {"resnet18": "ResNet18"}


def load_params():
    with open(ROOT / "params.json", encoding="utf-8") as f:
        p = json.load(f)
    trial = int(p["trial"])
    subset = p.get("subset", "full")
    assert 0 <= trial < 24 and subset in ("tiny", "full")
    return trial, subset


def main():
    for k in ("TORCH_HOME", "MPLCONFIGDIR"):
        os.environ[k] = str(TMP / k.lower())
    OUT.mkdir(exist_ok=True)
    import torch
    from safetensors.torch import save_file
    trial, subset = load_params()
    random.seed(trial)
    torch.manual_seed(trial)
    model = torch.nn.Linear(4, 2)
    model.eval()
    state = torch.load(DATA / "init.pt", weights_only=True)
    model.load_state_dict(state)
    save_file(model.state_dict(), str(OUT / "best.safetensors"))
    tmp = OUT / "RESULT.json.tmp"
    tmp.write_text(json.dumps({"ok": True, "trial": trial}), encoding="utf-8")
    tmp.replace(OUT / "RESULT.json")
    print(f"EPSILON-PROGRESS 1.000 trial {trial}", flush=True)


if __name__ == "__main__":
    main()
'''


def test_clean_package_has_no_findings_above_info(tmp_path):
    root = _pkg(tmp_path, dict(GOOD_JOB), {"train.py": CLEAN_TRAIN, "README.md": "# 说明\n"})
    fs = er.scan_package(root)
    bad = [(f.level, f.rule, f.message) for f in fs if f.level in (REJECT, EXPLAIN)]
    assert bad == []
    assert er.verdict(fs) == INFO or er.verdict(fs) is None


def test_job_schema_problems(tmp_path):
    job = dict(GOOD_JOB)
    del job["owner"]
    job["name"] = "Bad Name"
    root = _pkg(tmp_path, job, {"train.py": "x = 1\n"})
    fs = er.scan_package(root)
    assert "job-schema" in rules(fs, REJECT)


@pytest.mark.parametrize("entry", [["cmd", "/c", "x"], ["powershell", "-c", "x"], ["python", "-c", "print(1)"],
                                   ["sh", "x.sh"], ["train.exe"]])
def test_job_entry_problems(tmp_path, entry):
    job = dict(GOOD_JOB, entry=entry)
    root = _pkg(tmp_path, job, {"train.py": "x = 1\n"})
    assert "job-entry" in rules(er.scan_package(root), REJECT)


def test_job_sha_mismatch(tmp_path):
    job = dict(GOOD_JOB, code_sha256="0" * 64)
    root = _pkg(tmp_path, job, {"train.py": "x = 1\n"})
    assert "job-sha" in rules(er.scan_package(root), REJECT)


def test_unconstrained_params_need_explanation(tmp_path):
    job = dict(GOOD_JOB, params={"path": {"type": "string"}, "lr": {"type": "number"}})
    root = _pkg(tmp_path, job, {"train.py": "import json\nP = json.load(open('p'))\nx = P['path']\ny = P.get('lr')\n"})
    fs = er.scan_package(root)
    assert levels_of(fs, "param-unconstrained") == {EXPLAIN}


def test_undeclared_param_use(tmp_path):
    root = _pkg(tmp_path, dict(GOOD_JOB), {"train.py": "import json\nP = json.load(open('p'))\nx = P['script']\n"})
    fs = er.scan_package(root)
    assert any(f.rule == "param-undeclared" and "script" in f.message for f in fs)


# ======================================================================== 鲁棒性 / 输出

def test_syntax_error_is_tool_error():
    fs = scan_py("def f(:\n  pass")
    assert "parse-error" in rules(fs, er.ERROR)
    assert er.exit_code(fs) == 3


def test_corrupt_zip_is_tool_error(tmp_path):
    p = tmp_path / "code.zip"
    p.write_bytes(b"PK\x03\x04garbage")
    fs = er.scan_package(str(p))
    assert er.exit_code(fs) == 3


def test_exit_codes():
    assert er.exit_code([]) == 0
    assert er.exit_code(scan_py("getattr(o, 'w')")) == 0
    assert er.exit_code(scan_py("getattr(o, n)")) == 1
    assert er.exit_code(scan_py("eval('1')")) == 2
    assert er.exit_code(scan_py("getattr(o, n)"), strict=True) == 2


def test_json_report_shape(tmp_path):
    root = _pkg(tmp_path, dict(GOOD_JOB), {"train.py": "eval('1')\n"})
    fs = er.scan_package(root)
    rep = json.loads(er.render_json(root, fs))
    assert rep["verdict"] == REJECT and rep["counts"][REJECT] >= 1
    f = next(x for x in rep["findings"] if x["rule"] == "exec-call")
    assert {"level", "rule", "file", "line", "col", "snippet", "message", "hint"} <= set(f)
    assert f["file"] == "train.py" and f["line"] == 1


def test_text_report_mentions_location_and_hint():
    fs = scan_py("x = 1\ngetattr(models, name)()\n")
    txt = er.render_text("pkg", fs)
    assert "train.py:2" in txt and "需解释" in txt


def test_cli_end_to_end(tmp_path):
    import subprocess
    import sys
    root = _pkg(tmp_path, dict(GOOD_JOB), {"train.py": "import pickle\n"})
    r = subprocess.run([sys.executable, os.path.join(HERE, "epsilon-review.py"), root],
                       capture_output=True, text=True)
    assert r.returncode == 2 and "pickle" in r.stdout


def test_never_imports_scanned_code(tmp_path):
    # 被审核的代码里就算有顶层副作用, 扫描时也不能被执行
    marker = tmp_path / "pwned"
    src = f"open({str(marker)!r}, 'w').write('x')\n"
    scan_py(src)
    assert not marker.exists()
