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
import stat
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


# ======================================================================== 代码层: 动态执行 / 进程 / 系统 API / 联网
# 2026-11-01 分级调整 (issue #3 评论): 这四类从拒签降到需解释, 审核人当场判断;
# 拒签只留审核人读不到的代码 (二进制、pickle 系、写 .py 再导入、审计钩子).

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
def test_exec_family_needs_explanation(src):
    fs = scan_py(src)
    assert levels_of(fs, "exec-call") == {EXPLAIN}
    assert not rules(fs, REJECT)


def test_getattr_builtins_concat_eval_is_caught():
    fs = scan_py('getattr(__builtins__, "ev" + "al")("1")')
    assert "reflect-nonliteral" in rules(fs) and "dunder-access" in rules(fs)
    assert er.verdict(fs) in (REJECT, EXPLAIN)


def test_dunder_import_concat_os_system():
    fs = scan_py('__import__("o" + "s").system("whoami")')
    assert "reflect-nonliteral" in rules(fs, EXPLAIN)
    # .system 调用本身 (对着动态模块) 也要被标出来
    assert "process-call" in rules(fs, EXPLAIN)


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
def test_process_needs_explanation(src):
    fs = scan_py(src)
    assert "process-call" in rules(fs, EXPLAIN)
    assert not rules(fs, REJECT)


@pytest.mark.parametrize("src", ["import ctypes", "from ctypes import windll", "import cffi", "import winreg",
                                 "import win32api", "import _winapi", "import msvcrt"])
def test_native_needs_explanation(src):
    fs = scan_py(src)
    assert "native-api" in rules(fs, EXPLAIN)
    assert not rules(fs, REJECT)


@pytest.mark.parametrize("src", ["import socket", "import requests", "from urllib.request import urlopen",
                                 "import urllib", "import http.client", "import ftplib", "import smtplib",
                                 "import paramiko", "import aiohttp", "import httpx"])
def test_network_needs_explanation(src):
    fs = scan_py(src)
    assert "network" in rules(fs, EXPLAIN)
    assert not rules(fs, REJECT)


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


def test_base64_then_exec_needs_at_least_explanation():
    src = "import base64\nexec(base64.b64decode('cHJpbnQoMSk='))"
    fs = scan_py(src)
    assert er.verdict(fs) in (REJECT, EXPLAIN) and er.exit_code(fs) >= 1
    assert "string-decode" in rules(fs) and "exec-call" in rules(fs)


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
    assert er.exit_code(scan_py("eval('1')")) == 1
    assert er.exit_code(scan_py("eval('1')"), strict=True) == 2
    assert er.exit_code(scan_py("import pickle")) == 2
    assert er.exit_code(scan_py("getattr(o, n)"), strict=True) == 2


def test_json_report_shape(tmp_path):
    root = _pkg(tmp_path, dict(GOOD_JOB), {"train.py": "eval('1')\n"})
    fs = er.scan_package(root)
    rep = json.loads(er.render_json(root, fs))
    assert rep["verdict"] == EXPLAIN and rep["counts"][EXPLAIN] >= 1 and rep["counts"][REJECT] == 0
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


# ======================================================================== 补充: 绕过写法 / 分级边界

@pytest.mark.parametrize("src,rule", [
    ("__builtins__['exec'](s)", "exec-call"),
    ("import os\ngetattr(os, 'system')('x')", "process-call"),
    ("import importlib\nimportlib.import_module('subprocess')", "process-call"),
    ("m = __import__('socket')", "network"),
    ("import nt\nnt.system('x')", "process-call"),
    ("import asyncio\nasyncio.create_subprocess_shell('x')", "process-call"),
])
def test_bypass_forms_need_explanation(src, rule):
    assert rule in rules(scan_py(src), EXPLAIN)


def test_getattr_literal_dunder_is_not_just_info():
    fs = scan_py("getattr(f, '__globals__')")
    assert "dunder-access" in rules(fs, EXPLAIN)


def test_urllib_parse_is_not_network():
    assert "network" not in rules(scan_py("from urllib.parse import urlparse\nurlparse('x')"))


def test_multiprocessing_is_only_info():
    fs = scan_py("import multiprocessing as mp\nmp.Process(target=f).start()")
    assert not rules(fs, REJECT) and not rules(fs, EXPLAIN)


def test_non_utf8_coding_cookie_rejected():
    # 声明了别的源码编码: 审核人看到的字节和解释器执行的不是一回事
    fs = scan_py("# -*- coding: utf-7 -*-\nx = 1\n")
    assert "source-encoding" in rules(fs, REJECT)
    assert not rules(scan_py("# -*- coding: utf-8 -*-\nx = 1\n"))


@pytest.mark.parametrize("src", ["import tempfile\ntempfile.mkdtemp()", "import tempfile\ntempfile.NamedTemporaryFile()"])
def test_tempfile_without_dir_writes_outside(src):
    assert "write-outside" in rules(scan_py(src), EXPLAIN)


def test_tempfile_with_dir_is_fine():
    assert "write-outside" not in rules(scan_py("import tempfile\ntempfile.mkdtemp(dir=TMP)"))


def test_write_py_alone_needs_explanation():
    fs = scan_py("open('tmp/gen.py', 'w').write(s)\n")
    assert levels_of(fs, "write-then-import") == {EXPLAIN}


def test_no_cold_wording():
    # 11-01: 文案不再写"不接受解释"
    srcs = ["eval('1')", "import pickle", "import subprocess", "import socket", "import ctypes",
            "import sys\nsys.addaudithook(h)"]
    for src in srcs:
        for f in scan_py(src):
            assert "不接受" not in f.message + f.hint, (src, f.message, f.hint)


# ======================================================================== 补充: 文件层 / zip 层

@pytest.mark.parametrize("name,data", [
    ("arr.csv", b"\x93NUMPY\x01\x00v\x00{'descr': '<f8'"),           # .npy 改名
    ("w.txt", b"\x55\x0d\x0d\x0a" + b"\x00" * 12),                   # .pyc 改名成 .txt
    ("m.json", b"\x00asm\x01\x00\x00\x00"),                          # wasm
    ("t.md", b"x" * 257 + b"ustar\x0000" + b"\x00" * 240),           # tar 改名
    ("b.txt", b"BZh91AY&SY" + b"\x00" * 10),                         # bz2
    ("c.txt", b"\xfd7zXZ\x00\x00"),                                  # xz
    ("d.txt", b"\x28\xb5\x2f\xfd\x00"),                              # zstd
    ("e.txt", b"\xcf\xfa\xed\xfe\x07\x00"),                          # Mach-O 64 (反序)
    ("f.txt", b"\xca\xfe\xba\xbe\x00\x00"),                          # Mach-O fat
])
def test_more_magic(name, data):
    assert "file-magic" in rules(er.scan_files({name: data}), REJECT)


def test_text_starting_with_mz_is_not_pe():
    assert "file-magic" not in rules(er.scan_files({"notes.txt": b"MZ notes: hello\n"}))


def _zip(path, entries):
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        for name, data in entries:
            z.writestr(name, data)
    return str(path)


def _mark_encrypted(path, name):
    # zipfile 写不出加密条目, 直接在本地头和中央目录里置加密标志位 (bit 0)
    data = bytearray(path.read_bytes())
    with zipfile.ZipFile(path) as z:
        data[z.getinfo(name).header_offset + 6] |= 0x1
    i = data.find(b"PK\x01\x02")
    while i >= 0:
        n = int.from_bytes(data[i + 28:i + 30], "little")
        if data[i + 46:i + 46 + n] == name.encode():
            data[i + 8] |= 0x1
        i = data.find(b"PK\x01\x02", i + 4)
    path.write_bytes(bytes(data))


def test_encrypted_entry_rejected(tmp_path):
    p = tmp_path / "code.zip"
    _zip(p, [("a.py", "x = 1"), ("secret.py", "import os")])
    _mark_encrypted(p, "secret.py")
    assert "zip-encrypted" in rules(er.scan_package(str(p)), REJECT)


def test_duplicate_entry_rejected(tmp_path):
    import warnings
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        p = _zip(tmp_path / "code.zip", [("a.py", "x = 1"), ("a.py", "import pickle")])
    assert "bad-path" in rules(er.scan_package(p), REJECT)


def test_zip_bomb_is_tool_error(tmp_path, monkeypatch):
    monkeypatch.setattr(er, "MAX_UNPACKED_BYTES", 1 << 20)
    p = _zip(tmp_path / "code.zip", [("a.py", "x = 1"), ("big.txt", b"\x00" * (2 << 20))])
    fs = er.scan_package(p)
    assert "zip-too-big" in rules(fs, er.ERROR) and er.exit_code(fs) == 3


def test_empty_zip_is_tool_error(tmp_path):
    p = _zip(tmp_path / "code.zip", [])
    assert er.exit_code(er.scan_package(p)) == 3


def test_python2_and_non_utf8_source_are_tool_errors():
    assert er.exit_code(scan_py("print 'hello'\n")) == 3
    fs = er.scan_files({"train.py": "x = '中文'\n".encode("gbk")})
    assert er.exit_code(fs) == 3


def test_directory_package_with_symlink(tmp_path):
    code = tmp_path / "code"
    code.mkdir()
    (code / "a.py").write_text("x = 1\n", encoding="utf-8")
    os.symlink("/etc/passwd", code / "link.txt")
    assert "bad-path" in rules(er.scan_package(str(code)), REJECT)


# ======================================================================== 补充: 干净样本 / 性能 / 接入契约

HANDBOOK_13_1_JOB = {
    "schema": 1, "name": "cifar10-resnet18-hpsearch", "version": "1.0.0",
    "description": "CIFAR-10 上 ResNet-18 的学习率 × 权重衰减 × 种子网格搜索，每个 trial 一组",
    "owner": "zhangsan", "entry": ["python", "train.py"], "env": "py311-torch2.5-cu124@1", "data": ["cifar10@1"],
    "params": {"trial": {"type": "int", "min": 0, "max": 23},
               "epochs": {"type": "int", "min": 1, "max": 60, "default": 30}},
    "gpu_mem_mb": 3500, "max_hours": 2, "disk_max_mb": 1024, "output_max_mb": 100, "network": False, "gpu": True,
}

HANDBOOK_13_1_TRAIN = '''import json
import os
import random
from pathlib import Path

CODE = Path(__file__).resolve().parent
ROOT = CODE.parent
DATA, OUT, TMP = ROOT / "data" / "cifar10@1", ROOT / "output", ROOT / "tmp"

LRS = [0.2, 0.1, 0.05, 0.02]
WDS = [5e-4, 1e-4]
SEEDS = [0, 1, 2]


def load_params():
    with open(ROOT / "params.json", encoding="utf-8") as f:
        p = json.load(f)
    trial = int(p["trial"])
    epochs = int(p.get("epochs", 30))
    assert 0 <= trial < len(LRS) * len(WDS) * len(SEEDS), "trial 超出范围"
    assert 1 <= epochs <= 60, "epochs 超出范围"
    lr = LRS[trial % 4]
    wd = WDS[(trial // 4) % 2]
    seed = SEEDS[trial // 8]
    return trial, epochs, lr, wd, seed


def main():
    for k in ("TORCH_HOME", "MPLCONFIGDIR", "XDG_CACHE_HOME"):
        os.environ[k] = str(TMP / k.lower())
    OUT.mkdir(exist_ok=True)
    TMP.mkdir(exist_ok=True)

    import numpy as np
    import torch
    from safetensors.torch import save_file
    trial, epochs, lr, wd, seed = load_params()
    random.seed(seed); np.random.seed(seed); torch.manual_seed(seed); torch.cuda.manual_seed_all(seed)
    torch.cuda.set_per_process_memory_fraction(3500 / 8192)
    torch.set_num_threads(8)

    print(f"trial={trial} lr={lr} wd={wd} seed={seed} epochs={epochs}", flush=True)
    best = 0.0
    for epoch in range(1, epochs + 1):
        acc = train_one_epoch_and_eval(...)
        print(f"EPSILON-PROGRESS {epoch / epochs:.3f} epoch {epoch} val_acc {acc:.4f}", flush=True)
        if acc > best:
            best = acc
            save_file(model.state_dict(), str(OUT / "best.safetensors"))

    result = {"ok": True, "metrics": {"best_val_acc": best},
              "params": {"trial": trial, "lr": lr, "wd": wd, "seed": seed, "epochs": epochs}}
    tmp = OUT / "RESULT.json.tmp"
    tmp.write_text(json.dumps(result, ensure_ascii=False), encoding="utf-8")
    tmp.replace(OUT / "RESULT.json")


if __name__ == "__main__":
    main()
'''


def test_handbook_13_1_package_is_clean(tmp_path):
    root = _pkg(tmp_path, dict(HANDBOOK_13_1_JOB), {"train.py": HANDBOOK_13_1_TRAIN})
    fs = er.scan_package(root)
    assert [(f.level, f.rule, f.message) for f in fs if f.level != INFO] == []
    assert er.exit_code(fs, strict=True) == 0


def test_fifty_files_under_two_seconds(tmp_path):
    import time
    files = {f"mod{i:02d}.py": CLEAN_TRAIN * 3 for i in range(49)}
    files["README.md"] = "# 说明\n" * 100
    root = _pkg(tmp_path, dict(GOOD_JOB), files)
    t0 = time.perf_counter()
    fs = er.scan_package(root)
    assert time.perf_counter() - t0 < 2.0
    assert fs.meta["files"] == 50


def _cli(*args):
    import subprocess
    import sys
    return subprocess.run([sys.executable, "-I", os.path.join(HERE, "epsilon-review.py"), *args],
                          capture_output=True, text=True)


def test_cli_json_strict_contract(tmp_path):
    # sign-job 以后按这个契约接: --json 的 code_sha256 必须是被扫 zip 的哈希, 退出码和 strict 一致
    root = _pkg(tmp_path, dict(GOOD_JOB), {"train.py": "getattr(o, name)\n"})
    zsha = hashlib.sha256((tmp_path / "code.zip").read_bytes()).hexdigest()
    r = _cli(root, "--json")
    rep = json.loads(r.stdout)
    assert r.returncode == 1 and rep["exit_code"] == 1
    assert rep["code_sha256"] == zsha == rep["sha256"]
    assert isinstance(rep["rules_version"], int) and rep["tool_version"]
    r = _cli(root, "--json", "--strict")
    assert r.returncode == 2 and json.loads(r.stdout)["exit_code"] == 2
    r = _cli(str(tmp_path / "code.zip"), "--job", str(tmp_path / "job.json"), "--json")
    assert r.returncode == 1 and json.loads(r.stdout)["code_sha256"] == zsha


@pytest.mark.parametrize("kind", ["corrupt", "empty", "py2", "gbk", "missing"])
def test_cli_tool_errors_exit_3_without_traceback(tmp_path, kind):
    p = tmp_path / "code.zip"
    if kind == "corrupt":
        p.write_bytes(b"PK\x03\x04garbage")
    elif kind == "empty":
        _zip(p, [])
    elif kind == "py2":
        _zip(p, [("a.py", "print 'x'\n")])
    elif kind == "gbk":
        _zip(p, [("a.py", "x = '中文'\n".encode("gbk"))])
    r = _cli(str(p))
    assert r.returncode == 3, (r.stdout, r.stderr)
    assert "Traceback" not in r.stdout + r.stderr


def test_package_scan_never_executes_code(tmp_path):
    marker = tmp_path / "pwned"
    src = f"open({str(marker)!r}, 'w').write('x')\nimport os\nos.system('touch {marker}')\n"
    root = _pkg(tmp_path, dict(GOOD_JOB), {"train.py": src, "conftest.py": src, "setup.py": src})
    er.scan_package(root)
    _cli(root, "--json")
    assert not marker.exists()


@pytest.mark.parametrize("src", ["from os import *\nsystem('x')", "from subprocess import *"])
def test_star_import_from_risky_module(src):
    assert "star-import" in rules(scan_py(src), EXPLAIN)


def test_attrgetter_needs_explanation():
    fs = scan_py("import operator, os\noperator.attrgetter('system')(os)('x')")
    assert "reflect-nonliteral" in rules(fs, EXPLAIN)


@pytest.mark.parametrize("src,rule,level", [
    ("e = __builtins__.__dict__['exec']", "exec-call", EXPLAIN),
    ("import sys\ngetattr(sys, 'addaudithook')(h)", "audit-hook", REJECT),
    ("from torch import load\nload('w.pt')", "unsafe-load", REJECT),
    ("np = __import__('numpy')\nnp.load(p, allow_pickle=True)", "unsafe-load", REJECT),
    ("import importlib\nimportlib.import_module('pickle')", "pickle-use", REJECT),
    ("from pathlib import Path\nPath('tmp/gen.py').write_text(c)\nimport runpy\nrunpy.run_path('tmp/gen.py')",
     "write-then-import", REJECT),
    ("class X:\n    def __reduce__(self):\n        return (print, ())", "dunder-access", EXPLAIN),
])
def test_more_bypasses(src, rule, level):
    assert level in levels_of(scan_py(src), rule)


def test_bindings_are_scoped_per_function():
    # 另一个函数里同名变量指向 .py，不该把这里的写入算成写 .py 再导入
    src = ("import importlib\n"
           "def a():\n    p = 'mod.py'\n    return importlib.import_module('json')\n"
           "def b(out):\n    p = out / 'data.bin.txt'\n    p.write_bytes(b'')\n"
           "def c(p):\n    p.write_text('x')\n"
           "p = 'top.py'\n")
    assert "write-then-import" not in rules(scan_py(src))
    src2 = "import runpy\nP = 'gen.py'\ndef f():\n    open(P, 'w').write(s)\n    runpy.run_path(P)\n"
    assert "write-then-import" in rules(scan_py(src2), REJECT)


def test_sys_path_assignment_counts_as_import_mechanism():
    src = "import sys\nopen('tmp/gen.py', 'w').write(s)\nsys.path = ['tmp'] + sys.path\nimport gen\n"
    assert "write-then-import" in rules(scan_py(src), REJECT)


# ======================================================================== PR #14 审查意见的回归样本

@pytest.mark.parametrize("data", [
    b'#\x0cx\n# coding: utf-7\nx = 1 #+AAo-import os\n',      # \x0c: splitlines 算换行, 分词器不算
    b'#\x1cx\n# coding: utf-7\nx = 1\n',
    "#\x85x\n# coding: utf-7\nx = 1\n".encode("utf-8"),        # U+0085
    b'#x\r#y\n# coding: utf-7\nx = 1\n',                       # import 时按 \n 分行, 声明在第 2 行
    b'#x\r# coding: utf-7\nx = 1\n',                           # 直接运行时 \r 也算换行
])
def test_source_encoding_cookie_line_split_bypass(data):
    assert "source-encoding" in rules(er.scan_files({"main.py": data}), REJECT)


def test_coding_cookie_on_line_3_is_ignored_like_interpreter():
    assert "source-encoding" not in rules(scan_py("x = 1\ny = 2\n# coding: utf-7\n"))


def test_junk_dir_code_is_scanned():
    # __MACOSX 是合法标识符, 能当命名空间包导入
    fs = er.scan_files({"__MACOSX/evil.py": b"import pickle, os\nos.system('id')\n",
                        "train.py": b"import __MACOSX.evil\n"})
    assert "pickle-use" in rules(fs, REJECT) and "junk" in rules(fs, INFO)


def test_junk_dir_binary_is_rejected():
    fs = er.scan_files({".git/blob": bytes(range(256)) + b"x" * 44, "a.py": b"x = 1\n"})
    assert "file-type" in rules(fs, REJECT)


def test_entry_in_junk_dir_rejected():
    job = dict(GOOD_JOB, entry=["python", "__MACOSX/run.py"], code_sha256="0" * 64)
    fs = er.scan_files({"__MACOSX/run.py": b"x = 1\n"}, job=job)
    assert "job-entry" in rules(fs, REJECT)


@pytest.mark.parametrize("src,level", [
    ("import functools, numpy as np\nf = functools.partial(np.load, allow_pickle=True)\nf('a.npy')", REJECT),
    ("from functools import partial\nimport torch\nf = partial(torch.load, weights_only=False)", REJECT),
    ("import torch\nL = torch.load if True else None\nL('w.pt')", EXPLAIN),
    ("import yaml\nld = (yaml.load,)[0]\nld(open('a.yml'))", EXPLAIN),
    ("import numpy as np\nnp.lib.format.read_array(f, allow_pickle=True)", REJECT),
    ("import numpy as np\nnp.lib.npyio.load('x.txt', allow_pickle=True)", REJECT),
    ("from multiprocessing.reduction import ForkingPickler\nForkingPickler.loads(d)", REJECT),
    ("import multiprocessing as mp\nmp.reduction.ForkingPickler.loads(d)", REJECT),
])
def test_indirect_unsafe_load(src, level):
    fs = scan_py(src)
    assert level in {f.level for f in fs if f.rule in ("unsafe-load", "pickle-use")}, [(f.level, f.rule) for f in fs]


def test_direct_safe_load_has_no_indirect_finding():
    fs = scan_py("import torch\nfrom torch import load\ntorch.load(p, weights_only=True)\nload(p, weights_only=True)")
    assert "unsafe-load" not in rules(fs)


@pytest.mark.parametrize("src", [
    "import os\ndef f(m):\n    return m.system\nf(os)('id')",
    "import os\ndef f(m):\n    return getattr(m, 'system')\nf(os)('id')",
    "def f(m):\n    m.execv('/bin/sh', [])",
])
def test_process_attr_on_unknown_receiver(src):
    assert "process-call" in rules(scan_py(src), EXPLAIN)


def test_common_run_and_call_methods_not_flagged():
    assert "process-call" not in rules(scan_py("trainer.run()\nsess.call(x)\napp.run(debug=False)"))


@pytest.mark.parametrize("src", [
    "open('helper.py', 'w').write(s)\nimport helper\n",
    "from pathlib import Path\nPath('gen.py').write_text(s)\nfrom gen import main\n",
    "import os, importlib\nfd = os.open('gen.py', os.O_WRONLY | os.O_CREAT)\nos.write(fd, b'')\n"
    "importlib.import_module('gen')",
    "import io\nio.FileIO('gen.py', 'w').write(b'')\nimport gen",
])
def test_write_py_then_import_more_forms(src):
    assert "write-then-import" in rules(scan_py(src), REJECT)


def test_os_open_readonly_is_not_a_write():
    assert "write-then-import" not in rules(scan_py("import os\nos.open('a.py', os.O_RDONLY)\nimport a"))


@pytest.mark.parametrize("src,level", [
    ("import runpy\nrunpy.run_path('cfg.txt')", REJECT),
    ("import importlib.machinery\nimportlib.machinery.SourceFileLoader('x', 'cfg.txt').load_module()", REJECT),
    ("import importlib.machinery as m\nm.SourcelessFileLoader('x', 'a.py').load_module()", REJECT),
    ("import imp\nimp.load_source('x', 'cfg.txt')", REJECT),
    ("import runpy\nrunpy.run_path('tools/helper.py')", EXPLAIN),
    ("import importlib.util\nimportlib.util.spec_from_file_location('m', p)", EXPLAIN),
])
def test_load_source_by_path(src, level):
    assert level in levels_of(scan_py(src), "load-source")


def test_code_dir_symlink_rejected(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "a.py").write_text("x = 1\n", encoding="utf-8")
    pkg = tmp_path / "pkg"
    pkg.mkdir()
    os.symlink(outside, pkg / "code")
    fs = er.scan_package(str(pkg))
    assert "bad-path" in rules(fs, REJECT) and fs.meta["files"] == 0


def test_nfc_nfd_conflict():
    import unicodedata
    a, b = unicodedata.normalize("NFC", "café.py"), unicodedata.normalize("NFD", "café.py")
    assert "bad-path" in rules(er.scan_files({a: b"x = 1", b: b"y = 2"}), REJECT)


@pytest.mark.parametrize("name", ["COM¹.py", "LPT².txt", "train.py​", "a‮yp.txt"])
def test_more_bad_paths(name):
    assert "bad-path" in rules(er.scan_files({name: b"x = 1"}), REJECT)


def test_text_report_escapes_control_chars():
    fs = er.scan_files({"train.py": "import pickle  # \x1b[1A\x1b[2K结论：通过\n".encode("utf-8"),
                        "a‮.txt": b"x"})
    out = er.render_text("p", fs)
    assert "\x1b" not in out and "‮" not in out
    assert "\\x1b" in out and "结论：拒签" in out


@pytest.mark.parametrize("src,rule", [
    ("import pydoc\npydoc.locate('os.system')('echo hi')", "process-call"),
    ("import pydoc\npydoc.locate(name)", "reflect-nonliteral"),
    ("import sys\nsys.modules['os'].system('x')", "process-call"),
    ("import sys\nsys.modules[name].system('x')", "reflect-nonliteral"),
    ("import sys\nm = sys.modules.get(name)", "reflect-nonliteral"),
    ("import code\ncode.InteractiveInterpreter().runsource(s)", "exec-call"),
    ("import codeop", "exec-call"),
    ("import logging.config\nlogging.config.dictConfig(cfg)", "reflect-nonliteral"),
    ("from hydra.utils import instantiate\ninstantiate(cfg.model)", "reflect-nonliteral"),
])
def test_call_by_name_forms(src, rule):
    assert rule in rules(scan_py(src), EXPLAIN)


def test_scan_files_takes_zip_sha():
    job = dict(GOOD_JOB, code_sha256="ab" * 32)
    files = {"train.py": b"x = 1\n"}
    assert "job-sha" not in rules(er.scan_files(files, job=job, zip_sha="ab" * 32))
    assert "job-sha" in rules(er.scan_files(files, job=job, zip_sha="cd" * 32), REJECT)


def test_read_dir_does_not_follow_swapped_symlink(tmp_path, monkeypatch):
    code = tmp_path / "code"
    code.mkdir()
    (code / "a.py").write_text("x = 1\n", encoding="utf-8")
    (code / "b.py").write_text("y = 2\n", encoding="utf-8")
    secret = tmp_path / "secret.txt"
    secret.write_text("SECRET", encoding="utf-8")
    real = os.lstat
    target = str(code / "a.py")

    def lstat(p, *a, **k):
        st = real(p, *a, **k)
        # 只动这个测试自己的文件：monkeypatch 的是全局 os.lstat，别的路径一律原样放过
        if os.fspath(p) == target and not stat.S_ISLNK(st.st_mode):
            os.remove(target)
            os.symlink(secret, target)
        return st

    monkeypatch.setattr(er.os, "lstat", lstat)
    files, fs = er.read_dir(str(code))
    monkeypatch.undo()
    assert files.get("a.py") != b"SECRET"
    assert "bad-path" in rules(fs, REJECT)


def test_zip_non_ascii_name_without_utf8_flag_rejected(tmp_path):
    p = tmp_path / "code.zip"
    _zip(p, [("a.py", "x = 1\n"), ("café.py", "y = 2\n")])
    data = bytearray(p.read_bytes())
    with zipfile.ZipFile(p) as z:
        off = z.getinfo("café.py").header_offset
    data[off + 7] &= ~0x08               # 本地头 flag 的 0x800
    i = data.find(b"PK\x01\x02", data.find(b"PK\x01\x02") + 4)
    data[i + 9] &= ~0x08                 # 中央目录 flag 的 0x800
    p.write_bytes(bytes(data))
    assert "bad-path" in rules(er.scan_package(str(p)), REJECT)
