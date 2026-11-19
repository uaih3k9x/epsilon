#!/usr/bin/env python3
"""epsilon-review：任务包静态审核（签名前的第一道筛，issue #3）。

    python3 -I tools/epsilon-review.py <任务包目录|code.zip> [--job job.json] [--json] [--strict]

只用标准库；被审的代码只做 ast.parse，绝不 import、绝不执行。
工具不是沙箱、不做最终裁决：负责把可疑点一个不漏地列出来，签不签由审核人决定。

分级（2026-11-01 定）：拒签只留审核人读不到的代码（二进制、pickle 系、写 .py 再导入、审计钩子）；
动态执行、进程、系统 API、联网等需解释，审核人当场判断。11-18 补：原生调用逃生口（ctypes、cffi、pywin32、
_winapi、msvcrt、add_dll_directory、可执行 mmap）拒签，它们能绕过沙箱的目录 ACL 和审计钩子。规则、退出码、JSON 契约见 docs/review.md。
"""

import argparse
import ast
import builtins
import hashlib
import io
import json
import math
import os
import re
import stat
import sys
import unicodedata
import warnings
import zipfile
import zlib
from collections import Counter
from dataclasses import asdict, dataclass

TOOL_VERSION = "0.1.0"
RULES_VERSION = 2  # 规则或级别一改就加 1；sign-job 把它记进签名记录

REJECT, EXPLAIN, INFO, ERROR = "reject", "explain", "info", "error"
LABEL = {ERROR: "工具出错", REJECT: "拒签", EXPLAIN: "需解释", INFO: "提示"}
_RANK = {INFO: 0, EXPLAIN: 1, REJECT: 2, ERROR: 3}

ALLOWED_EXT = {".py", ".json", ".yaml", ".yml", ".toml", ".txt", ".md", ".csv", ".jinja", ".j2"}
MAX_TEXT_BYTES = 1 << 20          # 单个文本文件超过就要解释
MAX_UNPACKED_BYTES = 256 << 20    # 解压后总大小上限（防 zip 炸弹），超了按工具出错
MAX_ENTRIES = 10000
MAX_PATH = 120                    # 手册 5.1：路径不超过 120 字符


@dataclass
class Finding:
    level: str
    rule: str
    file: str
    line: int = 0
    col: int = 0
    snippet: str = ""
    message: str = ""
    hint: str = ""


class Report(list):
    """findings 列表，外加 meta（文件数、哈希、任务名），给报告用。"""

    def __init__(self, items=(), meta=None):
        super().__init__(items)
        self.meta = dict(meta or {})


# ============================================================================ 文件层

_RESERVED = {"CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"} | \
    {f"{p}{i}" for p in ("COM", "LPT") for i in list(range(10)) + ["\u00b9", "\u00b2", "\u00b3"]}
_JUNK_NAMES = {".DS_Store", "Thumbs.db", "desktop.ini"}
_JUNK_DIRS = {".git", "__MACOSX"}     # 出提示，但照常检查：__MACOSX 是合法标识符，能被 import
_MACHO = {bytes.fromhex(h) for h in ("feedface", "feedfacf", "cefaedfe", "cffaedfe", "cafebabe", "bebafeca")}
_BZ2 = re.compile(rb"BZh[1-9](1AY&SY|\x17rE8P\x90)")


def path_problem(name):
    """返回路径问题的说明；没问题返回 None。name 是包内相对路径，分隔符 /。"""
    if not name:
        return "空文件名"
    if "\\" in name:
        return "路径里有反斜杠：Windows 上会被当成目录分隔符"
    if name.startswith("/"):
        return "绝对路径"
    if re.match(r"[A-Za-z]:", name):
        return "带盘符"
    if ":" in name:
        return "路径里有冒号（NTFS 备用数据流）"
    if any(ord(c) < 32 or unicodedata.category(c) in ("Cc", "Cf", "Zl", "Zp") for c in name):
        return "路径里有控制字符或不可见字符（零宽、双向控制符）"
    if len(name) > MAX_PATH:
        return f"路径超过 {MAX_PATH} 字符"
    for part in name.split("/"):
        if part in ("", ".", ".."):
            return "路径里有 .. 或空的路径段"
        if part.endswith((".", " ")):
            return "文件名结尾是点或空格（Windows 会悄悄去掉）"
        if part.split(".")[0].rstrip(" ").upper() in _RESERVED:
            return f"Windows 保留名 {part}"
    return None


def check_paths(names):
    out = []
    for n in names:
        why = path_problem(n)
        if why:
            out.append(Finding(REJECT, "bad-path", n, message=why, hint="文件名只用字母、数字、- _ .，相对路径，不超过 120 字符"))
    by_key = {}
    for n in sorted(names):
        by_key.setdefault(unicodedata.normalize("NFC", n).casefold(), []).append(n)
    for group in by_key.values():
        if len(group) > 1:
            for n in group[1:]:
                out.append(Finding(REJECT, "bad-path", n, message=f"和 {group[0]} 只差大小写或 Unicode 写法，"
                                   "Windows / macOS 上会互相覆盖", hint="改成不冲突的名字"))
    return out


def sniff(data):
    """按文件头判断真实类型。是二进制或压缩包返回类型名，否则 None。"""
    h = data[:16]
    if data.startswith(b"MZ") and any(b < 9 or b >= 0x80 for b in data[2:64]):
        return "PE 可执行文件（exe/dll/pyd）"
    if h.startswith(b"\x7fELF"):
        return "ELF 可执行文件或库"
    if h[:4] in _MACHO:
        return "Mach-O 可执行文件或库"
    if h.startswith(b"\x00asm"):
        return "WebAssembly"
    if h[:4] in (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"):
        return "zip 压缩包"
    if h.startswith(b"\x1f\x8b"):
        return "gzip 压缩包"
    if _BZ2.match(h):
        return "bz2 压缩包"
    if h.startswith(b"\xfd7zXZ\x00"):
        return "xz 压缩包"
    if h.startswith(b"\x28\xb5\x2f\xfd"):
        return "zstd 压缩包"
    if h.startswith(b"7z\xbc\xaf\x27\x1c"):
        return "7z 压缩包"
    if h.startswith(b"Rar!\x1a\x07"):
        return "rar 压缩包"
    if data[257:262] == b"ustar":
        return "tar 包"
    if h.startswith(b"\x93NUMPY"):
        return ".npy 数组（可能带 pickle 对象）"
    if len(h) >= 2 and h[0] == 0x80 and 2 <= h[1] <= 5:
        return "pickle 序列化数据"
    if len(data) >= 8 and data[2:4] == b"\r\n" and (0x0b <= data[1] <= 0x0e or data[1] == 0xf3):
        return ".pyc 字节码"
    return None


def _is_junk(name):
    """打包残留只多出一条提示，内容照常检查：残留目录里的 .py 照样能被导入、被 exec 读进来。"""
    parts = name.split("/")
    return parts[-1] in _JUNK_NAMES or any(p in _JUNK_DIRS or p == "__pycache__" for p in parts[:-1])


def scan_contents(files):
    """逐个文件做内容检查（不含路径检查）。返回 (findings, 参数读取点)。"""
    out, uses = [], []
    for name in sorted(files):
        data = files[name]
        junk = _is_junk(name)
        if junk:
            out.append(Finding(INFO, "junk", name, message="打包没清干净（__pycache__ / .git / .DS_Store 之类）",
                               hint="打包前删掉"))
        ext = os.path.splitext(name)[1].lower()
        bad = False
        if ext not in ALLOWED_EXT:
            out.append(Finding(REJECT, "file-type", name, message=f"白名单以外的文件类型（{ext or '无扩展名'}）",
                               hint="代码包只放 .py .json .yaml .yml .toml .txt .md .csv .jinja .j2；"
                                    "二进制和模型权重走环境层或数据集上架"))
            bad = True
        kind = sniff(data)
        if kind:
            out.append(Finding(REJECT, "file-magic", name, message=f"文件头是 {kind}，审核人读不了",
                               hint="代码包里不能有二进制、序列化文件和压缩包；需要的走环境层或数据集上架"))
            bad = True
        if bad:
            continue
        if len(data) > MAX_TEXT_BYTES:
            out.append(Finding(EXPLAIN, "big-text", name, message=f"文本文件 {len(data) / 1048576:.1f} MB，超过 1 MB",
                               hint="数据走数据集上架；确实是代码或配置的，送审单里说明"))
        try:
            text = data.decode("utf-8-sig")
        except UnicodeDecodeError as e:
            if ext == ".py":
                out.append(Finding(ERROR, "parse-error", name, message=f"源码不是 UTF-8（第 {e.start} 字节），没法按审核人看到的样子解析",
                                   hint="存成 UTF-8"))
            else:
                out.append(Finding(EXPLAIN, "encoding", name, message="不是 UTF-8 文本", hint="存成 UTF-8；不是文本的送审单里说明"))
            continue
        if ext == ".py":
            fs, u = scan_python(name, text, data)
            out += fs
            uses += u
        elif "\x00" in text:
            out.append(Finding(EXPLAIN, "encoding", name, message="文本里有 NUL 字节，像是二进制", hint="送审单里说明这是什么"))
    return out, uses


def scan_files(files, job=None, zip_sha=None):
    """files: {包内相对路径: 字节}。job: job.json 的字节或 dict（可选）。zip_sha: files 来自的 code.zip 的哈希。"""
    out = check_paths(list(files))
    fs, uses = scan_contents(files)
    out += fs
    if job is not None:
        if isinstance(job, dict):
            job = json.dumps(job).encode("utf-8")
        out += check_job(job, "job.json", files, zip_sha, uses)[0]
    return _finish(out, {"files": len(files)})


# ============================================================================ zip / 目录

class _ToolError(Exception):
    def __init__(self, rule, file, message):
        super().__init__(message)
        self.rule, self.file = rule, file


_READ_ERRORS = (zipfile.BadZipFile, zlib.error, EOFError, OSError, NotImplementedError, RuntimeError, ValueError)
try:
    import lzma
    _READ_ERRORS += (lzma.LZMAError,)
except ImportError:  # pragma: no cover - 精简版 Python 可能没有 lzma
    pass


def read_zip(data, label):
    """解出 zip 里的普通文件。返回 (files, zip 层 findings)。读不了抛 _ToolError。"""
    try:
        z = zipfile.ZipFile(io.BytesIO(data))
        infos = z.infolist()
    except _READ_ERRORS as e:
        raise _ToolError("zip-corrupt", label, f"zip 读不了：{e}")
    if len(infos) > MAX_ENTRIES:
        raise _ToolError("zip-too-big", label, f"条目 {len(infos)} 个，超过 {MAX_ENTRIES}")
    total = sum(i.file_size for i in infos)
    if total > MAX_UNPACKED_BYTES:
        raise _ToolError("zip-too-big", label, f"解压后 {total} 字节，超过上限 {MAX_UNPACKED_BYTES}（zip 炸弹？）")
    out, files, names, read = [], {}, [], 0
    for info in infos:
        name = info.filename
        if name.endswith("/"):
            names.append(name.rstrip("/"))
            continue
        mode = info.external_attr >> 16
        if not info.flag_bits & 0x800 and not name.isascii():
            out.append(Finding(REJECT, "bad-path", name, message="非 ASCII 文件名没标 UTF-8：不同解压工具解出来的名字可能不一样",
                               hint="用支持 UTF-8 文件名的工具重新打包，或者文件名只用 ASCII"))
            names.append(name)
            continue
        if stat.S_ISLNK(mode):
            out.append(Finding(REJECT, "bad-path", name, message="符号链接", hint="打包时不要带符号链接"))
            names.append(name)
            continue
        if stat.S_IFMT(mode) not in (0, stat.S_IFREG):
            out.append(Finding(REJECT, "bad-path", name, message="不是普通文件", hint="只打包普通文件"))
            names.append(name)
            continue
        if info.flag_bits & 0x1:
            out.append(Finding(REJECT, "zip-encrypted", name, message="加密条目，审核人读不了", hint="不要加密"))
            names.append(name)
            continue
        key = name
        if name in files:
            out.append(Finding(REJECT, "bad-path", name, message="zip 里有重名条目，解压出来是哪个看工具",
                               hint="重新打包"))
            k = 2
            while f"{name}#{k}" in files:
                k += 1
            key = f"{name}#{k}"
        else:
            names.append(name)
        try:
            with z.open(info) as f:
                content = f.read(MAX_UNPACKED_BYTES - read + 1)
        except _READ_ERRORS as e:
            raise _ToolError("zip-corrupt", name, f"条目读不了：{e}")
        read += len(content)
        if read > MAX_UNPACKED_BYTES:
            raise _ToolError("zip-too-big", label, f"解压后超过上限 {MAX_UNPACKED_BYTES} 字节（zip 炸弹？）")
        files[key] = content
    if not any(not i.filename.endswith("/") for i in infos):
        raise _ToolError("empty", label, "zip 里没有文件")
    return files, check_paths(names) + out


def read_dir(root):
    """读目录里的普通文件；符号链接和特殊文件不跟、不读。"""
    out, files, total = [], {}, 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames.sort()
        for d in list(dirnames):
            if os.path.islink(os.path.join(dirpath, d)):
                rel = os.path.relpath(os.path.join(dirpath, d), root).replace(os.sep, "/")
                out.append(Finding(REJECT, "bad-path", rel, message="符号链接", hint="打包时不要带符号链接"))
                dirnames.remove(d)
        for fn in sorted(filenames):
            full = os.path.join(dirpath, fn)
            rel = os.path.relpath(full, root).replace(os.sep, "/")
            st = os.lstat(full)
            if stat.S_ISLNK(st.st_mode):
                out.append(Finding(REJECT, "bad-path", rel, message="符号链接", hint="打包时不要带符号链接"))
                continue
            if not stat.S_ISREG(st.st_mode):
                out.append(Finding(REJECT, "bad-path", rel, message="不是普通文件", hint="只打包普通文件"))
                continue
            if total + st.st_size > MAX_UNPACKED_BYTES:
                raise _ToolError("too-big", rel, f"目录总大小超过上限 {MAX_UNPACKED_BYTES} 字节")
            try:
                fd = os.open(full, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0))
            except OSError:
                fd = None
            if fd is None:
                out.append(Finding(REJECT, "bad-path", rel, message="扫描过程中文件被换掉了（变成了符号链接？）", hint="重新扫"))
                continue
            with os.fdopen(fd, "rb") as f:
                st2 = os.fstat(f.fileno())
                if not stat.S_ISREG(st2.st_mode) or (st2.st_dev, st2.st_ino) != (st.st_dev, st.st_ino):
                    out.append(Finding(REJECT, "bad-path", rel, message="扫描过程中文件被换掉了", hint="重新扫"))
                    continue
                content = f.read(MAX_UNPACKED_BYTES - total + 1)
            total += len(content)
            if total > MAX_UNPACKED_BYTES:
                raise _ToolError("too-big", rel, f"目录总大小超过上限 {MAX_UNPACKED_BYTES} 字节")
            files[rel] = content
    if not files:
        raise _ToolError("empty", root, "目录里没有文件")
    return files, check_paths(list(files)) + out


def scan_package(path, job_path=None):
    """扫任务包目录（job.json + code.zip 或 code/）、单独的 code.zip，或者一个代码目录。"""
    meta = {"package": str(path), "name": None, "version": None, "files": 0, "code_sha256": None}
    out = []
    try:
        if not os.path.exists(path):
            raise _ToolError("no-input", str(path), "路径不存在")
        if os.path.isdir(path):
            if job_path is None and os.path.isfile(os.path.join(path, "job.json")):
                job_path = os.path.join(path, "job.json")
            zp, cd = os.path.join(path, "code.zip"), os.path.join(path, "code")
            if os.path.isfile(zp):
                src = zp
            elif os.path.isdir(cd):
                src = cd
            elif job_path is not None:
                raise _ToolError("no-input", str(path), "有 job.json，但没有 code.zip 也没有 code/")
            else:
                src = path
        else:
            src = path
        if src != path and os.path.islink(src):
            out.append(Finding(REJECT, "bad-path", os.path.basename(src), message="code/ 或 code.zip 是符号链接，指向任务包以外",
                               hint="放真实的目录或文件"))
            return _finish(out, meta)
        if os.path.isdir(src):
            files, zfs = read_dir(src)
        else:
            with open(src, "rb") as f:
                data = f.read()
            meta["code_sha256"] = hashlib.sha256(data).hexdigest()
            files, zfs = read_zip(data, os.path.basename(src))
        meta["files"] = len(files)
        out += zfs
        fs, uses = scan_contents(files)
        out += fs
        if job_path is not None:
            try:
                with open(job_path, "rb") as f:
                    job = f.read()
            except OSError as e:
                raise _ToolError("no-input", os.path.basename(job_path), f"job.json 读不了：{e}")
            jfs, parsed = check_job(job, os.path.basename(job_path), files, meta["code_sha256"], uses)
            out += jfs
            if isinstance(parsed, dict):
                meta["name"], meta["version"] = parsed.get("name"), parsed.get("version")
    except _ToolError as e:
        out.append(Finding(ERROR, e.rule, e.file, message=str(e), hint="工具没能扫完，结果不能作为签名依据"))
    except Exception as e:  # 兜底：工具自己的毛病也只报退出码 3，不抛 traceback
        out.append(Finding(ERROR, "internal-error", str(path), message=f"{type(e).__name__}: {e}",
                           hint="这是工具的 bug，请报告"))
    return _finish(out, meta)


# ============================================================================ job.json

_REQUIRED = ["schema", "name", "version", "owner", "entry", "env",
             "gpu_mem_mb", "max_hours", "disk_max_mb", "output_max_mb", "code_sha256"]
_HARMLESS_FLAGS = {"-B", "-u"}
_SCRIPT_REL = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_./-]*\.py\Z")


def check_job(raw, label, files, zip_sha, uses):
    """只查和代码有关的交集；完整 schema 校验以 jobsign.checkJob 为准。返回 (findings, 解析结果)。"""
    out = []

    def bad(rule, msg, hint="", level=REJECT):
        out.append(Finding(level, rule, label, message=msg, hint=hint))

    if raw.startswith(b"\xef\xbb\xbf"):
        bad("job-schema", "job.json 带 BOM", "存成无 BOM 的 UTF-8")
        return out, None
    try:
        job = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as e:
        bad("job-schema", f"job.json 解析不了：{e}")
        return out, None
    if not isinstance(job, dict):
        bad("job-schema", "job.json 顶层不是对象")
        return out, None

    missing = [k for k in _REQUIRED if job.get(k) is None]
    if missing:
        bad("job-schema", "缺必填字段：" + "、".join(missing), "对照手册 5.2；格式细节以 epsilon-release sign-job 的校验为准")

    entry = job.get("entry")
    if not isinstance(entry, list) or not all(isinstance(a, str) for a in entry):
        bad("job-entry", "entry 要是字符串数组")
    else:
        i = 1
        while i < len(entry) and entry[i] in _HARMLESS_FLAGS:
            i += 1
        hint = '写成 ["python", "train.py", ...]：不经过 shell，不用 -c / -m'
        if len(entry) < 2 or entry[0] not in ("python", "python3"):
            bad("job-entry", f"entry[0] 只能是 python / python3，现在是 {entry[:1]}", hint)
        elif i >= len(entry) or not _SCRIPT_REL.match(entry[i]) or ".." in entry[i]:
            bad("job-entry", f"entry 里没有 code/ 下的相对 .py 脚本：{entry}", hint)
        elif entry[i] not in files:
            bad("job-entry", f"entry 的脚本 {entry[i]} 不在代码包里", hint)
        elif _is_junk(entry[i]):
            bad("job-entry", f"entry 的脚本 {entry[i]} 在打包残留目录里", hint)
        if any(a in ("-c", "-m") for a in entry[1:]):
            bad("job-entry", "entry 里不许出现 -c / -m", hint)

    want = job.get("code_sha256")
    if zip_sha is None:
        bad("job-sha", "没有 code.zip 的哈希（扫的是目录？），没核对 code_sha256", "送审前打好 code.zip 再扫一遍", INFO)
    elif want != zip_sha:
        bad("job-sha", f"code_sha256 和 code.zip 不一致（job.json {str(want)[:12]}…，实际 {zip_sha[:12]}…）",
            "重新打包后把哈希写进 job.json")

    params = job.get("params", {})
    if not isinstance(params, dict):
        bad("job-schema", "params 要是对象")
        params = {}
    for pname, spec in sorted(params.items()):
        hint = '写成带约束的形式：{"type": "int", "min": 0, "max": 23} 或 {"type": "string", "enum": [...]}'
        typ = spec.get("type") if isinstance(spec, dict) else spec
        if typ == "bool":
            continue
        if not isinstance(spec, dict):
            bad("param-unconstrained", f"参数 {pname} 是简写，没有约束", hint, EXPLAIN)
        elif typ == "string" and "enum" not in spec:
            bad("param-unconstrained", f"字符串参数 {pname} 没有 enum", hint, EXPLAIN)
        elif typ in ("int", "number") and ("min" not in spec or "max" not in spec):
            bad("param-unconstrained", f"数值参数 {pname} 没有 min/max", hint, EXPLAIN)

    for key, fname, node, snippet in uses:
        if key not in params:
            out.append(Finding(EXPLAIN, "param-undeclared", fname, node.lineno, node.col_offset + 1, snippet,
                               f"代码读了参数 {key!r}，job.json 的 params 里没声明（主控会拒掉不认识的参数）",
                               "在 params 里声明；如果这里读的不是 params.json，送审单里说明"))
    return out, job


# ============================================================================ 代码层：规则表

# 导入即命中的模块（前缀匹配：pickle 命中 pickle.xxx）。值：(级别, 规则, 说明, 建议)
_PICKLE_HINT = "权重用 safetensors，数据用 json/csv；pickle 系反序列化会执行文件里写好的任意调用"
MODULE_RULES = []
for _m in ("pickle", "_pickle", "cPickle", "cloudpickle", "dill", "joblib", "shelve", "marshal"):
    MODULE_RULES.append((_m, REJECT, "pickle-use", f"用了 {_m}（pickle 系），审核人读不到它会执行什么", _PICKLE_HINT))
for _m in ("subprocess", "_posixsubprocess", "asyncio.subprocess", "pty", "popen2", "commands"):
    MODULE_RULES.append((_m, EXPLAIN, "process-call", f"导入了 {_m}：会起子进程", "送审单里说明起什么进程、参数从哪来"))
for _m in ("multiprocessing", "concurrent.futures.process"):
    MODULE_RULES.append((_m, INFO, "process-call", f"{_m} 起的是环境层自己的 python，一般没问题", ""))
MODULE_RULES.append(("multiprocessing.reduction", REJECT, "pickle-use",
                     "用了 multiprocessing.reduction（ForkingPickler 就是 pickle）", _PICKLE_HINT))
for _m in ("code", "codeop"):
    MODULE_RULES.append((_m, EXPLAIN, "exec-call", f"导入了 {_m}：能把字符串当代码执行", "送审单里说明执行的是什么"))
# 原生调用逃生口：能直接调 CreateFileW / LoadLibrary / WNetAddConnection 之类，绕过沙箱 ACL 和审计钩子。
# win32* 前缀另在 check_module 里认；torch 等库内部用 ctypes 属于环境层，不在代码包里。
_NATIVE_MODULES = ("ctypes", "_ctypes", "cffi", "_cffi_backend", "_winapi", "msvcrt", "pywintypes", "pythoncom",
                   "comtypes")
_NATIVE_WHY = "能直接调系统原生 API（CreateFileW、LoadLibrary、WNetAddConnection、直连 SMB 等），可绕过沙箱 ACL/审计钩子"
_NATIVE_HINT = "任务代码不需要直接调原生 API；需要的功能找平台在环境层提供"
for _m in _NATIVE_MODULES:
    MODULE_RULES.append((_m, REJECT, "native-api", f"导入了 {_m}：{_NATIVE_WHY}", _NATIVE_HINT))
for _m in ("winreg", "_winreg", "_overlapped"):
    MODULE_RULES.append((_m, EXPLAIN, "native-api", f"导入了 {_m}：直接碰系统 API", "送审单里说明调了什么、为什么非用不可"))
# 属性链中间出现这些名字也算拿到了原生调用能力：sys.modules["ctypes"]、numpy.ctypeslib.ctypes
_NATIVE_SEGMENTS = set(_NATIVE_MODULES) | {"ctypeslib"}
# 接收者认不出来时（模块经参数传进来、numpy 数组的 .ctypes）取这些属性：需解释
_OPAQUE_NATIVE = _NATIVE_SEGMENTS | {"windll", "oledll", "cdll", "pydll", "pythonapi", "CDLL", "WinDLL", "OleDLL",
                                     "PyDLL", "add_dll_directory"}
for _m in ("socket", "_socket", "requests", "urllib", "urllib2", "urllib3", "http.client", "http.server", "httplib",
           "ftplib", "smtplib", "poplib", "imaplib", "telnetlib", "nntplib", "xmlrpc", "socketserver", "paramiko",
           "aiohttp", "httpx", "websocket", "websockets", "pycurl", "wget"):
    MODULE_RULES.append((_m, EXPLAIN, "network", f"导入了 {_m}：会联网", "默认只能连主控和同教室；送审单里说明连哪、传什么"))
_MODULE_EXEMPT = {"urllib.parse"}

_DECODE_HINT = "解出来的东西去了哪？送审单里要说明；不要把代码或模块名藏在编码后的字符串里"
_PROCESS_ATTRS = {"system", "popen", "startfile", "Popen", "run", "call", "check_call", "check_output", "getoutput",
                  "getstatusoutput", "fork", "forkpty", "posix_spawn", "posix_spawnp"}
_PROCESS_RE = re.compile(r"os\.(system|popen[234]?|startfile|exec[lv]p?e?|spawn[lv]p?e?|posix_spawnp?|fork|forkpty)\Z")
# 接收者认不出来时（模块经函数参数传进来）也报的属性名。run / call 太常见（trainer.run()），不算
_OPAQUE_PROCESS = re.compile(r"(system|popen[234]?|startfile|Popen|check_output|check_call|getoutput|getstatusoutput"
                             r"|exec[lv]p?e?|spawn[lv]p?e?|posix_spawnp?|fork|forkpty)\Z")

# 引用即命中的限定名（正则全匹配）。值：(级别, 规则, 说明, 建议)
FUNC_RULES = [
    (r"builtins\.(eval|exec|compile)", EXPLAIN, "exec-call", "动态执行代码（{q}）",
     "送审单里说明执行的是什么、从哪来；能写成普通代码就别用"),
    (r"types\.(CodeType|FunctionType)", EXPLAIN, "exec-call", "手工构造代码对象（{q}）", "送审单里说明"),
    (r"(timeit\.(timeit|repeat|Timer)|cProfile\.(run|runctx)|profile\.(run|runctx)|pdb\.(run|runeval)|pandas\.eval)",
     EXPLAIN, "exec-call", "{q} 会把字符串当代码执行", "送审单里说明执行的是什么"),
    (r"pandas\.read_pickle", REJECT, "pickle-use", "pandas.read_pickle 是 pickle 反序列化", _PICKLE_HINT),
    (r"torch\.save", EXPLAIN, "pickle-use", "torch.save 底层是 pickle，产物别人加载时会执行代码",
     "用 safetensors 的 save_file"),
    (r"multiprocessing\.reduction\..*|.*\.ForkingPickler(\..*)?", REJECT, "pickle-use", "{q} 是 pickle", _PICKLE_HINT),
    (r"yaml\.(unsafe_load|unsafe_load_all)", REJECT, "unsafe-load", "{q} 能构造任意 Python 对象", "用 yaml.safe_load"),
    (r"logging\.config\.(dictConfig|fileConfig|listen)|hydra\.utils\.(instantiate|call|get_method|get_class|get_object)",
     EXPLAIN, "reflect-nonliteral", "{q} 会按配置里写的名字导入并调用对象", "送审单里说明配置从哪来、会构造什么"),
    (r"sys\.addaudithook", REJECT, "audit-hook", "任务代码不该碰审计钩子（平台用它做运行时兜底）", "删掉"),
    (r"asyncio\.create_subprocess_(exec|shell)|platform\.popen", EXPLAIN, "process-call", "{q} 会起子进程",
     "送审单里说明起什么进程、参数从哪来"),
    (r"os\.add_dll_directory|importlib\.machinery\.ExtensionFileLoader|mmap\.PROT_EXEC", REJECT, "native-api",
     "{q}：加载本地二进制 / 可执行内存，" + _NATIVE_WHY, _NATIVE_HINT),
    (r"asyncio\.open_connection|asyncio\.start_server", EXPLAIN, "network", "{q} 会联网", "送审单里说明连哪、传什么"),
    (r"base64\.(b64decode|b32decode|b32hexdecode|b16decode|b85decode|a85decode|urlsafe_b64decode|standard_b64decode"
     r"|decodebytes|decodestring)|binascii\.(a2b_\w+|unhexlify)|codecs\.(decode|getdecoder|iterdecode|getincrementaldecoder)"
     r"|builtins\.(bytes|bytearray)\.fromhex|zlib\.(decompress|decompressobj)|lzma\.(decompress|LZMADecompressor)"
     r"|bz2\.(decompress|BZ2Decompressor)|gzip\.decompress",
     EXPLAIN, "string-decode", "字符串还原 / 解压（{q}）", _DECODE_HINT),
    (r"operator\.(attrgetter|methodcaller)", EXPLAIN, "reflect-nonliteral", "{q} 按名字间接取属性 / 调方法",
     "直接写属性访问"),
    (r"site\.addsitedir", EXPLAIN, "import-machinery", "{q} 改了导入路径", "送审单里说明"),
    (r"os\.path\.(expanduser|expandvars)|pathlib\.Path\.home", INFO, "write-outside", "{q} 指向用户目录或环境变量",
     "缓存和临时文件放 TMP（ROOT / \"tmp\"）"),
]
FUNC_RULES = [(re.compile("(?:" + p + r")\Z"), lv, r, m, h) for p, lv, r, m, h in FUNC_RULES]

_REFLECT = {  # 限定名 → 名字参数的位置
    "builtins.getattr": 1, "builtins.setattr": 1, "builtins.delattr": 1, "builtins.hasattr": 1,
    "builtins.__import__": 0, "importlib.import_module": 0, "importlib.__import__": 0,
    "runpy.run_module": 0, "runpy.run_path": 0,
    "pkgutil.resolve_name": 0, "pydoc.locate": 0, "imp.load_source": 0, "imp.load_module": 0,
}
_NAME_RESOLVERS = {"pkgutil.resolve_name", "pydoc.locate"}   # "os.system" 这样的名字 → 对象
# 按路径加载代码：限定名 → (路径参数位置, 关键字名, 是否只能是字节码)
_PATH_LOADERS = {
    "runpy.run_path": (0, "path_name", False), "imp.load_source": (1, "pathname", False),
    "imp.load_module": (2, "pathname", False), "imp.load_compiled": (1, "pathname", True),
    "importlib.machinery.SourceFileLoader": (1, "path", False),
    "importlib.machinery.SourcelessFileLoader": (1, "path", True),
    "importlib.util.spec_from_file_location": (1, "location", False),
    "zipimport.zipimporter": (0, "path", False),
}
# 要查参数的反序列化函数：不是被直接调用（赋给变量、塞进元组、传给 partial）就查不了参数
_CHECKED_LOADERS = {"torch.load", "torch.serialization.load", "numpy.load", "numpy.lib.npyio.load",
                    "numpy.lib.format.read_array", "yaml.load", "yaml.load_all", "yaml.full_load", "yaml.full_load_all"}
_ALLOW_PICKLE_POS = {"numpy.load": 2, "numpy.lib.npyio.load": 2, "numpy.lib.format.read_array": 1}
_DYN_IMPORT = {"builtins.__import__", "importlib.import_module", "importlib.__import__"}
_IMPORT_MECH = re.compile(r"(importlib\.(import_module|__import__|util\..*|machinery\..*)|runpy\..*|builtins\.__import__"
                          r"|imp\..*|zipimport\..*|pkgutil\..*|pydoc\.locate)\Z")
_IMPORT_STATE = {"sys.path", "sys.modules", "sys.meta_path", "sys.path_hooks", "sys.path_importer_cache"}
_MUTATORS = {"insert", "append", "extend", "remove", "pop", "clear", "update", "setdefault", "popitem",
             "__setitem__", "__delitem__", "__iadd__"}
_ENV_KEYS = {"PATH", "PYTHONPATH", "PYTHONHOME", "PYTHONSTARTUP", "PYTHONUSERBASE", "LD_PRELOAD", "LD_LIBRARY_PATH",
             "DYLD_LIBRARY_PATH", "DYLD_INSERT_LIBRARIES", "PATHEXT", "COMSPEC"}
_STAR_RISKY = {"os", "posix", "nt", "subprocess", "builtins", "sys", "importlib", "runpy", "ctypes", "socket", "pickle",
               "marshal", "shutil", "pty", "platform", "asyncio", "codecs", "base64", "zlib", "types", "io", "operator"}
_DUNDERS = {"__dict__", "__code__", "__globals__", "__subclasses__", "__reduce__", "__reduce_ex__", "__getattribute__",
            "__mro__", "__bases__", "__base__", "__closure__", "__builtins__"}
_DECODE_CODECS = {"rot13", "rot_13", "hex", "hex_codec", "base64", "base64_codec", "zlib", "zlib_codec", "bz2",
                  "bz2_codec", "uu", "uu_codec", "unicode_escape", "raw_unicode_escape", "punycode"}
_OPENERS = {"builtins.open", "io.open", "codecs.open", "os.fdopen", "io.FileIO", "_io.FileIO"}
_TEMPFILE = {"mkstemp": 2, "mkdtemp": 2, "TemporaryDirectory": 2, "NamedTemporaryFile": 6, "TemporaryFile": 6,
             "SpooledTemporaryFile": 7, "gettempdir": None}
_DOWNLOADERS = {"from_pretrained", "load_dataset", "snapshot_download", "hf_hub_download",
                "load_state_dict_from_url", "download_url_to_file"}
_OUTSIDE = re.compile(r"([A-Za-z]:|/|\\\\|~|.*%[A-Za-z_]+%|.*\$(HOME|TMP|TEMP|APPDATA)|.*(AppData|ProgramData)(/|\\|\Z))")
_SAFE_YAML_LOADERS = {"SafeLoader", "CSafeLoader", "BaseLoader", "CBaseLoader"}
_BUILTINS = set(dir(builtins))
_MODE = re.compile(r"[rwxabtU+]{1,4}\Z")
_COOKIE = re.compile(r"[ \t\f]*#.*?coding[:=][ \t]*([-\w.]+)")


def _entropy(s):
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in Counter(s).values())


def _const_str(node):
    return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else None


def _native_segment(q):
    """属性链中间出现 ctypes 之类（开头就是的由导入那条报）。"""
    parts = q.split(".")
    return parts[0] not in _NATIVE_SEGMENTS and not parts[0].startswith("win32") and \
        any(p in _NATIVE_SEGMENTS for p in parts[1:])


# ============================================================================ 代码层：扫描

class _PyScan:
    def __init__(self, name, text):
        self.name, self.lines = name, text.splitlines()
        self.out = []
        self.aliases = {}       # 名字 → 可能指向的限定名集合（文件内、不分流程）
        self.bindings = {}      # (作用域, 名字) → 赋给它的表达式列表（一跳数据流，按函数分作用域）
        self.flagged_imports = set()
        self.parent = {}

    # ---------------------------------------------------------------- 工具
    def add(self, level, rule, node, message, hint=""):
        line = getattr(node, "lineno", 0)
        snippet = self.lines[line - 1].strip()[:120] if 0 < line <= len(self.lines) else ""
        self.out.append(Finding(level, rule, self.name, line, getattr(node, "col_offset", -1) + 1, snippet, message, hint))

    def resolve(self, node, depth=0):
        """表达式可能指向的限定名集合；"?" 开头表示动态拼出来的模块。"""
        if depth > 20:
            return set()
        if isinstance(node, ast.Name):
            r = set(self.aliases.get(node.id, ()))
            if node.id in ("__builtins__", "__builtin__"):
                r.add("builtins")
            elif node.id in _BUILTINS:
                r.add("builtins." + node.id)   # 就算被重新赋值也照样认：flow-insensitive，宁可多报
            return r
        if isinstance(node, ast.Attribute):
            return {f"{b}.{node.attr}" for b in self.resolve(node.value, depth + 1)}
        if isinstance(node, ast.Call):
            fq = self.resolve(node.func, depth + 1)
            arg = self._arg(node, 1 if "builtins.getattr" in fq else 0)
            if "builtins.getattr" in fq:
                s = self._fold(arg)
                return {f"{b}.{s}" for b in self.resolve(node.args[0], depth + 1)} if s and node.args else set()
            if fq & _DYN_IMPORT:
                s = self._fold(arg)
                if s is None:
                    return {"?"}
                return {s.split(".")[0] if "builtins.__import__" in fq else s}
            if fq & _NAME_RESOLVERS:
                s = self._fold(arg)
                return {"?"} if s is None else {s.replace(":", ".")}
            if "builtins.vars" in fq and node.args:
                return self.resolve(node.args[0], depth + 1)
            if fq & {"builtins.globals", "builtins.locals"}:
                return {""}
            return set()
        if isinstance(node, ast.Subscript):
            s = _const_str(node.slice)
            if s is None:
                return set()
            r = set()
            for b in self.resolve(node.value, depth + 1):
                b = b[:-len(".__dict__")] if b.endswith(".__dict__") else b
                if b == "sys.modules":
                    r.add(s)
                else:
                    r |= self.resolve(ast.Name(id=s), depth + 1) if b == "" else {f"{b}.{s}"}
            return r
        if isinstance(node, ast.NamedExpr):
            return self.resolve(node.value, depth + 1)
        return set()

    def _fold(self, node, depth=0):
        """能静态算出来的字符串：字面量、+ 拼接、只含常量的 f-string、"".join([...])、只赋过一次值的变量。"""
        if node is None or depth > 10:
            return None
        s = _const_str(node)
        if s is not None:
            return s
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            a, b = self._fold(node.left, depth + 1), self._fold(node.right, depth + 1)
            return a + b if a is not None and b is not None else None
        if isinstance(node, ast.JoinedStr):
            out = []
            for v in node.values:
                if isinstance(v, ast.FormattedValue):
                    if v.format_spec is not None or v.conversion not in (-1, ord("s")):
                        return None
                    v = v.value
                x = self._fold(v, depth + 1)
                if x is None:
                    return None
                out.append(x)
            return "".join(out)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "join" \
                and len(node.args) == 1 and not node.keywords and isinstance(node.args[0], (ast.List, ast.Tuple)):
            sep = self._fold(node.func.value, depth + 1)
            parts = [self._fold(e, depth + 1) for e in node.args[0].elts]
            return sep.join(parts) if sep is not None and None not in parts else None
        if isinstance(node, ast.Name):
            vals = {self._fold(v, depth + 1) for v in self._lookup(node)}
            return vals.pop() if len(vals) == 1 and None not in vals else None
        return None

    @staticmethod
    def _arg(call, pos, kw=None):
        if kw:
            for k in call.keywords:
                if k.arg == kw:
                    return k.value
        if pos is not None and len(call.args) > pos and not any(isinstance(a, ast.Starred) for a in call.args[:pos + 1]):
            return call.args[pos]
        return None

    @staticmethod
    def _kw(call, name):
        for k in call.keywords:
            if k.arg == name:
                return k.value
        return None

    def _consts(self, node, depth=0, seen=None):
        """表达式里出现的字符串常量，Name 沿赋值展开两跳。"""
        seen = set() if seen is None else seen
        out = []
        for n in ast.walk(node):
            s = _const_str(n)
            if s is not None:
                out.append(s)
            elif isinstance(n, ast.Name) and depth < 2 and n.id not in seen:
                seen.add(n.id)
                for v in self._lookup(n):
                    out += self._consts(v, depth + 1, seen)
        return out

    def _scope(self, node):
        n = self.parent.get(node)
        while n is not None and not isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            n = self.parent.get(n)
        return n   # None = 模块

    def _bind(self, name_node, value):
        self.bindings.setdefault((self._scope(name_node), name_node.id), []).append(value)

    def _lookup(self, name_node):
        """名字在它所在的函数里绑定了什么；没有就往外层函数、模块找。"""
        scope = self._scope(name_node)
        while True:
            if (scope, name_node.id) in self.bindings:
                return self.bindings[(scope, name_node.id)]
            if scope is None:
                return []
            scope = self._scope(scope)

    def _py_written(self, node):
        """路径表达式里像 .py 的字符串常量 → 模块名集合（.pth / .pyc 记成空串）；不像就返回空集合。"""
        out = set()
        for s in self._consts(node) if node is not None else ():
            low = s.lower()
            if low.endswith((".py", ".pyw")):
                out.add(re.split(r"[/\\]", s)[-1].rsplit(".", 1)[0])
            elif low.endswith((".pth", ".pyc")):
                out.add("")
        return out

    # ---------------------------------------------------------------- 预处理
    def prepare(self, tree):
        self.nodes = list(ast.walk(tree))     # 只遍历一次，后面的规则都用它
        for node in self.nodes:
            for child in ast.iter_child_nodes(node):
                self.parent[child] = node
        assigns = []
        for node in self.nodes:
            if isinstance(node, ast.Import):
                for a in node.names:
                    if a.asname:
                        self.aliases.setdefault(a.asname, set()).add(a.name)
                    else:
                        top = a.name.split(".")[0]
                        self.aliases.setdefault(top, set()).add(top)
            elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
                for a in node.names:
                    if a.name != "*":
                        self.aliases.setdefault(a.asname or a.name, set()).add(f"{node.module}.{a.name}")
            elif isinstance(node, (ast.Assign, ast.AnnAssign, ast.NamedExpr)):
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                if node.value is not None:
                    for t in targets:
                        if isinstance(t, ast.Name):
                            assigns.append((t.id, node.value))
                            self._bind(t, node.value)
            elif isinstance(node, (ast.With, ast.AsyncWith)):
                for item in node.items:
                    if isinstance(item.optional_vars, ast.Name):
                        self._bind(item.optional_vars, item.context_expr)
            elif isinstance(node, (ast.For, ast.AsyncFor)) and isinstance(node.target, ast.Name):
                self._bind(node.target, node.iter)
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
                for a in node.args.posonlyargs + node.args.args + node.args.kwonlyargs + \
                        [x for x in (node.args.vararg, node.args.kwarg) if x]:
                    self.bindings.setdefault((node, a.arg), [])     # 参数：挡住外层同名变量
        for _ in range(5):  # 别名链 a = eval; b = a ...，到不动点为止
            changed = False
            for name, value in assigns:
                q = self.resolve(value)
                have = self.aliases.setdefault(name, set())
                if not q <= have:
                    have |= q
                    changed = True
            if not changed:
                break

    # ---------------------------------------------------------------- 规则
    def check_module(self, mod, node):
        hit = False
        if any(mod == e or mod.startswith(e + ".") for e in _MODULE_EXEMPT):
            return False
        for prefix, level, rule, msg, hint in MODULE_RULES:
            if mod == prefix or mod.startswith(prefix + "."):
                self.add(level, rule, node, msg, hint)
                hit = True
        if mod.split(".")[0].startswith("win32"):
            self.add(REJECT, "native-api", node, f"导入了 {mod}（pywin32）：{_NATIVE_WHY}", _NATIVE_HINT)
            hit = True
        if _native_segment(mod):
            hit |= self._native_reject(mod, node)
        return hit

    def _native_reject(self, q, node):
        """同一个位置只报一次（from numpy import ctypeslib 会先后经过导入和引用两条路）。"""
        pos = (getattr(node, "lineno", 0), getattr(node, "col_offset", -1) + 1)
        if any(f.rule == "native-api" and f.level == REJECT and (f.line, f.col) == pos for f in self.out):
            return True
        self.add(REJECT, "native-api", node, f"经 {q} 拿到了原生调用能力：{_NATIVE_WHY}", _NATIVE_HINT)
        return True

    def check_qualified(self, quals, node):
        for q in sorted(quals):
            if q.startswith(("nt.", "posix.")):
                q = "os." + q.split(".", 1)[1]
            if q.startswith("?."):
                if q[2:] in _PROCESS_ATTRS:
                    self.add(EXPLAIN, "process-call", node, f"对动态导入的模块调用 .{q[2:]}：可能是起进程",
                             "模块名写死；送审单里说明")
                continue
            if _native_segment(q):
                self._native_reject(q, node)
            if _PROCESS_RE.match(q):
                self.add(EXPLAIN, "process-call", node, f"{q} 会起子进程", "送审单里说明起什么进程、参数从哪来")
            for pat, level, rule, msg, hint in FUNC_RULES:
                if pat.match(q):
                    self.add(level, rule, node, msg.format(q=q), hint)

    def run(self, tree):
        self.prepare(tree)
        docstrings = set()
        for node in self.nodes:
            if isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and node.body:
                first = node.body[0]
                if isinstance(first, ast.Expr) and _const_str(first.value) is not None:
                    docstrings.add(id(first.value))
        writes_py, import_mech, static_imports = [], False, set()
        for node in self.nodes:
            parent = self.parent.get(node)
            if isinstance(node, ast.ImportFrom):     # 写 .py 再静态导入：记下所有导入里出现的名字
                static_imports.update((node.module or "").split("."))
                static_imports.update(a.name for a in node.names)
            if isinstance(node, ast.Import):
                for a in node.names:
                    static_imports.update(a.name.split("."))
                    if self.check_module(a.name, node):
                        self.flagged_imports.add(a.asname or a.name.split(".")[0])
                    import_mech |= bool(_IMPORT_MECH.match(a.name + ".x"))
            elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
                exempt = all(f"{node.module}.{a.name}" in _MODULE_EXEMPT for a in node.names)
                hit = not exempt and self.check_module(node.module, node)
                if any(a.name == "*" for a in node.names):
                    risky = node.module.split(".")[0] in _STAR_RISKY
                    self.add(EXPLAIN if risky else INFO, "star-import", node,
                             f"from {node.module} import *：工具认不出后面的名字从哪来",
                             "按名字导入要用的东西")
                for a in node.names:
                    q = f"{node.module}.{a.name}"
                    before = len(self.out)
                    if not hit and not exempt:
                        self.check_module(q, node)
                    self.check_qualified({q}, node)
                    if hit or len(self.out) > before:
                        self.flagged_imports.add(a.asname or a.name)
                    import_mech |= bool(_IMPORT_MECH.match(q))
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name in ("__reduce__", "__reduce_ex__"):
                self.add(EXPLAIN, "dunder-access", node, f"定义了 {node.name}：这是定制 pickle 行为的钩子", "送审单里说明")

            # 引用：只看属性链最外层，免得 os.system 里的 os 再报一次
            if isinstance(node, (ast.Name, ast.Attribute, ast.Call, ast.Subscript)) and not (
                    isinstance(parent, ast.Attribute) and parent.value is node):
                if not isinstance(getattr(node, "ctx", ast.Load()), (ast.Store, ast.Del)):
                    if not (isinstance(node, ast.Name) and node.id in self.flagged_imports):
                        quals = self.resolve(node)
                        self.check_qualified(quals, node)
                        import_mech |= any(_IMPORT_MECH.match(q) for q in quals)
                        hidden = quals & _CHECKED_LOADERS
                        if hidden and not (isinstance(parent, ast.Call) and parent.func is node):
                            self.add(EXPLAIN, "unsafe-load", node,
                                     f"间接引用了 {min(hidden)}（赋值、放进容器、传给别的函数）：工具查不了调用时的参数",
                                     "直接调用，并写明 weights_only=True / allow_pickle=False / Loader=yaml.SafeLoader")
            if isinstance(node, (ast.Name, ast.Attribute)) and isinstance(node.ctx, ast.Load) \
                    and "sys.modules" in self.resolve(node):
                self._check_sys_modules(node, parent)
            if isinstance(node, ast.Name) and node.id in ("__builtins__", "__builtin__"):
                self.add(EXPLAIN, "dunder-access", node, f"碰了 {node.id}", "直接写要用的函数，别经过内部属性")
            elif isinstance(node, ast.Attribute):
                if _OPAQUE_PROCESS.match(node.attr) and isinstance(node.ctx, ast.Load) and not self.resolve(node.value):
                    self.add(EXPLAIN, "process-call", node, f"对认不出来的对象取 .{node.attr}：可能是 os / subprocess 经参数传进来",
                             "直接写 os.xxx / subprocess.xxx；送审单里说明")
                if node.attr in _OPAQUE_NATIVE and isinstance(node.ctx, ast.Load) and not self.resolve(node.value):
                    self.add(EXPLAIN, "native-api", node, f"对认不出来的对象取 .{node.attr}：可能是经别的模块拿到 ctypes 一类",
                             "直接写出来源；送审单里说明")
                if node.attr in _DUNDERS:
                    self.add(EXPLAIN, "dunder-access", node, f"碰了内部属性 {node.attr}", "直接写要用的属性，别经过内部属性")
                if isinstance(node.ctx, (ast.Store, ast.Del)):
                    import_mech |= self._check_store(node, node)
            elif isinstance(node, ast.Subscript) and isinstance(node.ctx, (ast.Store, ast.Del)):
                import_mech |= self._check_store(node.value, node, node.slice)
            elif isinstance(node, ast.Call):
                import_mech |= self._check_call(node, parent, writes_py)
            elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add) and not (
                    isinstance(parent, ast.BinOp) and isinstance(parent.op, ast.Add)):
                if self._count_chr(node) >= 8:
                    self.add(EXPLAIN, "string-decode", node, "连续 chr() 拼字符串", _DECODE_HINT)
            elif isinstance(node, ast.Constant) and isinstance(node.value, (str, bytes)) and id(node) not in docstrings:
                self._check_literal(node)

        for w, mods in writes_py:
            imported = sorted(m for m in mods if m and m in static_imports)
            if import_mech or imported:
                why = f"又 import 了 {imported[0]}" if imported else "又有动态导入 / 改导入路径"
                self.add(REJECT, "write-then-import", w, f"写了 .py 文件，同一个文件里{why}：运行的代码审核人没看过",
                         "生成的代码审核人读不到；把它写成代码包里的普通模块")
            else:
                self.add(EXPLAIN, "write-then-import", w, "写了 .py 文件（同一个文件里没看到导入，别的文件可能导入）",
                         "送审单里说明写它做什么")

    def _count_chr(self, node):
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            return self._count_chr(node.left) + self._count_chr(node.right)
        return int(isinstance(node, ast.Call) and "builtins.chr" in self.resolve(node.func))

    def _check_store(self, target, node, key=None):
        """赋值 / 删除的目标。改了导入状态返回 True（算动态导入机制）。"""
        touched = False
        for q in self.resolve(target):
            if q in _IMPORT_STATE:
                self.add(EXPLAIN, "import-machinery", node, f"改了 {q}", "别改导入路径；同目录的模块直接 import")
                touched = True
            elif q.startswith("builtins.") and key is None and target is node:
                self.add(EXPLAIN, "import-machinery", node, f"改写了内置函数 {q}", "送审单里说明")
            elif q == "os.environ" and key is not None:
                self._check_env_key(key, node)
        return touched

    def _check_sys_modules(self, node, parent):
        """sys.modules["os"] 能认出来；下标不是字面量、.get(name) 之类就认不出取的是哪个模块。"""
        # torch / numpy 早就把 ctypes 载进来了：不 import 也能从 sys.modules 拿，字面量名字照导入查
        if isinstance(parent, ast.Subscript) and parent.value is node and isinstance(parent.ctx, ast.Load):
            name = self._fold(parent.slice)
            if name:
                self.check_module(name, parent)
        elif isinstance(parent, ast.Attribute) and parent.value is node and parent.attr in ("get", "pop", "__getitem__"):
            call = self.parent.get(parent)
            if isinstance(call, ast.Call) and call.func is parent:
                name = self._fold(self._arg(call, 0))
                if name:
                    self.check_module(name, call)
        if isinstance(parent, ast.Subscript) and parent.value is node and (
                _const_str(parent.slice) is not None or isinstance(parent.ctx, (ast.Store, ast.Del))):
            return
        if isinstance(parent, ast.Attribute) and parent.value is node and parent.attr in _MUTATORS:
            return     # 改 sys.modules 由 import-machinery 报
        self.add(EXPLAIN, "reflect-nonliteral", node, "按名字从 sys.modules 取模块，工具认不出是哪个",
                 "直接 import 要用的模块")

    def _check_env_key(self, key, node):
        keys = [s for s in self._consts(key)]
        if not keys:
            self.add(EXPLAIN, "import-machinery", node, "改了环境变量，变量名看不出是什么", "变量名写成字面量")
        elif any(k.upper() in _ENV_KEYS for k in keys):
            self.add(EXPLAIN, "import-machinery", node, "改了 PATH / PYTHONPATH 之类影响加载什么代码的环境变量", "送审单里说明")

    def _check_call(self, node, parent, writes_py):
        fq = self.resolve(node.func)
        f = node.func
        term = f.attr if isinstance(f, ast.Attribute) else f.id if isinstance(f, ast.Name) else ""
        import_mech = self._check_reflect(node, fq)
        self._check_namespace(node, fq, parent)
        self._check_deserialize(node, fq, term)
        if fq & {"functools.partial", "functools.partialmethod"} and node.args:
            inner = ast.Call(func=node.args[0], args=node.args[1:], keywords=node.keywords)
            ast.copy_location(inner, node)
            self._check_deserialize(inner, self.resolve(node.args[0]), "", partial=True)
        if "mmap.mmap" in fq:
            prot = self._arg(node, 3, "prot")
            if isinstance(prot, ast.Constant) and isinstance(prot.value, int) and prot.value & 4:   # PROT_EXEC
                self.add(REJECT, "native-api", node, f"mmap 申请了可执行内存：{_NATIVE_WHY}", _NATIVE_HINT)
        self._check_path_loader(node, fq)
        self._check_decode(node, fq, term)
        self._check_writes(node, fq, term, writes_py)
        self._check_download_kw(node, fq, term)
        return self._check_mutation(node, fq) or import_mech

    def _check_reflect(self, node, fq):
        import_mech = False
        for q in fq & set(_REFLECT):
            arg = self._arg(node, _REFLECT[q])
            s = _const_str(arg)
            short = q.replace("builtins.", "")
            if s is None:
                self.add(EXPLAIN, "reflect-nonliteral", node, f"{short} 的名字参数不是字面量",
                         "写死的字典分派 MODELS = {...}，参数声明成 enum")
                folded = self._fold(arg)    # "ct" + "ypes" 这类拼接：照拼出来的名字再查一遍
                if folded and (q in _DYN_IMPORT or q in _NAME_RESOLVERS or q == "runpy.run_module"):
                    self.check_module(folded.replace(":", "."), node)
                if folded and q == "builtins.getattr" and folded in _OPAQUE_NATIVE and node.args \
                        and not self.resolve(node.args[0]):
                    self.add(EXPLAIN, "native-api", node, f"对认不出来的对象取 {folded!r}：可能是经别的模块拿到 ctypes 一类",
                             "直接写出来源；送审单里说明")
            else:
                self.add(INFO, "reflect-literal", node, f"{short}({s!r})：名字是字面量", "能直接写属性 / import 就直接写")
                if s in _DUNDERS:
                    self.add(EXPLAIN, "dunder-access", node, f"经 {short} 碰了内部属性 {s}", "别经过内部属性")
                if q in _DYN_IMPORT or q in _NAME_RESOLVERS or q == "runpy.run_module":
                    self.check_module(s.replace(":", "."), node)
                if q == "builtins.getattr" and s in _OPAQUE_NATIVE and node.args and not self.resolve(node.args[0]):
                    self.add(EXPLAIN, "native-api", node, f"对认不出来的对象取 {s!r}：可能是经别的模块拿到 ctypes 一类",
                             "直接写出来源；送审单里说明")
                if q == "builtins.getattr" and _OPAQUE_PROCESS.match(s) and node.args and not self.resolve(node.args[0]):
                    self.add(EXPLAIN, "process-call", node, f"对认不出来的对象取 {s!r}：可能是 os / subprocess 经参数传进来",
                             "直接写 os.xxx / subprocess.xxx；送审单里说明")
            if q in _DYN_IMPORT or q in _NAME_RESOLVERS or q.startswith(("runpy.", "imp.")):
                import_mech = True
        for q in fq:
            if q.startswith("importlib.util.") and q not in _REFLECT:
                arg = node.args[0] if node.args else None
                if _const_str(arg) is None:
                    self.add(EXPLAIN, "reflect-nonliteral", node, f"{q}：按运行时的名字 / 路径加载模块", "送审单里说明")
                else:
                    self.add(INFO, "reflect-literal", node, f"{q}({_const_str(arg)!r})", "能直接 import 就直接写")
                import_mech = True
        return import_mech

    def _check_namespace(self, node, fq, parent):
        """globals() / locals() / vars() 被下标访问、取属性或传给别的函数"""
        if fq & {"builtins.globals", "builtins.locals", "builtins.vars"}:
            if (isinstance(parent, (ast.Subscript, ast.Attribute)) and parent.value is node) or \
                    (isinstance(parent, ast.Call) and node is not parent.func) or isinstance(parent, ast.keyword):
                self.add(EXPLAIN, "namespace-access", node, "按名字访问命名空间（globals/locals/vars）",
                         "写死的字典分派，别按名字取全局对象")

    def _check_deserialize(self, node, fq, term, partial=False):
        """反序列化。partial=True：查的是 functools.partial 里预先绑定的参数，没绑定的留给间接引用那条报"""
        if fq & {"torch.load", "torch.serialization.load"}:
            wo = self._kw(node, "weights_only")
            if isinstance(wo, ast.Constant) and wo.value is True or wo is None and partial:
                pass
            elif wo is None and not any(k.arg is None for k in node.keywords):
                self.add(REJECT, "unsafe-load", node, "torch.load 没有 weights_only=True：会按 pickle 执行文件里的调用",
                         "加 weights_only=True，或者改用 safetensors")
            elif isinstance(wo, ast.Constant):
                self.add(REJECT, "unsafe-load", node, "torch.load 关掉了 weights_only：会按 pickle 执行文件里的调用",
                         "改成 weights_only=True")
            else:
                self.add(EXPLAIN, "unsafe-load", node, "torch.load 的 weights_only 看不出是不是 True", "写成字面量 weights_only=True")
        np_pos = [_ALLOW_PICKLE_POS[q] for q in fq if q in _ALLOW_PICKLE_POS]
        ap = self._arg(node, np_pos[0] if np_pos else None, "allow_pickle")   # 关键字不管是哪个函数都查
        if isinstance(ap, ast.Constant):
            if ap.value is True:
                self.add(REJECT, "unsafe-load", node, "allow_pickle=True 会反序列化 pickle 对象", "去掉 allow_pickle")
        elif np_pos and (ap is not None or any(k.arg is None for k in node.keywords)):
            self.add(EXPLAIN, "unsafe-load", node, "np.load 的 allow_pickle 看不出是不是 False", "去掉 allow_pickle")
        if fq & {"yaml.full_load", "yaml.full_load_all"} and not partial:
            self.add(EXPLAIN, "unsafe-load", node, "yaml.full_load 比 safe_load 宽", "用 yaml.safe_load")
        if fq & {"yaml.load", "yaml.load_all"}:
            loader = self._arg(node, 1, "Loader")
            names = {q.rsplit(".", 1)[-1] for q in self.resolve(loader)} if loader is not None else set()
            if isinstance(loader, ast.Attribute):
                names.add(loader.attr)
            elif isinstance(loader, ast.Name):
                names.add(loader.id)
            if names and names <= _SAFE_YAML_LOADERS or loader is None and partial:
                pass
            elif loader is None or names & {"Loader", "UnsafeLoader", "FullLoader", "CLoader", "CUnsafeLoader", "CFullLoader"}:
                self.add(REJECT, "unsafe-load", node, "yaml.load 没用 SafeLoader：能构造任意 Python 对象", "用 yaml.safe_load")
            else:
                self.add(EXPLAIN, "unsafe-load", node, "yaml.load 的 Loader 看不出是不是安全的", "用 yaml.safe_load")
        if term in ("to_pickle", "read_pickle") and isinstance(node.func, ast.Attribute) and not fq & {"pandas.read_pickle"}:
            self.add(REJECT, "pickle-use", node, f".{term}() 是 pickle 读写", _PICKLE_HINT)

    def _check_decode(self, node, fq, term):
        """字符串还原：.decode("rot13") 之类，"".join(chr(...) ...)，bytes([..很多整数..])"""
        if term == "decode" and isinstance(node.func, ast.Attribute):
            codec = _const_str(self._arg(node, 0, "encoding"))
            if codec and codec.lower().replace("-", "_") in _DECODE_CODECS:
                self.add(EXPLAIN, "string-decode", node, f".decode({codec!r}) 是字符串还原", _DECODE_HINT)
        if term == "join" and isinstance(node.func, ast.Attribute) and node.args:
            if any(isinstance(n, (ast.Name, ast.Attribute)) and "builtins.chr" in self.resolve(n)
                   for n in ast.walk(node.args[0])):
                self.add(EXPLAIN, "string-decode", node, "用 chr() 拼字符串", _DECODE_HINT)
        if fq & {"builtins.bytes", "builtins.bytearray"} and node.args and isinstance(node.args[0], (ast.List, ast.Tuple)):
            if sum(isinstance(e, ast.Constant) and isinstance(e.value, int) for e in node.args[0].elts) >= 8:
                self.add(EXPLAIN, "string-decode", node, "用整数列表拼字节串", _DECODE_HINT)

    def _check_writes(self, node, fq, term, writes_py):
        """写文件：写到任务目录以外、写 .py"""
        path = mode = None
        unknown_mode_writes = False
        if fq & _OPENERS:
            path, mode = self._arg(node, 0, "file"), self._arg(node, 1, "mode")
            unknown_mode_writes = True
        elif term == "open" and isinstance(node.func, ast.Attribute) and not fq:     # Path(...).open("w")
            path, mode = node.func.value, self._arg(node, 0, "mode")
        if path is not None:
            m = _const_str(mode)
            if m is not None and _MODE.match(m):
                writing = any(c in m for c in "wax+")
            else:
                writing = unknown_mode_writes and mode is not None
            if writing:
                self._check_write_target(path, node)
                self._note_py(writes_py, node, path)
        if fq & {"os.open"}:     # os.open(path, flags)：只有 flags 明确是 O_RDONLY 才算只读
            path, flags = self._arg(node, 0, "path"), self._arg(node, 1, "flags")
            if flags is None or self.resolve(flags) != {"os.O_RDONLY"}:
                self._check_write_target(path, node)
                self._note_py(writes_py, node, path)
        if term in ("write_text", "write_bytes", "touch") and isinstance(node.func, ast.Attribute):
            self._check_write_target(node.func.value, node)
            self._note_py(writes_py, node, node.func.value)
        if fq & {"shutil.copy", "shutil.copy2", "shutil.copyfile", "shutil.move", "os.rename", "os.replace"}:
            self._note_py(writes_py, node, self._arg(node, 1, "dst"))
        for q in fq:
            if q.startswith("tempfile.") and q[9:] in _TEMPFILE:
                pos = _TEMPFILE[q[9:]]
                if pos is None or self._arg(node, pos, "dir") is None:
                    self.add(EXPLAIN, "write-outside", node, f"{q} 没给 dir：会写到系统临时目录 %TEMP%",
                             "加 dir=TMP（ROOT / \"tmp\"）")

    def _note_py(self, writes_py, node, path):
        mods = self._py_written(path)
        if mods:
            writes_py.append((node, mods))

    def _check_path_loader(self, node, fq):
        """按路径加载代码：路径不是 .py 的（或只能是字节码），工具没扫过它"""
        for q in sorted(fq & set(_PATH_LOADERS)):
            pos, kw, bytecode = _PATH_LOADERS[q]
            s = _const_str(self._arg(node, pos, kw))
            if bytecode:
                self.add(REJECT, "load-source", node, f"{q} 加载的是字节码，审核人读不到", "把源码放进代码包，直接 import")
            elif s is not None and not s.lower().endswith((".py", ".pyw")):
                self.add(REJECT, "load-source", node, f"{q} 按路径加载 {s!r}：不是 .py，工具没按代码扫它",
                         "代码写成 .py 模块放进代码包，直接 import")
            else:
                where = f"{s!r}" if s is not None else "运行时才知道的路径"
                self.add(EXPLAIN, "load-source", node, f"{q} 按路径加载代码（{where}）",
                         "包内模块直接 import；送审单里说明加载的是哪个文件")

    def _check_download_kw(self, node, fq, term):
        """框架下载"""
        if term in _DOWNLOADERS or fq & {"torch.hub.load"}:
            self._check_download(node, term, fq)
        for k in node.keywords:
            if k.arg == "download" and isinstance(k.value, ast.Constant) and k.value.value is True:
                self.add(EXPLAIN, "download", node, "download=True：会联网下载", "数据走数据集上架，代码里 download=False")
            if k.arg == "trust_remote_code" and not (isinstance(k.value, ast.Constant) and k.value.value is False):
                self.add(EXPLAIN, "download", node, "trust_remote_code：会执行模型目录里带的 Python 代码，审核人没读过",
                         "去掉 trust_remote_code")

    def _check_mutation(self, node, fq):
        """改导入路径和环境变量：sys.path.insert(...)、os.environ.update(PATH=...)、os.putenv("PATH", ...)"""
        import_mech = False
        if isinstance(node.func, ast.Attribute) and node.func.attr in _MUTATORS:
            for q in self.resolve(node.func.value):
                if q in _IMPORT_STATE:
                    self.add(EXPLAIN, "import-machinery", node, f"改了 {q}", "别改导入路径；同目录的模块直接 import")
                    import_mech = True
                elif q == "os.environ":
                    keys = [ast.Constant(value=k.arg) for k in node.keywords if k.arg]
                    for a in node.args:
                        if isinstance(a, ast.Dict):
                            keys += [k for k in a.keys if k is not None]
                        elif node.func.attr in ("setdefault", "__setitem__"):
                            keys.append(a)
                            break
                    for k in keys:
                        self._check_env_key(k, node)
        if fq & {"os.putenv"} and node.args:
            self._check_env_key(node.args[0], node)
        return import_mech

    def _check_write_target(self, path, node):
        s = _const_str(path)
        if s is None and isinstance(path, ast.Call) and path.args:     # Path("/etc/x").write_text(...)
            s = _const_str(path.args[0])
        if s is not None and _OUTSIDE.match(s):
            self.add(EXPLAIN, "write-outside", node, f"往任务目录以外写：{s!r}", "只写 OUT（output）和 TMP（tmp）")

    def _check_download(self, node, term, fq):
        if "torch.hub.load" in fq:
            self.add(EXPLAIN, "download", node, "torch.hub.load 会下载并执行仓库里的 hubconf.py", "权重走数据集上架，模型结构写在代码包里")
            return
        local_kw = self._kw(node, "local_files_only")
        arg = self._arg(node, 0, "pretrained_model_name_or_path") or self._arg(node, 0, "repo_id") or self._arg(node, 0, "path")
        if isinstance(local_kw, ast.Constant) and local_kw.value is True or self._is_local(arg):
            self.add(INFO, "download", node, f"{term}(...) 指向本地路径，OK", "记得设 HF_HUB_OFFLINE=1")
        else:
            self.add(EXPLAIN, "download", node, f"{term}(...) 看不出是本地路径：可能会联网下载",
                     "传 DATA / \"...\" 这样的本地路径，加 local_files_only=True")

    def _is_local(self, node, depth=0):
        if node is None or depth > 2:
            return False
        s = _const_str(node)
        if s is not None:
            return s.startswith((".", "/", "\\")) or bool(re.match(r"[A-Za-z]:", s))
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):
            return True
        if isinstance(node, ast.Call):
            return bool(self.resolve(node.func) & {"pathlib.Path", "os.path.join", "builtins.str"}) and \
                any(self._is_local(a, depth + 1) for a in node.args)
        if isinstance(node, ast.Name):
            vals = self._lookup(node)
            return bool(vals) and all(self._is_local(v, depth + 1) for v in vals)
        return False

    def _check_literal(self, node):
        v = node.value
        n = len(v)
        if n > 200:
            self.add(EXPLAIN, "suspicious-literal", node, f"很长的字面量（{n} 字符）",
                     "长文本放进 .txt / .jinja 文件；编码后的数据不该出现在代码里")
        elif n >= 64 and (isinstance(v, bytes) or v.isascii()) and _entropy(v) > 4.5:
            self.add(EXPLAIN, "suspicious-literal", node, f"高熵字面量（{n} 字符，{_entropy(v):.1f} 比特/字符）：像压缩或加密数据",
                     "送审单里说明这是什么")
        elif isinstance(v, str) and n >= 100 and re.fullmatch(r"[0-9a-fA-F]+|[A-Za-z0-9+/_-]+=*", v):
            self.add(EXPLAIN, "suspicious-literal", node, f"长串十六进制 / base64 形状的字面量（{n} 字符）", "送审单里说明这是什么")


def _param_uses(scan, tree):
    """代码里按字面量读的参数名：P["x"] / P.get("x")，P 是 json.load 的结果。"""
    loads = {}
    for node in scan.nodes:
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call) and \
                scan.resolve(node.value.func) & {"json.load", "json.loads"}:
            for t in node.targets:
                if isinstance(t, ast.Name):
                    mentions = any("params" in s for s in scan._consts(node.value))
                    loads[t.id] = loads.get(t.id, False) or mentions
    if any(loads.values()):  # 认得出哪个是 params.json，就只看它
        loads = {k: v for k, v in loads.items() if v}
    uses = []
    for node in scan.nodes:
        key = None
        if isinstance(node, ast.Subscript) and isinstance(node.value, ast.Name) and node.value.id in loads:
            key = _const_str(node.slice)
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.args \
                and node.func.attr in ("get", "pop", "setdefault") \
                and isinstance(node.func.value, ast.Name) and node.func.value.id in loads:
            key = _const_str(node.args[0])
        if key is not None:
            line = node.lineno
            snippet = scan.lines[line - 1].strip()[:120] if 0 < line <= len(scan.lines) else ""
            uses.append((key, scan.name, node, snippet))
    return uses


def _cookie_lines(text):
    """解释器只认前两行的编码声明。直接运行脚本时 \r 和 \n 都算换行，import 时只按 \n 分行；
    str.splitlines 还会在 \x0c \x1c \x85 这些字符处分行，不能用。两种分法都查。"""
    for lines in (text.split("\n", 2)[:2], re.split(r"\r\n|\r|\n", text, maxsplit=2)[:2]):
        yield from enumerate(lines, 1)


def scan_python(name, text, raw=None):
    """扫一个 .py 文件的源码。返回 (findings, 参数读取点)。只 ast.parse，不执行。
    raw：文件原始字节。给了就按字节解析，解码方式和解释器完全一样。"""
    for lineno, line in _cookie_lines(text):
        m = _COOKIE.match(line)
        if not m:
            continue
        enc = m.group(1).lower().replace("_", "-")
        if enc not in ("utf-8", "utf8") and not enc.startswith("utf-8-"):
            return [Finding(REJECT, "source-encoding", name, lineno, 1, m.group(0).strip()[:120],
                            f"声明了源码编码 {m.group(1)}：解释器按它解码，审核人和工具按 UTF-8 读，看到的可能不是同一份代码",
                            "删掉编码声明，存成 UTF-8")], []
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            tree = ast.parse(raw if raw is not None else text, filename=name)
    except SyntaxError as e:
        return [Finding(ERROR, "parse-error", name, e.lineno or 0, e.offset or 0, (e.text or "").strip()[:120],
                        f"语法错误（Python 2 代码？）：{e.msg}", "工具按 Python 3 解析；修好再送审")], []
    except (ValueError, RecursionError, MemoryError) as e:
        return [Finding(ERROR, "parse-error", name, message=f"解析不了：{type(e).__name__}: {e}", hint="修好再送审")], []
    scan = _PyScan(name, text)
    try:
        scan.run(tree)
    except RecursionError:
        return [Finding(ERROR, "parse-error", name, message="嵌套太深，工具扫不完", hint="拆开写")], []
    return scan.out, _param_uses(scan, tree)


# ============================================================================ 结论和报告

def _finish(findings, meta):
    seen, out = set(), []
    for f in findings:
        k = (f.level, f.rule, f.file, f.line, f.col, f.message)
        if k not in seen:
            seen.add(k)
            out.append(f)
    out.sort(key=lambda f: (-_RANK[f.level], f.file, f.line, f.col, f.rule))
    return Report(out, meta)


def verdict(fs):
    """最高的级别；没有发现返回 None。"""
    best = None
    for f in fs:
        if best is None or _RANK[f.level] > _RANK[best]:
            best = f.level
    return best


def exit_code(fs, strict=False):
    v = verdict(fs)
    if v == ERROR:
        return 3
    if v == REJECT or (v == EXPLAIN and strict):
        return 2
    return 1 if v == EXPLAIN else 0


def _counts(fs):
    c = {REJECT: 0, EXPLAIN: 0, INFO: 0, ERROR: 0}
    for f in fs:
        c[f.level] += 1
    return c


def _safe(s):
    """控制字符、零宽和双向控制符换成 \\xNN / \\uNNNN，免得被审代码里的转义序列改写审核人的终端。"""
    return "".join(c if unicodedata.category(c) not in ("Cc", "Cf", "Zl", "Zp")
                   else (f"\\x{ord(c):02x}" if ord(c) < 256 else f"\\u{ord(c):04x}") for c in s)


def render_text(pkg, fs, strict=False):
    meta = getattr(fs, "meta", {})
    c = _counts(fs)
    v = verdict(fs)
    title = " ".join(str(x) for x in (meta.get("name"), meta.get("version")) if x) or str(pkg)
    sha = meta.get("code_sha256")
    head = f"epsilon-review  {title}   {meta.get('files', 0)} 个文件"
    head += f"  sha256 {sha[:12]}…" if sha else "  （目录，没有 code.zip）"
    concl = LABEL.get(v, "通过") if v != INFO else "通过（只有提示）"
    if strict and v == EXPLAIN:
        concl += "（--strict：按拒签处理）"
    counts = f"拒签 {c[REJECT]} · 需解释 {c[EXPLAIN]} · 提示 {c[INFO]}" + (f" · 工具出错 {c[ERROR]}" if c[ERROR] else "")
    lines = [head, f"结论：{concl}（{counts}）", ""]
    for f in fs:
        loc = f"{f.file}:{f.line}" if f.line else f.file
        body = f"{f.snippet} —— {f.message}" if f.snippet else f.message
        lines.append(f"[{LABEL[f.level]}] {loc}  {body}  ({f.rule})")
        if f.hint:
            lines.append(f"         建议：{f.hint}")
    return "\n".join(_safe(x) for x in lines) + "\n"


def render_json(pkg, fs, strict=False):
    meta = getattr(fs, "meta", {})
    rep = {
        "tool_version": TOOL_VERSION,
        "rules_version": RULES_VERSION,
        "package": str(pkg),
        "name": meta.get("name"),
        "version": meta.get("version"),
        "files": meta.get("files", 0),
        "sha256": meta.get("code_sha256"),
        "code_sha256": meta.get("code_sha256"),
        "verdict": verdict(fs) or "pass",
        "counts": _counts(fs),
        "strict": strict,
        "exit_code": exit_code(fs, strict),
        "findings": [asdict(f) for f in fs],
    }
    return json.dumps(rep, ensure_ascii=False, indent=2) + "\n"


class _Parser(argparse.ArgumentParser):
    def error(self, message):  # argparse 默认退出码 2 会和“拒签”撞，改成 3
        self.print_usage(sys.stderr)
        sys.stderr.write(f"epsilon-review: {message}\n")
        sys.exit(3)


def main(argv=None):
    p = _Parser(prog="epsilon-review", description="任务包静态审核：只解析不执行，把可疑点列给审核人。")
    p.add_argument("package", help="任务包目录（job.json + code.zip 或 code/），或者 code.zip")
    p.add_argument("--job", help="job.json 路径（默认取任务包目录里的 job.json）")
    p.add_argument("--json", action="store_true", help="输出机器可读的 JSON")
    p.add_argument("--strict", action="store_true", help="需解释也按拒签处理（退出码 2）")
    args = p.parse_args(argv)
    for s in (sys.stdout, sys.stderr):
        try:
            s.reconfigure(errors="replace")
        except (AttributeError, ValueError):
            pass
    try:
        fs = scan_package(args.package, args.job)
        out = render_json(args.package, fs, args.strict) if args.json else render_text(args.package, fs, args.strict)
        sys.stdout.write(out)
        return exit_code(fs, args.strict)
    except Exception as e:  # 不抛 traceback
        sys.stderr.write(f"epsilon-review: 内部错误 {type(e).__name__}: {e}\n")
        return 3


if __name__ == "__main__":
    sys.exit(main())
