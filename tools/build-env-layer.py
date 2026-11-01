#!/usr/bin/env python3
"""在 Mac 上跨平台构建 Windows 环境层（手册第 7 节，设计书 22.6.1）。

    python3 tools/build-env-layer.py deploy/envs/py311-torch2.5-cu124 --out dist/envs

产出 <out>/chunks/<名字@版本>.json 和块；打印的摘要写进钥匙环的 env_layers。
只用官方源：embeddable Python 核对 SHA-256，wheel 按 requirements.lock 的哈希装（--require-hashes）。
"""

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

TARGET = "x86_64-pc-windows-msvc"
PY_VERSION = "3.11"
ZIP_TIME = (1980, 1, 1, 0, 0, 0)  # 固定时间：同样的输入得到同样的摘要
LAUNCHER_DIRS = ("bin", "Scripts")
PROVENANCE = ("layer.json", "requirements.in", "requirements.lock")


class BuildError(Exception):
    pass


def layer_id(spec):
    return f"{spec['name']}@{spec['version']}"


def sha256_of(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def verify_sha256(path, want):
    got = sha256_of(path)
    if got != want:
        raise BuildError(f"{path}: SHA-256 是 {got}，要的是 {want}")


def install_cmd(lock, site, indexes):
    cmd = ["uv", "pip", "install", "--require-hashes", "--no-deps", "-r", str(lock), "--target", str(site),
           "--python-platform", TARGET, "--python-version", PY_VERSION, "--only-binary", ":all:",
           "--index-url", indexes[0], "--index-strategy", "unsafe-best-match"]
    for extra in indexes[1:]:
        cmd += ["--extra-index-url", extra]
    return cmd


def compile_cmd(site):
    # unchecked-hash：解压不保留修改时间，按时间校验的 pyc 会全部失效。-s 去掉构建机路径。
    return ["uv", "run", "--no-project", "--python", PY_VERSION, "python", "-m", "compileall", "-q", "-j", "0",
            "--invalidation-mode", "unchecked-hash", "-s", str(site), "-p", "Lib/site-packages", str(site)]


def assemble(embed, site, spec_dir, layer):
    """拼层目录：embeddable + Lib/site-packages + 来源清单。"""
    embed, site, spec_dir, layer = Path(embed), Path(site), Path(spec_dir), Path(layer)
    if layer.exists():
        shutil.rmtree(layer)
    shutil.copytree(embed, layer)
    # ._pth 会打开 safe_path（CPython getpath.py）：脚本目录不进 sys.path，多文件任务全部导入失败。
    # 隔离改由执行器加 -E 负责：不读 PYTHON* 环境变量和注册表，脚本目录照常进 sys.path。
    for pth in layer.glob("*._pth"):
        pth.unlink()
    target = layer / "Lib" / "site-packages"
    shutil.copytree(site, target)
    for d in LAUNCHER_DIRS:
        if (target / d).is_dir():
            shutil.rmtree(target / d)
    for name in PROVENANCE:
        if (spec_dir / name).exists():
            shutil.copy2(spec_dir / name, layer / name)


def zip_layer(layer, out):
    layer = Path(layer)
    paths = sorted(layer.rglob("*"), key=lambda p: p.relative_to(layer).as_posix())
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED, compresslevel=6) as z:
        for p in paths:
            if p.is_symlink():
                raise BuildError(f"环境层里不许有软链接: {p}")
            if p.is_dir():
                continue
            info = zipfile.ZipInfo(p.relative_to(layer).as_posix(), ZIP_TIME)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.create_system = 3
            info.external_attr = 0o644 << 16
            with open(p, "rb") as src, z.open(info, "w", force_zip64=True) as dst:
                shutil.copyfileobj(src, dst, 1 << 20)


def fetch_embed(py, work):
    archive = work / Path(py["url"]).name
    if not archive.exists():
        print("下载", py["url"], flush=True)
        # 用 curl：python.org 版 Python 在 Mac 上常常没装 CA 证书。下载后还要核 SHA-256。
        subprocess.run(["curl", "-fsSL", "-o", str(archive), py["url"]], check=True)
    verify_sha256(archive, py["sha256"])
    embed = work / "embed"
    if embed.exists():
        shutil.rmtree(embed)
    with zipfile.ZipFile(archive) as z:
        z.extractall(embed)
    return embed


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("spec", type=Path, help="含 layer.json 和 requirements.lock 的目录")
    ap.add_argument("--out", type=Path, required=True)
    args = ap.parse_args()
    spec = json.loads((args.spec / "layer.json").read_text(encoding="utf-8"))
    name = layer_id(spec)
    work = args.out / "work" / name
    work.mkdir(parents=True, exist_ok=True)
    embed = fetch_embed(spec["python"], work)

    site = work / "site"
    if site.exists():
        shutil.rmtree(site)
    subprocess.run(install_cmd(args.spec / "requirements.lock", site, spec["indexes"]), check=True)
    # 个别文件编译失败（比如只在别的平台用的语法）不算致命：运行时照样能从源码导入
    if subprocess.run(compile_cmd(site)).returncode != 0:
        print("warning: compileall 有文件没编译成功", file=sys.stderr)

    layer = work / "layer"
    assemble(embed, site, args.spec, layer)
    src = args.out / "src"
    (src / "envs").mkdir(parents=True, exist_ok=True)
    rel = f"envs/{name}.zip"
    print("打包", rel, flush=True)
    zip_layer(layer, src / rel)
    chunks = args.out / "chunks"
    subprocess.run(["go", "run", "./cmd/epsilon-chunk", "build", "-id", name, "-root", str(src.resolve()),
                    "-out", str(chunks.resolve()), rel], check=True)
    digest = sha256_of(chunks / f"{name}.json")
    print(json.dumps({"layer": name, "digest": digest, "zip_bytes": (src / rel).stat().st_size,
                      "keyring_entry": {name: digest}}, ensure_ascii=False))


if __name__ == "__main__":
    main()
