"""build-env-layer 的测试（不联网、不调 uv）。运行: python3 -m pytest tools/test_build_env_layer.py"""

import hashlib
import importlib.util
import json
import os
import zipfile

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
_spec = importlib.util.spec_from_file_location("build_env_layer", os.path.join(HERE, "build-env-layer.py"))
bl = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(bl)


def write(path, text="x"):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


@pytest.fixture
def parts(tmp_path):
    embed = tmp_path / "embed"
    write(embed / "python.exe", "MZ")
    write(embed / "python311.zip")
    write(embed / "python311._pth", "python311.zip\n.\n#import site\n")
    site = tmp_path / "site"
    write(site / "torch" / "__init__.py")
    write(site / "torch" / "lib" / "torch_cpu.dll")
    write(site / "bin" / "torchrun.exe", "launcher")
    write(site / "Scripts" / "f2py.exe", "launcher")
    spec = tmp_path / "spec"
    write(spec / "layer.json", json.dumps({"name": "py311-t", "version": 1}))
    write(spec / "requirements.lock", "torch==1 --hash=sha256:aa\n")
    return embed, site, spec, tmp_path / "layer"


def test_layer_id():
    assert bl.layer_id({"name": "py311-torch2.5-cu124", "version": 1}) == "py311-torch2.5-cu124@1"


def test_assemble_removes_pth_because_it_breaks_multifile_jobs(parts):
    # ._pth 会打开 safe_path (CPython getpath.py): 脚本目录不进 sys.path, import experiment 直接失败
    embed, site, spec, layer = parts
    bl.assemble(embed, site, spec, layer)
    assert not list(layer.glob("*._pth"))
    assert (layer / "python.exe").exists() and (layer / "python311.zip").exists()


def test_assemble_places_site_packages_where_site_finds_them(parts):
    embed, site, spec, layer = parts
    bl.assemble(embed, site, spec, layer)
    assert (layer / "Lib" / "site-packages" / "torch" / "lib" / "torch_cpu.dll").exists()


def test_assemble_drops_launchers(parts):
    # 手册 7.1: 任务只能用解释器, 环境层不留可直接启动的 console script
    embed, site, spec, layer = parts
    bl.assemble(embed, site, spec, layer)
    assert not (layer / "Lib" / "site-packages" / "bin").exists()
    assert not (layer / "Lib" / "site-packages" / "Scripts").exists()


def test_assemble_records_provenance(parts):
    # 手册 7.1: 每层一份清单, 跟环境层一起存档
    embed, site, spec, layer = parts
    bl.assemble(embed, site, spec, layer)
    assert json.loads((layer / "layer.json").read_text(encoding="utf-8"))["name"] == "py311-t"
    assert "--hash=sha256" in (layer / "requirements.lock").read_text(encoding="utf-8")


def test_zip_is_reproducible(parts, tmp_path):
    embed, site, spec, layer = parts
    bl.assemble(embed, site, spec, layer)
    a, b = tmp_path / "a.zip", tmp_path / "b.zip"
    bl.zip_layer(layer, a)
    os.utime(layer / "python.exe", (1, 1))  # 修改时间变了, 结果不能变
    bl.zip_layer(layer, b)
    assert hashlib.sha256(a.read_bytes()).digest() == hashlib.sha256(b.read_bytes()).digest()
    with zipfile.ZipFile(a) as z:
        names = z.namelist()
    assert names == sorted(names) and "python.exe" in names
    assert all("\\" not in n for n in names)


def test_zip_refuses_symlink(parts, tmp_path):
    embed, site, spec, layer = parts
    bl.assemble(embed, site, spec, layer)
    os.symlink("/etc/passwd", layer / "evil")
    with pytest.raises(bl.BuildError):
        bl.zip_layer(layer, tmp_path / "a.zip")


def test_verify_sha256(tmp_path):
    f = tmp_path / "x"
    f.write_bytes(b"abc")
    bl.verify_sha256(f, hashlib.sha256(b"abc").hexdigest())
    with pytest.raises(bl.BuildError):
        bl.verify_sha256(f, "0" * 64)


def test_compile_uses_unchecked_hash():
    # 解压不保留修改时间, 按时间校验的 pyc 会全部失效; 又不写字节码, 等于每次启动重新编译 torch
    cmd = bl.compile_cmd("/x/site")
    assert "unchecked-hash" in cmd and "3.11" in cmd


def test_install_cmd_targets_windows_with_locked_hashes():
    cmd = bl.install_cmd("/spec/requirements.lock", "/x/site", ["https://a/simple", "https://b/whl"])
    assert "--require-hashes" in cmd and "--no-deps" in cmd
    assert cmd[cmd.index("--python-platform") + 1] == "x86_64-pc-windows-msvc"
    assert cmd[cmd.index("--only-binary") + 1] == ":all:"
