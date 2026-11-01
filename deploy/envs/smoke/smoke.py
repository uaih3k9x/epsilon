"""环境层真机冒烟。用执行器的方式跑: <层目录>\\python.exe -E -B smoke.py。全部通过退出 0，否则退出 1。"""
import json
import sys
import time
from pathlib import Path

report = {"checks": {}}


def check(name, ok, detail=None):
    report["checks"][name] = {"ok": bool(ok), "detail": detail}


layer = Path(sys.executable).resolve().parent
script_dir = Path(__file__).resolve().parent
report["sys_path"] = sys.path
check("flags_E_B", sys.flags.ignore_environment and sys.dont_write_bytecode)

try:
    import smoke_helper
    check("import_sibling_module", smoke_helper.VALUE == 42)
except Exception as error:
    check("import_sibling_module", False, repr(error))

# 不许有层外路径：学生机上装过 Python 时，注册表 / PYTHONPATH 不能混进来
foreign = [p for p in sys.path if p and not Path(p).resolve().is_relative_to(layer)
           and Path(p).resolve() != script_dir]
check("no_foreign_sys_path", not foreign, foreign)

try:
    start = time.perf_counter()
    import numpy
    import torch
    report["import_seconds"] = time.perf_counter() - start
    report["versions"] = {"python": sys.version.split()[0], "numpy": numpy.__version__, "torch": torch.__version__,
                          "cuda": torch.version.cuda}
    check("modules_from_layer", all(Path(m.__file__).resolve().is_relative_to(layer) for m in (numpy, torch)))
    check("numpy_torch_interop", torch.from_numpy(numpy.ones(3)).sum().item() == 3.0)
    check("cuda_available", torch.cuda.is_available())
    if torch.cuda.is_available():
        report["gpu"] = torch.cuda.get_device_name(0)
        x = torch.ones((256, 256), device="cuda")
        check("cuda_matmul", (x @ x).sum().item() == 256.0 ** 3)
        report["gpu_peak_allocated_mb"] = torch.cuda.max_memory_allocated(0) / (1 << 20)
except Exception as error:
    check("torch", False, repr(error))

report["ok"] = all(c["ok"] for c in report["checks"].values())
print(json.dumps(report, ensure_ascii=False, indent=2))
sys.exit(0 if report["ok"] else 1)
