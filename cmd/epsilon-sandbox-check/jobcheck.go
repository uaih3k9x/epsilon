package main

import _ "embed"

// jobCheckSrc 是任务侧脚本，写成测试任务目录的 code\main.py（任务账户只读）。
//
//go:embed py/job_check.py
var jobCheckSrc string

// shadowSitecustomize 放在测试任务的 code\ 里（第 6 项）：sitecustomize 必须先从环境层导入，这一份不该被执行。
const shadowSitecustomize = "import builtins\nbuiltins.EPS_SHADOW_SITECUSTOMIZE = True\nprint('SHADOW SITECUSTOMIZE RAN')\n"

// taskChecks 是 task 模式一定会报的 id（没有 torch、没有 GPU 时报 SKIP）。
var taskChecks = []string{"3.low_il", "16.privileges", "6.sitecustomize_first", "2.user32_window", "4.fs_ops",
	"7.mp_pool_spawn", "3.torch_import", "3.dataloader", "3.cuda", "4.cudnn", "16.cuda_after_drop"}
