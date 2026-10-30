#!/usr/bin/env python3
"""把座位 → 交换机端口表 ports.json 转成主控配置里的 topology。

用法：
    python3 pilot/ports2topology.py ports.json > topology.json
然后把输出贴进 controller.json 的 "topology"。

输入：{"<节点名>": ["<交换机名>", "<端口>", "<来源标签>"], ...}
输出：{"<节点名>": {"room": "<教室>", "switch": "<交换机名>"}, ...}
教室取交换机名里 U 之前的部分（R1U12 → R1），没有 U 就用交换机名本身。

自测：python3 -m doctest -v pilot/ports2topology.py

>>> room_of("R1U12")
'R1'
>>> room_of("core1")
'core1'
>>> convert({"pc-01": ["R1U12", "GE0/0/5", "test"], "pc-02": ["core1", "GE0/0/1", "test"]})
{'pc-01': {'room': 'R1', 'switch': 'R1U12'}, 'pc-02': {'room': 'core1', 'switch': 'core1'}}
"""
import json
import sys


def room_of(switch):
    i = switch.find("U")
    return switch[:i] if i > 0 else switch


def convert(ports):
    return {node: {"room": room_of(v[0]), "switch": v[0]} for node, v in sorted(ports.items()) if v and v[0]}


def main():
    if len(sys.argv) != 2:
        sys.exit(__doc__.split("\n\n")[1])
    with open(sys.argv[1], encoding="utf-8") as f:
        json.dump(convert(json.load(f)), sys.stdout, ensure_ascii=False, indent=2)
    print()


if __name__ == "__main__":
    main()
