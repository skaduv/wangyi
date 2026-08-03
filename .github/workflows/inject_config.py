#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""GitHub Actions - 检查 user.json 配置"""

import json
import os
import sys

USER_JSON = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "..", "..", "user.json"
)


def main():
    if not os.path.exists(USER_JSON):
        print(f"❌ user.json 不存在: {USER_JSON}")
        sys.exit(1)

    with open(USER_JSON, "r", encoding="utf-8") as f:
        cfg = json.load(f)

    music_u = cfg.get("MUSIC_U", "")
    device_id = cfg.get("DEVICE_ID", "")

    if not music_u:
        print(f"❌ user.json 中 MUSIC_U 为空")
        sys.exit(1)
    if not device_id:
        print(f"❌ user.json 中 DEVICE_ID 为空")
        sys.exit(1)

    print(f"✅ 从 user.json 加载成功")
    print(f"  MUSIC_U: {music_u[:12]}...{music_u[-4:]}")
    print(f"  DEVICE_ID: {device_id}")


if __name__ == "__main__":
    main()
