#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""GitHub Actions - 注入用户配置 (MUSIC_U / DEVICE_ID)"""

import os
import re
import sys

SCRIPT = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "..", "..", "netease_free_listen.py"
)


def main():
    music_u = os.environ.get("MUSIC_U", "")
    device_id = os.environ.get("DEVICE_ID", "")

    if not music_u:
        print("❌ 错误: 未设置 MUSIC_U secret")
        sys.exit(1)
    if not device_id:
        print("❌ 错误: 未设置 DEVICE_ID secret")
        sys.exit(1)

    with open(SCRIPT, "r", encoding="utf-8") as f:
        content = f.read()

    content = re.sub(
        r'(MUSIC_U\s*=\s*")[^"]*(")',
        r"\g<1>" + music_u + r"\g<2>",
        content,
        count=1,
    )
    content = re.sub(
        r'(DEVICE_ID\s*=\s*")[^"]*(")',
        r"\g<1>" + device_id + r"\g<2>",
        content,
        count=1,
    )

    with open(SCRIPT, "w", encoding="utf-8") as f:
        f.write(content)

    print(f"✅ 配置注入成功 (MUSIC_U: {music_u[:8]}..., DEVICE_ID: {device_id[:8]}...)")


if __name__ == "__main__":
    main()
