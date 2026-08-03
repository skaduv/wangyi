#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
GitHub Actions 执行脚本 - 随机间隔看广告

策略:
  - cron 触发后随机延迟 0~59 分钟启动
  - 每次广告间隔 2~8 分钟 (随机)
  - 每 5 次广告后间隔 20~50 分钟 (随机)
  - 默认 10 次广告
"""

import os
import random
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone

SHANGHAI = timezone(timedelta(hours=8))
SCRIPT = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "..", "..", "netease_free_listen.py"
)


def log(msg: str):
    now = datetime.now(SHANGHAI).strftime("%H:%M:%S")
    print(f"  [{now}] {msg}", flush=True)


def main():
    now = datetime.now(SHANGHAI)
    log(f"当前上海时间: {now.strftime('%Y-%m-%d %H:%M:%S')}")

    if os.environ.get("GITHUB_EVENT_NAME") == "schedule":
        delay = random.randint(0, 59 * 60)
        log(f"随机启动延迟: {delay // 60} 分 {delay % 60} 秒")
        time.sleep(delay)
        log(f"实际启动: {datetime.now(SHANGHAI).strftime('%H:%M:%S')}")

    rounds = 10
    env_rounds = os.environ.get("INPUT_ROUNDS", "")
    if env_rounds and env_rounds.isdigit():
        rounds = int(env_rounds)
    log(f"计划看广告: {rounds} 次")

    success = 0
    fail = 0

    for i in range(1, rounds + 1):
        print(f"\n{'=' * 50}")
        log(f"开始第 {i}/{rounds} 轮")
        print(f"{'=' * 50}")

        try:
            result = subprocess.run(
                [sys.executable, SCRIPT,
                 "--rounds", "1", "--watch-time", "16"],
                timeout=300,
            )
            if result.returncode == 0:
                success += 1
                log(f"第 {i} 轮 完成")
            else:
                fail += 1
                log(f"第 {i} 轮失败（退出码：{result.returncode}）")
        except subprocess.TimeoutExpired:
            fail += 1
            log(f"第 {i} 轮 超时")
        except Exception as e:
            fail += 1
            log(f"第 {i} 轮 异常: {e}")

        if i < rounds:
            if i % 5 == 0:
                gap = random.randint(20 * 60, 50 * 60)
                log(f"[长间隔] 已看 {i} 次, 休息 {gap // 60}分{gap % 60}秒")
            else:
                gap = random.randint(2 * 60, 8 * 60)
                log(f"[短间隔] 休息 {gap // 60}分{gap % 60}秒")
            time.sleep(gap)

    print(f"\n{'=' * 50}")
    log(f"全部完成! 成功: {success}, 失败: {fail}")
    log(f"结束时间: {datetime.now(SHANGHAI).strftime('%H:%M:%S')}")
    print(f"{'=' * 50}")


if __name__ == "__main__":
    main()
