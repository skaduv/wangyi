# 网易云音乐 - 看广告免费听 VIP 自动化

通过逆向网易云音乐 `eapi` 加密协议,使用 Python 模拟完整的「看广告 → 领取免费听权益」流程,实现自动化看广告获取免费听歌时长。

## 原理

### 整体流程

```
┌─────────────┐     ┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│  请求广告    │────>│  上报曝光     │────>│  上报点击     │────>│  领取权益    │
│  /ad/get    │     │ /monitor/    │     │ /monitor/    │     │ /rights/     │
│             │     │  impress     │     │  click       │     │  gain        │
└─────────────┘     └──────────────┘     └──────────────┘     └──────────────┘
                           │
                     模拟观看 N 秒
```

### eapi 加密协议

网易云音乐 `interface3.music.163.com/eapi/` 接口使用自定义加密:

**请求加密 (AES-128-ECB)**

```
text   = JSON.stringify(body)
digest = MD5("nobody" + path + "use" + text + "md5forencrypt")
payload = path + "-36cd479b6b5-" + text + "-36cd479b6b5-" + digest
params  = HEX(AES-128-ECB(payload, key="e82ckenh8dichen8")).toUpper()
```

**响应解密**

```
decrypted = AES-128-ECB-DECRYPT(response.body, key="e82ckenh8dichen8")
decrypted = PKCS7_unpad(decrypted)
if decrypted[0:2] == 0x1f8b:
    decrypted = gzip_decompress(decrypted)
result = JSON.parse(decrypted)
```

### 关键接口

| 接口 | 说明 |
|------|------|
| `/eapi/ad/listening/new/yunbei/login/request` | 初始化云贝广告会话 |
| `/eapi/ad/listening/free/tab/homepage/stage/info` | 查询免费听进度/阶段 |
| `/eapi/ad/get` | 获取激励广告 (`type_ids: ["400002_0"]`) |
| `/eapi/ad/monitor/impress` | 上报广告曝光 |
| `/eapi/ad/monitor/click` | 上报广告点击 |
| `/eapi/ad/listening/rights/gain` | 领取免费听权益 |

### 关键参数

| 参数 | 说明 |
|------|------|
| `MUSIC_U` | 用户登录凭证 Cookie |
| `deviceId` | 设备唯一标识 (32位hex) |
| `requestId` | 广告请求 ID,`ad/get` 响应中获取 |
| `req_id` | 服务端请求 ID,从 `extJson.contextInfo.req_id` 提取 |
| `rightsGainMethod` | 权益获取方式 (2=视频观看, 4=点击跳转) |
| `clickStayTime` | 点击后需停留秒数 |
| `validVideoInterval` | 有效观看间隔秒数 |

## 安装

```bash
pip install requests pycryptodome
```

## 使用方法

### 1. 配置

编辑 `netease_free_listen.py` 中的 `Config` 类,填入你的参数:

```python
class Config:
    # 必填 - 从浏览器 Cookie 或抓包获取
    MUSIC_U = "你的MUSIC_U值"
    DEVICE_ID = "你的设备ID"

    # 可选 - 有默认值
    WATCH_DELAY = 16   # 模拟观看秒数
    MAX_ROUNDS = 10    # 执行轮数
```

### 2. 获取 MUSIC_U 和 DEVICE_ID

**方法一: 浏览器抓包**

1. 打开网易云音乐网页版,登录
2. F12 → Application → Cookies → `MUSIC_U`

**方法二: 手机抓包**

1. 使用 mitmproxy/Charles 抓取网易云音乐 App 流量
2. 从任意 `eapi` 请求的 Cookie 中获取 `MUSIC_U`
3. 从请求头 `x-deviceid` 获取 `DEVICE_ID`

### 3. 运行

```bash
# 默认运行 10 轮
python netease_free_listen.py

# 自定义参数
python netease_free_listen.py --rounds 5 --watch-time 16 --delay 10
```

### 4. 运行示例

```
============================================================
  网易云音乐 - 看广告免费听 VIP 自动化
============================================================

[初始化] 云贝登录...
  code=200

[初始化] 查询进度...
  当前进度: 288/28320
  当前阶段: 0/15

============================================================
  第 1 轮
============================================================
[1/4] 请求广告...
  广告: 淘宝闪购今天发福利啦[憨笑]
  ad_id: 104565722318, req_id: 599f9185f4174a6c9d78c8df7e4ff85b
  方式: 4, 停留: 6s, 间隔: 1s
[2/4] 上报曝光...
  曝光: code=200
  模拟观看 16s...
[3/4] 上报点击...
  点击: code=200
[4/4] 领取权益...
  结果: code=200, gain=True
  消息: 处理成功
  内容: 恭喜您已成功解锁拼图

============================================================
  运行汇总
============================================================
  总轮数: 2
  成功: 2
  失败: 0
  最终进度: 368/28320
```

## 参数说明

| 命令行参数 | 说明 | 默认值 |
|-----------|------|--------|
| `--rounds` | 执行看广告轮数 | 10 |
| `--watch-time` | 模拟观看广告秒数 | 16 |
| `--delay` | 每轮之间间隔秒数 | 10 |

## GitHub Actions 定时任务

项目内置 GitHub Actions 工作流,每天北京时间 **08:00-11:00 随机时刻** 自动运行看广告脚本。

### 工作原理

```
cron 触发 (UTC 00:00/01:00/02:00 = 北京 08:00/09:00/10:00)
    │
    ├─ 随机启动延迟 0~59 分钟 → 实际 08:00~11:59 随机启动
    │
    ├─ 第 1 次广告 → 间隔 2~8 分钟
    ├─ 第 2 次广告 → 间隔 2~8 分钟
    ├─ 第 3 次广告 → 间隔 2~8 分钟
    ├─ 第 4 次广告 → 间隔 2~8 分钟
    ├─ 第 5 次广告 → 长间隔 20~50 分钟 ←── 每 5 次后长休息
    ├─ 第 6 次广告 → 间隔 2~8 分钟
    ├─ ...
    └─ 第 10 次广告 → 完成
```

### 间隔策略

| 场景 | 间隔时间 | 说明 |
|------|---------|------|
| 正常间隔 | 2~8 分钟 (随机) | 相邻两次广告之间 |
| 长间隔 | 20~50 分钟 (随机) | 每完成 5 次广告后 |
| 启动延迟 | 0~59 分钟 (随机) | cron 触发后的随机等待 |

### 配置步骤

1. **Fork 本仓库**到你的 GitHub 账号

2. **设置 Secrets** — 进入仓库 `Settings` → `Secrets and variables` → `Actions`,添加:

   | Secret 名称 | 说明 |
   |------------|------|
   | `MUSIC_U` | 网易云音乐 MUSIC_U Cookie 值 |
   | `DEVICE_ID` | 设备 ID (32位 hex) |

3. **启用 Actions** — 进入 `Actions` 页面,点击 `Enable workflow`

4. **手动测试** — 在 `Actions` 页面选择「网易云音乐 - 看广告免费听」,点击 `Run workflow` 手动触发

### 注意事项

- GitHub Actions 免费额度: 公开仓库无限制,私有仓库每月 2000 分钟
- 每次运行约 60-120 分钟 (含随机间隔),不会超出额度
- `concurrency` 设置确保同一时间只有一个实例运行
- cron 触发在实际执行时可能有数分钟延迟 (GitHub 调度机制)

## 文件结构

```
netease-free-listen/
├── .github/
│   └── workflows/
│       ├── free_listen.yml      # GitHub Actions 定时任务
│       ├── inject_config.py     # Secrets 注入脚本
│       └── run_ads.py           # 随机间隔执行脚本
├── netease_free_listen.py       # 主程序 (单文件,包含所有模块)
└── README.md                    # 本文档
```

## 注意事项

- **仅供学习研究**: 本项目仅用于逆向工程学习和研究目的
- **账号风险**: 自动化操作可能违反网易云音乐用户协议,存在账号被封禁的风险
- **使用限制**: 每日看广告领取权益有上限,超出后接口会返回错误
- **参数时效性**: `MUSIC_U` 有过期时间,过期后需重新获取
- **广告可用性**: 广告库存由广告平台决定,某些时段可能无广告可投

## 免责声明

本项目仅供学习和研究使用,不得用于商业目的或违反相关服务条款的行为。使用本项目所产生的一切后果由使用者自行承担。

## License

MIT
