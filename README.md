# 网易云音乐 - 看广告免费听 VIP 自动化

通过逆向网易云音乐 `eapi` 加密协议与易盾 `checkToken` 生成算法,使用 Python 模拟完整的「看广告 → 领取免费听权益」流程,实现自动化看广告获取免费听歌时长。

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

### checkToken 生成算法 (逆向自易盾 NEYiDunFingerprint SDK)

`/eapi/ad/listening/rights/gain` 等接口要求请求头携带 `X-AntiCheatToken`
(即 body 中的 `checkToken`)。该 token 由网易易盾设备指纹 SDK 生成,
通过逆向 iOS 主二进制 (`NTESCSGuardian createTokenWithTimeout:bToken:`)
还原出完整算法:

**生成步骤**

```
1. 构造 JSON 载荷:
     {"b":"<b_tag>","r":4,"d":"<d_tag>"}
     - b: 动态会话标识 (24字节 base64, 由易盾服务器下发,可轮换复用)
     - r: 固定值 4
     - d: 设备绑定固定值 (24字节 base64, 同一设备不变)

2. XOR 混淆变换 (6 字节循环表):
     out[i] = (0 - (in[i] ^ TABLE[i % 6])) & 0xff
     TABLE = [0x1f, 0x7d, 0xf4, 0x3c, 0x20, 0x30]

3. hex 编码 → checkToken
```

**验证结果**

- 前缀 `9ca16ae2e6ee` 恰好等于 `transform('{"b":"')` 的前 6 字节 ✓
- 对 HAR 抓包的全部 4 个 token 解码 → JSON → 重新编码,100% 匹配 ✓
- JSON 键 `b`/`r`/`d` 由主二进制全局常量 XOR 派生 (`0xd9bb→'b'` 等) ✓

`d` 值与 `b_tag` 池为设备绑定数据,需从本人设备的抓包中提取,配置在
`user.json` 的 `CHECKTOKEN_DEVICE_D` / `CHECKTOKEN_B_TAG_POOL` 字段。

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

## 配置

编辑项目根目录下的 `user.json` 文件,填入你的用户信息:

```json
{
  "MUSIC_U": "你的MUSIC_U值",
  "DEVICE_ID": "你的设备ID",
  "USER_ID": "你的用户ID(数字)",
  "CHECKTOKEN_DEVICE_D": "你的设备checkToken固定值d",
  "CHECKTOKEN_B_TAG_POOL": ["b_tag1", "b_tag2", "b_tag3", "b_tag4"]
}
```

**必需字段** (缺失时脚本启动报错):

| 字段 | 说明 |
|------|------|
| `MUSIC_U` | 登录凭证 Cookie |
| `DEVICE_ID` | 设备唯一标识 (32位hex) |
| `USER_ID` | 用户ID,用于广告请求 ID |
| `CHECKTOKEN_DEVICE_D` | checkToken 设备绑定值 `d` |
| `CHECKTOKEN_B_TAG_POOL` | checkToken 会话标识 `b` 池 (非空数组) |

**可选字段** (缺失时请求中自动省略,可能影响广告匹配精度):
`IDFV`、`OPENUDID`、`IYUN_ID`、`LAST_IYUN_ID`、`IYUN_VERSION`、
`LAST_IYUN_VERSION`、`LONGITUDE`、`LATITUDE`、`NTES_NUID`、`NMTID`

> **注意**: 代码中不保留任何用户信息,全部从 `user.json` 读取。
> `user.json` 已被 `.gitignore` 排除,请勿强制提交。

### 获取 checkToken 参数 (CHECKTOKEN_DEVICE_D / B_TAG_POOL)

`checkToken` 由易盾 SDK 生成,`d` 为设备绑定固定值,`b_tag` 为会话标识。
提取方法:

1. 用 mitmproxy/Charles 抓取网易云音乐 App 流量
2. 任选 4 次不同会话的 `rights/gain` 请求
3. 对每个 `x-anticheattoken` 请求头调用脚本内置的解码函数还原 JSON:

```bash
python -c "from netease_free_listen import decode_check_token; \
import sys; print(decode_check_token(sys.argv[1]))" 你的token
```

4. 将 JSON 中的 `d` 填入 `CHECKTOKEN_DEVICE_D`,各次会话的 `b` 填入
   `CHECKTOKEN_B_TAG_POOL` 数组

### 获取 MUSIC_U 和 DEVICE_ID

**方法一: 浏览器抓包**

1. 打开网易云音乐网页版,登录
2. F12 → Application → Cookies → `MUSIC_U`

**方法二: 手机抓包**

1. 使用 mitmproxy/Charles 抓取网易云音乐 App 流量
2. 从任意 `eapi` 请求的 Cookie 中获取 `MUSIC_U`
3. 从请求头 `x-deviceid` 获取 `DEVICE_ID`

## 运行

```bash
# 默认运行 10 轮
python netease_free_listen.py

# 自定义参数
python netease_free_listen.py --rounds 5 --watch-time 16 --delay 10
```

### 权益规则 (与 App 一致)

- **每看 5 次广告领取 1 次权益** — 脚本在第 5、10 次广告观看完成后自动领取
- **每天最多看 10 次广告** — 达到上限后脚本提示"今天广告次数已用完"并以退出码 2 退出
- **跨天自动重置** — 广告计数保存在本地 `ad_state.json`,日期变化后自动清零
- **跨进程共享计数** — 本地运行/多次调用共享同一文件,不会超量

### GitHub Actions 中的计数持久化

GitHub Actions 每次运行都是**全新环境**,本地 `ad_state.json` 默认会丢失。
workflow 已配置 `actions/cache` 按日期缓存计数文件:

```
key: ad-state-<北京时间日期>-<文件哈希>
restore-keys: ad-state-<北京时间日期>-
```

- **同一天多次调度**:restore-keys 按日期前缀匹配,恢复当天最新计数,不会重复看广告
- **key 带文件哈希**:计数变化后生成新 key,保证 save 阶段总能写入新状态
- **跨天自动重置**:日期变化后前缀不同,无缓存可恢复,计数从 0 开始
- **当天已满**:主脚本退出码 2,`run_ads.py` 识别后提前停止,不浪费请求

### 运行示例

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

2. **编辑 `user.json`** — 在仓库根目录的 `user.json` 中填入你的 `MUSIC_U` 和 `DEVICE_ID`

3. **启用 Actions** — 进入 `Actions` 页面,点击 `Enable workflow`

4. **手动测试** — 在 `Actions` 页面选择「网易云音乐 - 看广告免费听」,点击 `Run workflow` 手动触发

> **注意**: `user.json` 包含登录凭证,**不要提交到公开仓库**。建议将仓库设为私有,或将 `user.json` 加入 `.gitignore` 后通过其他方式同步。

### 注意事项

- GitHub Actions 免费额度: 公开仓库无限制,私有仓库每月 2000 分钟
- 每次运行约 60-120 分钟 (含随机间隔),不会超出额度
- `concurrency` 设置确保同一时间只有一个实例运行
- cron 触发在实际执行时可能有数分钟延迟 (GitHub 调度机制)

## 文件结构

```
netease-free-listen/
├── .gitignore                   # 排除 user.json 等敏感文件
├── netease_free_listen.py       # 主程序 (单文件,含 checkToken 生成算法)
├── user.json                    # 用户配置 (MUSIC_U / DEVICE_ID / checkToken 参数)
└── README.md                    # 本文档
```

## 注意事项

- **仅供学习研究**: 本项目仅用于逆向工程学习和研究目的
- **账号风险**: 自动化操作可能违反网易云音乐用户协议,存在账号被封禁的风险
- **使用限制**: 每日看广告领取权益有上限,超出后接口会返回错误
- **参数时效性**: `MUSIC_U` 有过期时间,过期后需重新获取
- **广告可用性**: 广告库存由广告平台决定,某些时段可能无广告可投
- **凭证安全**: `user.json` 包含敏感登录凭证,请勿泄露或提交到公开仓库

## 免责声明

本项目仅供学习和研究使用,不得用于商业目的或违反相关服务条款的行为。使用本项目所产生的一切后果由使用者自行承担。

## License

MIT
