#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
网易云音乐看广告领取免费听权益的自动化脚本
"""

import argparse
import gzip
import hashlib
import json
import os
import sys
import time

import requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

_BASE_DIR = os.path.dirname(os.path.abspath(__file__))


def _load_user_json() -> dict:
    """从 user.json 加载用户配置,文件缺失或损坏时返回空字典。"""
    json_path = os.path.join(_BASE_DIR, "user.json")
    if not os.path.exists(json_path):
        return {}
    try:
        with open(json_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return {}


_USER = _load_user_json()


class Config:
    """运行配置。用户相关字段全部来自 user.json,无硬编码默认值。

    必需字段 (缺失时 validate() 报错):
        MUSIC_U, DEVICE_ID, USER_ID, CHECKTOKEN_DEVICE_D, CHECKTOKEN_B_TAG_POOL
    可选字段 (缺失时请求中省略,可能影响广告匹配精度):
        IDFV, OPENUDID, IYUN_ID, LAST_IYUN_ID, IYUN_VERSION, LAST_IYUN_VERSION,
        LONGITUDE, LATITUDE, NTES_NUID, NMTID
    """

    # ---- 必需: 登录凭证/设备标识 ----
    MUSIC_U = _USER.get("MUSIC_U", "")
    DEVICE_ID = _USER.get("DEVICE_ID", "")
    USER_ID = _USER.get("USER_ID", "")

    # ---- 必需: checkToken 参数 (易盾设备指纹,同一设备固定) ----
    CHECKTOKEN_DEVICE_D = _USER.get("CHECKTOKEN_DEVICE_D", "")
    CHECKTOKEN_B_TAG_POOL = _USER.get("CHECKTOKEN_B_TAG_POOL", [])

    # ---- 可选: 设备指纹扩展 (缺失时请求中省略) ----
    IDFV = _USER.get("IDFV", "")
    OPENUDID = _USER.get("OPENUDID", "")
    IYUN_ID = _USER.get("IYUN_ID", "")
    LAST_IYUN_ID = _USER.get("LAST_IYUN_ID", "")
    IYUN_VERSION = _USER.get("IYUN_VERSION", "")
    LAST_IYUN_VERSION = _USER.get("LAST_IYUN_VERSION", "")
    LONGITUDE = _USER.get("LONGITUDE", "")
    LATITUDE = _USER.get("LATITUDE", "")
    NTES_NUID = _USER.get("NTES_NUID", "")
    NMTID = _USER.get("NMTID", "")

    # ---- App 环境信息 (非用户数据,可随版本更新) ----
    APP_VER = "9.3.41"
    BUILD_VER = "6116"
    OS_VER = "26.1"

    # ---- 运行参数 ----
    AD_POSITION = "400002"
    WATCH_DELAY = 16
    CLAIM_DELAY = 3
    MAX_ROUNDS = 10
    ROUND_DELAY = 10

    # ---- App 规则 (看广告免费听权益) ----
    # 每支广告观看完成后立即领取 1 次权益 (与 App 行为一致);
    # 每日上限由服务端 rights/gain 的 gainFlag 判定

    @classmethod
    def validate(cls):
        """校验必填配置,缺失时抛出 SystemExit。"""
        required = ("MUSIC_U", "DEVICE_ID", "USER_ID",
                    "CHECKTOKEN_DEVICE_D", "CHECKTOKEN_B_TAG_POOL")
        missing = [k for k in required
                   if not getattr(cls, k, None)
                   or (k == "CHECKTOKEN_B_TAG_POOL" and not cls.CHECKTOKEN_B_TAG_POOL)]
        if missing:
            raise SystemExit(
                f"[错误] user.json 缺少必填字段: {', '.join(missing)}\n"
                "请参考 README.md 配置后重试。"
            )

    @staticmethod
    def _nonempty(**kwargs) -> dict:
        """过滤空值字段,用于构造请求时省略未配置的可选参数。"""
        return {k: v for k, v in kwargs.items() if v not in ("", [], {}, None)}


EAPI_KEY = b"e82ckenh8dichen8"
EAPI_NONCE = "36cd479b6b5"
EAPI_SIGN_SALT = "md5forencrypt"

# ============================================================
# checkToken 生成算法 (逆向自易盾 NEYiDunFingerprint SDK)
#
# 逆向分析 neteasemusic iOS 9.5.65 主二进制得出完整算法:
#   1. 构造 JSON 载荷: {"b":"<b_tag>","r":4,"d":"<d_tag>"}
#      - b: 动态会话标识 (24字节 base64, 易盾服务器下发)
#      - r: 固定值 4
#      - d: 设备绑定固定值 (24字节 base64, 同一设备不变)
#   2. XOR 混淆变换: out[i] = (0 - (in[i] ^ TABLE[i % 6])) & 0xff
#      TABLE = [0x1f, 0x7d, 0xf4, 0x3c, 0x20, 0x30]
#   3. hex 编码输出即为 checkToken
#
# 验证: 前缀 9ca16ae2e6ee == transform('{"b":"'), 对 HAR 抓包全部
# 4 个 token 解码->JSON->重新编码 100% 匹配。
#
# 逆向来源:
#   - NTESCSGuardian createTokenWithTimeout:bToken: (0x100b51ac4)
#   - XOR 表: __TEXT,__const @ 0x10a745baf
#   - JSON 键 b/r/d 由全局常量 XOR 派生
#   - 主密钥: 0x10ebcb4f2 XOR 0x14 = '5DEW8opxIX4hR6CVxjh3iJkZ6czm4fi9'
# ============================================================

CHECKTOKEN_XOR_TABLE = [0x1f, 0x7d, 0xf4, 0x3c, 0x20, 0x30]


def _checktoken_xor(payload: bytes) -> bytes:
    """易盾 XOR 混淆变换: out[i] = (0 - (in[i] ^ TABLE[i % 6])) & 0xff"""
    t = CHECKTOKEN_XOR_TABLE
    return bytes(((0 - (p ^ t[i % 6])) & 0xff) for i, p in enumerate(payload))


def _checktoken_unxor(data: bytes) -> bytes:
    """逆变换: in[i] = ((0 - out[i]) & 0xff) ^ TABLE[i % 6]"""
    t = CHECKTOKEN_XOR_TABLE
    return bytes(((0 - d) & 0xff) ^ t[i % 6] for i, d in enumerate(data))


def encode_check_token(b_tag: str, d_tag: str, r: int = 4) -> str:
    """按逆向算法生成 checkToken (JSON + XOR 混淆 + hex)。"""
    payload = json.dumps(
        {"b": b_tag, "r": r, "d": d_tag},
        separators=(",", ":"),
        ensure_ascii=False,
    ).replace("/", "\\/")
    return _checktoken_xor(payload.encode("utf-8")).hex()


def decode_check_token(token: str) -> dict:
    """解码 checkToken 为 JSON 结构 (用于验证/提取字段)。"""
    raw = bytes.fromhex(token)
    payload = _checktoken_unxor(raw).decode("utf-8")
    return json.loads(payload)


# ============================================================
# b_tag 轮换索引 (跨进程持久化)
#
# 实测 (2026-08-06): 服务端对 checkToken 的 b_tag 按「当日单次」判定 ——
# 同一 b_tag 当天约可成功领取 1 次权益, 复用会被 rights/gain 拒绝
# (code=2002, 消息「休息一下，请稍后再试」, gainFlag=false)。不同 b_tag
# 相隔数分钟即可再次成功领取。
#
# 调度脚本 run_ads.py 每轮以独立子进程调用本脚本, 模块级计数器每次都
# 从 0 开始, 轮换形同虚设 (每轮都用 pool[0], 第 1 轮成功后当天即废)。
# 因此把轮换索引持久化到 b_tag_state.json, 跨进程/跨 cron 运行共享,
# 跨天自动重置。
# ============================================================

_B_TAG_STATE_FILE = os.path.join(_BASE_DIR, "b_tag_state.json")


def _load_b_tag_state() -> dict:
    """读取 b_tag 轮换索引, 跨天自动重置。文件缺失或损坏时从 0 开始。"""
    if not os.path.exists(_B_TAG_STATE_FILE):
        return {"date": "", "index": 0}
    try:
        with open(_B_TAG_STATE_FILE, "r", encoding="utf-8") as f:
            state = json.load(f)
        if state.get("date") != time.strftime("%Y-%m-%d"):
            return {"date": "", "index": 0}
        return {"date": state.get("date", ""), "index": int(state.get("index", 0))}
    except (json.JSONDecodeError, OSError, ValueError):
        return {"date": "", "index": 0}


def _save_b_tag_state(index: int):
    """保存 b_tag 轮换索引 (仅保存当天数据, 跨天自动重置)。"""
    try:
        with open(_B_TAG_STATE_FILE, "w", encoding="utf-8") as f:
            json.dump({"date": time.strftime("%Y-%m-%d"), "index": index}, f)
    except OSError:
        pass


def current_b_tag_index() -> int:
    """当前轮次应使用的 b_tag 索引 (基于持久化状态)。

    首次调用时确保 b_tag_state.json 存在 (供 GitHub Actions
    actions/cache 跨 cron 运行持久化轮换状态)。
    """
    if not os.path.exists(_B_TAG_STATE_FILE):
        _save_b_tag_state(0)
    return _load_b_tag_state()["index"]


def advance_b_tag_index():
    """领取得到服务端判定后推进轮换索引 (该 b_tag 当日不可复用)。"""
    state = _load_b_tag_state()
    _save_b_tag_state(state["index"] + 1)


def generate_check_token() -> str:
    """按逆向算法动态生成 checkToken (每轮轮换 B_TAG_POOL 中的 b_tag)。

    注意: 索引推进由 advance_b_tag_index() 在领取得到服务端判定后执行,
    不在本函数内自增 —— 广告/曝光等与领取无关的失败不应消耗 b_tag。
    """
    pool = Config.CHECKTOKEN_B_TAG_POOL
    if not pool:
        raise SystemExit("[错误] CHECKTOKEN_B_TAG_POOL 为空,请检查 user.json。")
    b_tag = pool[current_b_tag_index() % len(pool)]
    return encode_check_token(b_tag, Config.CHECKTOKEN_DEVICE_D)


def eapi_encrypt(url_path: str, data: dict) -> str:
    """按 eapi 协议加密请求参数。"""
    text = json.dumps(data, separators=(",", ":"), ensure_ascii=False)
    message = f"nobody{url_path}use{text}{EAPI_SIGN_SALT}"
    digest = hashlib.md5(message.encode("utf-8")).hexdigest()
    payload = f"{url_path}-{EAPI_NONCE}-{text}-{EAPI_NONCE}-{digest}"

    cipher = AES.new(EAPI_KEY, AES.MODE_ECB)
    padded = pad(payload.encode("utf-8"), AES.block_size)
    encrypted = cipher.encrypt(padded)
    return encrypted.hex().upper()


def eapi_decrypt_response(raw_bytes: bytes) -> str:
    """解密 eapi 响应内容,并处理可能的 gzip 压缩。"""
    cipher = AES.new(EAPI_KEY, AES.MODE_ECB)
    decrypted = cipher.decrypt(raw_bytes)
    try:
        decrypted = unpad(decrypted, AES.block_size)
    except ValueError:
        pass
    if decrypted[:2] == b"\x1f\x8b":
        decrypted = gzip.decompress(decrypted)
    return decrypted.decode("utf-8", errors="replace")


class NetEaseEapi:
    """封装网易云音乐 eapi 请求。"""

    BASE_URL = "https://interface3.music.163.com"

    def __init__(self, cfg: Config = None):
        self.cfg = cfg or Config()
        self.session = requests.Session()
        self._setup_headers()
        self._setup_cookies()

    def _get_next_check_token(self) -> str:
        """按逆向算法动态生成 checkToken (轮换 b_tag 池避免风控)。"""
        return generate_check_token()

    def _setup_headers(self):
        c = self.cfg
        self.session.headers.update({
            "User-Agent": (
                f"NeteaseMusic {c.APP_VER}/{c.BUILD_VER} "
                f"(iPhone; iOS {c.OS_VER}; zh-Hans_US)"
            ),
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "*/*",
            "Accept-Language": "zh-Hans-US;q=1, en-US;q=0.9",
            "X-AppVer": c.APP_VER,
            "X-BuildVer": c.BUILD_VER,
            "X-DeviceId": c.DEVICE_ID,
            "X-SDeviceId": c.DEVICE_ID,
            "X-OS": "iPhone OS",
            "X-OSVer": c.OS_VER,
            "X-Aeapi": "true",
            "X-Music-U": c.MUSIC_U,
            "X-MAM-CustomMark": "nm_Cronet",   # 广告请求使用 nm_Cronet
            "X-Netlib": "Cronet",
            "MConfig-Info": json.dumps({
                "zr4bw6pKFDIZScpo": {"version": 3807232, "appver": c.APP_VER},
                "tPJJnts2H31BZXmp": {"version": 5023744, "appver": "2.0.30"},
                "c0Ve6C0uNl2Am0Rl": {"version": 600064, "appver": "1.7.50"},
                "IuRPVVmc3WWul9fT": {"version": 113385472, "appver": c.APP_VER},
            }),
        })

    def _setup_cookies(self):
        c = self.cfg
        cookies = self.cfg._nonempty(
            MUSIC_U=c.MUSIC_U,
            _ntes_nuid=c.NTES_NUID,
            NMTID=c.NMTID,
            appver=c.APP_VER,
            buildver=c.BUILD_VER,
            deviceId=c.DEVICE_ID,
            sDeviceId=c.DEVICE_ID,
            os="iPhone OS",
            osver=c.OS_VER,
            channel="distribution",
            appkey="IuRPVVmc3WWul9fT",
            EVNSM="1.0.0",
            machineid="iPhone16.1",
            packageType="release",
            idfv=c.IDFV,
            idfa="",
            ntes_kaola_ad="1",
            _iuqxldmzr_="33",
        )
        for k, v in cookies.items():
            self.session.cookies.set(k, v, domain=".music.163.com")

    def request(self, api_path: str, data: dict, extra_headers: dict = None) -> dict:
        """发送 eapi 请求并返回解密后的 JSON 数据。"""
        url = f"{self.BASE_URL}/eapi{api_path.replace('/api', '', 1)}"
        c = self.cfg

        data.setdefault("deviceId", c.DEVICE_ID)
        data.setdefault("os", "iOS")
        data.setdefault("verifyId", 1)
        data.setdefault("header", {})
        data.setdefault("e_r", True)

        encrypted = eapi_encrypt(api_path, data)

        headers = {}
        if extra_headers:
            headers.update(extra_headers)

        resp = self.session.post(url, data={"params": encrypted}, headers=headers, timeout=30)
        resp.raise_for_status()

        decrypted = eapi_decrypt_response(resp.content)
        return json.loads(decrypted)

    def _make_ad_req_id(self) -> str:
        """构造广告请求 ID (uid_时间戳_3963)。"""
        return f"{self.cfg.USER_ID}_{int(time.time() * 1000)}_3963"

    def yunbei_login(self) -> dict:
        """初始化云贝广告会话(使用 ne_AFN mark)。"""
        extra_headers = {"X-MAM-CustomMark": "ne_AFN"}
        return self.request("/api/ad/listening/new/yunbei/login/request", {},
                            extra_headers=extra_headers)

    def get_stage_info(self) -> dict:
        """查询免费听活动进度。"""
        return self.request("/api/ad/listening/free/tab/homepage/stage/info", {
            "method": "GET",
            "data": {"entranceType": "FREE_LISTEN"},
        })

    def get_ad(self, ad_req_id: str = "") -> dict:
        """请求激励广告，并允许调用方固定本轮请求 ID。"""
        c = self.cfg
        ad_req_id = ad_req_id or self._make_ad_req_id()
        ad_ext = c._nonempty(
            ipv4="",
            fromRN="1",
            isNeedGetRights="false",
            opensdkVer="2.0.4",
            ext=c._nonempty(
                teenMode=False,
                ipv4="",
                sourceFrame="note",
                homePageType=1,
                wxInstalled=True,
                iyunVersion=c.IYUN_VERSION,
                iyunId=c.IYUN_ID,
                opensdkVer="2.0.4",
                idfv=c.IDFV,
                lastIyunId=c.LAST_IYUN_ID,
                supportWechatCanvas=True,
                lastIyunVersion=c.LAST_IYUN_VERSION,
            ),
            lbs=c._nonempty(longitude=c.LONGITUDE, latitude=c.LATITUDE),
            adReqId=ad_req_id,
            isNativeSampling=False,
            network=1,
            lastIyunVersion=c.LAST_IYUN_VERSION,
            iyunVersion=c.IYUN_VERSION,
            teenMode=False,
            ipv6="",
            source="132",
            op="0",
            useragent=(
                "Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X) "
                "AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148"
            ),
            homePageType=1,
            supportWechatCanvas=True,
            wxInstalled=True,
            newAgent=(
                "Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X) "
                "AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148"
            ),
            idfv=c.IDFV,
            idfa="00000000-0000-0000-0000-000000000000",
            resourceId="0",
            iyunId=c.IYUN_ID,
            openudid=c.OPENUDID,
            sourceFrame="note",
            appState=0,
            adPosition=c.AD_POSITION,
            lastIyunId=c.LAST_IYUN_ID,
            resolution={"width": 1179, "height": 2556},
            pid="0",
            isShowEndToast="true",
            showRightsEndDialog="false",
        )
        return self.request("/api/ad/get", {
            "adextjson": json.dumps(ad_ext, separators=(",", ":")),
            "type_ids": json.dumps([f"{c.AD_POSITION}_0"]),
        })

    def _build_dev_info(self) -> str:
        c = self.cfg
        dev_info = c._nonempty(
            ipv4="",
            idfa="00000000-0000-0000-0000-000000000000",
            iyunVersion=c.IYUN_VERSION,
            useragent=(
                "Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X) "
                "AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148"
            ),
            seq=int(time.time()) % 10000,
            iyunId=c.IYUN_ID,
            openudid=c.OPENUDID,
            lastIyunId=c.LAST_IYUN_ID,
            lbs=c._nonempty(longitude=c.LONGITUDE, latitude=c.LATITUDE),
            ipv6="",
            network=1,
            op="0",
            resolution={"width": 1179, "height": 2556},
            lastIyunVersion=c.LAST_IYUN_VERSION,
        )
        return json.dumps(dev_info, separators=(",", ":"))

    def report_impress(self, ad_data: dict) -> dict:
        """上报广告曝光。"""
        return self.request("/api/ad/monitor/impress", {
            "dev_info": self._build_dev_info(),
            "ad_data": json.dumps(ad_data, separators=(",", ":")),
        })

    def report_click(self, ad_data: dict) -> dict:
        """上报广告点击。"""
        return self.request("/api/ad/monitor/click", {
            "dev_info": self._build_dev_info(),
            "ad_data": json.dumps(ad_data, separators=(",", ":")),
        })

    def claim_rights(self, req_param: dict, check_token: str = "") -> dict:
        """领取免费听权益。
        """
        extra_headers = {"X-AntiCheatToken": check_token}
        return self.request("/api/ad/listening/rights/gain", {
            "checkToken": check_token,
            "reqParam": json.dumps(req_param, separators=(",", ":")),
        }, extra_headers=extra_headers)

    def get_free_listen_data(self) -> dict:
        """获取免费听权益数据。"""
        return self.request("/api/vipnewcenter/app/free/listen/data/v2", {
            "limit": 12,
            "refresh": False,
        })


def _parse_json(val, default=None):
    """安全解析 JSON 数据。"""
    if not val:
        return default or {}
    if isinstance(val, (dict, list)):
        return val
    try:
        return json.loads(val)
    except (json.JSONDecodeError, TypeError):
        return default or {}


def _get_context_info(ad_info: dict) -> dict:
    """提取广告响应中的 contextInfo。"""
    ci = _parse_json(ad_info.get("contextInfo"))
    if ci:
        return ci
    ej = _parse_json(ad_info.get("extJson"))
    return _parse_json(ej.get("contextInfo")) if ej else {}


def _get_context_info_str(ad_info: dict) -> str:
    """提取字符串形式的 contextInfo。"""
    ci_str = ad_info.get("contextInfo", "")
    if ci_str:
        return ci_str
    ej = _parse_json(ad_info.get("extJson"))
    ci_raw = ej.get("contextInfo", "") if ej else ""
    if isinstance(ci_raw, dict):
        return json.dumps(ci_raw, separators=(",", ":"))
    return str(ci_raw) if ci_raw else ""


def build_ad_data_for_monitor(
        ad_info: dict, ad_req_id: str, cfg: Config,
        exposure_time_ms: int = None) -> dict:
    """构造广告曝光和点击上报参数。"""
    ci = _get_context_info(ad_info)
    gri = _parse_json(ad_info.get("generalRightsInfo"))
    ej = _parse_json(ad_info.get("extJson"))
    lri = ad_info.get("listeningRightsInfo") or {}
    context_info_str = _get_context_info_str(ad_info)

    serverreqid = ci.get("req_id", "")

    monitors = []
    if ad_info.get("monitorClick"):
        monitors.append({"monitorClick": ad_info["monitorClick"]})
    if ad_info.get("monitorImpress"):
        monitors.append({"monitorImpress": ad_info["monitorImpress"]})

    ext_monitor_info = ej.get("extMonitorInfo", {}) if ej else {}
    videos = []
    ad_material = ad_info.get("adMaterial") or {}
    if ad_material.get("videoInfo"):
        videos.append(ad_material["videoInfo"])

    now_ms = exposure_time_ms if exposure_time_ms is not None else int(time.time() * 1000)

    return {
        "universalLinkType": 0,
        "offlineTime": ad_info.get("offlineTime", 0),
        "fromRN": "1",
        "ad_loc": ci.get("tag_id", ""),
        "id": ad_info.get("id", 0),
        "incentiveClick": 0,
        "isNeedGetRights": "false",
        "target": "ad_video",
        "location": ad_info.get("adLocation", "10001"),
        "text": ad_info.get("text", ""),
        "url": ad_info.get("url", ""),
        "autoReportClick": False,
        "actual_invocation_style": 0,
        "material": ci.get("material_id", ""),
        "onlineTime": ad_info.get("onlineTime", 0),
        "isNativeSampling": False,
        "lbs": cfg._nonempty(longitude=cfg.LONGITUDE, latitude=cfg.LATITUDE),
        "type": ad_info.get("type", 400002),
        "adsource_ssp": ci.get("dsp_id", ""),
        "dspid": ci.get("dsp_id", ""),
        "resourceType": "-1",
        "adPid": "0",
        "imgs": [ad_info.get("picUrl", "")],
        "schedule": "",
        "showRightsEndDialog": "false",
        "actualInvocationStyle": 0,
        "source": "132",
        "op": "0",
        "appState": 0,
        "requestid": ad_req_id,
        "serverreqid": serverreqid,
        "adid": str(ad_info.get("id", "")),
        "adSource": str(ad_info.get("adSource", "")),
        "showAdTag": True,
        "context_info": context_info_str,
        "contextInfo": context_info_str,
        "extMonitorInfo": ext_monitor_info,
        "monitors": monitors,
        "videos": videos,
        "page": "motivational_video_ad",
        "invocationstyle": 0,
        "button": "learnmore",
        "clientTime": now_ms,
        "resourceId": "-1",
        "impressid": f"{ad_req_id}_{int(now_ms // 1000)}_12",
        "winPrice": ad_info.get("winPrice", 0),
        "position": ad_info.get("position", 1),
        "freeListenRequest": ad_info.get("freeListenRequest", ""),
        "generalRightsInfo": ad_info.get("generalRightsInfo", ""),
        "nextRightsGainDuration": lri.get("nextRightsGainDuration", 0),
        "exposureTime": int(now_ms),
        "extraRightsType": lri.get("extraRightsType", 0),
        "qualified": False,
        "delayPopTime": lri.get("delayPopTime") or 10,
        "rightType": lri.get("rightType") or 10,
        "clickTime": int(now_ms),
        "adPosition": cfg.AD_POSITION,
        "rightsGainDuration": 0,
        "isShowEndToast": "true",
    }


def _extract_rights_metadata(ad_info: dict) -> tuple:
    """规范化广告的通用权益与免费听权益元数据。"""
    return (
        _parse_json(ad_info.get("generalRightsInfo")),
        ad_info.get("listeningRightsInfo") or {},
    )


def build_rights_claim_params(
        ad_info: dict, ad_req_id: str, cfg: Config,
        exposure_time_ms: int = None, click_time_ms: int = None) -> dict:
    """构造权益领取请求参数，复用本轮真实曝光和点击时间。"""
    ci = _get_context_info(ad_info)
    gri, lri = _extract_rights_metadata(ad_info)
    context_info_str = _get_context_info_str(ad_info)

    app_info = json.dumps({
        "avatar": ad_info.get("picUrl", ""),
        "productName": ad_info.get("text", ""),
    })

    if exposure_time_ms is None or click_time_ms is None:
        now_ms = int(time.time() * 1000)
        exposure_time_ms = now_ms if exposure_time_ms is None else exposure_time_ms
        click_time_ms = now_ms if click_time_ms is None else click_time_ms

    return {
        "rightsGainMethod": gri.get("rightsGainMethod", lri.get("rightsGainMethod", 4)),
        "clickStayTimeExtend": gri.get("clickStayTimeExtend") or lri.get("clickStayTimeExtend") or 2,
        "source": "132",
        "isNeedGetRights": "false",
        "appInfo": app_info,
        "contextInfo": context_info_str,
        "rightsExtJson": "",
        "hasAnotherChance": False,
        "rightsUpperLimit": gri.get("rightsUpperLimit", True),
        "clickStayTime": gri.get("clickStayTime", lri.get("clickStayTime", 6)),
        "resourceId": "0",
        "reqUid": ci.get("req_id", ""),
        "fromRN": "1",
        "showRightsEndDialog": "false",
        "creativeType": ad_info.get("creativeType", 1),
        "rightsGainType": lri.get("rightsGainType", 0),
        "isShowEndToast": "true",
        "validVideoInterval": gri.get("validVideoInterval", lri.get("validVideoInterval", 15)),
        "showElement": gri.get("showElement", {}),
        "sniffTime": 0,
        "generalRightsInfo": ad_info.get("generalRightsInfo", ""),
        "nextRightsGainDuration": lri.get("nextRightsGainDuration", 0),
        "exposureTime": exposure_time_ms,
        "extraRightsType": lri.get("extraRightsType", 0),
        "qualified": False,
        "delayPopTime": gri.get("delayPopTime", 10),
        "rightType": gri.get("rightType", 10),
        "clickTime": click_time_ms,
        "adPosition": cfg.AD_POSITION,
        "rightsGainDuration": 0,
    }


def _business_success(resp: dict, operation: str) -> bool:
    """校验接口业务响应，失败时输出不含敏感数据的摘要。"""
    if not isinstance(resp, dict):
        print(f"  {operation}失败: 响应格式无效")
        return False
    if resp.get("code") != 200:
        print(f"  {operation}失败: code={resp.get('code')}, "
              f"message={resp.get('message', '未知错误')}")
        return False
    return True


def _nonnegative_seconds(value):
    """将广告返回的秒数安全转换为非负浮点数。"""
    if isinstance(value, bool):
        return None
    try:
        seconds = float(value)
    except (TypeError, ValueError):
        return None
    if seconds < 0 or seconds == float("inf") or seconds != seconds:
        return None
    return seconds


def _wait_seconds(seconds: float):
    """基于单调时钟等待，避免系统时间调整缩短停留时间。"""
    deadline = time.monotonic() + seconds
    remaining = seconds
    while remaining > 0:
        time.sleep(remaining)
        remaining = deadline - time.monotonic()


def _print_stage_state(stage: dict, prefix: str = "当前"):
    """输出阶段响应中的进度和阶段摘要。"""
    data = stage.get("data", {}) if isinstance(stage, dict) else {}
    data = data if isinstance(data, dict) else {}
    print(f"  {prefix}进度:{data.get('currentAmount', '未知')}/"
          f"{data.get('maximumAmount', '未知')}")
    print(f"  {prefix}阶段:{data.get('currentIndex', '未知')}/"
          f"{data.get('totalStage', '未知')}")


def _refresh_rights_state(client: NetEaseEapi):
    """领取成功后刷新阶段和免费听数据；刷新失败不改变领取结果。"""
    print("  刷新权益状态...")
    time.sleep(1)

    try:
        stage = client.get_stage_info()
        if _business_success(stage, "阶段刷新"):
            _print_stage_state(stage)
    except Exception as e:
        print(f"  [警告] 阶段刷新异常:{e}")

    try:
        free_listen = client.get_free_listen_data()
        if _business_success(free_listen, "免费听数据刷新"):
            data = free_listen.get("data")
            keys = sorted(data.keys()) if isinstance(data, dict) else []
            print(f"  免费听数据刷新成功, data 字段:{', '.join(keys) or '无'}")
    except Exception as e:
        print(f"  [警告] 免费听数据刷新异常:{e}")


def run_one_round(client: NetEaseEapi, round_num: int, cfg: Config) -> tuple:
    """执行一轮「观看广告 + 领取权益」流程。

    领取复用同一广告会话的 requestId、contextInfo 和真实曝光/点击时间。
    返回: (观看是否成功, 领取是否成功, 领取响应 code 或 None)。
    """
    print(f"\n{'=' * 60}")
    print(f"  第 {round_num} 轮")
    print(f"{'=' * 60}")

    print("[1/4] 请求广告...")
    sent_ad_req_id = client._make_ad_req_id()
    ad_resp = client.get_ad(ad_req_id=sent_ad_req_id)

    if not _business_success(ad_resp, "请求广告"):
        return False, False, None

    ads = ad_resp.get("ads", {})
    ad_key = f"{cfg.AD_POSITION}_0"
    if ad_key not in ads:
        print(f"  没有可用广告:{ad_resp.get('message', '无')}")
        return False, False, None

    ad_info = ads[ad_key]
    ci = _get_context_info(ad_info)
    gri, lri = _extract_rights_metadata(ad_info)

    print(f"  广告:{ad_info.get('text', '无标题')[:60]}")
    print(f"  ad_id: {ad_info.get('ad_id')}, req_id: {ci.get('req_id', 'N/A')}")

    response_request_id = ad_info.get("requestId", "")
    ad_req_id = response_request_id or sent_ad_req_id
    if response_request_id:
        print("  requestId: 使用广告响应值")
        if response_request_id != sent_ad_req_id:
            print("  [提示] 响应 requestId 与发送的 adReqId 不同，后续沿用响应值")
    else:
        print("  requestId: 响应缺失，沿用本轮发送的 adReqId")

    rights_gain_method = gri.get(
        "rightsGainMethod", lri.get("rightsGainMethod", 4))
    click_stay_raw = gri.get(
        "clickStayTime", lri.get("clickStayTime"))
    click_stay_time = _nonnegative_seconds(click_stay_raw)
    click_stay_extend = gri.get(
        "clickStayTimeExtend", lri.get("clickStayTimeExtend"))
    valid_video_interval = gri.get(
        "validVideoInterval", lri.get("validVideoInterval"))
    print(f"  领取方式:{rights_gain_method},停留:{click_stay_raw if click_stay_raw is not None else '未知'} 秒,"
          f"扩展:{click_stay_extend if click_stay_extend is not None else '未知'} 秒,"
          f"有效间隔:{valid_video_interval if valid_video_interval is not None else '未知'} 秒")

    check_token = client._get_next_check_token()
    tag_index = current_b_tag_index() % len(Config.CHECKTOKEN_B_TAG_POOL)
    tag_count = len(Config.CHECKTOKEN_B_TAG_POOL)
    print(f"  checkToken: 已生成 (长度: {len(check_token)}, "
          f"b_tag[{tag_index}/{tag_count}])")

    print("[2/4] 上报广告曝光...")
    exposure_time_ms = int(time.time() * 1000)
    ad_data = build_ad_data_for_monitor(
        ad_info, ad_req_id, cfg, exposure_time_ms=exposure_time_ms)
    impress_resp = client.report_impress(ad_data)
    if not _business_success(impress_resp, "曝光上报"):
        return False, False, None
    print("  曝光上报结果:code=200")

    print(f"  模拟观看 {cfg.WATCH_DELAY} 秒...")
    _wait_seconds(cfg.WATCH_DELAY)

    print("[3/4] 上报广告点击...")
    click_time_ms = int(time.time() * 1000)
    ad_data["clickTime"] = click_time_ms
    click_resp = client.report_click(ad_data)
    if not _business_success(click_resp, "点击上报"):
        return False, False, None
    print("  点击上报结果:code=200")

    if click_stay_time is None:
        claim_delay = float(cfg.CLAIM_DELAY)
        print(f"  [警告] clickStayTime 无效，使用兼容下限 {claim_delay:g} 秒")
    else:
        claim_delay = max(float(cfg.CLAIM_DELAY), click_stay_time)
    print(f"  点击后停留 {claim_delay:g} 秒 "
          f"(广告要求:{click_stay_time if click_stay_time is not None else '未知'}, "
          f"兼容下限:{cfg.CLAIM_DELAY})...")
    _wait_seconds(claim_delay)

    print("[4/4] 领取免费听权益...")
    req_param = build_rights_claim_params(
        ad_info, ad_req_id, cfg,
        exposure_time_ms=exposure_time_ms,
        click_time_ms=click_time_ms,
    )
    gain_resp = client.claim_rights(req_param, check_token=check_token)

    gain_resp = gain_resp if isinstance(gain_resp, dict) else {}
    data = gain_resp.get("data", {})
    data = data if isinstance(data, dict) else {}
    code = gain_resp.get("code")
    msg = gain_resp.get("message", "")
    gain_flag = data.get("gainFlag", False)
    show_content = data.get("showContent", "")
    rights_duration = data.get("gainRightsDuration")
    rights_unit = data.get("rightsDurationUnit")

    print(f"  领取结果:code={code},成功={gain_flag}")
    if msg:
        print(f"  消息:{msg}")
    if show_content:
        print(f"  内容:{show_content}")
    if rights_duration:
        print(f"  获得时长:{rights_duration} {rights_unit or ''}")
    if code == 200 and not gain_flag:
        print("  [失败] 接口请求成功，但服务端未发放权益")

    if code in (200, 2002):
        advance_b_tag_index()

    if gain_flag:
        _refresh_rights_state(client)

    return True, gain_flag, code


def main():
    parser = argparse.ArgumentParser(
        description="网易云音乐看广告免费听自动化工具"
    )
    parser.add_argument(
        "--rounds", type=int, default=Config.MAX_ROUNDS,
        help="广告执行轮数(默认:10)"
    )
    parser.add_argument(
        "--delay", type=int, default=Config.ROUND_DELAY,
        help="轮次之间的间隔秒数(默认:10)"
    )
    parser.add_argument(
        "--watch-time", type=int, default=Config.WATCH_DELAY,
        help="模拟观看广告的秒数(默认:16)"
    )
    args = parser.parse_args()

    Config.validate()

    cfg = Config()
    cfg.WATCH_DELAY = args.watch_time

    client = NetEaseEapi(cfg)

    print("=" * 60)
    print("  网易云音乐看广告免费听自动化工具")
    print("=" * 60)
    print("  App 规则: 每支广告观看完成后立即领取 1 次权益,"
          "每日上限由服务端判定 (gainFlag)")

    print("\n[初始化] 云贝登录...")
    try:
        login_resp = client.yunbei_login()
        print(f"  code={login_resp.get('code')}")
    except Exception as e:
        print(f"  登录异常:{e}")

    print("\n[初始化] 查询免费听进度...")
    try:
        stage = client.get_stage_info()
        _print_stage_state(stage)
    except Exception as e:
        print(f"  查询进度异常:{e}")

    rounds = args.rounds

    watch_success = 0
    watch_fail = 0
    claim_success = 0
    claim_fail = 0

    for i in range(1, rounds + 1):
        # 观看广告 + 领取权益 (每轮立即领取,与 App 行为一致)
        try:
            watch_ok, gain_ok, gain_code = run_one_round(client, i, cfg)
        except Exception as e:
            print(f"  本轮异常:{e}")
            watch_fail += 1
            continue

        if not watch_ok:
            watch_fail += 1
            continue

        watch_success += 1

        if gain_ok:
            claim_success += 1
        else:
            claim_fail += 1
            # 领取失败时提前停止,避免继续消耗广告次数。
            # 实测 code=2002「休息一下，请稍后再试」= 当日 b_tag 已用尽
            # (服务端风控, 同一 b_tag 每天约可成功领取 1 次), 并非当日广告
            # 次数上限; 补充 CHECKTOKEN_B_TAG_POOL 可增加当日领取次数。
            print("  权益领取失败,提前停止本轮执行。")
            if gain_code == 2002:
                print("  诊断: 2002「休息一下」通常表示当日 b_tag 已用尽。"
                      "每个 b_tag 每天约可领取 1 次权益, 可在 user.json 的 "
                      "CHECKTOKEN_B_TAG_POOL 中补充更多 b_tag 增加当日领取次数。")
            break

        if i < rounds:
            print(f"\n  等待 {args.delay} 秒后开始下一轮...")
            time.sleep(args.delay)

    print("\n" + "=" * 60)
    print("  执行汇总")
    print("=" * 60)
    print(f"  观看广告: 成功 {watch_success}, 失败 {watch_fail}")
    print(f"  领取权益: 成功 {claim_success}, 失败 {claim_fail}")

    try:
        stage = client.get_stage_info()
        print()
        _print_stage_state(stage, prefix="最终")
    except Exception:
        pass

    print("\n执行完成!")

    # 退出码 2 表示服务端未发放权益，供调度器停止后续轮次；
    # 退出码 1 表示所有轮次均未走到有效领取，避免被调度器误记为完成。
    if claim_fail > 0:
        sys.exit(2)
    if watch_fail > 0 and claim_success == 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
