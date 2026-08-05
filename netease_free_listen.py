#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
网易云音乐看广告领取免费听权益的自动化脚本。
"""

import argparse
import base64
import gzip
import hashlib
import json
import secrets
import time
import hmac
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

import requests as _requests


import os as _os

def _load_user_json() -> dict:
    """从 user.json 加载用户配置"""
    json_path = _os.path.join(_os.path.dirname(_os.path.abspath(__file__)), "user.json")
    if not _os.path.exists(json_path):
        return {}
    try:
        with open(json_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}

_USER = _load_user_json()

class Config:
    MUSIC_U = _USER.get("MUSIC_U", "00E3A81A784CE2D10307A46CB9AB5FE210B53B76BB78BFD4135BC2DAB606BD676AF59BA3FDCAD8648ACC68ED32420B3A19187A4BB78345DE21DB702E9FDCC30B42F81EB36C741A380A62BAD90152C5FFA13906E031EC29C0B403B597091DF747AE51A60CD16FA96A1BFDF411491E0057AE67BFE49A688AF761143B46F2215231E5961E0C2A5BE8B62DA521D25CC4F03B41B2C9352EBFD8A3C61F91BE4C5B75FA6DFA54CE66E20E937F7105CE76FA5F40D8B493733D9BC19139523A2D203E79C079E423FA34538341335F9E83673AD1CDDA932B539CCD123B5DE924A29372A86604B07FB4F9CD4E2740F46E6EE8575EA9EAB79E898F8B0DC757D8CD3B2618297DD93696BBE65DFC4BED8CC8CCE7AB4CF7EAE1B60BB65F8C2C1051AA31F379EA521289622354A68A87E0FBE4B9B0546F765361E32289D3F699A6DDFB4F43FA688545EE9916CB83EC89F4CD56CDF203B5198E9C11C4D006F254CFF5103CE82630A016")

    DEVICE_ID = _USER.get("DEVICE_ID", "76b5116eace97a142fd6549819c8e3c3")

    IDFV = _USER.get("IDFV", "4E3FED83-A963-4C4C-8251-459C73719EFC")
    OPENUDID = _USER.get("OPENUDID", "15dff6dc9df4eadc78821d3cba0a3f5517854e45")
    IYUN_ID = _USER.get("IYUN_ID", "c4dbc4875fb1e228b4f1792ceef565d8")
    LAST_IYUN_ID = _USER.get("LAST_IYUN_ID", "04538f499c2986eb2271763e4ecbd554")
    IYUN_VERSION = _USER.get("IYUN_VERSION", "20260506")
    LAST_IYUN_VERSION = _USER.get("LAST_IYUN_VERSION", "20250325")

    LONGITUDE = _USER.get("LONGITUDE", "115.088872")
    LATITUDE = _USER.get("LATITUDE", "33.405355")

    APP_VER = "9.3.41"
    BUILD_VER = "6116"
    OS_VER = "26.1"

    NTES_NUID = _USER.get("NTES_NUID", "6f406b21a028b790f5b09e170ec1df67")
    NMTID = _USER.get("NMTID", "00OZDVbiTDL3TpO6EcvqGB6G98QkzgAAAGfwEFg6A")

    AD_POSITION = "400002"
    WATCH_DELAY = 16
    CLAIM_DELAY = 3
    MAX_ROUNDS = 10
    ROUND_DELAY = 10


EAPI_KEY = b"e82ckenh8dichen8"
EAPI_NONCE = "36cd479b6b5"
EAPI_SIGN_SALT = "md5forencrypt"

# 从真实App抓包中提取的 checkToken 池(设备绑定,长期有效)
# 每个 checkToken 包含不同的 b_tag,服务端用于验证设备指纹
# 由于 b_tag 与时间戳的哈希算法是易盾SDK内部实现(无法逆向),
# 直接复用这些已验证的 checkToken
CHECKTOKEN_POOL = [
    "9ca16ae2e6ee8ec84fbcb387d9c86efb9a8ea3c44e829f9eadd77ab28d8baec5798eb6a8b4eb2af0febec3b940f0feacc3b92a888ffdd4d86096ebfea7eb4e928e9aa2c44a9489beccd858ed9b8cabc64088eeadc300",
    "9ca16ae2e6ee98d55ca0f1fc84ce6af190fba6d1c1efa9a8db7ba0f19ca7e74af1e9aca2e579e2f4ee93a132f8f4ee85a132e29c9fd4b25f988afbd3c564868e9eb7c44b82909993aa5fa0f18ba5c94df89cfe84a177",
    "9ca16ae2e6eeb6eb6785ed8383e76295968fb6d1c1efa9a8db7ba0f19ca7e74af1e9aca2e579e2f4ee93a132f8f4ee85a132e29c9fd4b25f988afbd3c564868e9eb7c44b82909993aa5fa0f18ba5c94df89cfe84a177",
]


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
        self.session = _requests.Session()
        self._check_token_index = 0
        self._setup_headers()
        self._setup_cookies()

    def _get_next_check_token(self) -> str:
        """轮换 checkToken 池,避免重复使用导致风控。"""
        ct = CHECKTOKEN_POOL[self._check_token_index % len(CHECKTOKEN_POOL)]
        self._check_token_index += 1
        return ct

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
        cookies = {
            "MUSIC_U": c.MUSIC_U,
            "_ntes_nuid": c.NTES_NUID,
            "NMTID": c.NMTID,
            "appver": c.APP_VER,
            "buildver": c.BUILD_VER,
            "deviceId": c.DEVICE_ID,
            "sDeviceId": c.DEVICE_ID,
            "os": "iPhone OS",
            "osver": c.OS_VER,
            "channel": "distribution",
            "appkey": "IuRPVVmc3WWul9fT",
            "EVNSM": "1.0.0",
            "machineid": "iPhone16.1",
            "packageType": "release",
            "idfv": c.IDFV,
            "idfa": "",
            "ntes_kaola_ad": "1",
            "_iuqxldmzr_": "33",
        }
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

    def yunbei_login(self) -> dict:
        """初始化云贝广告会话(使用 ne_AFN mark)。"""
        c = self.cfg
        extra_headers = {"X-MAM-CustomMark": "ne_AFN"}
        return self.request("/api/ad/listening/new/yunbei/login/request", {}, extra_headers=extra_headers)

    def get_stage_info(self) -> dict:
        """查询免费听活动进度。"""
        return self.request("/api/ad/listening/free/tab/homepage/stage/info", {
            "method": "GET",
            "data": {"entranceType": "FREE_LISTEN"},
        })

    def get_ad(self) -> dict:
        """请求激励广告。"""
        c = self.cfg
        ad_ext = {
            "ipv4": "",
            "fromRN": "1",
            "isNeedGetRights": "false",
            "opensdkVer": "2.0.4",
            "ext": {
                "teenMode": False,
                "ipv4": "",
                "sourceFrame": "note",
                "homePageType": 1,
                "wxInstalled": True,
                "iyunVersion": c.IYUN_VERSION,
                "iyunId": c.IYUN_ID,
                "opensdkVer": "2.0.4",
                "idfv": c.IDFV,
                "lastIyunId": c.LAST_IYUN_ID,
                "supportWechatCanvas": True,
                "lastIyunVersion": c.LAST_IYUN_VERSION,
            },
            "lbs": {"longitude": c.LONGITUDE, "latitude": c.LATITUDE},
            "adReqId": f"1773290531_{int(time.time() * 1000)}_3963",
            "isNativeSampling": False,
            "network": 1,
            "lastIyunVersion": c.LAST_IYUN_VERSION,
            "iyunVersion": c.IYUN_VERSION,
            "teenMode": False,
            "ipv6": "",
            "source": "132",
            "op": "0",
            "useragent": (
                "Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X) "
                "AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148"
            ),
            "homePageType": 1,
            "supportWechatCanvas": True,
            "wxInstalled": True,
            "newAgent": (
                "Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X) "
                "AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148"
            ),
            "idfv": c.IDFV,
            "idfa": "00000000-0000-0000-0000-000000000000",
            "resourceId": "0",
            "iyunId": c.IYUN_ID,
            "openudid": c.OPENUDID,
            "sourceFrame": "note",
            "appState": 0,
            "adPosition": c.AD_POSITION,
            "lastIyunId": c.LAST_IYUN_ID,
            "resolution": {"width": 1179, "height": 2556},
            "pid": "0",
            "isShowEndToast": "true",
            "showRightsEndDialog": "false",
        }
        return self.request("/api/ad/get", {
            "adextjson": json.dumps(ad_ext, separators=(",", ":")),
            "type_ids": json.dumps([f"{c.AD_POSITION}_0"]),
        })

    def _build_dev_info(self) -> str:
        c = self.cfg
        dev_info = {
            "ipv4": "",
            "idfa": "00000000-0000-0000-0000-000000000000",
            "iyunVersion": c.IYUN_VERSION,
            "useragent": (
                "Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X) "
                "AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148"
            ),
            "seq": int(time.time()) % 10000,
            "iyunId": c.IYUN_ID,
            "openudid": c.OPENUDID,
            "lastIyunId": c.LAST_IYUN_ID,
            "lbs": {"longitude": c.LONGITUDE, "latitude": c.LATITUDE},
            "ipv6": "",
            "network": 1,
            "op": "0",
            "resolution": {"width": 1179, "height": 2556},
            "lastIyunVersion": c.LAST_IYUN_VERSION,
        }
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

        真实App需要在Header中同时传递 x-anticheattoken。
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


def build_ad_data_for_monitor(ad_info: dict, ad_req_id: str, cfg: Config) -> dict:
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

    now_ms = time.time() * 1000

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
        "lbs": {"longitude": cfg.LONGITUDE, "latitude": cfg.LATITUDE},
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
        "impressid": f"{ad_req_id}_{int(time.time())}_12",
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


def build_rights_claim_params(ad_info: dict, ad_req_id: str, cfg: Config) -> dict:
    """构造权益领取请求参数。"""
    ci = _get_context_info(ad_info)
    gri = _parse_json(ad_info.get("generalRightsInfo"))
    lri = ad_info.get("listeningRightsInfo") or {}
    context_info_str = _get_context_info_str(ad_info)

    app_info = json.dumps({
        "avatar": ad_info.get("picUrl", ""),
        "productName": ad_info.get("text", ""),
    })

    now_ms = int(time.time() * 1000)

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
        "generalRightsInfo": ad_info.get("generalRightsInfo", ""),
        "nextRightsGainDuration": lri.get("nextRightsGainDuration", 0),
        "exposureTime": now_ms,
        "extraRightsType": lri.get("extraRightsType", 0),
        "qualified": False,
        "delayPopTime": gri.get("delayPopTime", 10),
        "rightType": gri.get("rightType", 10),
        "clickTime": now_ms,
        "adPosition": cfg.AD_POSITION,
        "rightsGainDuration": 0,
    }


def run_one_round(client: NetEaseEapi, round_num: int, cfg: Config) -> bool:
    """执行一轮广告领取流程,并返回是否领取成功。"""
    print(f"\n{'=' * 60}")
    print(f"  第 {round_num} 轮")
    print(f"{'=' * 60}")

    print("[1/4] 请求广告...")
    ad_resp = client.get_ad()

    if ad_resp.get("code") != 200:
        print(f"  请求广告失败:{ad_resp.get('message', '未知错误')}")
        return False

    ads = ad_resp.get("ads", {})
    ad_key = f"{cfg.AD_POSITION}_0"

    if ad_key not in ads:
        print(f"  没有可用广告:{ad_resp.get('message', '无')}")
        return False

    ad_info = ads[ad_key]
    ci = _get_context_info(ad_info)
    gri = _parse_json(ad_info.get("generalRightsInfo"))
    lri = ad_info.get("listeningRightsInfo") or {}

    print(f"  广告:{ad_info.get('text', '无标题')[:60]}")
    print(f"  ad_id: {ad_info.get('ad_id')}, req_id: {ci.get('req_id', 'N/A')}")
    print(f"  领取方式:{gri.get('rightsGainMethod', '未知')},"
          f"停留:{gri.get('clickStayTime', '未知')} 秒,"
          f"有效间隔:{gri.get('validVideoInterval', '未知')} 秒")

    # 轮换 checkToken 池
    check_token = client._get_next_check_token()
    print(f"  checkToken: {check_token[:40]}... (长度: {len(check_token)})")

    ad_req_id = ad_info.get("requestId", "")
    if not ad_req_id:
        ad_req_id = f"1773290531_{int(time.time() * 1000)}_3963"

    print("[2/4] 上报广告曝光...")
    ad_data = build_ad_data_for_monitor(ad_info, ad_req_id, cfg)
    impress_resp = client.report_impress(ad_data)
    print(f"  曝光上报结果:code={impress_resp.get('code')}")

    print(f"  模拟观看 {cfg.WATCH_DELAY} 秒...")
    time.sleep(cfg.WATCH_DELAY)

    print("[3/4] 上报广告点击...")
    ad_data["clickTime"] = int(time.time() * 1000)
    click_resp = client.report_click(ad_data)
    print(f"  点击上报结果:code={click_resp.get('code')}")

    time.sleep(cfg.CLAIM_DELAY)

    print("[4/4] 领取免费听权益...")
    req_param = build_rights_claim_params(ad_info, ad_req_id, cfg)
    gain_resp = client.claim_rights(req_param, check_token=check_token)

    code = gain_resp.get("code")
    msg = gain_resp.get("message", "")
    data = gain_resp.get("data", {})

    gain_flag = data.get("gainFlag", False) if isinstance(data, dict) else False
    show_content = data.get("showContent", "") if isinstance(data, dict) else ""
    rights_duration = data.get("gainRightsDuration") if isinstance(data, dict) else None
    rights_unit = data.get("rightsDurationUnit") if isinstance(data, dict) else None

    print(f"  领取结果:code={code},成功={gain_flag}")
    if msg:
        print(f"  消息:{msg}")
    if show_content:
        print(f"  内容:{show_content}")
    if rights_duration:
        print(f"  获得时长:{rights_duration} {rights_unit or ''}")

    return gain_flag


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

    cfg = Config()
    cfg.WATCH_DELAY = args.watch_time

    client = NetEaseEapi(cfg)

    print("=" * 60)
    print("  网易云音乐看广告免费听自动化工具")
    print("=" * 60)

    print("\n[初始化] 云贝登录...")
    try:
        login_resp = client.yunbei_login()
        print(f"  code={login_resp.get('code')}")
    except Exception as e:
        print(f"  登录异常:{e}")

    print("\n[初始化] 查询免费听进度...")
    try:
        stage = client.get_stage_info()
        sd = stage.get("data", {})
        current_amount = sd.get('currentAmount', 0)
        maximum_amount = sd.get('maximumAmount', 0)
        print(f"  当前进度:{current_amount}/{maximum_amount}")
        print(f"  当前阶段:{sd.get('currentIndex', '未知')}/{sd.get('totalStage', '未知')}")

        if maximum_amount > 0 and current_amount >= maximum_amount:
            print("\n  ⚠️ 每日免费听权益已领完,无需继续!")
            print("\n执行完成!")
            return
    except Exception as e:
        print(f"  查询进度异常:{e}")

    success_count = 0
    fail_count = 0

    for i in range(1, args.rounds + 1):
        try:
            if run_one_round(client, i, cfg):
                success_count += 1
            else:
                fail_count += 1
        except Exception as e:
            print(f"  本轮执行异常:{e}")
            fail_count += 1

        if i < args.rounds:
            print(f"\n  等待 {args.delay} 秒后开始下一轮...")
            time.sleep(args.delay)

    print("\n" + "=" * 60)
    print("  执行汇总")
    print("=" * 60)
    print(f"  总轮数:{args.rounds}")
    print(f"  成功:{success_count}")
    print(f"  失败:{fail_count}")

    try:
        stage = client.get_stage_info()
        sd = stage.get("data", {})
        print(f"\n  最终进度:{sd.get('currentAmount', '未知')}/{sd.get('maximumAmount', '未知')}")
        print(f"  最终阶段:{sd.get('currentIndex', '未知')}/{sd.get('totalStage', '未知')}")
    except Exception:
        pass

    print("\n执行完成!")


if __name__ == "__main__":
    main()