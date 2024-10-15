import asyncio
import datetime
import json
import time
import urllib

import aiofiles
import aiohttp

from homeassistant.helpers.storage import STORAGE_DIR

from .const import CONF_FILE_PREFIX
from .mysm4 import MyCryptSM
from .utils.func import (
    getLastMonth,
    getLastYear,
    getstatusoutput,
    getThisMonth_Yesterday,
    getThisYear,
    getYesterday,
    uuid,
)
from .utils.logger import LOGGER
from .utils.store import async_save_to_store


class SgccProDataClient:  # noqa: D101
    def __init__(self, hass, config=None):  # noqa: D107
        self.hass = hass
        self.coordinator = None
        self.request_data = None

        self.USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        self.appKey = "7e5b5e84ddad4994b0ebc68dedca4962"
        self.appSecret = "2bc37a881e1541aaa6e6e174658d150b"
        self.publicKey = "042D12DFBC179202AC4B7B7BADCDA6FF7B604339263F6AB732CE7107B7EA3830A2CA714DC303920D3CFF7647D898F1A8CC6C24E9EC3CC194E22D984AF7E16B42DC"
        self.privkeyhex = (
            "cb772811f1fef955ce1b4051130870d86cca6afede806f1e7c225d7359591d2b"
        )

        self.need_update_this_year_dict = {}
        self.need_update_last_year_dict = {}
        self.need_update_this_month_dict = {}
        self.need_update_last_month_dict = {}
        self.need_update_yesterday_dict = {}

        self.cookies = None
        self.newKeyCode = None
        self.newPublicKey = None

        self.verify_code_key = None

        self.user_token = None
        self.user_id = None
        self.login_account = None
        self.password = None

        self.authorize_code = None

        self.access_token = None
        self.refresh_token = None

        self.power_user_list = None

        self.is_debug = True

        # 数据刷新间隔，以小时为单位
        self.refresh_interval = 6
        self.last_update_time = None

        # 开门持久化通知
        self.is_persistent_notify = True
        self.has_send_token_valid = False

        # 移动应用推送
        self.push_notify_device = []

        self.session = aiohttp.ClientSession(
            cookie_jar=aiohttp.CookieJar(quote_cookie=True),
            connector=aiohttp.TCPConnector(ssl=False),
        )

        if config is not None:
            try:
                self.newKeyCode = config["key_code"]
                self.newPublicKey = config["public_key"]
                self.user_id = config["user_id"]
                self.user_token = config["user_token"]
                self.access_token = config["access_token"]
                self.refresh_token = config["refresh_token"]
                self.authorize_code = config["authorize_code"]
                self.power_user_list = config["power_user_list"]
                self.cookies = config["cookies"]
                self.login_account = config["login_account"]
                self.password = config["password"]
                self.is_debug = config["is_debug"]
                self.refresh_interval = config["refresh_interval"]
                self.is_persistent_notify = config["is_persistent_notify"]
                self.push_notify_device = config["push_notify_device"]
                self.last_update_time = config["last_update_time"]
            except Exception as err:
                LOGGER.error(err)

    async def refresh_data(self, force_update=False, setup=False):
        now = int(datetime.datetime.now().timestamp())
        if (
            setup
            or force_update
            or self.last_update_time is None
            or ((now - self.last_update_time) >= (self.refresh_interval * 60 * 60))
        ):
            self.log_if_debug("start refresh data")
            self.last_update_time = now

            res_data = {}

            for poweruser in self.power_user_list:
                res_data[poweruser["consNo_dst"]] = None
                res_account = await self.get_account_info(poweruser)
                if res_account["errcode"] != 0:
                    res_relogin = await self.relogin_and_refresh_tokens()
                    if res_relogin["errcode"] != 0:
                        continue
                    res_account = await self.get_account_info(poweruser)
                    if res_account["errcode"] != 0:
                        continue
                self.log_if_debug(f"account_info: >>> {res_account["data"]}")

                power_info = {}
                power_info["balance"] = res_account["data"][0]["accountBalance"]
                power_info["refresh_time"] = time.strftime(
                    "%Y-%m-%d %H:%M:%S", time.localtime()
                )
                power_info["last_month_meter_num"] = res_account["data"][0]["totalPq"]
                power_info["last_month_meter_cost"] = res_account["data"][0]["sumMoney"]

                thisyear_usage = await self.refresh_thisyear_data(poweruser)
                if thisyear_usage is not None:
                    power_info["year_ele_num"] = [
                        thisyear_usage["dataInfo"]["totalEleNum"],
                        thisyear_usage["mothEleList"],
                    ]
                    power_info["year_ele_cost"] = [
                        thisyear_usage["dataInfo"]["totalEleCost"],
                        thisyear_usage["mothEleList"],
                    ]

                thismonth_usage = await self.refresh_thismonth_data(poweruser)
                if thismonth_usage is not None:
                    power_info["month_ele_num"] = thismonth_usage["total"]
                    power_info["month_v_ele_num"] = thismonth_usage["vpq"]
                    power_info["month_t_ele_num"] = thismonth_usage["tpq"]
                    power_info["month_n_ele_num"] = thismonth_usage["npq"]
                    power_info["month_p_ele_num"] = thismonth_usage["ppq"]

                lastmonth_usage = await self.refresh_lastmonth_data(poweruser)
                if lastmonth_usage is not None:
                    power_info["last_month_ele_num"] = lastmonth_usage["total"]
                    power_info["last_month_v_ele_num"] = lastmonth_usage["vpq"]
                    power_info["last_month_t_ele_num"] = lastmonth_usage["tpq"]
                    power_info["last_month_n_ele_num"] = lastmonth_usage["npq"]
                    power_info["last_month_p_ele_num"] = lastmonth_usage["ppq"]

                lastyear_usage = await self.refresh_lastyear_data(poweruser)
                if lastyear_usage is not None:
                    power_info["last_year_ele_num"] = [
                        lastyear_usage["dataInfo"]["totalEleNum"],
                        lastyear_usage["mothEleList"],
                    ]
                    power_info["last_year_ele_cost"] = [
                        lastyear_usage["dataInfo"]["totalEleCost"],
                        lastyear_usage["mothEleList"],
                    ]

                # power_info["yesterday_usage"] = await self.refresh_yesterday_data(
                #     poweruser
                # )

                res_data[poweruser["consNo_dst"]] = power_info
            self.request_data = res_data
            return res_data
        return self.request_data

    async def refresh_thisyear_data(self, poweruser):
        year = getThisYear()
        if (
            poweruser["consNo_dst"] not in self.need_update_this_year_dict
            or self.need_update_this_year_dict[poweruser["consNo_dst"]] != year
        ):
            self.need_update_this_year_dict[poweruser["consNo_dst"]] = year
            res_list = await self.get_bill_list(poweruser, year, None, None)
            if res_list["errcode"] != 0:
                return None
            return res_list["data"]
        return None

    async def refresh_lastyear_data(self, poweruser):
        year = getLastYear()
        if (
            poweruser["consNo_dst"] not in self.need_update_last_year_dict
            or self.need_update_last_year_dict[poweruser["consNo_dst"]] != year
        ):
            self.need_update_last_year_dict[poweruser["consNo_dst"]] = year
            res_list = await self.get_bill_list(poweruser, year, None, None)
            if res_list["errcode"] != 0:
                return None
            return res_list["data"]
        return None

    async def refresh_thismonth_data(self, poweruser):
        first_day = getThisMonth_Yesterday()[0]
        last_day = getThisMonth_Yesterday()[1]
        if (
            poweruser["consNo_dst"] not in self.need_update_this_month_dict
            or self.need_update_this_month_dict[poweruser["consNo_dst"]] != first_day
        ):
            self.need_update_this_month_dict[poweruser["consNo_dst"]] = first_day
            res_list = await self.get_bill_list(poweruser, None, first_day, last_day)
            if res_list["errcode"] != 0:
                return None

            if res_list["data"] is not None:
                sum_VPq = 0
                sum_TPq = 0
                sum_NPq = 0
                sum_PPq = 0

                list_totalq = []
                list_VPq = []
                list_TPq = []
                list_NPq = []
                list_PPq = []

                for day_info in res_list["data"]["sevenEleList"]:
                    day = day_info["day"]
                    vpq = 0
                    if "thisVPq" in day_info:
                        vpq = float(day_info["thisVPq"])

                    tpq = 0
                    if "thisTPq" in day_info:
                        tpq = float(day_info["thisTPq"])

                    npq = 0
                    if "thisNPq" in day_info:
                        npq = float(day_info["thisNPq"])

                    ppq = 0
                    if "thisPPq" in day_info:
                        ppq = float(day_info["thisPPq"])

                    totalq = vpq + tpq + npq + ppq

                    list_totalq.append({"day": day, "val": totalq})
                    list_VPq.append({"day": day, "val": vpq})
                    list_TPq.append({"day": day, "val": tpq})
                    list_NPq.append({"day": day, "val": npq})
                    list_PPq.append({"day": day, "val": ppq})

                    sum_VPq += vpq
                    sum_TPq += tpq
                    sum_NPq += npq
                    sum_PPq += ppq
            return {
                "total": [sum_VPq + sum_TPq + sum_NPq + sum_PPq, list_totalq],
                "vpq": [sum_VPq, list_VPq],
                "tpq": [sum_TPq, list_TPq],
                "npq": [sum_NPq, list_NPq],
                "ppq": [sum_PPq, list_PPq],
            }
        return None

    async def refresh_lastmonth_data(self, poweruser):
        first_day = getLastMonth()[0]
        last_day = getLastMonth()[1]
        if (
            poweruser["consNo_dst"] not in self.need_update_last_month_dict
            or self.need_update_last_month_dict[poweruser["consNo_dst"]] != first_day
        ):
            self.need_update_last_month_dict[poweruser["consNo_dst"]] = first_day
            res_list = await self.get_bill_list(poweruser, None, first_day, last_day)
            if res_list["errcode"] != 0:
                return None
            if res_list["data"] is not None:
                sum_VPq = 0
                sum_TPq = 0
                sum_NPq = 0
                sum_PPq = 0

                list_totalq = []
                list_VPq = []
                list_TPq = []
                list_NPq = []
                list_PPq = []

                for day_info in res_list["data"]["sevenEleList"]:
                    day = day_info["day"]
                    vpq = 0
                    if "thisVPq" in day_info:
                        vpq = float(day_info["thisVPq"])

                    tpq = 0
                    if "thisTPq" in day_info:
                        tpq = float(day_info["thisTPq"])

                    npq = 0
                    if "thisNPq" in day_info:
                        npq = float(day_info["thisNPq"])

                    ppq = 0
                    if "thisPPq" in day_info:
                        ppq = float(day_info["thisPPq"])

                    totalq = vpq + tpq + npq + ppq

                    list_totalq.append({"day": day, "val": totalq})
                    list_VPq.append({"day": day, "val": vpq})
                    list_TPq.append({"day": day, "val": tpq})
                    list_NPq.append({"day": day, "val": npq})
                    list_PPq.append({"day": day, "val": ppq})

                    sum_VPq += vpq
                    sum_TPq += tpq
                    sum_NPq += npq
                    sum_PPq += ppq
            return {
                "total": [sum_VPq + sum_TPq + sum_NPq + sum_PPq, list_totalq],
                "vpq": [sum_VPq, list_VPq],
                "tpq": [sum_TPq, list_TPq],
                "npq": [sum_NPq, list_NPq],
                "ppq": [sum_PPq, list_PPq],
            }
        return None

    async def refresh_yesterday_data(self, poweruser):
        yesterday = getYesterday()
        if (
            poweruser["consNo_dst"] not in self.need_update_yesterday_dict
            or self.need_update_yesterday_dict[poweruser["consNo_dst"]] != yesterday
        ):
            self.need_update_yesterday_dict[poweruser["consNo_dst"]] = yesterday
            res_list = await self.get_bill_list(poweruser, None, yesterday, yesterday)
            if res_list["errcode"] != 0:
                return None
            return res_list["data"]
        return None

    def log_if_debug(self, text):  # noqa: D102
        if self.is_debug:
            LOGGER.error(text)

    async def save_data(self):  # noqa: D102
        data = {}
        data["key_code"] = self.newKeyCode
        data["public_key"] = self.newPublicKey
        data["user_id"] = self.user_id
        data["user_token"] = self.user_token
        data["access_token"] = self.access_token
        data["refresh_token"] = self.refresh_token
        data["authorize_code"] = self.authorize_code
        data["power_user_list"] = self.power_user_list
        data["cookies"] = self.cookies
        data["login_account"] = self.login_account
        data["password"] = self.password
        data["is_debug"] = self.is_debug
        data["refresh_interval"] = self.refresh_interval
        data["is_persistent_notify"] = self.is_persistent_notify
        data["push_notify_device"] = self.push_notify_device
        data["last_update_time"] = self.last_update_time

        await async_save_to_store(
            self.hass, f"{CONF_FILE_PREFIX}-{self.login_account}", data
        )

    def get_headers(self, timestamp, need_keycode=False):  # noqa: D102
        headers = {
            "User-Agent": self.USER_AGENT,
            "Accept": "application/json;charset=UTF-8",
            "Accept-Language": "zh-Hans-CN;q=1",
            "appKey": self.appKey,
            "timestamp": timestamp,
            "version": "1.0",
            "wsgwType": "web",
            "source": "0901",
            "Content-type": "application/json;charset=UTF-8",
        }

        if need_keycode:
            headers["keycode"] = self.newKeyCode

        return headers

    async def get_key_code_and_public_key(self):  # noqa: D102
        try:
            keycode = uuid(32, 16, 2)
            timestamp = str(int(time.time() * 1000))
            headers = self.get_headers(timestamp)

            data = {"client_secret": self.appSecret, "client_id": self.appKey}
            my_crypt = MyCryptSM(keycode, self.publicKey, self.privkeyhex)
            encrypt_data = my_crypt.sm4_encrypt_cbc_data(data, timestamp)
            base64_skey = my_crypt.sm2_encrypt_keycode(keycode)
            params = {
                "data": encrypt_data,
                "skey": base64_skey,
                "client_id": self.appKey,
                "timestamp": timestamp,
            }
            url = "https://www.95598.cn/api/oauth2/outer/c02/f02"

            self.log_if_debug("start call get_key_code_and_public_key")

            async with self.session.post(
                url=url, headers=headers, data=json.dumps(params)
            ) as response:
                response_text = await response.text()

                if response.status == 200:
                    self.cookies = response.cookies

                    if response_text.startswith("{"):
                        json_data = json.loads(response_text)
                        result = my_crypt.sm4_decrypt_cbc_data(json_data["encryptData"])
                        self.log_if_debug(
                            f"call get_key_code_and_public_key result: {
                                result}"
                        )
                        if result["code"] == 1 or result["code"] == "1":
                            self.newKeyCode = result["data"]["keyCode"]
                            self.newPublicKey = result["data"]["publicKey"]
                            return {
                                "data": result["data"],
                                "errcode": 0,
                                "errmsg": "",
                            }

                        return {
                            "data": None,
                            "errcode": 502,
                            "errmsg": f"返回结果码错误: {result['code']} - {result['message']}",
                        }
                    return {
                        "data": None,
                        "errcode": 502,
                        "errmsg": f"json格式不合法: {response_text}",
                    }
                return {
                    "data": None,
                    "errcode": 502,
                    "errmsg": f"返回状态码错误: {response.status} - {response.reason}",
                }
        except Exception as err:
            import traceback

            LOGGER.error("exception: %s", traceback.format_exc())
            raise err

    async def password_login_request(self, username, password):  # noqa: D102
        try:
            timestamp = str(int(time.time() * 1000))
            headers = self.get_headers(timestamp, need_keycode=True)
            data = {
                "_access_token": "",
                "_t": "",
                "_data": {
                    "password": password,
                    "account": username,
                    "canvasHeight": 200,
                    "canvasWidth": 410,
                },
                "timestamp": timestamp,
            }
            my_crypt = MyCryptSM(self.newKeyCode, self.newPublicKey, self.privkeyhex)
            encrypt_data = my_crypt.sm4_encrypt_cbc_data(data, timestamp)
            base64_skey = my_crypt.sm2_encrypt_keycode(self.newKeyCode)
            params = {"data": encrypt_data, "skey": base64_skey, "timestamp": timestamp}
            url = "https://www.95598.cn/api/osg-web0004/open/c44/f05"

            self.log_if_debug("start call password_login_request")

            async with self.session.post(
                url=url, headers=headers, data=json.dumps(params), cookies=self.cookies
            ) as response:
                response_text = await response.text()

                if response.status == 200:
                    self.cookies = response.cookies
                    if response_text.startswith("{"):
                        json_data = json.loads(response_text)
                        if "code" in json_data:
                            return {
                                "data": None,
                                "errcode": 502,
                                "errmsg": f"登录失败: code {json_data['code']}",
                            }
                        result = my_crypt.sm4_decrypt_cbc_data(json_data["encryptData"])
                        self.log_if_debug(
                            f"call password_login_request result: {str(result)[:100]}......"
                        )
                        if result["code"] == 1 or result["code"] == "1":
                            self.verify_code_key = result["data"]["ticket"]
                            return {"data": result["data"], "errcode": 0, "errmsg": ""}

                        return {
                            "data": None,
                            "errcode": 502,
                            "errmsg": f"返回结果码错误: {result['code']} - {result['message']}",
                        }
                    return {
                        "data": None,
                        "errcode": 502,
                        "errmsg": f"json格式不合法: {response_text}",
                    }
                return {
                    "data": None,
                    "errcode": 502,
                    "errmsg": f"返回状态码错误: {response.status} - {response.reason}",
                }
        except Exception as err:
            import traceback

            LOGGER.error("exception: %s", traceback.format_exc())
            return err

    async def password_login(self, username, password, slide_code, login_key):  # noqa: D102
        try:
            timestamp = str(int(time.time() * 1000))
            headers = self.get_headers(timestamp, need_keycode=True)
            data = {
                "_access_token": "",
                "_t": "",
                "_data": {
                    "loginKey": login_key,
                    "code": int(slide_code),
                    "params": {
                        "uscInfo": {
                            "devciceIp": "",
                            "tenant": "state_grid",
                            "member": "0902",
                            "devciceId": "",
                        },
                        "quInfo": {
                            "optSys": "android",
                            "pushId": "000000",
                            "addressProvince": "110100",
                            "password": password,
                            "addressRegion": "110101",
                            "account": username,
                            "addressCity": "330100",
                        },
                    },
                },
                "timestamp": timestamp,
            }
            my_crypt = MyCryptSM(self.newKeyCode, self.newPublicKey, self.privkeyhex)
            encrypt_data = my_crypt.sm4_encrypt_cbc_data(data, timestamp)
            base64_skey = my_crypt.sm2_encrypt_keycode(self.newKeyCode)
            params = {"data": encrypt_data, "skey": base64_skey, "timestamp": timestamp}
            url = "https://www.95598.cn/api/osg-web0004/open/c44/f06"

            self.log_if_debug("start call password_login")

            async with self.session.post(
                url=url, headers=headers, data=json.dumps(params), cookies=self.cookies
            ) as response:
                response_text = await response.text()

                if response.status == 200:
                    self.cookies = response.cookies
                    if response_text.startswith("{"):
                        json_data = json.loads(response_text)
                        if "code" in json_data:
                            return {
                                "data": None,
                                "errcode": 502,
                                "errmsg": f"登录失败: code {json_data['code']}",
                            }
                        result = my_crypt.sm4_decrypt_cbc_data(json_data["encryptData"])
                        self.log_if_debug(f"call password_login result: {result}")
                        if result["code"] == 1 or result["code"] == "1":
                            if result["data"]["srvrt"]["resultCode"] != "0000":
                                return {
                                    "data": None,
                                    "errcode": 502,
                                    "errmsg": result["data"]["srvrt"]["resultMessage"],
                                }
                            self.user_token = result["data"]["bizrt"]["token"]
                            self.user_id = result["data"]["bizrt"]["userInfo"][0][
                                "userId"
                            ]
                            self.login_account = username
                            self.password = password
                            return {"data": self.user_token, "errcode": 0, "errmsg": ""}

                        return {
                            "data": None,
                            "errcode": 502,
                            "errmsg": f"返回结果码错误: {result['code']} - {result['message']}",
                        }
                    return {
                        "data": None,
                        "errcode": 502,
                        "errmsg": f"json格式不合法: {response_text}",
                    }
                return {
                    "data": None,
                    "errcode": 502,
                    "errmsg": f"返回状态码错误: {response.status} - {response.reason}",
                }
        except Exception as err:
            import traceback

            LOGGER.error("exception: %s", traceback.format_exc())
            return err

    async def do_authorize(self, token):  # noqa: D102
        try:
            timestamp = str(int(time.time() * 1000))
            headers = {
                "Host": "www.95598.cn",
                "Connection": "keep-alive",
                "keyCode": self.newKeyCode,
                "sec-ch-ua-platform": "Windows",
                "timestamp": timestamp,
                "sec-ch-ua": '"Microsoft Edge";v="129", "Not=A?Brand";v="8", "Chromium";v="129"',
                "wsgwType": "web",
                "sec-ch-ua-mobile": "?0",
                "source": "0901",
                "User-Agent": self.USER_AGENT,
                "Accept": "application/json;charset=UTF-8",
                "appKey": self.appKey,
                "version": "1.0",
                "Origin": "https://www.95598.cn",
                "Sec-Fetch-Site": "same-origin",
                "Sec-Fetch-Mode": "cors",
                "Sec-Fetch-Dest": "empty",
                "Referer": "https://www.95598.cn/osgweb/login?status=0",
                "Accept-Encoding": "gzip, deflate, br, zstd",
                "Accept-Language": "zh-CN,zh;q=0.9",
                "Content-type": "application/x-www-form-urlencoded;charset=UTF-8",
            }
            params = {
                "client_id": self.appKey,
                "response_type": "code",
                "redirect_url": "/test",
                "timestamp": timestamp,
                "rsi": token,
            }
            params = urllib.parse.urlencode(params)
            url = "https://www.95598.cn/api/oauth2/oauth/authorize"

            self.log_if_debug("start call do_authorize")

            async with self.session.post(
                url=url, headers=headers, data=params, cookies=self.cookies
            ) as response:
                response_text = await response.text()
                if response.status == 200:
                    self.cookies = response.cookies
                    if response_text.startswith("{"):
                        json_data = json.loads(response_text)
                        if "code" in json_data:
                            return {
                                "data": None,
                                "errcode": 502,
                                "errmsg": f"登录失败: code {json_data['code']}, msg {json_data["message"]}",
                            }
                        my_crypt = MyCryptSM(token, self.newPublicKey, self.privkeyhex)
                        result = my_crypt.sm4_decrypt_cbc_data(json_data["data"])
                        self.log_if_debug(f"call do_authorize result: {result}")
                        if result["code"] == 1 or result["code"] == "1":
                            self.authorize_code = result["data"]["redirect_url"].split(
                                "code=", 1
                            )[1]
                            return {
                                "data": self.authorize_code,
                                "errcode": 0,
                                "errmsg": "",
                            }
                        return {
                            "data": None,
                            "errcode": 502,
                            "errmsg": f"返回结果码错误: {result['code']} - {result['message']}",
                        }
                    return {
                        "data": None,
                        "errcode": 502,
                        "errmsg": f"json格式不合法: {response_text}",
                    }
                return {
                    "data": None,
                    "errcode": 502,
                    "errmsg": f"返回状态码错误: {response.status} - {response.reason}",
                }

        except Exception as err:
            import traceback

            LOGGER.error("exception: %s", traceback.format_exc())
            return err

    async def get_web_token(self, auth_code):  # noqa: D102
        try:
            timestamp = str(int(time.time() * 1000))
            my_crypt = MyCryptSM(self.newKeyCode, self.newPublicKey, self.privkeyhex)
            headers = self.get_headers(timestamp, need_keycode=True)
            data = {
                "grant_type": "authorization_code",
                "sign": my_crypt.sm3_sign_appkey(self.appKey, timestamp),
                "client_secret": self.appSecret,
                "state": "464606a4-184c-4beb-b442-2ab7761d0796",
                "key_code": self.newKeyCode,
                "client_id": self.appKey,
                "timestamp": timestamp,
                "code": auth_code,
            }
            encrypt_data = my_crypt.sm4_encrypt_cbc_data(data, timestamp)
            base64_skey = my_crypt.sm2_encrypt_keycode(self.newKeyCode)
            params = {"data": encrypt_data, "skey": base64_skey, "timestamp": timestamp}
            url = "https://www.95598.cn/api/oauth2/outer/getWebToken"

            self.log_if_debug("start call get_web_token")

            async with self.session.post(
                url=url, headers=headers, data=json.dumps(params), cookies=self.cookies
            ) as response:
                response_text = await response.text()
                if response.status == 200:
                    self.cookies = response.cookies
                    if response_text.startswith("{"):
                        json_data = json.loads(response_text)
                        if "code" in json_data:
                            return {
                                "data": None,
                                "errcode": 502,
                                "errmsg": f"登录失败: code {json_data['code']}",
                            }
                        result = my_crypt.sm4_decrypt_cbc_data(json_data["encryptData"])
                        self.log_if_debug(f"call get_web_token result: {result}")
                        if result["code"] == 1 or result["code"] == "1":
                            self.access_token = result["data"]["access_token"]
                            self.refresh_token = result["data"]["refresh_token"]
                            return {
                                "data": result,
                                "errcode": 0,
                                "errmsg": "",
                            }
                        return {
                            "data": None,
                            "errcode": 502,
                            "errmsg": f"返回结果码错误: {result['code']} - {result['message']}",
                        }
                    return {
                        "data": None,
                        "errcode": 502,
                        "errmsg": f"json格式不合法: {response_text}",
                    }
                return {
                    "data": None,
                    "errcode": 502,
                    "errmsg": f"返回状态码错误: {response.status} - {response.reason}",
                }

        except Exception as err:
            import traceback

            LOGGER.error("exception: %s", traceback.format_exc())
            return err

    async def get_power_user_list(self):  # noqa: D102
        try:
            timestamp = str(int(time.time() * 1000))
            headers = {
                "User-Agent": self.USER_AGENT,
                "Accept": "application/json;charset=UTF-8",
                "Accept-Language": "zh-Hans-CN;q=1",
                "Authorization": "Bearer "
                + self.access_token[: len(self.access_token) // 2],
                "appKey": self.appKey,
                "timestamp": timestamp,
                "version": "1.0",
                "wsgwType": "web",
                "source": "0901",
                "t": self.user_token[: len(self.user_token) // 2],
                "keycode": self.newKeyCode,
                "Content-type": "application/json;charset=UTF-8",
            }
            data = {
                "_access_token": self.access_token[len(self.access_token) // 2 :],
                "_t": self.user_token[len(self.user_token) // 2 :],
                "_data": {
                    "serviceCode": "0101183",
                    "source": "SGAPP",
                    "target": "32101",
                    "uscInfo": {
                        "member": "0902",
                        "devciceIp": "",
                        "devciceId": "",
                        "tenant": "state_grid",
                    },
                    "quInfo": {"userId": self.user_id},
                    "token": self.user_token,
                    "Channels": "web",
                },
                "timestamp": timestamp,
            }
            my_crypt = MyCryptSM(self.newKeyCode, self.newPublicKey, self.privkeyhex)
            encrypt_data = my_crypt.sm4_encrypt_cbc_data(data, timestamp)
            base64_skey = my_crypt.sm2_encrypt_keycode(self.newKeyCode)
            params = {"data": encrypt_data, "skey": base64_skey, "timestamp": timestamp}
            url = "https://www.95598.cn/api/osg-open-uc0001/member/c9/f02"

            self.log_if_debug("start call get_power_user_list")

            async with self.session.post(
                url=url, headers=headers, data=json.dumps(params), cookies=self.cookies
            ) as response:
                response_text = await response.text()
                if response.status == 200:
                    self.cookies = response.cookies
                    if response_text.startswith("{"):
                        json_data = json.loads(response_text)
                        if "code" in json_data:
                            return {
                                "data": None,
                                "errcode": 502,
                                "errmsg": f"登录失败: code {json_data['code']}",
                            }
                        result = my_crypt.sm4_decrypt_cbc_data(json_data["encryptData"])
                        self.log_if_debug(f"call get_power_user_list result: {result}")
                        if result["code"] == 1 or result["code"] == "1":
                            self.power_user_list = result["data"]["bizrt"][
                                "powerUserList"
                            ]
                            return {
                                "data": self.power_user_list,
                                "errcode": 0,
                                "errmsg": "",
                            }
                        return {
                            "data": None,
                            "errcode": 502,
                            "errmsg": f"返回结果码错误: {result['code']} - {result['message']}",
                        }
                    return {
                        "data": None,
                        "errcode": 502,
                        "errmsg": f"json格式不合法: {response_text}",
                    }
                return {
                    "data": None,
                    "errcode": 502,
                    "errmsg": f"返回状态码错误: {response.status} - {response.reason}",
                }

        except Exception as err:
            import traceback

            LOGGER.error("exception: %s", traceback.format_exc())
            return err

    async def get_account_info(self, power_user):  # noqa: D102
        try:
            timestamp = str(int(time.time() * 1000))
            headers = {
                "User-Agent": self.USER_AGENT,
                "Accept": "application/json;charset=UTF-8",
                "Accept-Language": "zh-Hans-CN;q=1",
                "Authorization": "Bearer "
                + self.access_token[: len(self.access_token) // 2],
                "appKey": self.appKey,
                "timestamp": timestamp,
                "version": "1.0",
                "wsgwType": "web",
                "source": "0901",
                "t": self.user_token[: len(self.user_token) // 2],
                "keycode": self.newKeyCode,
                "Content-type": "application/json;charset=UTF-8",
            }
            data = {
                "_access_token": self.access_token[len(self.access_token) // 2 :],
                "_t": self.user_token[len(self.user_token) // 2 :],
                "_data": {
                    "data": {
                        "srvCode": "",
                        "serialNo": "",
                        "channelCode": "0902",
                        "funcCode": "WEBA1007200",
                        "acctId": self.user_id,
                        "userName": self.login_account,
                        "promotType": "1",
                        "promotCode": "1",
                        "userAccountId": self.user_id,
                        "list": [
                            {
                                "consNoSrc": power_user["consNo_dst"],
                                "proCode": power_user["proNo"],
                                "sceneType": power_user["constType"],
                                "consNo": power_user["consNo"],
                                "orgNo": power_user["orgNo"],
                            }
                        ],
                    },
                    "serviceCode": "0101143",
                    "source": "SGAPP",
                    "target": power_user["proNo"],
                },
                "timestamp": timestamp,
            }
            my_crypt = MyCryptSM(self.newKeyCode, self.newPublicKey, self.privkeyhex)
            encrypt_data = my_crypt.sm4_encrypt_cbc_data(data, timestamp)
            base64_skey = my_crypt.sm2_encrypt_keycode(self.newKeyCode)
            params = {"data": encrypt_data, "skey": base64_skey, "timestamp": timestamp}
            url = "https://www.95598.cn/api/osg-open-bc0001/member/c05/f01"

            self.log_if_debug("start call get_account_info")

            async with self.session.post(
                url=url, headers=headers, data=json.dumps(params), cookies=self.cookies
            ) as response:
                response_text = await response.text()
                if response.status == 200:
                    self.cookies = response.cookies
                    if response_text.startswith("{"):
                        json_data = json.loads(response_text)
                        if "code" in json_data:
                            return {
                                "data": None,
                                "errcode": 502,
                                "errmsg": f"登录失败: code {json_data['code']}",
                            }
                        result = my_crypt.sm4_decrypt_cbc_data(json_data["encryptData"])
                        self.log_if_debug(f"call get_account_info result: {result}")
                        if result["code"] == 1 or result["code"] == "1":
                            return {
                                "data": result["data"]["list"],
                                "errcode": 0,
                                "errmsg": "",
                            }
                        return {
                            "data": None,
                            "errcode": 502,
                            "errmsg": f"返回结果码错误: {result['code']} - {result['message']}",
                        }
                    return {
                        "data": None,
                        "errcode": 502,
                        "errmsg": f"json格式不合法: {response_text}",
                    }
                return {
                    "data": None,
                    "errcode": 502,
                    "errmsg": f"返回状态码错误: {response.status} - {response.reason}",
                }

        except Exception as err:
            import traceback

            LOGGER.error("exception: %s", traceback.format_exc())
            return err

    async def get_bill_list(self, power_user, year=None, startday=None, endday=None):  # noqa: D102
        try:
            timestamp = str(int(time.time() * 1000))
            param4 = "010102"
            if startday is not None and endday is not None:
                param4 = "010103"

            headers = {
                "User-Agent": self.USER_AGENT,
                "Accept": "application/json;charset=UTF-8",
                "Accept-Language": "zh-Hans-CN;q=1",
                "Authorization": "Bearer "
                + self.access_token[: len(self.access_token) // 2],
                "appKey": self.appKey,
                "timestamp": timestamp,
                "version": "1.0",
                "wsgwType": "web",
                "source": "0901",
                "t": self.user_token[: len(self.user_token) // 2],
                "keycode": self.newKeyCode,
                "Content-type": "application/json;charset=UTF-8",
            }
            data = {
                "_access_token": self.access_token[len(self.access_token) // 2 :],
                "_t": self.user_token[len(self.user_token) // 2 :],
                "_data": {
                    "params1": {
                        "serviceCode": {
                            "order": "0101154",
                            "uploadPic": "0101296",
                            "pauseSCode": "0101250",
                            "pauseTCode": "0101251",
                            "listconsumers": "0101093",
                            "messageList": "0101343",
                            "submit": "0101003",
                            "sbcMsg": "0101210",
                            "powercut": "0104514",
                            "BkAuth01": "f15",
                            "BkAuth02": "f18",
                            "BkAuth03": "f02",
                            "BkAuth04": "f17",
                            "BkAuth05": "f05",
                            "BkAuth06": "f16",
                            "BkAuth07": "f01",
                            "BkAuth08": "f03",
                        },
                        "source": "SGAPP",
                        "target": "32101",
                        "uscInfo": {
                            "member": "0902",
                            "devciceIp": "",
                            "devciceId": "",
                            "tenant": "state_grid",
                        },
                        "quInfo": {
                            "userId": self.user_id,
                        },
                        "token": self.user_token,
                    },
                    "params3": {
                        "data": {
                            "acctId": self.user_id,
                            "consNo": power_user["consNo_dst"],
                            "consType": power_user["elecTypeCode"],
                            "orgNo": power_user["orgNo"],
                            "proCode": power_user["proNo"],
                            "provinceCode": power_user["proNo"],
                            "serialNo": "",
                            "srvCode": "",
                            "userName": self.login_account,
                            "funcCode": "WEBALIPAY_01",
                            "channelCode": "0902",
                            "clearCache": "11",
                            "promotCode": "1",
                            "promotType": "1",
                        },
                        "serviceCode": "BCP_000026",
                        "source": "app",
                        "target": power_user["proNo"],
                    },
                    "params4": param4,
                },
                "timestamp": timestamp,
            }
            if year is not None:
                data["_data"]["params3"]["data"]["queryYear"] = year
            if startday is not None and endday is not None:
                data["_data"]["params3"]["data"]["startTime"] = startday
                data["_data"]["params3"]["data"]["endTime"] = endday

            my_crypt = MyCryptSM(self.newKeyCode, self.newPublicKey, self.privkeyhex)
            encrypt_data = my_crypt.sm4_encrypt_cbc_data(data, timestamp)
            base64_skey = my_crypt.sm2_encrypt_keycode(self.newKeyCode)
            params = {"data": encrypt_data, "skey": base64_skey, "timestamp": timestamp}
            url = "https://www.95598.cn/api/osg-web0004/member/c24/f01"

            self.log_if_debug("start call get_bill_list")

            async with self.session.post(
                url=url, headers=headers, data=json.dumps(params), cookies=self.cookies
            ) as response:
                response_text = await response.text()
                if response.status == 200:
                    self.cookies = response.cookies
                    if response_text.startswith("{"):
                        json_data = json.loads(response_text)
                        if "code" in json_data:
                            return {
                                "data": None,
                                "errcode": 502,
                                "errmsg": f"登录失败: code {json_data['code']}",
                            }
                        result = my_crypt.sm4_decrypt_cbc_data(json_data["encryptData"])
                        self.log_if_debug(f"call get_bill_list result: {result}")
                        if result["code"] == 1 or result["code"] == "1":
                            return {
                                "data": result["data"],
                                "errcode": 0,
                                "errmsg": "",
                            }
                        return {
                            "data": None,
                            "errcode": 502,
                            "errmsg": f"返回结果码错误: {result['code']} - {result['message']}",
                        }
                    return {
                        "data": None,
                        "errcode": 502,
                        "errmsg": f"json格式不合法: {response_text}",
                    }
                return {
                    "data": None,
                    "errcode": 502,
                    "errmsg": f"返回状态码错误: {response.status} - {response.reason}",
                }
        except Exception as err:
            import traceback

            LOGGER.error("exception: %s", traceback.format_exc())
            return err

    async def refresh_tokens(self):  # noqa: D102
        res_getkp = await self.get_key_code_and_public_key()

        if res_getkp["errcode"] != 0:
            return res_getkp

        self.log_if_debug(f"refresh keycode: >>> {res_getkp["data"]["keyCode"]}")
        self.log_if_debug(f"refresh publickey: >>> {res_getkp["data"]["publicKey"]}")

        res_authorized = await self.do_authorize(self.user_token)
        if res_authorized["errcode"] != 0:
            return res_authorized

        self.log_if_debug(f"refresh authorized_code: >>> {res_authorized["data"]}")

        for _i in range(3):
            asyncio.sleep(1)
            res_web_token = await self.get_web_token(self.authorize_code)
            if res_web_token["errcode"] == 0:
                self.log_if_debug(f"refresh web_token: >>> {res_web_token["data"]}")
                await self.save_data()
                return {
                    "data": None,
                    "errcode": 0,
                    "errmsg": "",
                }
        return {
            "data": None,
            "errcode": 502,
            "errmsg": "refresh_tokens 刷新token失败",
        }

    async def relogin_and_refresh_tokens(self):  # noqa: D102
        res_refresh = await self.refresh_tokens()
        if res_refresh["errcode"] == 0:
            return res_refresh

        res_getkp = await self.get_key_code_and_public_key()
        if res_getkp["errcode"] != 0:
            return res_getkp
        self.log_if_debug(f"refresh keycode: >>> {res_getkp["data"]["keyCode"]}")
        self.log_if_debug(f"refresh publickey: >>> {res_getkp["data"]["publicKey"]}")

        res_login = await self.password_login_request(self.login_account, self.password)
        if res_login["errcode"] != 0:
            return res_login

        # 识别图片验证码登录
        slide_path = self.hass.config.path(STORAGE_DIR, ".slide.dat")
        async with aiofiles.open(slide_path, mode="w", encoding="utf-8") as f:
            await f.write(json.dumps(res_login["data"]))
        asyncio.sleep(2)
        script_path = self.hass.config.path(
            "custom_components/sgcc_pro", "get_slide_code.py"
        )
        ret, verify_code, std_err = await getstatusoutput(
            f"python3 {script_path} {slide_path}"
        )
        if std_err != "":
            return {"errcode": 502, "errmsg": std_err, "data": None}

        self.log_if_debug(f"run get_slide_code.py success: >>> verify_code is {ret}")

        res_token = await self.password_login(
            self.login_account, self.password, verify_code, self.verify_code_key
        )
        if res_token["errcode"] != 0:
            return res_token
        asyncio.sleep(2)

        # 验证登录
        res_authorized = await self.do_authorize(self.user_token)
        if res_authorized["errcode"] != 0:
            return res_authorized
        asyncio.sleep(2)

        for _i in range(3):
            asyncio.sleep(2)
            res_web_token = await self.get_web_token(self.authorize_code)
            if res_web_token["errcode"] == 0:
                self.log_if_debug(f"refresh web_token: >>> {res_web_token["data"]}")
                await self.save_data()
                return {
                    "data": None,
                    "errcode": 0,
                    "errmsg": "",
                }
        return {
            "data": None,
            "errcode": 502,
            "errmsg": "relogin_and_refresh_tokens 刷新token失败",
        }


if __name__ == "__main__":
    import logging
    import sys

    LOGGER.addHandler(logging.StreamHandler(sys.stderr))
    LOGGER.setLevel(logging.DEBUG)

    sgcc_pro = SgccProDataClient()
