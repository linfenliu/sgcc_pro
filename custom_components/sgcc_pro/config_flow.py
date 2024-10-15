import asyncio
import hashlib
import json
from typing import Any

import aiofiles
import voluptuous as vol

from homeassistant import config_entries
from homeassistant.const import CONF_PASSWORD, CONF_USERNAME
from homeassistant.core import HomeAssistant, callback
from homeassistant.data_entry_flow import FlowResult
import homeassistant.helpers.config_validation as cv
from homeassistant.helpers.selector import selector
from homeassistant.helpers.storage import STORAGE_DIR

from .const import CONF_SW, DOMAIN, VERSION
from .data_client import SgccProDataClient
from .utils.func import getstatusoutput


async def login_and_access_token(
    hass: HomeAssistant, data_client: SgccProDataClient, data: dict[str, Any], pin: str
) -> dict[str, Any]:
    try:
        # 获取新的keyCode和ppublicKey.
        res_getkp = await data_client.get_key_code_and_public_key()
        if res_getkp["errcode"] != 0:
            return res_getkp

        # md5密码
        password = hashlib.md5(pin.encode()).hexdigest()

        # 登录请求，获取图片验证码
        res_login = await data_client.password_login_request(
            data[CONF_USERNAME], password
        )
        if res_login["errcode"] != 0:
            return res_login

        # 识别图片验证码登录
        slide_path = hass.config.path(STORAGE_DIR, ".slide.dat")
        async with aiofiles.open(slide_path, mode="w", encoding="utf-8") as f:
            await f.write(json.dumps(res_login["data"]))
        asyncio.sleep(2)
        script_path = hass.config.path(
            "custom_components/sgcc_pro", "get_slide_code.py"
        )
        ret, verify_code, std_err = await getstatusoutput(
            f"python3 {script_path} {slide_path}"
        )
        if std_err != "":
            return {"errcode": 502, "errmsg": std_err, "data": None}

        # 密码登录
        res_token = await data_client.password_login(
            data[CONF_USERNAME], password, verify_code, data_client.verify_code_key
        )
        if res_token["errcode"] != 0:
            return res_token
        asyncio.sleep(2)

        # 验证登录
        res_authorized = await data_client.do_authorize(res_token["data"])
        if res_authorized["errcode"] != 0:
            return res_authorized
        asyncio.sleep(2)

        # 获取web token
        res_web_token = await data_client.get_web_token(res_authorized["data"])
        if res_web_token["errcode"] != 0:
            return res_web_token
        asyncio.sleep(2)

        # 获取电量用户列表
        res_powerlist = await data_client.get_power_user_list()
        if res_powerlist["errcode"] != 0:
            return res_powerlist

        # 保存数据到.storage
        await data_client.save_data()

    except Exception as err:
        return {"data": None, "errcode": 502, "errmsg": str(err.args)}

    return {"data": None, "errcode": 0, "errmsg": ""}


class SgccProConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    VERSION = 1

    def __init__(self):
        self._data = None
        self._data_client = None

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        self._data_client = SgccProDataClient(hass=self.hass)
        if user_input is not None:
            await self.async_set_unique_id(f"{user_input[CONF_USERNAME]}")
            self._abort_if_unique_id_configured()

            self._data = user_input

            return await self.async_step_pin()

        data_schema = vol.Schema({vol.Required(CONF_USERNAME): str})
        return self.async_show_form(step_id="user", data_schema=data_schema)

    async def async_step_pin(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        errors: dict[str, str] = {}
        if user_input is not None:
            pin = user_input[CONF_PASSWORD]
            await self.async_set_unique_id(f"{self._data[CONF_USERNAME]}")

            result = await login_and_access_token(
                self.hass, self._data_client, self._data, pin
            )

            if result["errcode"] == 0:
                self._data[CONF_SW] = VERSION
                return self.async_create_entry(
                    title=f"{self._data[CONF_USERNAME]}", data=self._data
                )

            errors["base"] = result["errmsg"]

        data_schema = vol.Schema({vol.Required(CONF_PASSWORD): str})
        return self.async_show_form(
            step_id="pin", data_schema=data_schema, errors=errors
        )

    @staticmethod
    @callback
    def async_get_options_flow(entry: config_entries.ConfigEntry):
        return OptionsFlowHandler(entry)


class OptionsFlowHandler(config_entries.OptionsFlow):
    def __init__(self, config_entry: config_entries.ConfigEntry):
        self.config_entry = config_entry

    async def async_step_init(self, user_input=None):
        self._data_client: SgccProDataClient = self.hass.data[DOMAIN][self.handler]

        return await self.async_step_debug()

    async def async_step_debug(self, user_input=None):
        if user_input is None:
            user_input = {}
        else:
            self._data_client.refresh_interval = int(user_input["refresh_interval"])
            self._data_client.is_persistent_notify = user_input["is_persistent_notify"]
            self._data_client.is_debug = user_input["is_debug"]
            self._data_client.push_notify_device = user_input["push_notify_device"]

            self._data_client.save_data()

            return self.async_create_entry(title="国家电网", data={})

        push_regs = []
        mobile_app = self.hass.data.get("mobile_app")
        if mobile_app is not None:
            push_regs = list(mobile_app["notify"].registered_targets.keys())

        data_schema = vol.Schema(
            {
                vol.Required(
                    "refresh_interval", default=str(self._data_client.refresh_interval)
                ): selector(
                    {
                        "select": {
                            "options": [
                                {"label": "每1小时", "value": "1"},
                                {"label": "每2小时", "value": "2"},
                                {"label": "每3小时", "value": "3"},
                                {"label": "每4小时", "value": "4"},
                                {"label": "每5小时", "value": "5"},
                                {"label": "每6小时", "value": "6"},
                                {"label": "每7小时", "value": "7"},
                                {"label": "每8小时", "value": "8"},
                                {"label": "每9小时", "value": "9"},
                                {"label": "每10小时", "value": "10"},
                                {"label": "每11小时", "value": "11"},
                                {"label": "每12小时", "value": "12"},
                                {"label": "每16小时", "value": "16"},
                                {"label": "每20小时", "value": "20"},
                                {"label": "每24小时", "value": "24"},
                            ]
                        }
                    }
                ),
                vol.Required(
                    "is_persistent_notify",
                    default=self._data_client.is_persistent_notify,
                ): selector({"boolean": {}}),
                vol.Required("is_debug", default=self._data_client.is_debug): selector(
                    {"boolean": {}}
                ),
            }
        )
        if len(push_regs) > 0:
            data_schema = data_schema.extend(
                {
                    vol.Required(
                        "push_notify_device",
                        default=self._data_client.push_notify_device,
                    ): cv.multi_select(push_regs),
                }
            )

        return self.async_show_form(step_id="debug", data_schema=data_schema)
