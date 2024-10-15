import datetime

from homeassistant.components.sensor import (
    DOMAIN as SENSOR_DOMAIN,
    SensorDeviceClass,
    SensorEntity,
    SensorStateClass,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import UnitOfEnergy
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN, VERSION
from .coordinator import SgccProCoordinator
from .data_client import SgccProDataClient

UNIT_YUAN = "元"

ENTITY_ID_SENSOR_FORMAT = SENSOR_DOMAIN + ".sgcc_pro_"


SENSOR_TYPES = [
    {
        "key": "balance",
        "name": "账户余额",
        "native_unit_of_measurement": UNIT_YUAN,
        "device_class": SensorDeviceClass.MONETARY,
        "state_class": SensorStateClass.TOTAL,
    },
    {
        "key": "year_ele_num",
        "name": "今年累计用电",
        "native_unit_of_measurement": UnitOfEnergy.KILO_WATT_HOUR,
        "device_class": SensorDeviceClass.ENERGY,
        "state_class": SensorStateClass.TOTAL,
    },
    {
        "key": "year_ele_cost",
        "name": "今度累计电费",
        "native_unit_of_measurement": UNIT_YUAN,
        "device_class": SensorDeviceClass.MONETARY,
        "state_class": SensorStateClass.TOTAL,
    },
    {
        "key": "last_year_ele_num",
        "name": "去年累计用电",
        "native_unit_of_measurement": UnitOfEnergy.KILO_WATT_HOUR,
        "device_class": SensorDeviceClass.ENERGY,
        "state_class": SensorStateClass.TOTAL,
    },
    {
        "key": "last_year_ele_cost",
        "name": "去年累计电费",
        "native_unit_of_measurement": UNIT_YUAN,
        "device_class": SensorDeviceClass.MONETARY,
        "state_class": SensorStateClass.TOTAL,
    },
    {
        "key": "last_month_meter_num",
        "name": "上月抄表用电",
        "native_unit_of_measurement": UnitOfEnergy.KILO_WATT_HOUR,
        "device_class": SensorDeviceClass.ENERGY,
        "state_class": SensorStateClass.TOTAL,
    },
    {
        "key": "last_month_meter_cost",
        "name": "上月抄表电费",
        "native_unit_of_measurement": UNIT_YUAN,
        "device_class": SensorDeviceClass.MONETARY,
        "state_class": SensorStateClass.TOTAL,
    },
    {
        "key": "month_ele_num",
        "name": "当月累计用电",
        "native_unit_of_measurement": UnitOfEnergy.KILO_WATT_HOUR,
        "device_class": SensorDeviceClass.ENERGY,
        "state_class": SensorStateClass.TOTAL,
    },
    {
        "key": "month_p_ele_num",
        "name": "当月累计峰用电",
        "native_unit_of_measurement": UnitOfEnergy.KILO_WATT_HOUR,
        "device_class": SensorDeviceClass.ENERGY,
        "state_class": SensorStateClass.TOTAL,
    },
    {
        "key": "month_v_ele_num",
        "name": "当月累计谷用电",
        "native_unit_of_measurement": UnitOfEnergy.KILO_WATT_HOUR,
        "device_class": SensorDeviceClass.ENERGY,
        "state_class": SensorStateClass.TOTAL,
    },
    {
        "key": "month_n_ele_num",
        "name": "当月累计平用电",
        "native_unit_of_measurement": UnitOfEnergy.KILO_WATT_HOUR,
        "device_class": SensorDeviceClass.ENERGY,
        "state_class": SensorStateClass.TOTAL,
    },
    {
        "key": "month_t_ele_num",
        "name": "当月累计尖用电",
        "native_unit_of_measurement": UnitOfEnergy.KILO_WATT_HOUR,
        "device_class": SensorDeviceClass.ENERGY,
        "state_class": SensorStateClass.TOTAL,
    },
    {
        "key": "last_month_ele_num",
        "name": "上月累计用电",
        "native_unit_of_measurement": UnitOfEnergy.KILO_WATT_HOUR,
        "device_class": SensorDeviceClass.ENERGY,
        "state_class": SensorStateClass.TOTAL,
    },
    {
        "key": "last_month_p_ele_num",
        "name": "上月累计峰用电",
        "native_unit_of_measurement": UnitOfEnergy.KILO_WATT_HOUR,
        "device_class": SensorDeviceClass.ENERGY,
        "state_class": SensorStateClass.TOTAL,
    },
    {
        "key": "last_month_v_ele_num",
        "name": "上月累计谷用电",
        "native_unit_of_measurement": UnitOfEnergy.KILO_WATT_HOUR,
        "device_class": SensorDeviceClass.ENERGY,
        "state_class": SensorStateClass.TOTAL,
    },
    {
        "key": "last_month_n_ele_num",
        "name": "上月累计平用电",
        "native_unit_of_measurement": UnitOfEnergy.KILO_WATT_HOUR,
        "device_class": SensorDeviceClass.ENERGY,
        "state_class": SensorStateClass.TOTAL,
    },
    {
        "key": "last_month_t_ele_num",
        "name": "上月累计尖用电",
        "native_unit_of_measurement": UnitOfEnergy.KILO_WATT_HOUR,
        "device_class": SensorDeviceClass.ENERGY,
        "state_class": SensorStateClass.TOTAL,
    },
    {"key": "refresh_time", "name": "最近刷新时间"},
]
# SENSOR_TYPES = [
#     {
#         "key": "balance",
#         "name": "账户余额",
#         "native_unit_of_measurement": UNIT_YUAN,
#         "device_class": SensorDeviceClass.MONETARY,
#         "state_class": SensorStateClass.TOTAL,
#     },
#     {
#         "key": "year_ele_num",
#         "name": "年度累计用电",
#         "native_unit_of_measurement": UnitOfEnergy.KILO_WATT_HOUR,
#         "device_class": SensorDeviceClass.ENERGY,
#         "state_class": SensorStateClass.TOTAL,
#     },
#     {
#         "key": "year_p_ele_num",
#         "name": "年度累计峰用电",
#         "native_unit_of_measurement": UnitOfEnergy.KILO_WATT_HOUR,
#         "device_class": SensorDeviceClass.ENERGY,
#         "state_class": SensorStateClass.TOTAL,
#     },
#     {
#         "key": "year_v_ele_num",
#         "name": "年度累计谷用电",
#         "native_unit_of_measurement": UnitOfEnergy.KILO_WATT_HOUR,
#         "device_class": SensorDeviceClass.ENERGY,
#         "state_class": SensorStateClass.TOTAL,
#     },
#     {
#         "key": "year_n_ele_num",
#         "name": "年度累计平用电",
#         "native_unit_of_measurement": UnitOfEnergy.KILO_WATT_HOUR,
#         "device_class": SensorDeviceClass.ENERGY,
#         "state_class": SensorStateClass.TOTAL,
#     },
#     {
#         "key": "year_t_ele_num",
#         "name": "年度累计尖用电",
#         "native_unit_of_measurement": UnitOfEnergy.KILO_WATT_HOUR,
#         "device_class": SensorDeviceClass.ENERGY,
#         "state_class": SensorStateClass.TOTAL,
#     },
#     {
#         "key": "year_ele_cost",
#         "name": "年度累计电费",
#         "native_unit_of_measurement": UNIT_YUAN,
#         "device_class": SensorDeviceClass.MONETARY,
#         "state_class": SensorStateClass.TOTAL,
#     },
#     {
#         "key": "last_month_ele_num",
#         "name": "上个月用电",
#         "native_unit_of_measurement": UnitOfEnergy.KILO_WATT_HOUR,
#         "device_class": SensorDeviceClass.ENERGY,
#         "state_class": SensorStateClass.TOTAL,
#     },
#     {
#         "key": "last_month_ele_cost",
#         "name": "上个月电费",
#         "native_unit_of_measurement": UNIT_YUAN,
#         "device_class": SensorDeviceClass.MONETARY,
#         "state_class": SensorStateClass.TOTAL,
#     },
#     {"key": "last_month_meter_num", "name": "上个月抄表"},
#     {
#         "key": "month_ele_num",
#         "name": "当月累计用电",
#         "native_unit_of_measurement": UnitOfEnergy.KILO_WATT_HOUR,
#         "device_class": SensorDeviceClass.ENERGY,
#         "state_class": SensorStateClass.TOTAL,
#     },
#     {
#         "key": "month_p_ele_num",
#         "name": "当月累计峰用电",
#         "native_unit_of_measurement": UnitOfEnergy.KILO_WATT_HOUR,
#         "device_class": SensorDeviceClass.ENERGY,
#         "state_class": SensorStateClass.TOTAL,
#     },
#     {
#         "key": "month_v_ele_num",
#         "name": "当月累计谷用电",
#         "native_unit_of_measurement": UnitOfEnergy.KILO_WATT_HOUR,
#         "device_class": SensorDeviceClass.ENERGY,
#         "state_class": SensorStateClass.TOTAL,
#     },
#     {
#         "key": "month_n_ele_num",
#         "name": "当月累计平用电",
#         "native_unit_of_measurement": UnitOfEnergy.KILO_WATT_HOUR,
#         "device_class": SensorDeviceClass.ENERGY,
#         "state_class": SensorStateClass.TOTAL,
#     },
#     {
#         "key": "month_t_ele_num",
#         "name": "当月累计尖用电",
#         "native_unit_of_measurement": UnitOfEnergy.KILO_WATT_HOUR,
#         "device_class": SensorDeviceClass.ENERGY,
#         "state_class": SensorStateClass.TOTAL,
#     },
#     {
#         "key": "daily_ele_num",
#         "name": "日总用电",
#         "native_unit_of_measurement": UnitOfEnergy.KILO_WATT_HOUR,
#         "device_class": SensorDeviceClass.ENERGY,
#         "state_class": SensorStateClass.TOTAL,
#     },
#     {
#         "key": "daily_p_ele_num",
#         "name": "日峰用电",
#         "native_unit_of_measurement": UnitOfEnergy.KILO_WATT_HOUR,
#         "device_class": SensorDeviceClass.ENERGY,
#         "state_class": SensorStateClass.TOTAL,
#     },
#     {
#         "key": "daily_v_ele_num",
#         "name": "日谷用电",
#         "native_unit_of_measurement": UnitOfEnergy.KILO_WATT_HOUR,
#         "device_class": SensorDeviceClass.ENERGY,
#         "state_class": SensorStateClass.TOTAL,
#     },
#     {
#         "key": "daily_n_ele_num",
#         "name": "日平用电",
#         "native_unit_of_measurement": UnitOfEnergy.KILO_WATT_HOUR,
#         "device_class": SensorDeviceClass.ENERGY,
#         "state_class": SensorStateClass.TOTAL,
#     },
#     {
#         "key": "daily_t_ele_num",
#         "name": "日尖用电",
#         "native_unit_of_measurement": UnitOfEnergy.KILO_WATT_HOUR,
#         "device_class": SensorDeviceClass.ENERGY,
#         "state_class": SensorStateClass.TOTAL,
#     },
#     {"key": "refresh_time", "name": "最近刷新时间"},
# ]

SENSOR_TYPES_FOR_LADDER = [
    {"key": "ladder_level", "name": "当前阶梯"},
]


async def async_setup_entry(
    hass: HomeAssistant, entry: ConfigEntry, async_add_entities: AddEntitiesCallback
) -> None:
    data_client: SgccProDataClient = hass.data[DOMAIN][entry.entry_id]
    coordinator = SgccProCoordinator(hass, data_client)
    data_client.coordinator = coordinator
    await coordinator.async_config_entry_first_refresh()

    for door_account in data_client.power_user_list:
        async_add_entities(
            [
                SgccProSensor(door_account, sensor_type, entry.entry_id, coordinator)
                for sensor_type in SENSOR_TYPES
            ],
            update_before_add=True,
        )


class SgccProSensor(CoordinatorEntity[SgccProCoordinator], SensorEntity):
    _attr_has_entity_name = True

    def __init__(
        self,
        door_account,
        sensor_type,
        entry_id: str,
        coordinator: SgccProCoordinator,
    ) -> None:
        super().__init__(coordinator)
        self.door_account = door_account
        self.sensor_type = sensor_type
        self.entity_id = (
            SENSOR_DOMAIN
            + ".state_grid"
            + "_"
            + door_account["consNo_dst"]
            + "_"
            + sensor_type["key"]
        )
        self._attr_name = sensor_type["name"]
        self._attr_unique_id = (
            entry_id + "-" + door_account["consNo_dst"] + "-" + sensor_type["key"]
        )

        if "device_class" in sensor_type:
            self._attr_device_class = sensor_type["device_class"]

        if "state_class" in sensor_type:
            self._attr_state_class = sensor_type["state_class"]

        if "native_unit_of_measurement" in sensor_type:
            self._attr_native_unit_of_measurement = sensor_type[
                "native_unit_of_measurement"
            ]

        self._attr_extra_state_attributes = {}

        self._attr_device_info = {
            "name": door_account["elecAddr_dst"],
            "identifiers": {(DOMAIN, door_account["consNo_dst"])},
            "sw_version": VERSION,
            "manufacturer": "HassBox",
            "model": "户号："
            + door_account["consName_dst"]
            + " - "
            + door_account["consNo_dst"],
        }

    def _handle_coordinator_update(self) -> None:
        cd_data = self.coordinator.data
        if cd_data is None:
            return

        da_data = cd_data[self.door_account["consNo_dst"]]
        if da_data is None:
            return

        if self.sensor_type["key"] not in da_data:
            return

        val_data = da_data[self.sensor_type["key"]]
        if val_data is None:
            return

        sensor_key = self.sensor_type["key"]
        if sensor_key in ("year_ele_num", "last_year_ele_num"):
            self._attr_native_value = val_data[0]
            for mothEle in val_data[1]:
                self._attr_extra_state_attributes[mothEle["month"]] = mothEle[
                    "monthEleNum"
                ]
        elif sensor_key in ("year_ele_cost", "last_year_ele_cost"):
            self._attr_native_value = val_data[0]
            for mothEle in val_data[1]:
                self._attr_extra_state_attributes[mothEle["month"]] = mothEle[
                    "monthEleCost"
                ]
        elif sensor_key in (
            "month_ele_num",
            "month_v_ele_num",
            "month_t_ele_num",
            "month_n_ele_num",
            "month_p_ele_num",
            "last_month_ele_num",
            "last_month_v_ele_num",
            "last_month_t_ele_num",
            "last_month_n_ele_num",
            "last_month_p_ele_num",
        ):
            self._attr_native_value = val_data[0]
            for dayEle in val_data[1]:
                self._attr_extra_state_attributes[dayEle["day"]] = dayEle["val"]
        else:
            self._attr_native_value = val_data

        self.async_write_ha_state()
