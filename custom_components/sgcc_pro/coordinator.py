from __future__ import annotations

from datetime import timedelta

from homeassistant.core import HomeAssistant
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator

from homeassistant.config_entries import ConfigEntry

from .const import DOMAIN
from .data_client import SgccProDataClient
from .utils.logger import LOGGER


class SgccProCoordinator(DataUpdateCoordinator):
    def __init__(
        self,
        hass: HomeAssistant,
        data_client: SgccProDataClient,
    ) -> None:
        self.data_client = data_client
        super().__init__(
            hass, LOGGER, name=DOMAIN, update_interval=timedelta(seconds=120)
        )

        self.first_setup = True

    async def _async_update_data(self):
        data = await self.data_client.refresh_data(setup=self.first_setup)
        self.first_setup = False
        return data
