from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_USERNAME, Platform
from homeassistant.core import HomeAssistant

from .const import CONF_FILE_PREFIX, DOMAIN
from .data_client import SgccProDataClient
from .utils.store import async_load_from_store

PLATFORMS: list[Platform] = [Platform.SENSOR]


async def async_setup_entry(hass: HomeAssistant, config_entry: ConfigEntry) -> bool:
    """Set up this integration using UI."""
    hass.data.setdefault(DOMAIN, {})
    config = (
        await async_load_from_store(
            hass, f"{CONF_FILE_PREFIX}-{config_entry.data[CONF_USERNAME]}"
        )
        or None
    )
    hass.data[DOMAIN][config_entry.entry_id] = SgccProDataClient(
        hass=hass, config=config
    )

    await hass.config_entries.async_forward_entry_setups(config_entry, PLATFORMS)
    return True


async def async_unload_entry(hass: HomeAssistant, config_entry: ConfigEntry) -> bool:
    """Unload a config entry."""
    if unload_ok := await hass.config_entries.async_unload_platforms(
        config_entry, PLATFORMS
    ):
        hass.data[DOMAIN].pop(config_entry.entry_id)
    return unload_ok
