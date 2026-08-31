"""Fleet management — multi-profile configuration management."""
import json
import logging
from typing import Optional
from pydantic import BaseModel

logger = logging.getLogger("baraq.fleet.config")


class ConfigProfile(BaseModel):
    name: str
    description: str = ""
    settings: dict = {}
    hosts: list[str] = []


DEFAULT_SETTINGS = {
    "telemetry_interval_seconds": 30,
    "enabled_collectors": ["event_log", "sysmon", "powershell", "network"],
    "detection_enabled": True,
    "ml_scoring_enabled": True,
    "log_level": "INFO",
    "heartbeat_interval_seconds": 60,
}


class ConfigProfileManager:
    def __init__(self):
        self._profiles: dict[str, ConfigProfile] = {
            "default": ConfigProfile(name="default", description="Default agent config", settings=DEFAULT_SETTINGS),
        }

    def create_profile(self, name: str, settings: dict, description: str = "") -> ConfigProfile:
        profile = ConfigProfile(name=name, description=description, settings=settings)
        self._profiles[name] = profile
        logger.info("Config profile created: %s", name)
        return profile

    def get_profile(self, name: str) -> Optional[ConfigProfile]:
        return self._profiles.get(name)

    def list_profiles(self) -> list[ConfigProfile]:
        return list(self._profiles.values())

    def assign_host(self, profile_name: str, host_id: str) -> bool:
        profile = self._profiles.get(profile_name)
        if not profile:
            return False
        if host_id not in profile.hosts:
            profile.hosts.append(host_id)
        return True

    def get_host_profile(self, host_id: str) -> Optional[ConfigProfile]:
        for profile in self._profiles.values():
            if host_id in profile.hosts:
                return profile
        return self._profiles.get("default")

    def update_profile(self, name: str, settings: dict) -> Optional[ConfigProfile]:
        profile = self._profiles.get(name)
        if not profile:
            return None
        profile.settings.update(settings)
        return profile

    def delete_profile(self, name: str) -> bool:
        if name == "default":
            return False
        return self._profiles.pop(name, None) is not None
