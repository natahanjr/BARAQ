"""Host software inventory (read-only, no admin required).

Windows: enumerates the installed-products registry keys. Non-Windows
hosts return an empty product list so the collector simply stays silent.
"""

from __future__ import annotations

import logging
import platform

logger = logging.getLogger("baraq.vulnscan.inventory")

_UNINSTALL_KEYS = (
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
    r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
)

_VALUE_NAMES = ("DisplayName", "DisplayVersion", "Publisher")


def _product_from_key(key) -> dict | None:
    try:
        values = {}
        for name in _VALUE_NAMES:
            try:
                value, _ = __import__("winreg").QueryValueEx(key, name)
                values[name] = str(value).strip()
            except OSError:
                values[name] = ""
        if values["DisplayName"] and values["DisplayVersion"]:
            return {
                "name": values["DisplayName"],
                "version": values["DisplayVersion"],
                "publisher": values["Publisher"],
            }
    except OSError:
        pass
    return None


def _windows_products() -> list[dict]:
    import winreg

    products: list[dict] = []
    for subkey_path in _UNINSTALL_KEYS:
        try:
            base = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, subkey_path)
        except OSError:
            continue
        try:
            index = 0
            while True:
                try:
                    name = winreg.EnumKey(base, index)
                except OSError:
                    break
                index += 1
                try:
                    with winreg.OpenKey(base, name) as key:
                        product = _product_from_key(key)
                        if product:
                            products.append(product)
                except OSError:
                    continue
        finally:
            base.Close()
    return products


def host_inventory() -> dict:
    """Full host inventory: OS identity + installed products."""
    inventory = {
        "os": platform.platform(),
        "os_version": platform.version(),
        "os_release": platform.release(),
        "products": [],
    }
    if platform.system() == "Windows":
        try:
            inventory["products"] = _windows_products()
        except Exception as exc:
            logger.warning("Software inventory failed: %s", exc)
    else:
        inventory["products"] = []
    return inventory
