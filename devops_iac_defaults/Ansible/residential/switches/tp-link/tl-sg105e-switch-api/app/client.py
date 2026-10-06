from __future__ import annotations

from dataclasses import asdict, is_dataclass
from typing import Any

import requests
from tplink_tool import Switch, make_switch

from .config import settings


def _serialize(obj: Any) -> Any:
    if is_dataclass(obj) and not isinstance(obj, type):
        return {k: _serialize(v) for k, v in asdict(obj).items()}
    if isinstance(obj, list):
        return [_serialize(v) for v in obj]
    if isinstance(obj, tuple):
        return [_serialize(v) for v in obj]
    if isinstance(obj, dict):
        return {k: _serialize(v) for k, v in obj.items()}
    if hasattr(obj, "name"):  # Enum
        return obj.name
    return obj


class TpLinkSwitchClient:
    """TP-Link Easy Smart switch client (TL-SG105E / TL-SG108E)."""

    def __init__(self) -> None:
        self._switch = None
        self._logged_in = False

    def _connect(self) -> None:
        if self._switch is not None and self._logged_in:
            return
        if not settings.switch_password:
            raise RuntimeError(
                "Switch password not configured. Set SWITCH_PASSWORD in .env"
            )
        self._switch = make_switch(
            settings.switch_host,
            username=settings.switch_username,
            password=settings.switch_password,
            model=settings.switch_model,
        )
        self._logged_in = True

    def is_reachable(self) -> bool:
        try:
            r = requests.get(
                f"http://{settings.switch_host}/",
                timeout=5,
            )
            return r.status_code == 200 and "TP-Link" in r.text
        except requests.RequestException:
            return False

    def ensure_logged_in(self) -> None:
        self._connect()

    def logout(self) -> None:
        if self._switch is not None and self._logged_in:
            try:
                self._switch.logout()
            except Exception:
                pass
        self._switch = None
        self._logged_in = False

    def system_info(self) -> dict[str, Any]:
        self._connect()
        return _serialize(self._switch.get_system_info())

    def port_settings(self) -> list[dict[str, Any]]:
        self._connect()
        return _serialize(self._switch.get_port_settings())

    def port_statistics(self) -> list[dict[str, Any]]:
        self._connect()
        return _serialize(self._switch.get_port_statistics())

    def dot1q_vlans(self) -> dict[str, Any]:
        self._connect()
        enabled, vlans = self._switch.get_dot1q_vlans()
        payload = {"enabled": enabled, "vlans": _serialize(vlans)}
        return _serialize(payload)

    def port_vlan(self) -> dict[str, Any]:
        self._connect()
        enabled, entries = self._switch.get_port_vlan()
        payload = {"enabled": enabled, "entries": _serialize(entries)}
        return _serialize(payload)

    def port_mirror(self) -> dict[str, Any]:
        self._connect()
        return _serialize(self._switch.get_port_mirror())

    def igmp_snooping(self) -> dict[str, Any]:
        self._connect()
        return _serialize(self._switch.get_igmp_snooping())

    def qos_settings(self) -> dict[str, Any]:
        self._connect()
        mode, ports = self._switch.get_qos_settings()
        payload = {"mode": mode, "ports": _serialize(ports)}
        return _serialize(payload)

    def rpc(self, method: str, params: dict[str, Any], *, confirm: bool) -> Any:
        """
        Low-level method invocation for tplink-tool write operations.

        Safety:
        - Only allows known tplink_tool methods.
        - Destructive methods require `confirm=true`.
        """
        if not isinstance(params, dict):
            raise ValueError("params must be an object")

        method_name = method.strip()
        if not method_name:
            raise ValueError("method is required")

        # Safe-ish prefix gate:
        # - Read-only: get_* (and we also accept run_* like diagnostics)
        # - Mutations: set_/add_/delete_/change_/reset_/restore_/backup_/save_...
        allowed_prefixes = (
            "get_",
            "list_",
            "set_",
            "add_",
            "delete_",
            "change_",
            "reset_",
            "restore_",
            "backup_",
            "run_",
            "save_",
            "factory_reset",
            "reboot",
            "logout",
        )

        dangerous = {
            "factory_reset",
            "reboot",
            "change_password",
            "restore_config",
            "save_config",
            "backup_config",
            "reset_port_statistics",
            "logout_others",
        }

        if not hasattr(self._switch, method_name):
            raise ValueError(f"Unknown switch method: {method_name}")

        if not any(method_name == d for d in dangerous) and not method_name.startswith(allowed_prefixes):
            if not any(method_name.startswith(p) for p in allowed_prefixes):
                raise ValueError(f"Method not allowed: {method_name}")

        if method_name in dangerous and not confirm:
            raise RuntimeError(f"Method {method_name} requires confirm=true")

        self._connect()
        fn = getattr(self._switch, method_name)
        out = fn(**params) if params else fn()
        return _serialize(out)
