"""Let the tests import the integration without a full Home Assistant install.

Two obstacles: ``custom_components.audiconnect.__init__`` pulls in Home
Assistant's helpers on import, and ``const`` needs ``homeassistant.const``.
Neither has anything to do with the authentication code under test, so the
package is registered without executing its ``__init__``, and a minimal
``homeassistant.const`` is supplied only when the real one is absent. If Home
Assistant is installed, the real module is used untouched.
"""

from __future__ import annotations

import enum
import importlib.util
import pathlib
import sys
import types

ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def _ensure_homeassistant_const() -> None:
    if importlib.util.find_spec("homeassistant") is not None:
        return

    ha = sys.modules.setdefault("homeassistant", types.ModuleType("homeassistant"))
    ha.__path__ = []  # mark as a package so submodule imports resolve

    const = types.ModuleType("homeassistant.const")
    const.CONF_USERNAME = "username"
    const.CONF_PASSWORD = "password"

    # Home Assistant's full Platform enum, so const.py loads whichever
    # platforms the integration grows.
    Platform = enum.StrEnum(
        "Platform",
        {
            name.upper(): name
            for name in (
                "air_quality", "alarm_control_panel", "binary_sensor", "button",
                "calendar", "camera", "climate", "cover", "date", "datetime",
                "device_tracker", "event", "fan", "geo_location", "humidifier",
                "image", "lawn_mower", "light", "lock", "media_player", "notify",
                "number", "remote", "scene", "select", "sensor", "siren", "stt",
                "switch", "text", "time", "todo", "tts", "update", "vacuum",
                "valve", "wake_word", "water_heater", "weather",
            )
        },
    )

    const.Platform = Platform
    sys.modules["homeassistant.const"] = const
    ha.const = const


def _register_package_without_init() -> None:
    """Make ``custom_components.audiconnect`` importable, __init__ unread."""
    parent = sys.modules.get("custom_components")
    if parent is None:
        parent = types.ModuleType("custom_components")
        parent.__path__ = [str(ROOT / "custom_components")]
        sys.modules["custom_components"] = parent

    if "custom_components.audiconnect" in sys.modules:
        return
    package = types.ModuleType("custom_components.audiconnect")
    package.__path__ = [str(ROOT / "custom_components" / "audiconnect")]
    sys.modules["custom_components.audiconnect"] = package
    parent.audiconnect = package


_ensure_homeassistant_const()
_register_package_without_init()
