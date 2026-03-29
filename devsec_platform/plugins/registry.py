from __future__ import annotations

from devsec_platform.plugins.base import SecurityPlugin
from devsec_platform.plugins.builtin import builtin_plugins


class PluginRegistry:
    def __init__(self) -> None:
        self._plugins: dict[str, SecurityPlugin] = builtin_plugins()

    def register(self, plugin: SecurityPlugin) -> None:
        self._plugins[plugin.plugin_type] = plugin

    def get(self, plugin_type: str) -> SecurityPlugin | None:
        return self._plugins.get(plugin_type)

    def list_plugins(self) -> list[str]:
        return sorted(self._plugins.keys())
