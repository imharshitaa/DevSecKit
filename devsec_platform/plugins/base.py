from __future__ import annotations

from abc import ABC, abstractmethod

from devsec_platform.schemas import Finding, ScanRequest


class SecurityPlugin(ABC):
    plugin_type: str
    tool_name: str

    @abstractmethod
    def run(self, request: ScanRequest) -> list[Finding]:
        raise NotImplementedError
