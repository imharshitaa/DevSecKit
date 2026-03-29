from __future__ import annotations

from datetime import datetime
from pathlib import Path

from devsec_platform.schemas import AuditEvent


class AuditLogger:
    def __init__(self, log_file: str | None = None) -> None:
        if log_file:
            self.log_file = Path(log_file)
        else:
            date_part = datetime.utcnow().strftime("%Y%m%d")
            self.log_file = Path(f"reports/audit/devsec_platform_audit_{date_part}.log")
        self.log_file.parent.mkdir(parents=True, exist_ok=True)

    def write(self, event: AuditEvent) -> None:
        ts = datetime.utcnow().isoformat() + "Z"
        line = f"{ts} actor={event.actor} action={event.action} resource={event.resource} status={event.status} msg={event.message}\n"
        self.log_file.open("a", encoding="utf-8").write(line)
