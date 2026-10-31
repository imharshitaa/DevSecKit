from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from devsec_platform.schemas import AuditEvent, utcnow_iso


class AuditLogger:
    def __init__(self, log_file: str | None = None) -> None:
        if log_file:
            self.log_file = Path(log_file)
        else:
            date_part = datetime.now(timezone.utc).strftime("%Y%m%d")
            self.log_file = Path(f"reports/audit/devsec_platform_audit_{date_part}.log")
        self.log_file.parent.mkdir(parents=True, exist_ok=True)

    def write(self, event: AuditEvent) -> None:
        ts = utcnow_iso()
        line = f"{ts} actor={event.actor} action={event.action} resource={event.resource} status={event.status} msg={event.message}\n"
        with self.log_file.open("a", encoding="utf-8") as fh:
            fh.write(line)
