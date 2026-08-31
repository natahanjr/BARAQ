"""Fleet management — remote log fetch command."""
import logging
from typing import Optional
from pydantic import BaseModel

logger = logging.getLogger("baraq.fleet.log_fetch")


class LogFetchRequest(BaseModel):
    host_id: str
    log_type: str = "event_log"
    since_minutes: int = 60
    max_lines: int = 1000


class LogFetchResult(BaseModel):
    host_id: str
    log_type: str
    lines: list[str] = []
    total_lines: int = 0
    status: str = "pending"


class LogFetchManager:
    def __init__(self):
        self._pending: list[LogFetchRequest] = []

    def create_request(self, req: LogFetchRequest) -> LogFetchRequest:
        self._pending.append(req)
        logger.info("Log fetch requested for %s: %s", req.host_id, req.log_type)
        return req

    def list_pending(self) -> list[LogFetchRequest]:
        return list(self._pending)

    def complete_request(self, host_id: str, lines: list[str]) -> LogFetchResult:
        self._pending = [r for r in self._pending if r.host_id != host_id]
        return LogFetchResult(
            host_id=host_id, log_type="event_log",
            lines=lines, total_lines=len(lines), status="completed",
        )
