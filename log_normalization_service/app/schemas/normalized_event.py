from __future__ import annotations

import uuid
from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field


class SourceInfo(BaseModel):
    type: str
    product: Optional[str] = None
    hostname: Optional[str] = None
    ip: Optional[str] = None


class EventInfo(BaseModel):
    id: Optional[str] = None
    category: str = "unknown"
    action: Optional[str] = None
    result: Optional[str] = None
    severity: Optional[str] = None


class UserInfo(BaseModel):
    name: Optional[str] = None
    domain: Optional[str] = None


class NetworkInfo(BaseModel):
    src_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_ip: Optional[str] = None
    dst_port: Optional[int] = None
    protocol: Optional[str] = None


class ProcessInfo(BaseModel):
    name: Optional[str] = None
    pid: Optional[int] = None
    command_line: Optional[str] = None


class NormalizedEvent(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    schema_version: str = "1.0"
    event_time: Optional[datetime] = None
    received_time: datetime
    source: SourceInfo
    event: EventInfo
    user: Optional[UserInfo] = None
    network: Optional[NetworkInfo] = None
    process: Optional[ProcessInfo] = None
    message: Optional[str] = None
    raw_log: str
    parse_error: Optional[str] = None
