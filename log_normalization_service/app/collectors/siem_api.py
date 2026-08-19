import asyncio
from typing import AsyncIterator, Dict, Any, Optional

import httpx
from loguru import logger

from .base import BaseCollector
from ..config import settings


class SIEMApiCollector(BaseCollector):
    """
    Polls a SIEM REST API and yields raw event dicts.
    Supports JSON array response or {"events"|"data"|"results"|...} wrappers.
    """

    def __init__(self) -> None:
        self._client: Optional[httpx.AsyncClient] = None

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                base_url=settings.siem_base_url,
                headers={
                    "Authorization": f"Bearer {settings.siem_api_token}",
                    "Accept": "application/json",
                },
                timeout=30.0,
                verify=settings.siem_verify_ssl,
            )
        return self._client

    async def collect(self) -> AsyncIterator[Dict[str, Any]]:
        while True:
            try:
                events = await self._fetch_events()
                for event in events:
                    yield self._extract_raw(event)
            except Exception as exc:
                logger.error(f"[SIEMApiCollector] fetch error: {exc}")

            await asyncio.sleep(settings.siem_poll_interval_seconds)

    async def _fetch_events(self) -> list[Dict[str, Any]]:
        client = await self._get_client()
        response = await client.get(settings.siem_events_path)
        response.raise_for_status()
        data = response.json()

        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            for key in ("events", "data", "results", "items", "hits", "logs"):
                if key in data and isinstance(data[key], list):
                    return data[key]
        logger.warning("[SIEMApiCollector] Unexpected response structure")
        return []

    @staticmethod
    def _extract_raw(event: Dict[str, Any]) -> Dict[str, Any]:
        """Pull the raw log string from whichever field the SIEM provides."""
        raw_log = (
            event.get("raw_log")
            or event.get("raw")
            or event.get("original")
            or event.get("message")
            or event.get("event")
            or str(event)
        )
        return {"raw_log": raw_log, "siem_fields": event}

    async def close(self) -> None:
        if self._client and not self._client.is_closed:
            await self._client.aclose()
