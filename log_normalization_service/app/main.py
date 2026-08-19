import asyncio
import sys
from contextlib import asynccontextmanager
from typing import List

from fastapi import FastAPI, HTTPException
from loguru import logger
from pydantic import BaseModel

from .collectors.siem_api import SIEMApiCollector
from .config import settings
from .pipelines.processing_pipeline import ProcessingPipeline

logger.remove()
logger.add(sys.stdout, level=settings.log_level, backtrace=True, diagnose=False)

pipeline = ProcessingPipeline()
collector = SIEMApiCollector()
_collector_task: asyncio.Task | None = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _collector_task
    if settings.siem_api_token:
        _collector_task = asyncio.create_task(_run_collector())
        logger.info("SIEM background collector started")
    else:
        logger.warning("SIEM_API_TOKEN not set — background collector disabled")
    yield
    if _collector_task:
        _collector_task.cancel()
    await collector.close()


async def _run_collector() -> None:
    async for raw_event in collector.collect():
        raw_log = raw_event.get("raw_log", "")
        if raw_log:
            result = pipeline.process(raw_log)
            logger.debug(
                f"event processed | source={result.source.type} "
                f"category={result.event.category} severity={result.event.severity}"
            )


app = FastAPI(
    title="Log Normalization Service",
    version="1.0.0",
    description="SIEM → AI SOC Agent normalization middleware",
    lifespan=lifespan,
)


class RawLogRequest(BaseModel):
    raw_log: str


class BatchRequest(BaseModel):
    logs: List[str]


@app.get("/health", tags=["ops"])
async def health():
    return {"status": "ok", "version": "1.0.0"}


@app.post("/api/v1/logs/ingest", tags=["ingestion"])
async def ingest_log(request: RawLogRequest):
    if not request.raw_log.strip():
        raise HTTPException(status_code=400, detail="raw_log must not be empty")
    normalized = pipeline.process(request.raw_log)
    return normalized.model_dump(mode="json")


@app.post("/api/v1/logs/batch", tags=["ingestion"])
async def ingest_batch(request: BatchRequest):
    if not request.logs:
        raise HTTPException(status_code=400, detail="logs list must not be empty")
    return [pipeline.process(raw).model_dump(mode="json") for raw in request.logs]
