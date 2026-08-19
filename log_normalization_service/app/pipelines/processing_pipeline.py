from datetime import datetime, timezone

from loguru import logger

from ..classifiers.event_classifier import EventClassifier
from ..detectors.source_detector import SourceDetector
from ..normalizers.normalizer import EventNormalizer
from ..parsers.base import BaseParser
from ..parsers.generic import GenericParser
from ..parsers.linux.syslog import LinuxParser
from ..parsers.macos.unified_log import MacOSParser
from ..parsers.windows.eventlog import WindowsEventLogParser
from ..schemas.normalized_event import EventInfo, NormalizedEvent, SourceInfo


class ProcessingPipeline:
    """
    Orchestrates: Detector → Parser → Normalizer → Classifier → NormalizedEvent.

    To add a new source, create a parser that extends BaseParser, then add
    an instance to self._parsers below — nothing else changes.
    """

    def __init__(self) -> None:
        self._detector = SourceDetector()
        self._parsers: list[BaseParser] = [
            WindowsEventLogParser(),
            LinuxParser(),
            MacOSParser(),
            # ← add new parsers here
        ]
        self._fallback = GenericParser()
        self._normalizer = EventNormalizer()
        self._classifier = EventClassifier()

    def process(self, raw_log: str) -> NormalizedEvent:
        try:
            source_type = self._detector.detect(raw_log)
            parser = self._select_parser(source_type, raw_log)
            parsed = parser.safe_parse(raw_log)
            normalized = self._normalizer.normalize(parsed, raw_log)
            normalized.event.category = self._classifier.classify(normalized)
            return normalized
        except Exception as exc:
            logger.error(f"[ProcessingPipeline] unexpected error: {exc}")
            return self._make_fallback_event(raw_log, str(exc))

    def _select_parser(self, source_type: str, raw_log: str) -> BaseParser:
        # Prefer a parser whose source_type matches the detector result
        for parser in self._parsers:
            if parser.source_type == source_type and parser.can_parse(raw_log):
                return parser
        # Fall back to any parser that claims it can handle the log
        for parser in self._parsers:
            if parser.can_parse(raw_log):
                return parser
        return self._fallback

    @staticmethod
    def _make_fallback_event(raw_log: str, error: str) -> NormalizedEvent:
        now = datetime.now(timezone.utc)
        return NormalizedEvent(
            event_time=now,
            received_time=now,
            source=SourceInfo(type="unknown"),
            event=EventInfo(category="unknown"),
            message=f"Pipeline error: {error}",
            raw_log=raw_log,
            parse_error=error,
        )
