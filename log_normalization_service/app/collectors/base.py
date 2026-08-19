from abc import ABC, abstractmethod
from typing import AsyncIterator, Dict, Any


class BaseCollector(ABC):

    @abstractmethod
    async def collect(self) -> AsyncIterator[Dict[str, Any]]:
        """Yields dicts with at least a 'raw_log' key."""
        pass
