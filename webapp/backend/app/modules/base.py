from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Callable, Awaitable, Optional

class BaseModule(ABC):
    id: str
    name: str
    description: str
    category: str
    icon: str

    @abstractmethod
    async def run(
        self,
        job_id: str,
        target: str,
        output_dir: Path,
        update_progress: Callable[[int, str], Awaitable[None]],
    ) -> dict[str, Any]:
        """
        Execute the module capability on the target domain.
        Must return a JSON-serializable dictionary of findings/results.
        """
        pass
