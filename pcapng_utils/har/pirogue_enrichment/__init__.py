import json
import logging
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any

logger = logging.getLogger('enrichment')


class HarEnrichment(ABC):
    def __init__(self, har_data: dict, input_data_file: Path) -> None:
        self.har_data = har_data
        self.input_data_file = input_data_file
        self.can_enrich = False
        self.input_data = None

        if not input_data_file.exists() or not input_data_file.is_file():
            logger.error(f'Invalid input file: {input_data_file}')
            return

        with self.input_data_file.open('r') as f:
            try:
                self.input_data = json.load(f)
                self.can_enrich = bool(self.input_data) and bool(self.har_data)
            except Exception:
                logger.error(f'Invalid input file format: {input_data_file}')
                self.can_enrich = False

    def enrich(self) -> bool:
        """Enrich, in-place, the HAR data with input-data."""
        # TODO? add metadata in `creator` as well?
        if not self.can_enrich:
            return False
        for entry in self.har_data["log"]["entries"]:
            self.enrich_entry(entry)
        return True

    @abstractmethod
    def enrich_entry(self, har_entry: dict[str, Any]) -> None:
        """Enrich, in-place, one entry of the HAR data with input-data."""
