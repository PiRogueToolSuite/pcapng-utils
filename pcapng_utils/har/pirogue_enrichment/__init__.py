import json
import logging
from abc import ABC, abstractmethod
from hashlib import file_digest
from pathlib import Path
from typing import ClassVar, Any

logger = logging.getLogger('enrichment')

HASH_ALGO = 'sha1'
ENRICHMENT_KEY = f'enrichment_files_{HASH_ALGO}'


class HarEnrichment(ABC):

    ID: ClassVar[str]

    def __init__(self, har_data: dict, input_data_file: Path) -> None:
        self.har_data = har_data
        self.input_data_file = input_data_file
        self.input_data_hash: str | None = None
        self.can_enrich: bool = False
        self.input_data: Any | None = None

        if not input_data_file.exists() or not input_data_file.is_file():
            logger.error(f'Invalid input file: {input_data_file}')
            return

        if not self.har_data:
            return

        with self.input_data_file.open('rb') as f:
            self.input_data_hash = file_digest(f, HASH_ALGO).hexdigest()
            f.seek(0)  # reset file stream to the beginning
            try:
                self.input_data = json.load(f)
                self.can_enrich = bool(self.input_data)
            except Exception as e:
                logger.error(f'Invalid input file format: {input_data_file} ({e})')
                self.can_enrich = False

    def enrich(self) -> bool:
        """Enrich, in-place, the HAR data with input-data."""
        if not self.can_enrich:
            return False
        meta: dict = self.har_data['log']['creator']['_metadata']
        meta.setdefault(ENRICHMENT_KEY, {})
        if self.ID in meta[ENRICHMENT_KEY]:
            raise ValueError(f'{self.ID} enrichment already performed')
        assert self.input_data_hash is not None
        meta[ENRICHMENT_KEY][self.ID] = self.input_data_hash
        for entry in self.har_data["log"]["entries"]:
            self.enrich_entry(entry)
        return True

    @abstractmethod
    def enrich_entry(self, har_entry: dict[str, Any]) -> None:
        """Enrich, in-place, one entry of the HAR data with input-data."""
