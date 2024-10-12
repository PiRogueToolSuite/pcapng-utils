import json
import logging
from json import JSONDecodeError
from pathlib import Path

logger = logging.getLogger('enrichment')


class HarEnrichment:
    def __init__(self, har_data: dict, input_data_file: Path):
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
                self.can_enrich = bool(self.input_data) & bool(self.har_data)
            except (JSONDecodeError, TypeError, Exception):
                logger.error(f'Invalid input file format: {input_data_file}')
                self.can_enrich = False


    def enrich(self):
        raise NotImplementedError()
