from pathlib import Path


class Enrichment:
    def __init__(self, har_data: dict, extra_file: Path):
        self.har_data = har_data
        self.extra_file = extra_file
    def enrich(self):
        raise NotImplementedError()
