"""
CSV forensic-tool output importer.

Supports CSV files with headers.  Column names are matched
case-insensitively to known forensic metadata fields.
"""

import csv
import io
from typing import Optional

from app.importers.base import BaseImporter, ParsedForensicRecord

_SHA256_COLS   = {"sha256", "sha256hash", "sha-256", "hash_sha256"}
_SHA512_COLS   = {"sha512", "sha512hash", "sha-512", "hash_sha512"}
_MD5_COLS      = {"md5", "md5hash", "md5sum", "hash_md5"}
_FILENAME_COLS = {"filename", "file_name", "name", "path", "filepath", "file_path"}
_SIZE_COLS     = {"size", "file_size", "filesize", "bytes", "length"}
_TS_COLS       = {"timestamp", "datetime", "date", "modified", "created", "acquisition_time"}
_SOURCE_COLS   = {"source", "origin", "device", "location"}
_DESC_COLS     = {"description", "notes", "comment", "info"}

ALL_KNOWN = _SHA256_COLS | _SHA512_COLS | _MD5_COLS | _FILENAME_COLS | _SIZE_COLS | _TS_COLS | _SOURCE_COLS | _DESC_COLS


def _col(row: dict, keys: set) -> Optional[str]:
    for k, v in row.items():
        if k.lower().strip() in keys:
            return v.strip() if v else None
    return None


class CSVImporter(BaseImporter):
    @property
    def supported_extensions(self) -> list[str]:
        return [".csv"]

    def parse(self, content: str) -> list[ParsedForensicRecord]:
        reader = csv.DictReader(io.StringIO(content))
        records = []
        for row in reader:
            size_raw = _col(row, _SIZE_COLS)
            try:
                size = int(size_raw) if size_raw else None
            except ValueError:
                size = None

            extra = {
                k.strip(): v.strip()
                for k, v in row.items()
                if k and k.lower().strip() not in ALL_KNOWN
            }

            records.append(ParsedForensicRecord(
                filename=_col(row, _FILENAME_COLS),
                sha256=_col(row, _SHA256_COLS),
                sha512=_col(row, _SHA512_COLS),
                md5=_col(row, _MD5_COLS),
                file_size=size,
                timestamp=_col(row, _TS_COLS),
                source=_col(row, _SOURCE_COLS),
                description=_col(row, _DESC_COLS),
                extra_metadata=extra,
            ))
        return records
