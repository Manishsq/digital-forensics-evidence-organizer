"""
JSON forensic-tool output importer.

Supports both single-record and list-of-records JSON structures.
Example input:
    {
        "filename": "suspect_disk.dd",
        "sha256": "abc123...",
        "size": 1073741824,
        "timestamp": "2026-01-15T10:30:00Z"
    }
or:
    [
        { "filename": "...", "sha256": "...", ... },
        ...
    ]
"""

import json
from typing import Optional

from app.importers.base import BaseImporter, ParsedForensicRecord

# Field aliases from various forensic tools
_SHA256_KEYS   = {"sha256", "sha256hash", "sha-256", "hash_sha256"}
_SHA512_KEYS   = {"sha512", "sha512hash", "sha-512", "hash_sha512"}
_MD5_KEYS      = {"md5", "md5hash", "md5sum", "hash_md5"}
_FILENAME_KEYS = {"filename", "file_name", "name", "path", "filepath", "file_path"}
_SIZE_KEYS     = {"size", "file_size", "filesize", "bytes", "length"}
_TS_KEYS       = {"timestamp", "datetime", "date", "modified", "created", "acquisition_time"}
_SOURCE_KEYS   = {"source", "origin", "device", "location"}
_DESC_KEYS     = {"description", "notes", "comment", "info"}


def _pick(d: dict, keys: set) -> Optional[str]:
    for k in d:
        if k.lower() in keys:
            return d[k]
    return None


class JSONImporter(BaseImporter):
    @property
    def supported_extensions(self) -> list[str]:
        return [".json"]

    def parse(self, content: str) -> list[ParsedForensicRecord]:
        try:
            data = json.loads(content)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Invalid JSON: {exc}") from exc

        if isinstance(data, dict):
            items = [data]
        elif isinstance(data, list):
            items = data
        else:
            raise ValueError("JSON root must be an object or array.")

        records = []
        for item in items:
            if not isinstance(item, dict):
                continue
            size_raw = _pick(item, _SIZE_KEYS)
            try:
                size = int(size_raw) if size_raw is not None else None
            except (ValueError, TypeError):
                size = None

            # Collect remaining keys as extra metadata
            known_keys = _SHA256_KEYS | _SHA512_KEYS | _MD5_KEYS | _FILENAME_KEYS | _SIZE_KEYS | _TS_KEYS | _SOURCE_KEYS | _DESC_KEYS
            extra = {k: str(v) for k, v in item.items() if k.lower() not in known_keys}

            records.append(ParsedForensicRecord(
                filename=_pick(item, _FILENAME_KEYS),
                sha256=_pick(item, _SHA256_KEYS),
                sha512=_pick(item, _SHA512_KEYS),
                md5=_pick(item, _MD5_KEYS),
                file_size=size,
                timestamp=_pick(item, _TS_KEYS),
                source=_pick(item, _SOURCE_KEYS),
                description=_pick(item, _DESC_KEYS),
                extra_metadata=extra,
            ))
        return records
