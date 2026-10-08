"""
Plain-text / log-file forensic output importer.

Parses lines of the form:
    KEY: VALUE
    KEY = VALUE

Common key synonyms from forensic tools are recognised.
"""

import re
from typing import Optional

from app.importers.base import BaseImporter, ParsedForensicRecord

_LINE_RE = re.compile(r"^([A-Za-z0-9_\-\s]+?)\s*[=:]\s*(.+)$")

_SHA256_KEYS   = {"sha256", "sha256 hash", "sha-256", "sha256checksum"}
_SHA512_KEYS   = {"sha512", "sha512 hash", "sha-512"}
_MD5_KEYS      = {"md5", "md5 hash", "md5sum", "md5checksum"}
_FILENAME_KEYS = {"filename", "file name", "file_name", "name", "filepath", "path"}
_SIZE_KEYS     = {"size", "file size", "file_size", "filesize", "bytes"}
_TS_KEYS       = {"timestamp", "date", "datetime", "modified", "created", "acquisition time"}
_SOURCE_KEYS   = {"source", "origin", "device", "location"}
_DESC_KEYS     = {"description", "notes", "comment", "info"}


class TextImporter(BaseImporter):
    @property
    def supported_extensions(self) -> list[str]:
        return [".txt", ".log", ".text"]

    def parse(self, content: str) -> list[ParsedForensicRecord]:
        """
        Each blank-line-separated block is treated as one record.
        """
        blocks = re.split(r"\n\s*\n", content.strip())
        records = []
        for block in blocks:
            block = block.strip()
            if not block:
                continue
            kv: dict[str, str] = {}
            for line in block.splitlines():
                m = _LINE_RE.match(line.strip())
                if m:
                    kv[m.group(1).strip().lower()] = m.group(2).strip()

            if not kv:
                continue

            def pick(keys: set) -> Optional[str]:
                for k in kv:
                    if k in keys:
                        return kv[k]
                return None

            size_raw = pick(_SIZE_KEYS)
            try:
                size = int(size_raw) if size_raw else None
            except ValueError:
                size = None

            known = _SHA256_KEYS | _SHA512_KEYS | _MD5_KEYS | _FILENAME_KEYS | _SIZE_KEYS | _TS_KEYS | _SOURCE_KEYS | _DESC_KEYS
            extra = {k: v for k, v in kv.items() if k not in known}

            records.append(ParsedForensicRecord(
                filename=pick(_FILENAME_KEYS),
                sha256=pick(_SHA256_KEYS),
                sha512=pick(_SHA512_KEYS),
                md5=pick(_MD5_KEYS),
                file_size=size,
                timestamp=pick(_TS_KEYS),
                source=pick(_SOURCE_KEYS),
                description=pick(_DESC_KEYS),
                extra_metadata=extra,
            ))
        return records
