"""
Base importer interface.

All forensic-tool output importers extend this class.
Importers parse structured metadata from forensic tool outputs.
They NEVER execute the imported content.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class ParsedForensicRecord:
    """Metadata extracted from a forensic tool output file."""
    filename: Optional[str] = None
    sha256: Optional[str] = None
    sha512: Optional[str] = None
    md5: Optional[str] = None
    file_size: Optional[int] = None
    timestamp: Optional[str] = None
    source: Optional[str] = None
    description: Optional[str] = None
    extra_metadata: dict = field(default_factory=dict)


class BaseImporter(ABC):
    """Abstract base for all forensic-tool output importers."""

    @property
    @abstractmethod
    def supported_extensions(self) -> list[str]:
        """Return a list of file extensions this importer handles."""
        ...

    @abstractmethod
    def parse(self, content: str) -> list[ParsedForensicRecord]:
        """
        Parse the raw text content and return a list of records.
        Must NOT execute any content.
        """
        ...

    def can_handle(self, filename: str) -> bool:
        ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
        return f".{ext}" in self.supported_extensions
