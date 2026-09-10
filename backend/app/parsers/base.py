from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, List, Dict, Any, Type
from enum import Enum
from inspect import signature


class ScannerCategory(str, Enum):
    SAST = "sast"
    DAST = "dast"
    SCA = "sca"
    INFRASTRUCTURE = "infrastructure"
    CONTAINER = "container"
    CLOUD = "cloud"
    SECRETS = "secrets"
    GENERIC = "generic"
    BUGBOUNTY = "bugbounty"
    NETWORK = "network"
    MOBILE = "mobile"
    OTHER = "other"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @classmethod
    def normalize(cls, value: str) -> "Severity":
        mapping = {
            "critical": cls.CRITICAL,
            "crit": cls.CRITICAL,
            "5": cls.CRITICAL,
            "high": cls.HIGH,
            "4": cls.HIGH,
            "error": cls.HIGH,
            "medium": cls.MEDIUM,
            "med": cls.MEDIUM,
            "moderate": cls.MEDIUM,
            "3": cls.MEDIUM,
            "warning": cls.MEDIUM,
            "low": cls.LOW,
            "2": cls.LOW,
            "info": cls.INFO,
            "informational": cls.INFO,
            "note": cls.INFO,
            "1": cls.INFO,
            "0": cls.INFO,
            "none": cls.INFO,
            "unknown": cls.INFO,
        }
        return mapping.get(str(value).lower().strip(), cls.INFO)


@dataclass
class ParsedFinding:
    title: str
    severity: Severity
    tool: str
    
    description: str = ""
    asset: str = "unknown"
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    cwe_id: Optional[int] = None
    cve_id: Optional[str] = None
    cvss_score: Optional[float] = None
    # Compatibility aliases used by older parser implementations.
    cwe: Optional[Any] = field(default=None, repr=False)
    cve: Optional[str] = field(default=None, repr=False)
    
    recommendation: str = ""
    references: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    raw_data: Dict[str, Any] = field(default_factory=dict)
    
    detected_at: Optional[datetime] = None

    def __post_init__(self) -> None:
        if not isinstance(self.severity, Severity):
            self.severity = Severity.normalize(str(self.severity))

        if not self.cve_id and self.cve:
            self.cve_id = str(self.cve)

        if self.cwe_id is None and self.cwe not in (None, ""):
            candidate = self.cwe[0] if isinstance(self.cwe, list) and self.cwe else self.cwe
            try:
                self.cwe_id = int(str(candidate).upper().replace("CWE-", "").split(":")[0])
            except (TypeError, ValueError):
                self.cwe_id = None
    
    def to_signal_payload(self, *, include_raw_data: bool = False) -> Dict[str, Any]:
        """Return normalized evidence, omitting raw scanner output by default.

        Raw results frequently contain credentials, secret matches, source-code
        snippets, and other sensitive data. Operators can explicitly opt in to
        storing them when their database controls and retention policy allow it.
        """

        payload = {
            "tool": self.tool,
            "title": self.title,
            "severity": self.severity.value,
            "asset": self.asset,
            "description": self.description,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "cwe_id": self.cwe_id,
            "cve_id": self.cve_id,
            "cvss_score": self.cvss_score,
            "recommendation": self.recommendation,
            "references": self.references,
            "tags": self.tags,
        }
        if include_raw_data:
            payload["raw_data"] = self.raw_data
        return payload


class BaseParser(ABC):
    name: str = "base"
    display_name: str = "Base Parser"
    category: ScannerCategory = ScannerCategory.GENERIC
    file_types: List[str] = ["json"]
    description: str = "Base parser class"
    auto_detectable: bool = True
    
    @abstractmethod
    def parse(self, content: str, filename: Optional[str] = None) -> List[ParsedFinding]:
        pass
    
    @classmethod
    def can_parse(cls, content: str, filename: Optional[str] = None) -> bool:
        return False
    
    def get_info(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "display_name": self.display_name,
            "category": self.category.value,
            "file_types": self.file_types,
            "description": self.description,
        }


class ParserRegistry:
    _parsers: Dict[str, Type[BaseParser]] = {}
    
    @classmethod
    def register(cls, parser_class: Type[BaseParser]) -> Type[BaseParser]:
        cls._parsers[parser_class.name] = parser_class
        return parser_class
    
    @classmethod
    def get(cls, name: str) -> Optional[Type[BaseParser]]:
        return cls._parsers.get(name)

    @classmethod
    def contains_secret_evidence(cls, name: str) -> bool:
        parser_class = cls.get(name)
        return bool(parser_class and parser_class.category == ScannerCategory.SECRETS)

    @staticmethod
    def _can_parse(
        parser_class: Type[BaseParser], content: str, filename: Optional[str] = None
    ) -> bool:
        method = parser_class().can_parse
        if len(signature(method).parameters) == 1:
            return bool(method(content))
        return bool(method(content, filename))

    @staticmethod
    def parse(
        parser: BaseParser, content: str, filename: Optional[str] = None
    ) -> List[ParsedFinding]:
        method = parser.parse
        if len(signature(method).parameters) == 1:
            return method(content)
        return method(content, filename)

    @classmethod
    def is_auto_detectable(cls, parser_class: Type[BaseParser]) -> bool:
        if not parser_class.auto_detectable:
            return False

        # Several compatibility parsers intentionally accept arbitrary JSON.
        # They are useful when selected explicitly, but cannot safely
        # participate in auto-detection because they shadow specific parsers.
        try:
            catches_any_object = cls._can_parse(parser_class, "{}") and cls._can_parse(
                parser_class, '{"_secops_probe": true}'
            )
            catches_any_array = cls._can_parse(parser_class, "[]") and cls._can_parse(
                parser_class, '[{"_secops_probe": true}]'
            )
            catches_any_json = catches_any_object or catches_any_array
        except Exception:
            catches_any_json = False
        return not catches_any_json
    
    @classmethod
    def list_all(cls) -> List[Dict[str, Any]]:
        results = []
        for parser_class in cls._parsers.values():
            info = parser_class().get_info()
            info["auto_detectable"] = cls.is_auto_detectable(parser_class)
            results.append(info)
        return results
    
    @classmethod
    def list_by_category(cls, category: ScannerCategory) -> List[Dict[str, Any]]:
        results = []
        for parser_class in cls._parsers.values():
            if parser_class.category != category:
                continue
            info = parser_class().get_info()
            info["auto_detectable"] = cls.is_auto_detectable(parser_class)
            results.append(info)
        return results
    
    @classmethod
    def auto_detect(cls, content: str, filename: Optional[str] = None) -> Optional[Type[BaseParser]]:
        matches = []
        for parser_class in cls._parsers.values():
            if not cls.is_auto_detectable(parser_class):
                continue
            try:
                if cls._can_parse(parser_class, content, filename):
                    matches.append(parser_class)
            except Exception:
                continue

        if len(matches) > 1:
            names = ", ".join(parser.name for parser in matches)
            raise ValueError(
                f"Ambiguous scan format; select a parser explicitly. Matches: {names}"
            )
        return matches[0] if matches else None
