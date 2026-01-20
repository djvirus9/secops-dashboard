from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, List, Dict, Any, Type
from enum import Enum


class ScannerCategory(str, Enum):
    SAST = "sast"
    DAST = "dast"
    SCA = "sca"
    INFRASTRUCTURE = "infrastructure"
    CONTAINER = "container"
    CLOUD = "cloud"
    SECRETS = "secrets"
    GENERIC = "generic"


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
    
    recommendation: str = ""
    references: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    raw_data: Dict[str, Any] = field(default_factory=dict)
    
    detected_at: Optional[datetime] = None
    
    def to_signal_payload(self) -> Dict[str, Any]:
        return {
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
            "raw_data": self.raw_data,
        }


class BaseParser(ABC):
    name: str = "base"
    display_name: str = "Base Parser"
    category: ScannerCategory = ScannerCategory.GENERIC
    file_types: List[str] = ["json"]
    description: str = "Base parser class"
    
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
    def list_all(cls) -> List[Dict[str, Any]]:
        return [p().get_info() for p in cls._parsers.values()]
    
    @classmethod
    def list_by_category(cls, category: ScannerCategory) -> List[Dict[str, Any]]:
        return [
            p().get_info() 
            for p in cls._parsers.values() 
            if p.category == category
        ]
    
    @classmethod
    def auto_detect(cls, content: str, filename: Optional[str] = None) -> Optional[Type[BaseParser]]:
        for parser_class in cls._parsers.values():
            if parser_class.can_parse(content, filename):
                return parser_class
        return None
