from typing import Optional, List, Dict, Any

from .base import BaseParser, ParsedFinding, ParserRegistry

from .sast import *
from .dast import *
from .sca import *
from .infrastructure import *
from .container import *
from .cloud import *
from .generic import *


def get_parser(name: str) -> Optional[BaseParser]:
    parser_class = ParserRegistry.get(name)
    if parser_class:
        return parser_class()
    return None


def list_parsers() -> List[Dict[str, Any]]:
    return ParserRegistry.list_all()


def parse_scan_results(
    content: str,
    parser_name: Optional[str] = None,
    filename: Optional[str] = None,
) -> List[ParsedFinding]:
    if parser_name:
        parser = get_parser(parser_name)
        if not parser:
            raise ValueError(f"Unknown parser: {parser_name}")
    else:
        parser_class = ParserRegistry.auto_detect(content, filename)
        if not parser_class:
            raise ValueError("Could not auto-detect parser for this content")
        parser = parser_class()
    
    return parser.parse(content, filename)
