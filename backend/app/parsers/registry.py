from typing import Optional, List, Dict, Any
from defusedxml.common import DefusedXmlException

from .base import BaseParser, ParsedFinding, ParserRegistry
from .support import VERIFIED_PARSERS, parser_availability
from .validation import ScanValidationError, decode_document, validate_findings, validate_verified_document

from .sast import *
from .dast import *
from .sca import *
from .infrastructure import *
from .container import *
from .cloud import *
from .generic import *
from .bugbounty import *
from .network import *
from .mobile import *
from .other import *
from .secrets import *


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
    content = content.lstrip("\ufeff")
    if parser_name:
        parser = get_parser(parser_name)
        if not parser:
            raise ScanValidationError("Unknown parser; select a parser from the supported parser list")
    else:
        parser_class = ParserRegistry.auto_detect(content, filename)
        if not parser_class:
            raise ScanValidationError("Could not auto-detect parser for this content; select a verified parser explicitly")
        parser = parser_class()

    availability = parser_availability(parser.name)
    if not availability["enabled"]:
        raise ScanValidationError(f"Parser '{parser.name}' is disabled. {availability['unavailable_reason']}")

    try:
        kind, document = decode_document(parser, content)
        expected_count = None
        if parser.name in VERIFIED_PARSERS:
            expected_count = validate_verified_document(parser.name, kind, document)
        findings = ParserRegistry.parse(parser, content, filename)
        validate_findings(findings, expected_count)
        return findings
    except (ScanValidationError, DefusedXmlException):
        raise
    except Exception as error:
        # Some legacy parsers include values from scanner output in exception
        # messages. Never expose those messages in the API or import history.
        raise ScanValidationError("Unable to parse the complete report; verify its format and field types") from error
