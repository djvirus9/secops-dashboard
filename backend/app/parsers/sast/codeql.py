import json
from typing import Optional

from ..base import ParserRegistry, ScannerCategory
from ..generic.sarif import SARIFParser


@ParserRegistry.register
class CodeQLParser(SARIFParser):
    name = "codeql"
    display_name = "CodeQL / GitHub Advanced Security"
    category = ScannerCategory.SAST
    description = "GitHub CodeQL SARIF 2.1 output"

    @classmethod
    def can_parse(cls, content: str, filename: Optional[str] = None) -> bool:
        try:
            runs = json.loads(content).get("runs", [])
            return bool(runs) and all(
                run.get("tool", {}).get("driver", {}).get("name", "").lower().startswith("codeql")
                for run in runs
            )
        except (ValueError, AttributeError, TypeError):
            return False
