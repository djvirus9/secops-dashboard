import csv
import io
import json

from ..base import BaseParser, ParsedFinding, ParserRegistry, ScannerCategory


@ParserRegistry.register
class CredScanParser(BaseParser):
    name = "credscan"
    display_name = "CredScan"
    category = ScannerCategory.SECRETS
    file_types = ["csv", "json"]
    description = "Microsoft CredScan for detecting credentials in code"

    def can_parse(self, content: str) -> bool:
        try:
            if "CredentialType" in content or "SearcherName" in content:
                return True
            data = json.loads(content)
            return "credentials" in data or "matches" in data
        except:
            return False

    def parse(self, content: str) -> list[ParsedFinding]:
        findings = []
        try:
            if content.strip().startswith("{") or content.strip().startswith("["):
                data = json.loads(content)
                creds = data if isinstance(data, list) else data.get("credentials", data.get("matches", []))
                for cred in creds:
                    findings.append(ParsedFinding(
                        title=f"Credential Found: {cred.get('type', cred.get('SearcherName', 'Unknown'))}",
                        description=cred.get("description", "Hardcoded credential detected"),
                        severity="high",
                        tool=self.name,
                        asset=cred.get("file", cred.get("FileName", "unknown")),
                        source_id=cred.get("type", cred.get("SearcherName")),
                        file_path=cred.get("file", cred.get("FileName")),
                        line_number=int(cred.get("line", cred.get("LineNumber"))) if cred.get("line", cred.get("LineNumber")) else None,
                        raw_data=cred
                    ))
            else:
                reader = csv.DictReader(io.StringIO(content))
                for row in reader:
                    findings.append(ParsedFinding(
                        title=f"Credential Found: {row.get('CredentialType', row.get('SearcherName', 'Unknown'))}",
                        description=row.get("Description", "Hardcoded credential detected"),
                        severity="high",
                        tool=self.name,
                        asset=row.get("FileName", row.get("File", "unknown")),
                        source_id=row.get("CredentialType", row.get("SearcherName")),
                        file_path=row.get("FileName", row.get("File")),
                        line_number=int(row.get("LineNumber")) if row.get("LineNumber") else None,
                        raw_data=dict(row)
                    ))
        except:
            pass
        return findings
