import json
import xml.etree.ElementTree as ET
from typing import List, Optional

from ..base import BaseParser, ParsedFinding, Severity, ScannerCategory, ParserRegistry


@ParserRegistry.register
class ZAPParser(BaseParser):
    name = "zap"
    display_name = "OWASP ZAP"
    category = ScannerCategory.DAST
    file_types = ["json", "xml"]
    description = "OWASP Zed Attack Proxy web application scanner"
    
    @classmethod
    def can_parse(cls, content: str, filename: Optional[str] = None) -> bool:
        try:
            if content.strip().startswith("{"):
                data = json.loads(content)
                return "@version" in data or "site" in data or "OWASPZAPReport" in str(data)
            elif content.strip().startswith("<"):
                root = ET.fromstring(content)
                return root.tag == "OWASPZAPReport" or "zap" in root.tag.lower()
            return False
        except:
            return False
    
    def parse(self, content: str, filename: Optional[str] = None) -> List[ParsedFinding]:
        if content.strip().startswith("{"):
            return self._parse_json(content)
        else:
            return self._parse_xml(content)
    
    def _parse_json(self, content: str) -> List[ParsedFinding]:
        data = json.loads(content)
        findings = []
        
        sites = data.get("site", [])
        if isinstance(sites, dict):
            sites = [sites]
        
        for site in sites:
            host = site.get("@name", "unknown")
            
            alerts = site.get("alerts", [])
            if isinstance(alerts, dict):
                alerts = [alerts]
            
            for alert in alerts:
                risk = alert.get("riskcode", "0")
                severity_map = {"3": Severity.HIGH, "2": Severity.MEDIUM, "1": Severity.LOW, "0": Severity.INFO}
                
                cwe_id = None
                if alert.get("cweid"):
                    try:
                        cwe_id = int(alert["cweid"])
                    except:
                        pass
                
                instances = alert.get("instances", [])
                if isinstance(instances, dict):
                    instances = [instances]
                
                for instance in instances:
                    finding = ParsedFinding(
                        title=alert.get("name", "Unknown Alert"),
                        severity=severity_map.get(str(risk), Severity.INFO),
                        tool="zap",
                        description=alert.get("desc", ""),
                        asset=instance.get("uri", host),
                        cwe_id=cwe_id,
                        recommendation=alert.get("solution", ""),
                        references=[alert.get("reference", "")] if alert.get("reference") else [],
                        tags=["zap", alert.get("pluginid", "")],
                        raw_data={"alert": alert, "instance": instance},
                    )
                    findings.append(finding)
        
        return findings
    
    def _parse_xml(self, content: str) -> List[ParsedFinding]:
        root = ET.fromstring(content)
        findings = []
        
        for site in root.findall(".//site"):
            host = site.get("name", "unknown")
            
            for alert in site.findall(".//alertitem"):
                risk = alert.findtext("riskcode", "0")
                severity_map = {"3": Severity.HIGH, "2": Severity.MEDIUM, "1": Severity.LOW, "0": Severity.INFO}
                
                cwe_id = None
                cweid = alert.findtext("cweid")
                if cweid:
                    try:
                        cwe_id = int(cweid)
                    except:
                        pass
                
                for instance in alert.findall(".//instance"):
                    finding = ParsedFinding(
                        title=alert.findtext("name", "Unknown Alert"),
                        severity=severity_map.get(str(risk), Severity.INFO),
                        tool="zap",
                        description=alert.findtext("desc", ""),
                        asset=instance.findtext("uri", host),
                        cwe_id=cwe_id,
                        recommendation=alert.findtext("solution", ""),
                        tags=["zap", alert.findtext("pluginid", "")],
                        raw_data={},
                    )
                    findings.append(finding)
        
        return findings
