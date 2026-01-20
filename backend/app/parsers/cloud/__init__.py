from .aws_asff import AWSASFFParser
from .aws_inspector import AWSInspectorParser
from .aws_security_hub import AWSSecurityHubParser
from .azure_security_center import AzureSecurityCenterParser
from .cloudflare import CloudflareParser
from .cycognito import CycognitoParser
from .gcp_artifact import GCPArtifactParser
from .gcp_scc import GCPSecurityCommandCenterParser
from .ms_defender import MSDefenderParser
from .scout_suite import ScoutSuiteParser
from .wiz import WizParser

__all__ = [
    "AWSASFFParser",
    "AWSInspectorParser",
    "AWSSecurityHubParser",
    "AzureSecurityCenterParser",
    "CloudflareParser",
    "CycognitoParser",
    "GCPArtifactParser",
    "GCPSecurityCommandCenterParser",
    "MSDefenderParser",
    "ScoutSuiteParser",
    "WizParser",
]
