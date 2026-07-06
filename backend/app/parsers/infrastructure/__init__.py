from .checkov import CheckovParser
from .chef_inspec import ChefInspecParser
from .cloudsploit import CloudsploitParser
from .gitlab_api_fuzz import GitLabAPIFuzzParser
from .gitlab_container import GitLabContainerParser
from .gitlab_dast import GitLabDASTParser
from .gitlab_dependency import GitLabDependencyParser
from .gitlab_sast import GitLabSASTParser
from .kics import KICSParser
from .krakend import KrakenDParser
from .kube_bench import KubeBenchParser
from .kube_hunter import KubeHunterParser
from .kubeaudit import KubeauditParser
from .kubescape import KubescapeParser
from .kubesec import KubesecParser
from .legitify import LegitifyParser
from .nessus import NessusParser
from .nexpose import NexposeParser
from .openscap import OpenSCAPParser
from .openvas import OpenVASParser
from .prowler import ProwlerParser
from .qualys import QualysParser
from .terrascan import TerrascanParser
from .tfsec import TfsecParser
from .zora import ZoraParser
from .popeye import PopeyeParser
from .pingcastle import PingCastleParser
from .picus import PicusParser
from .threagile import ThreagileParser
from .threat_composer import ThreatComposerParser
from .tenable import TenableParser
from .redhatsatellite import RedHatSatelliteParser
from .wazuh import WazuhParser
from .alertlogic import AlertLogicParser

__all__ = [
    "CheckovParser",
    "ChefInspecParser",
    "CloudsploitParser",
    "GitLabAPIFuzzParser",
    "GitLabContainerParser",
    "GitLabDASTParser",
    "GitLabDependencyParser",
    "GitLabSASTParser",
    "KICSParser",
    "KrakenDParser",
    "KubeBenchParser",
    "KubeHunterParser",
    "KubeauditParser",
    "KubescapeParser",
    "KubesecParser",
    "LegitifyParser",
    "NessusParser",
    "NexposeParser",
    "OpenSCAPParser",
    "OpenVASParser",
    "ProwlerParser",
    "QualysParser",
    "TerrascanParser",
    "TfsecParser",
    "ZoraParser",
    "PopeyeParser",
    "PingCastleParser",
    "PicusParser",
    "ThreagileParser",
    "ThreatComposerParser",
    "TenableParser",
    "RedHatSatelliteParser",
    "WazuhParser",
    "AlertLogicParser",
]
