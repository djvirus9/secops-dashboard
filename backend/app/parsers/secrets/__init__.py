from .ggshield import GgshieldParser
from .github_secrets import GithubSecretsParser
from .gitlab_secrets import GitLabSecretsParser
from .n0s1 import N0s1Parser
from .rusty_hog import RustyHogParser
from .talisman import TalismanParser
from .trufflehog import TruffleHogParser
from .trufflehog3 import TruffleHog3Parser
from .whispers import WhispersParser

__all__ = [
    "GgshieldParser",
    "GithubSecretsParser",
    "GitLabSecretsParser",
    "N0s1Parser",
    "RustyHogParser",
    "TalismanParser",
    "TruffleHogParser",
    "TruffleHog3Parser",
    "WhispersParser",
]
