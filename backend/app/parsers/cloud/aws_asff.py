from ..base import ParserRegistry
from .aws_security_hub import AWSSecurityHubParser


@ParserRegistry.register
class AWSASFFParser(AWSSecurityHubParser):
    """Explicit alias for the same ASFF format and normalized scanner identity."""

    name = "aws_asff"
    display_name = "AWS Security Finding Format"
    auto_detectable = False
