"""Stranger Test — an authorized-only MCP confused-deputy leak tester."""

from .guard import (  # noqa: F401
    Authorization,
    AuthorizationError,
    authorize,
    extract_host,
    is_local_target,
)
from .mcp_client import JSONRPCError, MCPClient, Transport  # noqa: F401
from .delegate import DelegationReport, MockUpstream, run_delegation_probe  # noqa: F401
from .probe import Identity, ProbeError, ProbePlan, ProbeReport, new_marker, run_probe  # noqa: F401
from .subscribe import SubscriptionReport, run_subscription_probe  # noqa: F401
from .transports import HTTPTransport, StdioTransport  # noqa: F401

__version__ = "0.1.0"
