"""Short import alias for tests or scripts expecting ``service.DiscoveryService``."""

from federated_discovery import *  # noqa: F401,F403
from federated_discovery import DiscoveryService, DiscoveryCache

ServiceDiscovery = DiscoveryService

__all__ = ["DiscoveryService", "ServiceDiscovery", "DiscoveryCache"]
