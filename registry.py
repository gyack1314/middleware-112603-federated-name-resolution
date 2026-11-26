"""Registry/facade alias."""

from federated_discovery import DiscoveryService as Registry
from federated_discovery import DiscoveryService

FederatedRegistry = DiscoveryService

__all__ = ["Registry", "FederatedRegistry", "DiscoveryService"]
