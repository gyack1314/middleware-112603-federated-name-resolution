"""Client/agent alias."""

from federated_discovery import Agent, DiscoveryAgent, DiscoveryCache

Client = DiscoveryAgent

__all__ = ["Agent", "Client", "DiscoveryAgent", "DiscoveryCache"]
