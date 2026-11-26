"""Conventional import alias: ``from discovery_service import DiscoveryService``."""

from federated_discovery import *  # noqa: F401,F403
from federated_discovery import (  # noqa: F401
    Cache,
    ControlledCache,
    DiscoveryCache,
    DiscoveryEngine,
    DiscoveryError,
    DiscoveryService,
    FederatedDiscovery,
    FederatedDiscoveryService,
    StaleQualification,
    prefix_matches,
)

if __name__ == "__main__":
    from scenario_runner import main

    raise SystemExit(main())
