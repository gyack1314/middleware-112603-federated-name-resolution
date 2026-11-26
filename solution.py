"""Alias for harnesses that look for ``solution.py``."""

from federated_discovery import *  # noqa: F401,F403
from federated_discovery import DiscoveryService, DiscoveryCache, create_service, run_scenario, solve  # noqa: F401

run_simulation = run_scenario
simulate = run_scenario
Federation = DiscoveryService

if __name__ == "__main__":
    from scenario_runner import main

    raise SystemExit(main())
