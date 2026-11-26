"""Simulation entry-point alias."""

from scenario_runner import main, run_file, run_rows

__all__ = ["main", "run_file", "run_rows"]


if __name__ == "__main__":
    raise SystemExit(main())
