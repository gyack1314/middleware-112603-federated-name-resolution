"""把 JSONL 演练记录交给联合发现服务，并输出确定性的 JSON 回执。"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from federated_discovery import DiscoveryService
from scenario_reader import iter_messages


def load_supported_kinds(examples_dir: Path | None = None) -> set[str]:
    candidates = [
        examples_dir / "message_types.json" if examples_dir else None,
        Path(__file__).with_name("examples") / "message_types.json",
    ]
    for candidate in candidates:
        if candidate and candidate.exists():
            return set(json.loads(candidate.read_text(encoding="utf-8")))
    from federated_discovery import MESSAGE_KINDS

    return set(MESSAGE_KINDS)


def run_file(path: str | Path, *, pretty: bool = False) -> dict[str, Any]:
    path = Path(path)
    kinds = load_supported_kinds(path.parent if (path.parent / "message_types.json").exists() else None)
    service = DiscoveryService()
    reports = []
    for message in iter_messages(path, kinds):
        reports.append(service.handle(message))
    return {
        "scenario": path.name,
        "report_count": len(reports),
        "reports": reports,
        "desk": service.desk_overview(),
    }


def run_rows(rows: list[dict[str, Any]], *, scenario: str = "<stdin>") -> dict[str, Any]:
    service = DiscoveryService()
    reports = service.process_records(rows)
    return {"scenario": scenario, "report_count": len(reports), "reports": reports, "desk": service.desk_overview()}


def iter_scenario_files(target: Path) -> list[Path]:
    if target.is_file():
        return [target]
    return sorted(target.glob("*.jsonl"))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="运行联合发现 JSONL 演练")
    parser.add_argument("path", nargs="?", type=Path, help="JSONL 文件或包含 JSONL 的目录")
    parser.add_argument("--stdin", action="store_true", help="从标准输入读取 JSONL")
    parser.add_argument("--out", type=Path, help="把完整 JSON 报告写入文件；默认逐行输出简要回执")
    parser.add_argument("--full", action="store_true", help="stdout 输出完整 JSON")
    args = parser.parse_args(argv)

    all_results = []
    read_piped_stdin = args.path is None and not sys.stdin.isatty()
    if args.stdin or read_piped_stdin:
        rows = []
        for line_number, raw in enumerate(sys.stdin, 1):
            if not raw.strip():
                continue
            try:
                row = json.loads(raw)
            except json.JSONDecodeError as exc:
                raise ValueError(f"<stdin> 第 {line_number} 行不是合法 JSON: {exc}") from exc
            rows.append(row)
        if rows or args.stdin:
            all_results.append(run_rows(rows))

    if not all_results:
        target = args.path or Path("examples")
        if not target.exists():
            parser.error(f"路径不存在: {target}")
        files = iter_scenario_files(target)
        if not files:
            parser.error(f"没有 JSONL 场景: {target}")
        for path in files:
            all_results.append(run_file(path))

    for result in all_results:
        if args.full:
            print(json.dumps(result, ensure_ascii=False, indent=2))
        else:
            for report in result["reports"]:
                summary = {
                    "scenario": result["scenario"],
                    "at": report.get("at"),
                    "kind": report.get("kind"),
                    "ok": report.get("ok", True),
                    "status": report.get("status"),
                    "reason": report.get("reason"),
                    "must_resync": report.get("must_resync"),
                    "version": report.get("version"),
                }
                print(json.dumps(summary, ensure_ascii=False))

    if args.out:
        args.out.write_text(json.dumps(all_results, ensure_ascii=False, indent=2), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
