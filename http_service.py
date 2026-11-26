"""仅使用标准库的本地 HTTP/JSON 联合发现服务。

启动::

    python3 http_service.py --host 127.0.0.1 --port 8765

所有标识仍是本地合成标识；该服务不访问真实 DNS 或网络目录。
"""

from __future__ import annotations

import argparse
import json
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlparse

from federated_discovery import DiscoveryError, DiscoveryService


class JsonDiscoveryServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address: tuple[str, int], service: DiscoveryService | None = None):
        super().__init__(address, DiscoveryRequestHandler)
        self.discovery = service or DiscoveryService()
        self.discovery_lock = threading.RLock()


def _first(query: dict[str, list[str]], key: str, default: Any = None) -> Any:
    values = query.get(key)
    return values[0] if values else default


class DiscoveryRequestHandler(BaseHTTPRequestHandler):
    server_version = "FederatedDiscovery/1.0"

    @property
    def discovery_server(self) -> JsonDiscoveryServer:
        return self.server  # type: ignore[return-value]

    def _send_json(self, status: int, payload: Any) -> None:
        body = json.dumps(payload, ensure_ascii=False, default=str).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length) if length else b"{}"
        try:
            value = json.loads(raw.decode("utf-8") or "{}")
        except json.JSONDecodeError as exc:
            raise DiscoveryError(f"请求体不是合法 JSON: {exc}") from exc
        if not isinstance(value, dict):
            raise DiscoveryError("请求体必须是 JSON 对象")
        return value

    def log_message(self, fmt: str, *args: Any) -> None:
        # 仿真值班输出保持安静；需要调试时可设置 DISCOVERY_HTTP_DEBUG=1。
        if os.environ.get("DISCOVERY_HTTP_DEBUG"):
            super().log_message(fmt, *args)

    def do_GET(self) -> None:  # noqa: N802
        try:
            parsed = urlparse(self.path)
            query = parse_qs(parsed.query)
            with self.discovery_server.discovery_lock:
                svc = self.discovery_server.discovery
                if parsed.path in {"/", "/health", "/healthz"}:
                    self._send_json(200, {"ok": True, "service": "federated-discovery", "version": "1.0"})
                elif parsed.path in {"/v1/inspect", "/inspect"}:
                    payload = svc.inspect(
                        client=_first(query, "client"),
                        name=_first(query, "name"),
                    )
                    self._send_json(200, payload)
                elif parsed.path in {"/v1/desk", "/desk"}:
                    self._send_json(200, svc.desk_overview())
                elif parsed.path in {"/v1/query", "/query"}:
                    tenant = _first(query, "tenant")
                    name = _first(query, "name")
                    if not tenant or name is None:
                        raise DiscoveryError("query 需要 tenant 和 name")
                    at = _first(query, "at")
                    result = svc.query(
                        tenant,
                        name,
                        mode=_first(query, "mode", "start"),
                        scope=_first(query, "scope"),
                        prior=_first(query, "version"),
                        at=int(at) if at is not None else None,
                    )
                    self._send_json(200, result)
                else:
                    self._send_json(404, {"ok": False, "error": "not_found", "path": parsed.path})
        except DiscoveryError as exc:
            self._send_json(400, {"ok": False, "error": "invalid_request", "message": str(exc)})
        except Exception as exc:  # pragma: no cover - HTTP boundary
            self._send_json(500, {"ok": False, "error": "internal", "message": str(exc)})

    def do_POST(self) -> None:  # noqa: N802
        try:
            payload = self._read_json()
            parsed = urlparse(self.path)
            path = parsed.path.rstrip("/")
            with self.discovery_server.discovery_lock:
                svc = self.discovery_server.discovery
                if path in {"/v1/handle", "/handle", "/v1/messages"}:
                    response = svc.handle(payload)
                elif path in {"/v1/query", "/query"}:
                    response = svc.query(**self._query_kwargs(payload))
                elif path in {"/v1/watch", "/watch"}:
                    response = svc.watch(**self._watch_kwargs(payload))
                elif path in {"/v1/delegate", "/delegate"}:
                    response = svc.handle_delegate(payload, at=int(payload.get("at", svc.now)))
                elif path in {"/v1/service", "/service"}:
                    response = svc.handle_service(payload, at=int(payload.get("at", svc.now)))
                elif path in {"/v1/cover", "/cover"}:
                    response = svc.handle_cover(payload, at=int(payload.get("at", svc.now)))
                elif path in {"/v1/trim", "/trim"}:
                    response = svc.handle_trim(payload, at=int(payload.get("at", svc.now)))
                elif path in {"/v1/restart", "/restart"}:
                    response = svc.handle_restart(payload, at=int(payload.get("at", svc.now)))
                elif path in {"/v1/cache/apply", "/cache/apply"}:
                    # 无状态 HTTP 边界只返回可缓存结果；客户端缓存通常在进程内使用 DiscoveryCache。
                    response = {"ok": True, "hint": "use DiscoveryCache.apply_notification in-process"}
                else:
                    self._send_json(404, {"ok": False, "error": "not_found", "path": path})
                    return
            self._send_json(200, response)
        except DiscoveryError as exc:
            self._send_json(400, {"ok": False, "error": "invalid_request", "message": str(exc)})
        except TypeError as exc:
            self._send_json(400, {"ok": False, "error": "invalid_arguments", "message": str(exc)})
        except Exception as exc:  # pragma: no cover - HTTP boundary
            self._send_json(500, {"ok": False, "error": "internal", "message": str(exc)})

    @staticmethod
    def _query_kwargs(payload: dict[str, Any]) -> dict[str, Any]:
        if "tenant" not in payload or "name" not in payload:
            raise DiscoveryError("query 需要 tenant 和 name")
        return {
            "tenant": str(payload["tenant"]),
            "name": str(payload["name"]),
            "query_id": payload.get("query_id", payload.get("query")),
            "mode": payload.get("mode", "start"),
            "scope": payload.get("scope"),
            "prior": payload.get("prior", payload.get("version")),
            "at": payload.get("at"),
            "client": payload.get("client"),
        }

    @staticmethod
    def _watch_kwargs(payload: dict[str, Any]) -> dict[str, Any]:
        if not all(k in payload for k in ("client", "tenant", "name")):
            raise DiscoveryError("watch 需要 client、tenant、name")
        return {
            "client": str(payload["client"]),
            "tenant": str(payload["tenant"]),
            "name": str(payload["name"]),
            "after": int(payload.get("after", 0)),
            "at": payload.get("at"),
            "scope": payload.get("scope", "exact"),
            "snapshot_token": payload.get("snapshot_token") or payload.get("consistency_token"),
        }


def serve(host: str | None = None, port: int | None = None) -> JsonDiscoveryServer:
    host = host or os.environ.get("DISCOVERY_HOST", "127.0.0.1")
    port = int(port if port is not None else os.environ.get("PORT", os.environ.get("DISCOVERY_PORT", "8765")))
    httpd = JsonDiscoveryServer((host, port))
    print(f"federated discovery listening on http://{host}:{port}", flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:  # pragma: no cover
        pass
    finally:
        httpd.server_close()
    return httpd


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="本地联合发现 HTTP 服务")
    parser.add_argument("--host", default=os.environ.get("DISCOVERY_HOST", "127.0.0.1"))
    parser.add_argument("--port", type=int, default=int(os.environ.get("PORT", os.environ.get("DISCOVERY_PORT", "8765"))))
    args = parser.parse_args(argv)
    serve(args.host, args.port)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
