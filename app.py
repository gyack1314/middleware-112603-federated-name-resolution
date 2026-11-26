"""Application alias for platforms expecting ``app.py``."""

from http_service import JsonDiscoveryServer, main, serve
from federated_discovery import DiscoveryService, create_service

app = None  # 标准库 HTTP 服务没有 WSGI app；需要时调用 create_server()。


def create_server(host: str = "127.0.0.1", port: int = 8765) -> JsonDiscoveryServer:
    return JsonDiscoveryServer((host, port), DiscoveryService())


if __name__ == "__main__":
    raise SystemExit(main())
