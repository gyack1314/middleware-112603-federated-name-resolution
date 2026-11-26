"""联合命名域发现服务的标准库实现。

本模块不依赖网络或第三方包，适合仿真平台直接导入或通过
``python3 federated_discovery.py examples/xxx.jsonl`` 演练。

核心不变量：

* 管辖方由最长匹配的有效委托前缀决定，代次只在同一前缀内比较。
* 只有当前代次、未过期且覆盖到当前记录版本的 cover 才能证明缺失。
* 所有查询结果都是某个已提交 ``view_seq`` 上的一致快照。
* 通知日志、保留点和订阅游标使用同一个单调序号。
"""

from __future__ import annotations

import copy
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

_ROOT = Path(__file__).resolve().parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from scenario_reader import iter_messages  # noqa: E402

MESSAGE_KINDS = {
    "cover",
    "delegate",
    "inspect",
    "query",
    "restart",
    "service",
    "trim",
    "watch",
}

_ROOT_TOKENS = {"", "@", "*", "<root>", "."}
_LABEL_RE = re.compile(r"^[^\s.]+$")


class DiscoveryError(ValueError):
    """输入契约或调用方式错误。"""


class StaleQualification(RuntimeError):
    """旧资格已经不能用于启动新调用。"""

    def __init__(self, diagnosis: dict[str, Any]):
        self.diagnosis = diagnosis
        super().__init__(diagnosis.get("reason") or "discovery qualification is stale")


def root_prefix() -> str:
    return ""


def normalize_prefix(value: str | None) -> str:
    if value is None:
        return ""
    if not isinstance(value, str):
        raise DiscoveryError("前缀必须是字符串")
    value = value.strip()
    if value in _ROOT_TOKENS:
        return ""
    value = value.strip(".")
    if not value:
        return ""
    _validate_labels(value)
    return value


def normalize_name(value: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise DiscoveryError("名字必须是非空字符串")
    value = value.strip().rstrip(".")
    if value in _ROOT_TOKENS:
        return ""
    _validate_labels(value)
    return value


def _validate_labels(dotted: str) -> None:
    labels = dotted.split(".")
    if any(not label or not _LABEL_RE.match(label) for label in labels):
        raise DiscoveryError(f"非法合成名称或前缀: {dotted!r}")


def prefix_matches(prefix: str, name: str) -> bool:
    prefix = normalize_prefix(prefix)
    name = normalize_name(name) if name else ""
    return not prefix or name == prefix or name.startswith(prefix + ".")


def prefix_depth(prefix: str) -> int:
    return 0 if not prefix else len(prefix.split("."))


def parse_query_target(name: str | None, scope: str | None = None) -> tuple[str, str]:
    """返回 (规范化名字/前缀, exact|prefix)。"""
    if name is None:
        raise DiscoveryError("query/watch 需要 name")
    raw = str(name).strip()
    wants_prefix = scope in {"prefix", "subtree", "range", "children", "all"}
    if raw in {"*", ".*"} or raw.endswith(".*") or raw.endswith(".**"):
        wants_prefix = True
        raw = raw[:-2] if raw.endswith(".*") else raw[:-3]
    normalized = normalize_prefix(raw) if wants_prefix else normalize_name(raw)
    return normalized, "prefix" if wants_prefix else "exact"


def _tenant_list(value: Any) -> list[str]:
    if value is None:
        return ["*"]
    if isinstance(value, str):
        return [value]
    if isinstance(value, Iterable) and not isinstance(value, dict):
        tenants = [str(item) for item in value]
        return tenants or ["*"]
    raise DiscoveryError("tenants 必须是字符串或字符串数组")


def _visible(tenants: Iterable[str], tenant: str) -> bool:
    tenants = list(tenants)
    return "*" in tenants or "all" in tenants or "public" in tenants or tenant in tenants


def _finite_until(value: Any, at: int | None = None, ttl: Any = None) -> int | None:
    if value is None and ttl is not None and at is not None:
        if not isinstance(ttl, int) or isinstance(ttl, bool) or ttl < 0:
            raise DiscoveryError("ttl 必须是非负整数秒")
        return at + ttl
    if value is None:
        return None
    if not isinstance(value, int) or isinstance(value, bool):
        raise DiscoveryError("until 必须是整数秒点")
    return value


@dataclass
class CacheEntry:
    key: tuple[str, str, str]
    result: dict[str, Any]
    cached_at: int

    def public(self) -> dict[str, Any]:
        return copy.deepcopy(self.result)


class DiscoveryCache:
    """租户隔离、尊重 TTL 与失效通知的受控缓存。"""

    def __init__(self, service: "DiscoveryService | None" = None, *, now: int = 0,
                 default_ttl: int | None = None, **options: Any):
        self.service = service
        self.now = now
        self.default_ttl = default_ttl
        self.options = options
        self._entries: dict[tuple[str, str, str], CacheEntry] = {}
        self.tombstones: set[tuple[str, str, str]] = set()

    @staticmethod
    def make_key(tenant: str, name: str, scope: str = "exact") -> tuple[str, str, str]:
        target, parsed_scope = parse_query_target(name, scope)
        return tenant, target, parsed_scope

    def put(self, result: dict[str, Any], *, force: bool = False) -> dict[str, Any]:
        key = self.make_key(result["tenant"], result["name"], result.get("scope", "exact"))
        at = int(result.get("issued_at", self.now))
        self.now = max(self.now, at)
        response = copy.deepcopy(result)
        # 受控缓存不把 coverage_pending/authority_pending/未证明的撤回当成
        # 可长期复用的结论；调用方仍可从本次响应读取，但缓存键立即失效。
        if result.get("cacheable") is False and not force:
            self.invalidate(result["tenant"], result["name"], result.get("scope", "exact"))
            response["cached"] = False
            return response
        self._entries[key] = CacheEntry(key, copy.deepcopy(result), at)
        self.tombstones.discard(key)
        response["cached"] = True
        return response

    def get(
        self,
        tenant: str,
        name: str,
        scope: str = "exact",
        *,
        at: int | None = None,
        revalidate: bool = True,
        include_stale: bool = False,
    ) -> dict[str, Any] | None:
        key = self.make_key(tenant, name, scope)
        moment = self.now if at is None else at
        self.now = max(self.now, moment)
        entry = self._entries.get(key)
        if entry is None or key in self.tombstones:
            return None
        result = entry.result
        diagnosis = self._local_diagnosis(result, moment)
        if self.service is not None and revalidate and not diagnosis["locally_expired"]:
            remote = self.service.revalidate_result(result, at=moment)
            diagnosis.update({k: remote.get(k) for k in ("valid", "state", "reason", "current")})
            if not remote.get("valid", False):
                diagnosis["stale"] = True
                current = remote.get("current")
                if not include_stale and isinstance(current, dict) and current.get("cacheable") is not False:
                    self.put(current)
                    return copy.deepcopy(current)
        stale = diagnosis.get("stale") or diagnosis.get("locally_expired") or result.get("invalidated")
        if stale:
            self.invalidate(tenant, name, scope)
            if include_stale:
                stale_result = copy.deepcopy(result)
                stale_result["stale_diagnosis"] = diagnosis
                return stale_result
            return None
        return copy.deepcopy(result)

    def require_start_qualification(self, token_or_result: str | dict[str, Any], *, at: int | None = None) -> dict:
        if self.service is None:
            raise DiscoveryError("缓存未绑定 DiscoveryService，无法检查代次资格")
        return self.service.require_start_qualification(token_or_result, at=at)

    def _local_diagnosis(self, result: dict[str, Any], at: int) -> dict[str, Any]:
        until = result.get("until")
        expired = until is not None and at >= int(until)
        return {
            "locally_expired": expired,
            "valid": not expired and not result.get("invalidated", False),
            "state": "expired" if expired else ("invalidated" if result.get("invalidated") else "current"),
            "reason": "ttl_expired" if expired else result.get("invalidated_reason"),
        }

    def invalidate(self, tenant: str, name: str, scope: str = "exact") -> None:
        key = self.make_key(tenant, name, scope)
        self._entries.pop(key, None)
        self.tombstones.add(key)

    def invalidate_matching(self, name: str, *, tenant: str | None = None, scope: str = "exact") -> list[tuple[str, str, str]]:
        """按精确名或前缀失效；tenant=None 表示所有租户缓存键。"""
        target, parsed_scope = parse_query_target(name, scope)
        removed = []
        for key in list(self._entries):
            key_tenant, key_name, key_scope = key
            if tenant is not None and key_tenant != tenant:
                continue
            if parsed_scope == "prefix":
                matches = key_scope == "exact" and prefix_matches(target, key_name) or key_scope == "prefix" and key_name == target
            else:
                matches = key_name == target
            if matches:
                self._entries.pop(key, None)
                self.tombstones.add(key)
                removed.append(key)
        if tenant is not None:
            key = self.make_key(tenant, target, parsed_scope)
            self.tombstones.add(key)
            removed.append(key)
        return removed

    def apply_notification(self, notification: dict[str, Any]) -> dict[str, Any]:
        """应用 watch 输出中的一条通知或整个 watch 响应。"""
        applied: list[dict[str, Any]] = []
        if not isinstance(notification, dict):
            return {"applied": applied, "count": 0}

        raw_items: list[dict[str, Any]]
        if isinstance(notification.get("notifications"), list):
            raw_items = notification["notifications"]
        elif isinstance(notification.get("events"), list):
            raw_items = notification["events"]
        elif isinstance(notification.get("changes"), list):
            raw_items = notification["changes"]
        else:
            raw_items = [notification]

        # watch 响应可能同时在顶层携带最终快照。
        if any(notification.get(k) for k in ("replacement", "snapshot", "view", "current")):
            raw_items.append(notification)

        seen: set[Any] = set()
        items: list[dict[str, Any]] = []
        for item in raw_items:
            key = item.get("seq", id(item))
            if key in seen:
                continue
            seen.add(key)
            items.append(item)

        for item in items:
            replacement = item.get("replacement") or item.get("snapshot") or item.get("current") or item.get("view")
            if replacement and replacement.get("tenant") and replacement.get("name"):
                applied.append(self.put(replacement))
                continue
            tenant = item.get("tenant")
            name = item.get("name") or item.get("prefix")
            invalidates = bool(item.get("invalidates_cache", True) or item.get("invalidates_missing", False))
            if tenant == "*":
                tenant = None
            if name and invalidates:
                kind = item.get("kind", "")
                event_scope = item.get("scope")
                if event_scope is None:
                    event_scope = "prefix" if kind in {"delegation_changed", "cover_updated"} else "exact"
                event_tenants = item.get("tenants")
                if tenant is None and isinstance(event_tenants, list) and not item.get("all_tenants") and "*" not in event_tenants:
                    removed = []
                    for allowed_tenant in event_tenants:
                        removed.extend(self.invalidate_matching(name, tenant=str(allowed_tenant), scope=event_scope))
                else:
                    removed = self.invalidate_matching(name, tenant=tenant, scope=event_scope)
                applied.append({"invalidated": removed})
        return {"applied": applied, "count": len(applied)}


class DiscoveryService:
    """事件溯源的联合发现服务。"""

    def __init__(self, now: int = 0, retain_events: int | None = None, **options: Any):
        self.now = now
        self.retain_events = retain_events
        self.options = options
        self.seq = 0
        self.authority_revision = 0
        self.trim_through = 0
        self.restart_count = 0
        self.events: list[dict[str, Any]] = []
        self.delegations: dict[str, dict[str, Any]] = {}
        self.authority_history: list[dict[str, Any]] = []
        self.catalogs: dict[str, dict[str, Any]] = {}
        self.covers: list[dict[str, Any]] = []
        self.fenced_reports: list[dict[str, Any]] = []
        self.subscriptions: dict[str, dict[str, Any]] = {}
        self.clients: dict[str, dict[str, Any]] = {}
        self.results: dict[str, dict[str, Any]] = {}
        self.results_by_version: dict[int, str] = {}
        self.qualifications: dict[str, dict[str, Any]] = {}
        self.unreachable_holders: set[str] = set()
        self.unreachable_prefixes: dict[str, str] = {}
        self._result_counter = 0
        self._qual_counter = 0
        self._sub_counter = 0

    # ------------------------------------------------------------------
    # 输入入口
    # ------------------------------------------------------------------
    def handle(self, message: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(message, dict):
            raise DiscoveryError("消息必须是对象")
        kind = message.get("kind") or message.get("type") or message.get("message_type")
        if "record" in message and isinstance(message["record"], dict):
            record = message["record"]
        elif kind in MESSAGE_KINDS and ("prefix" in message or "holder" in message or "tenant" in message or "through" in message or "client" in message):
            # 兼容扁平消息：{"type":"delegate","prefix":...}。
            record = {k: v for k, v in message.items() if k not in {"at", "kind", "type", "message_type"}}
        else:
            record = message.get("record", {})
        at_value = message.get("at", self.now)
        if isinstance(at_value, str) and at_value.isdigit():
            at_value = int(at_value)
        if type(at_value) is not int or at_value < 0:
            raise DiscoveryError("at 必须是非负整数")
        at = at_value
        if not isinstance(kind, str) or kind not in MESSAGE_KINDS:
            raise DiscoveryError(f"未登记/未支持的消息名称: {kind}")
        if not isinstance(record, dict):
            raise DiscoveryError("record 应为对象")
        self._set_time(at)
        handler = {
            "delegate": self.handle_delegate,
            "service": self.handle_service,
            "cover": self.handle_cover,
            "query": self.handle_query_message,
            "watch": self.handle_watch_message,
            "trim": self.handle_trim,
            "restart": self.handle_restart,
            "inspect": self.handle_inspect_message,
        }.get(kind)
        if handler is None:
            raise DiscoveryError(f"未支持的消息类型: {kind}")
        response = handler(record, at=at)
        report = {"at": at, "kind": kind, "ok": response.get("ok", True)}
        if isinstance(response, dict):
            report.update(response)
        return report

    def ingest(self, message: dict[str, Any] | str | None = None, record: dict[str, Any] | None = None,
               *, kind: str | None = None, at: int | None = None, **kwargs: Any) -> dict[str, Any]:
        """兼容 dict 信封、扁平 dict 和 ``ingest("query", record={...})`` 调用。"""
        if isinstance(message, str):
            kind = message
            message = None
        if message is not None:
            return self.handle(message)
        if kind is None:
            raise DiscoveryError("ingest 需要消息 dict 或 kind")
        payload_record = record if record is not None else kwargs
        return self.handle({"at": self.now if at is None else at, "kind": kind, "record": payload_record})

    process_message = ingest
    submit_message = ingest
    on_message = ingest
    process_event = ingest

    def process_records(self, rows: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
        return [self.handle(row) for row in rows]

    def run_file(self, path: str | Path) -> list[dict[str, Any]]:
        path = Path(path)
        types = set(json.loads((Path(__file__).with_name("examples") / "message_types.json").read_text("utf-8")))
        return self.process_records(iter_messages(path, types))

    # 便于不同调用习惯使用的别名。
    process_message = handle
    dispatch = handle

    # ------------------------------------------------------------------
    # 时间、事件和 ID
    # ------------------------------------------------------------------
    def _set_time(self, at: int) -> None:
        if at >= self.now:
            self.now = at
            self._expire_due(at)
        else:
            self.now = at

    def _new_id(self, prefix: str) -> str:
        if prefix == "res":
            self._result_counter += 1
            return f"res-{self._result_counter}"
        if prefix == "qual":
            self._qual_counter += 1
            return f"qual-{self._qual_counter}"
        if prefix == "sub":
            self._sub_counter += 1
            return f"sub-{self._sub_counter}"
        self._result_counter += 1
        return f"{prefix}-{self._result_counter}"

    def _emit(self, kind: str, at: int, **payload: Any) -> dict[str, Any]:
        self.seq += 1
        event = {"seq": self.seq, "at": at, "kind": kind, "event": kind, **payload}
        self.events.append(event)
        if self.retain_events is not None and len(self.events) > self.retain_events:
            removed = self.events[: -self.retain_events]
            self.events = self.events[-self.retain_events :]
            self.trim_through = max(self.trim_through, removed[-1]["seq"])
        return event

    def _events_after(self, after: int) -> list[dict[str, Any]]:
        return [copy.deepcopy(e) for e in self.events if e["seq"] > after]

    def retained_from(self) -> int:
        return self.trim_through + 1

    # ------------------------------------------------------------------
    # 委托和管辖方
    # ------------------------------------------------------------------
    def handle_delegate(self, record: dict[str, Any], *, at: int) -> dict[str, Any]:
        prefix = normalize_prefix(record.get("prefix"))
        epoch = record.get("epoch")
        holder = record.get("holder", None)
        if not isinstance(epoch, int) or isinstance(epoch, bool) or epoch < 1:
            raise DiscoveryError("delegate.epoch 必须是正整数")
        action = str(record.get("action", "")).lower()
        state = str(record.get("state", "")).lower()
        revoked = bool(
            record.get("revoked")
            or record.get("revoke")
            or record.get("active") is False
            or action in {"revoke", "revoked", "remove", "release", "reclaim"}
            or state in {"revoked", "inactive", "removed"}
            or holder is None
            or holder == ""
        )
        if not revoked and (not isinstance(holder, str) or not holder):
            raise DiscoveryError("有效委托需要 holder，或用 holder=null/revoked=true 表示收回")

        old = self.delegations.get(prefix)
        if old and epoch < int(old["epoch"]):
            report = {
                "ok": False,
                "accepted": False,
                "status": "fenced",
                "reason": "stale_delegation_epoch",
                "prefix": prefix,
                "current_epoch": old["epoch"],
                "record_epoch": epoch,
            }
            self.fenced_reports.append({"at": at, "kind": "delegate", **record, "diagnosis": report})
            return report
        if old and epoch == int(old["epoch"]):
            same = bool(old["active"]) == (not revoked) and old.get("holder") == holder
            if same:
                return {"ok": True, "accepted": True, "idempotent": True, "delegation": copy.deepcopy(old)}
            report = {
                "ok": False,
                "accepted": False,
                "status": "epoch_conflict",
                "reason": "conflicting_delegation_for_same_epoch",
                "prefix": prefix,
                "existing": copy.deepcopy(old),
                "incoming": dict(record),
            }
            return report

        previous = copy.deepcopy(old) if old else None
        change = "established"
        if old:
            if revoked:
                change = "revoked"
            elif old.get("holder") != holder:
                change = "transferred"
            else:
                change = "reepoch"
        elif revoked:
            change = "revoked_unknown_prefix"

        generation = self._generation(prefix, holder if not revoked else None, epoch)
        delegation = {
            "prefix": prefix,
            "holder": holder if not revoked else None,
            "last_holder": holder if holder is not None else (old or {}).get("last_holder") or (old or {}).get("holder"),
            "epoch": epoch,
            "generation": generation,
            "active": not revoked,
            "established_at": at,
            "updated_at": at,
            "change": change,
        }
        self.delegations[prefix] = delegation
        self.authority_revision += 1
        history_row = {
            "at": at,
            "prefix": prefix,
            "epoch": epoch,
            "holder": delegation["holder"],
            "active": delegation["active"],
            "generation": generation,
            "change": change,
            "authority_revision": self.authority_revision,
        }
        self.authority_history.append(history_row)
        event = self._emit(
            "delegation_changed",
            at,
            change=change,
            prefix=prefix,
            name=prefix,
            scope_prefix=prefix,
            holder=delegation["holder"],
            epoch=epoch,
            generation=generation,
            active=not revoked,
            previous=previous,
            tenant="*",
            all_tenants=True,
            invalidates_cache=True,
            authority_revision=self.authority_revision,
        )
        return {"ok": True, "accepted": True, "delegation": copy.deepcopy(delegation), "event": copy.deepcopy(event)}

    def delegate(self, prefix: str, holder: str | None, epoch: int, *, at: int | None = None, **extra: Any):
        record = {"prefix": prefix, "holder": holder, "epoch": epoch, **extra}
        return self.handle_delegate(record, at=self.now if at is None else at)

    def revoke_prefix(self, prefix: str, epoch: int, *, holder: str | None = None, at: int | None = None):
        return self.delegate(prefix, holder, epoch, at=at, revoked=True)

    @staticmethod
    def _generation(prefix: str, holder: str | None, epoch: int) -> str:
        scope = prefix or "<root>"
        actor = holder or "parent"
        return f"{scope}#{epoch}@{actor}"

    def authority_for(self, name: str) -> dict[str, Any] | None:
        name = normalize_name(name)
        matches = [
            d
            for p, d in self.delegations.items()
            if d.get("active") and prefix_matches(p, name)
        ]
        if not matches:
            return None
        chosen = max(matches, key=lambda d: prefix_depth(d["prefix"]))
        return copy.deepcopy(chosen)

    def _authority_or_gap(self, name: str, at: int) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
        authority = self.authority_for(name)
        if authority:
            if authority["holder"] in self.unreachable_holders or authority["prefix"] in self.unreachable_prefixes:
                authority = copy.deepcopy(authority)
                authority["source_state"] = "unreachable"
                authority["unreachable_reason"] = self.unreachable_prefixes.get(authority["prefix"], "holder_unreachable")
            return authority, None
        return None, {
            "code": "no_authority",
            "meaning": "unassigned_or_parent_unreachable",
            "message": "没有覆盖该名字的有效委托；不能证明缺失",
        }

    def set_source_reachable(self, reachable: bool = True, *, holder: str | None = None, prefix: str | None = None, reason: str = "upstream_disconnected"):
        if holder:
            if reachable:
                self.unreachable_holders.discard(holder)
            else:
                self.unreachable_holders.add(holder)
        if prefix is not None:
            p = normalize_prefix(prefix)
            if reachable:
                self.unreachable_prefixes.pop(p, None)
            else:
                self.unreachable_prefixes[p] = reason
        return {"unreachable_holders": sorted(self.unreachable_holders), "unreachable_prefixes": self.unreachable_prefixes}

    # ------------------------------------------------------------------
    # 服务端点和撤回
    # ------------------------------------------------------------------
    def _catalog(self, name: str) -> dict[str, Any]:
        name = normalize_name(name)
        if name not in self.catalogs:
            self.catalogs[name] = {"name": name, "endpoints": {}, "tombstones": [], "reports": [], "latest_revision": 0}
        return self.catalogs[name]

    def handle_service(self, record: dict[str, Any], *, at: int) -> dict[str, Any]:
        name = normalize_name(record.get("name"))
        authority = self.authority_for(name)
        holder = record.get("holder")
        epoch = record.get("epoch")
        revision = record.get("revision", 1)
        if not isinstance(epoch, int) or isinstance(epoch, bool) or epoch < 1:
            raise DiscoveryError("service.epoch 必须是正整数")
        if not isinstance(revision, int) or isinstance(revision, bool) or revision < 1:
            raise DiscoveryError("service.revision 必须是正整数")
        if authority is None or holder != authority["holder"] or epoch != authority["epoch"]:
            diagnosis = {
                "ok": False,
                "accepted": False,
                "status": "fenced",
                "reason": "wrong_authority_generation",
                "name": name,
                "required_authority": authority,
                "record_holder": holder,
                "record_epoch": epoch,
            }
            self.fenced_reports.append({"at": at, "kind": "service", "record": copy.deepcopy(record), "diagnosis": diagnosis})
            return diagnosis

        catalog = self._catalog(name)
        tenant_declaration = record.get(
            "tenants",
            record.get("allowed_tenants", record.get("tenant", record.get("visibility", None))),
        )
        tenants = _tenant_list(tenant_declaration)
        tenants_provided = any(k in record for k in ("tenants", "allowed_tenants", "tenant", "visibility"))
        until = _finite_until(record.get("until", record.get("expires_at")), at, record.get("ttl"))
        generation = authority["generation"]
        endpoint_value = record.get("endpoint", "__missing__")
        is_withdrawal = endpoint_value is None or record.get("withdrawn") is True or record.get("withdraw") is True
        target_endpoint = record.get("endpoint_id") or record.get("target")

        if is_withdrawal:
            return self._apply_withdrawal(
                catalog, authority, generation, revision, tenants, until, at, record,
                target_endpoint=target_endpoint, tenants_provided=tenants_provided,
            )

        endpoint_id = str(endpoint_value)
        existing = catalog["endpoints"].get(endpoint_id)
        if existing and existing.get("generation") == generation and revision < int(existing.get("revision", 0)):
            return {
                "ok": True,
                "accepted": False,
                "status": "stale_revision_ignored",
                "name": name,
                "endpoint": endpoint_id,
                "current_revision": existing["revision"],
                "record_revision": revision,
            }
        endpoint = {
            "id": endpoint_id,
            "endpoint": endpoint_id,
            "name": name,
            "holder": holder,
            "epoch": epoch,
            "authority_prefix": authority["prefix"],
            "generation": generation,
            "revision": revision,
            "tenants": tenants,
            "until": until,
            "expires_at": until,
            "reported_at": at,
            "status": "active",
            "withdrawn_at": None,
        }
        catalog["endpoints"][endpoint_id] = endpoint
        catalog["latest_revision"] = max(catalog["latest_revision"], revision)
        catalog["reports"].append({"at": at, "type": "upsert", "endpoint": endpoint_id, "revision": revision, "generation": generation})
        event = self._emit(
            "service_changed",
            at,
            change="endpoint_registered" if existing is None else "endpoint_updated",
            name=name,
            prefix=name,
            scope_prefix=authority["prefix"],
            endpoint=endpoint_id,
            endpoint_id=endpoint_id,
            revision=revision,
            generation=generation,
            authority=copy.deepcopy(authority),
            tenants=tenants,
            until=until,
            expires_at=until,
            tenant="*",
            all_tenants=False,
            invalidates_missing=True,
            invalidates_cache=False,
            endpoint_view=copy.deepcopy(endpoint),
        )
        self._invalidate_matching_results(name=name, tenant=None, at=at, seq=event["seq"], reason="endpoint_registered", tenants=tenants)
        return {"ok": True, "accepted": True, "endpoint": copy.deepcopy(endpoint), "event": copy.deepcopy(event)}

    def register_service(self, name: str, endpoint: str, *, holder: str, epoch: int, revision: int,
                         tenants: Any = None, until: int | None = None, at: int | None = None, **extra: Any):
        record = {
            "name": name, "endpoint": endpoint, "holder": holder, "epoch": epoch,
            "revision": revision, "tenants": tenants, "until": until, **extra,
        }
        if tenants is None:
            record.pop("tenants")
        return self.handle_service(record, at=self.now if at is None else at)

    def _apply_withdrawal(self, catalog, authority, generation, revision, tenants, until, at, record, *,
                          target_endpoint=None, tenants_provided=False):
        affected: list[dict[str, Any]] = []
        if target_endpoint:
            ep = catalog["endpoints"].get(str(target_endpoint))
            if ep and ep.get("generation") == generation and revision >= int(ep.get("revision", 0)):
                ep["status"] = "withdrawn"
                ep["withdrawn_at"] = at
                ep["withdrawal_revision"] = revision
                affected.append(copy.deepcopy(ep))
        else:
            for ep in catalog["endpoints"].values():
                if ep.get("generation") == generation and ep.get("status") == "active" and revision >= int(ep.get("revision", 0)):
                    ep["status"] = "withdrawn"
                    ep["withdrawn_at"] = at
                    ep["withdrawal_revision"] = revision
                    affected.append(copy.deepcopy(ep))
        tombstone = {
            "name": catalog["name"],
            "revision": revision,
            "generation": generation,
            "authority": copy.deepcopy(authority),
            "tenants": sorted({t for ep in affected for t in ep.get("tenants", [])} | set(tenants)),
            "until": until,
            "at": at,
            "target_endpoint": str(target_endpoint) if target_endpoint else None,
        }
        catalog["tombstones"].append(tombstone)
        catalog["latest_revision"] = max(catalog["latest_revision"], revision)
        catalog["reports"].append({"at": at, "type": "withdraw", "revision": revision, "generation": generation, "affected": [e["id"] for e in affected]})
        visible_tenants = sorted({t for ep in affected for t in ep.get("tenants", [])})
        if "*" in visible_tenants:
            visible_tenants = ["*"]
        if visible_tenants:
            event_tenants = visible_tenants
            all_tenants = "*" in visible_tenants
        elif tenants_provided:
            event_tenants = tenants
            all_tenants = "*" in tenants
        else:
            event_tenants = ["*"]
            all_tenants = True
        event = self._emit(
            "service_changed",
            at,
            change="endpoint_withdrawn",
            name=catalog["name"],
            prefix=catalog["name"],
            scope_prefix=authority["prefix"],
            endpoint=None,
            endpoint_id=target_endpoint,
            revision=revision,
            generation=generation,
            authority=copy.deepcopy(authority),
            tenants=event_tenants,
            affected_endpoints=[e["id"] for e in affected],
            affected_views=copy.deepcopy(affected),
            tenant="*",
            all_tenants=all_tenants,
            invalidates_cache=True,
            withdrawal=copy.deepcopy(tombstone),
        )
        # 撤回必须让所有持有该名字结果的租户重新读取；响应中不会再带旧端点。
        self._invalidate_matching_results(name=catalog["name"], tenant=None, at=at, seq=event["seq"], reason="endpoint_withdrawn", tenants=None, all_tenants=True)
        return {"ok": True, "accepted": True, "withdrawn": copy.deepcopy(tombstone), "affected": affected, "event": copy.deepcopy(event)}

    def withdraw_service(self, name: str, *, holder: str, epoch: int, revision: int,
                         endpoint_id: str | None = None, at: int | None = None, **extra):
        record = {"name": name, "endpoint": None, "holder": holder, "epoch": epoch,
                  "revision": revision, "endpoint_id": endpoint_id, **extra}
        return self.handle_service(record, at=self.now if at is None else at)

    def _expire_due(self, at: int) -> None:
        for catalog in self.catalogs.values():
            for ep in catalog["endpoints"].values():
                if ep.get("status") == "active" and ep.get("until") is not None and at >= int(ep["until"]):
                    ep["status"] = "expired"
                    ep["expired_at"] = at
                    event = self._emit(
                        "endpoint_expired",
                        at,
                        change="endpoint_expired",
                        name=ep["name"],
                        prefix=ep["name"],
                        scope_prefix=ep.get("authority_prefix"),
                        endpoint=ep["id"],
                        endpoint_id=ep["id"],
                        revision=ep["revision"],
                        generation=ep["generation"],
                        tenants=ep["tenants"],
                        tenant="*",
                        invalidates_cache=True,
                        endpoint_view=copy.deepcopy(ep),
                    )
                    self._invalidate_matching_results(
                        name=ep["name"], tenant=None, at=at, seq=event["seq"],
                        reason="endpoint_ttl_expired", tenants=ep["tenants"]
                    )

    # ------------------------------------------------------------------
    # Cover 证明
    # ------------------------------------------------------------------
    def handle_cover(self, record: dict[str, Any], *, at: int) -> dict[str, Any]:
        prefix = normalize_prefix(record.get("prefix"))
        holder = record.get("holder")
        epoch = record.get("epoch")
        revision = record.get("revision")
        until = record.get("until")
        if not isinstance(epoch, int) or isinstance(epoch, bool) or epoch < 1:
            raise DiscoveryError("cover.epoch 必须是正整数")
        if not isinstance(revision, int) or isinstance(revision, bool) or revision < 1:
            raise DiscoveryError("cover.revision 必须是正整数")
        if not isinstance(until, int) or isinstance(until, bool):
            raise DiscoveryError("cover.until 必须是整数过期秒点")
        authority = self.authority_for(prefix or "<root>")
        # cover 的 prefix 可能比委托前缀更具体；按该 prefix 的管辖方鉴权。
        authority_for_cover = self.authority_for(prefix) if prefix else authority
        if authority_for_cover is None or holder != authority_for_cover["holder"] or epoch != authority_for_cover["epoch"]:
            diagnosis = {
                "ok": False,
                "accepted": False,
                "status": "fenced",
                "reason": "cover_from_old_or_wrong_generation",
                "prefix": prefix,
                "required_authority": authority_for_cover,
                "record_holder": holder,
                "record_epoch": epoch,
            }
            proof = {
                "prefix": prefix, "holder": holder, "epoch": epoch, "revision": revision,
                "until": until, "received_at": at, "current": False, "fenced": True,
            }
            self.covers.append(proof)
            self.fenced_reports.append({"at": at, "kind": "cover", "record": copy.deepcopy(record), "diagnosis": diagnosis})
            return diagnosis

        existing = [c for c in self.covers if c["prefix"] == prefix and c["generation"] == authority_for_cover["generation"] and not c.get("fenced")]
        if existing and revision < max(c["revision"] for c in existing):
            return {"ok": True, "accepted": False, "status": "stale_cover_revision_ignored", "prefix": prefix}
        proof = {
            "id": f"cover-{len(self.covers) + 1}",
            "prefix": prefix,
            "holder": holder,
            "epoch": epoch,
            "generation": authority_for_cover["generation"],
            "authority_prefix": authority_for_cover["prefix"],
            "revision": revision,
            "covered_revision": revision,
            "until": until,
            "expires_at": until,
            "received_at": at,
            "current": True,
            "fenced": False,
        }
        self.covers.append(proof)
        event = self._emit(
            "cover_updated",
            at,
            change="coverage_proof_updated",
            prefix=prefix,
            name=prefix,
            scope_prefix=prefix,
            revision=revision,
            until=until,
            expires_at=until,
            generation=proof["generation"],
            proof=copy.deepcopy(proof),
            tenant="*",
            all_tenants=True,
            invalidates_cache=False,
        )
        return {"ok": True, "accepted": True, "proof": copy.deepcopy(proof), "event": copy.deepcopy(event)}

    def cover_prefix(self, prefix: str, *, holder: str, epoch: int, revision: int, until: int, at: int | None = None):
        return self.handle_cover(
            {"prefix": prefix, "holder": holder, "epoch": epoch, "revision": revision, "until": until},
            at=self.now if at is None else at,
        )

    def _applicable_covers(self, name: str, authority: dict[str, Any], at: int, *, valid_only: bool = True) -> list[dict[str, Any]]:
        result = []
        for cover in self.covers:
            if cover.get("fenced") or cover.get("generation") != authority["generation"]:
                continue
            if not prefix_matches(cover["prefix"], name):
                continue
            if valid_only and at >= int(cover["until"]):
                continue
            result.append(copy.deepcopy(cover))
        result.sort(key=lambda c: (prefix_depth(c["prefix"]), c["revision"], c["until"]), reverse=True)
        return result

    def _coverage_diagnosis(self, name: str, authority: dict[str, Any] | None, at: int, *, aggregate: bool = False) -> dict[str, Any]:
        if authority is None:
            return {"complete": False, "proof": None, "gaps": [{"code": "no_authority", "prefix": None, "message": "没有当前管辖委托"}]}
        covers = self._applicable_covers(name, authority, at, valid_only=True)
        all_current = self._applicable_covers(name, authority, at, valid_only=False)
        if aggregate:
            latest_revision = max(
                (catalog["latest_revision"] for catalog_name, catalog in self.catalogs.items() if prefix_matches(name, catalog_name)),
                default=0,
            )
        else:
            catalog = self.catalogs.get(name)
            latest_revision = catalog["latest_revision"] if catalog else 0
        if not all_current:
            gap = {"code": "cover_missing", "prefix": authority["prefix"], "meaning": "当前管辖方尚未给出覆盖证据",
                   "message": f"管辖方 {authority.get('holder')}#{authority.get('epoch')} 尚未为 {name} 提供有效 cover"}
            return {"complete": False, "proof": None, "covers": [], "gaps": [gap], "latest_revision": latest_revision}
        expired = [c for c in all_current if at >= int(c["until"])]
        if not covers:
            return {
                "complete": False, "proof": None, "covers": all_current,
                "gaps": [{"code": "cover_expired", "prefix": all_current[0]["prefix"], "until": all_current[0]["until"],
                          "message": f"cover 已在 {all_current[0]['until']} 过期，不能继续证明范围完整"}],
                "latest_revision": latest_revision,
            }
        proof = covers[0]
        if int(proof["revision"]) < latest_revision:
            return {
                "complete": False, "proof": proof, "covers": covers,
                "gaps": [{
                    "code": "cover_behind",
                    "prefix": proof["prefix"],
                    "covered_revision": proof["revision"],
                    "latest_revision": latest_revision,
                    "message": f"cover 只到修订 {proof['revision']}，目录已出现修订 {latest_revision}；需等待追齐证明",
                }],
                "latest_revision": latest_revision,
            }
        return {"complete": True, "proof": proof, "covers": covers, "gaps": [], "latest_revision": latest_revision}

    # ------------------------------------------------------------------
    # 查询和一致结果
    # ------------------------------------------------------------------
    def handle_query_message(self, record: dict[str, Any], *, at: int) -> dict[str, Any]:
        tenant = record.get("tenant")
        name = record.get("name", record.get("prefix", record.get("scope_prefix")))
        if not tenant:
            raise DiscoveryError("query 需要 tenant")
        query_id = record.get("query") or record.get("query_id") or record.get("id")
        mode = record.get("mode", "start")
        scope = record.get("scope")
        if "prefix" in record and record.get("name") is None:
            scope = "prefix"
        prior = record.get("version", record.get("result_version", record.get("based_on", record.get("after_version"))))
        if prior is None and mode == "inspect" and query_id and f"query:{query_id}" in self.results:
            prior = self.results[f"query:{query_id}"]
        return self.query(
            str(tenant), str(name), query_id=query_id, mode=mode, scope=scope,
            prior=prior, at=at, client=record.get("client"),
            include_historical=record.get("include_historical", True),
        )

    def query(
        self,
        tenant: str,
        name: str | None = None,
        *,
        prefix: str | None = None,
        query_id: str | None = None,
        mode: str = "start",
        scope: str | None = None,
        prior: Any = None,
        at: int | None = None,
        client: str | None = None,
        include_historical: bool = True,
    ) -> dict[str, Any]:
        if name is None:
            name = prefix
        if name is None:
            raise DiscoveryError("query 需要 name 或 prefix")
        moment = self.now if at is None else at
        self._set_time(moment)
        target, parsed_scope = parse_query_target(name, scope or ("prefix" if prefix is not None else None))
        if parsed_scope == "prefix":
            result = self.query_prefix(tenant, target, query_id=query_id, at=moment, prior=prior)
        else:
            result = self._build_exact_result(
                str(tenant), target, moment, query_id=query_id, mode=mode,
                include_historical=include_historical, client=client,
            )
        if prior is not None:
            result["reread"] = self._reread_diagnosis(prior, result, moment)
            reread_state = result["reread"].get("state")
            result["unchanged"] = reread_state == "unchanged"
            result["not_modified"] = reread_state == "unchanged"
            result["changed"] = reread_state != "unchanged"
            result["superseded"] = reread_state in {"changed", "invalidated", "expired", "authority_changed"}
            result["reread_status"] = 304 if reread_state == "unchanged" else 200
        if client:
            self._associate_result_to_client(client, result)
        return copy.deepcopy(result)

    def _build_exact_result(
        self,
        tenant: str,
        name: str,
        at: int,
        *,
        query_id: str | None = None,
        mode: str = "start",
        include_historical: bool = True,
        client: str | None = None,
    ) -> dict[str, Any]:
        authority, authority_gap = self._authority_or_gap(name, at)
        catalog = self.catalogs.get(name)
        all_endpoints = list(catalog["endpoints"].values()) if catalog else []
        current_endpoints = [e for e in all_endpoints if authority and e.get("generation") == authority["generation"]]
        valid_now = [e for e in current_endpoints if e.get("status") == "active" and (e.get("until") is None or at < int(e["until"]))]
        visible = [copy.deepcopy(e) for e in valid_now if _visible(e.get("tenants", []), tenant)]
        visible.sort(key=lambda e: e["id"])
        hidden_active = [e for e in valid_now if not _visible(e.get("tenants", []), tenant)]
        coverage = self._coverage_diagnosis(name, authority, at) if authority else {
            "complete": False, "proof": None, "gaps": [authority_gap], "latest_revision": 0
        }
        historical = self._historical_basis(name, tenant, at, authority) if include_historical else None

        result_id = self._new_id("res")
        version = self._result_counter
        consistency = self.consistency_token()
        result: dict[str, Any] = {
            "ok": True,
            "result_id": result_id,
            "id": result_id,
            "version": version,
            "result_version": version,
            "etag": f'W/"v{version}-s{self.seq}-a{self.authority_revision}"',
            "query_id": query_id,
            "query": query_id,
            "mode": mode,
            "tenant": tenant,
            "name": name,
            "scope": "exact",
            "at": at,
            "issued_at": at,
            "view_seq": self.seq,
            "seq": self.seq,
            "authority_revision": self.authority_revision,
            "consistency_token": consistency,
            "authority": authority,
            "endpoints": visible,
            "records": visible,
            "coverage": coverage,
            "proof": coverage.get("proof"),
            "historical_basis": historical,
            "historical_endpoints": (historical or {}).get("endpoints", []),
            "stale_endpoints": (historical or {}).get("endpoints", []),
            "invalidated": False,
            "invalidated_by": None,
            "reread_supported": True,
        }

        finite = [e["until"] for e in visible if e.get("until") is not None]
        endpoint_until = min(finite) if finite else None
        result["endpoint_until"] = endpoint_until

        if authority is None:
            status = "upstream_unreachable" if authority_gap and authority_gap["code"] != "no_authority" else "unassigned"
            if self.unreachable_holders or self.unreachable_prefixes:
                status = "upstream_unreachable"
            result.update({
                "status": status,
                "state": status,
                "meaning": status,
                "usable": False,
                "authoritative": False,
                "can_start": False,
                "start_allowed": False,
                "cacheable": False,
                "negative_cacheable": False,
                "may_close_job": False,
                "until": None,
                "ttl": None,
                "gaps": coverage.get("gaps", []),
                "reason": "authority_unavailable",
            })
        elif visible:
            result.update({
                "status": "found",
                "state": "ready",
                "ready": True,
                "has_endpoints": True,
                "meaning": "endpoints_available",
                "usable": True,
                "authoritative": True,
                "can_start": True,
                "start_allowed": True,
                "cacheable": True,
                "negative_cacheable": False,
                "may_close_job": False,
                "until": endpoint_until,
                "expires_at": endpoint_until,
                "ttl": None if endpoint_until is None else max(0, endpoint_until - at),
                "gaps": coverage.get("gaps", []),
            })
            qual = self._issue_qualification(result, at, client=client)
            result["qualification"] = qual
            result["lease"] = qual
            result["capability"] = qual
            result["start_token"] = qual["id"]
            result["start_lease"] = qual["id"]
        else:
            self._fill_empty_status(result, authority, coverage, current_endpoints, hidden_active, catalog, at, historical)

        self.results[result_id] = result
        self.results_by_version[version] = result_id
        if query_id:
            # 允许用 query 身份找到最近一次结果。
            self.results[f"query:{query_id}"] = result  # type: ignore[index]
        return result

    def _later_change_is_applicable_to_tenant(self, catalog: dict[str, Any] | None, authority: dict[str, Any],
                                              covered_revision: int, tenant: str) -> bool:
        """cover 之后的已知修订是否可能改变该租户的视图。

        另一租户的端点对当前租户不是“适用变更”；但当前租户曾可见的端点撤回/过期，
        或名字级 tombstone，仍意味着 cover 本身没有完整证明当前空视图。
        """
        if not catalog:
            return False
        generation = authority["generation"]
        for ep in catalog["endpoints"].values():
            if ep.get("generation") != generation or int(ep.get("revision", 0)) <= covered_revision:
                continue
            if _visible(ep.get("tenants", []), tenant):
                return True
        for tombstone in catalog.get("tombstones", []):
            if tombstone.get("generation") != generation or int(tombstone.get("revision", 0)) <= covered_revision:
                continue
            target = tombstone.get("target_endpoint")
            if not target:
                return True
            ep = catalog["endpoints"].get(target)
            if ep is None or _visible(ep.get("tenants", []), tenant):
                return True
        return False

    def _fill_empty_status(self, result, authority, coverage, current_endpoints, hidden_active, catalog, at, historical):
        latest_revision = catalog["latest_revision"] if catalog else 0
        current_tombstones = [t for t in (catalog["tombstones"] if catalog else []) if t.get("generation") == authority["generation"]]
        latest_tombstone = max(current_tombstones, key=lambda t: t["revision"], default=None)
        proof = coverage.get("proof") if coverage.get("complete") else None
        tenant_scoped_proof = False
        tenant = result["tenant"]
        if proof is None and coverage.get("proof"):
            candidate = coverage["proof"]
            gap_codes = {g.get("code") for g in coverage.get("gaps", [])}
            if "cover_behind" in gap_codes and not self._later_change_is_applicable_to_tenant(
                catalog, authority, int(candidate["revision"]), tenant
            ):
                proof = candidate
                tenant_scoped_proof = True
        source_unreachable = authority.get("source_state") == "unreachable"

        # 有完整证明且证明覆盖该名字的最新版本，才能签发带 TTL 的缺失结果。
        if proof is not None:
            globally_live = [e for e in current_endpoints if e.get("status") == "active" and (e.get("until") is None or at < int(e["until"]))]
            globally_absent = not globally_live
            explicit = latest_tombstone is not None and latest_tombstone["revision"] <= int(proof["revision"])
            until = int(proof["until"])
            if tenant_scoped_proof:
                meaning = "tenant_scoped_absence_proven"
                reason = "later_revisions_only_hidden_from_tenant"
            elif explicit:
                meaning = "explicit_no_result"
                reason = "explicit_tombstone_covered"
            else:
                meaning = "proven_absent"
                reason = "complete_coverage_without_record"
            result.update({
                "status": "explicit_empty" if explicit and not tenant_scoped_proof else "missing",
                "state": "not_found",
                "meaning": meaning,
                "not_found": True,
                "withdrawn": explicit,
                "proven_absent": globally_absent and not explicit and not tenant_scoped_proof,
                "tenant_scoped_proof": tenant_scoped_proof,
                "globally_absent": globally_absent,
                "tenant_view_empty": True,
                "explicit_withdrawal": explicit,
                "usable": True,
                "authoritative": True,
                "can_start": False,
                "start_allowed": False,
                "cacheable": True,
                "negative_cacheable": True,
                "may_close_job": True,
                "until": until,
                "expires_at": until,
                "ttl": max(0, until - at),
                "gaps": [],
                "reason": reason,
            })
            result["coverage"]["tenant_scoped_complete"] = tenant_scoped_proof
            if tenant_scoped_proof:
                result["coverage"]["effective_proof"] = proof
            qual = self._issue_qualification(result, at, kind="negative_decision")
            result["qualification"] = qual
            result["negative_token"] = qual["id"]
            result["negative_lease"] = qual
            return

        # 当前管辖方已经明确撤回，但 cover 尚未追齐：知道现在没有端点，
        # 却不能把“整个范围为空”做成带有效期的负缓存。
        if latest_tombstone is not None:
            result.update({
                "status": "explicit_empty",
                "state": "withdrawn_uncovered",
                "meaning": "explicit_no_result_without_complete_proof",
                "not_found": True,
                "withdrawn": True,
                "explicit_withdrawal": True,
                "usable": True,
                "authoritative": True,
                "can_start": False,
                "start_allowed": False,
                "cacheable": False,
                "negative_cacheable": False,
                "may_close_job": True,
                "until": None,
                "ttl": None,
                "gaps": coverage.get("gaps", []),
                "reason": "withdrawal_known_but_coverage_incomplete",
            })
            return

        if source_unreachable:
            result.update({
                "status": "upstream_unreachable",
                "state": "unknown",
                "meaning": "upstream_connection_lost",
                "usable": False,
                "authoritative": False,
                "can_start": False,
                "start_allowed": False,
                "cacheable": False,
                "negative_cacheable": False,
                "may_close_job": False,
                "until": None,
                "ttl": None,
                "gaps": coverage.get("gaps", []),
                "reason": authority.get("unreachable_reason", "holder_unreachable"),
                "unreachable": True,
                "upstream_unreachable": True,
            })
            return

        if historical and historical.get("endpoints"):
            reason = "new_authority_has_not_caught_up"
            status = "authority_pending"
        else:
            reason = (coverage.get("gaps") or [{}])[0].get("code", "coverage_pending")
            status = "coverage_pending"
        result.update({
            "status": status,
            "state": "incomplete",
            "meaning": "coverage_not_yet_proven",
            "usable": False,
            "authoritative": False,
            "can_start": False,
            "start_allowed": False,
            "cacheable": False,
            "negative_cacheable": False,
            "may_close_job": False,
            "until": None,
            "ttl": None,
            "gaps": coverage.get("gaps", []),
            "reason": reason,
            "pending": True,
            "coverage_pending": status == "coverage_pending",
            "authority_pending": status == "authority_pending",
            "generation_changed": status == "authority_pending",
        })

    def query_prefix(self, tenant: str, prefix: str, *, query_id=None, at: int | None = None, prior=None) -> dict[str, Any]:
        moment = self.now if at is None else at
        self._set_time(moment)
        authority = self.authority_for(prefix)
        names = sorted(n for n in self.catalogs if prefix_matches(prefix, n))
        items = []
        gaps = []
        for name in names:
            item = self._build_exact_result(tenant, name, moment)
            items.append(item)
            gaps.extend(item.get("gaps", []))
        # 范围查询本身也需要 prefix 的 cover 才能声称完整。
        coverage = self._coverage_diagnosis(prefix, authority, moment, aggregate=True) if authority else {"complete": False, "gaps": [{"code": "no_authority"}]}
        result_id = self._new_id("res")
        result = {
            "ok": True,
            "result_id": result_id,
            "version": self._result_counter,
            "query_id": query_id,
            "tenant": tenant,
            "name": prefix,
            "prefix": prefix,
            "scope": "prefix",
            "at": moment,
            "issued_at": moment,
            "view_seq": self.seq,
            "consistency_token": self.consistency_token(),
            "authority": authority,
            "results": items,
            "endpoints": [ep for item in items for ep in item["endpoints"]],
            "coverage": coverage,
            "gaps": gaps + coverage.get("gaps", []),
            "complete": bool(coverage.get("complete")),
            "usable": bool(coverage.get("complete")) or any(i["usable"] for i in items),
            "can_start": any(i["can_start"] for i in items),
            "cacheable": bool(coverage.get("complete")),
            "until": (coverage.get("proof") or {}).get("until"),
            "invalidated": False,
        }
        self.results[result_id] = result
        self.results_by_version[result["version"]] = result_id
        if prior is not None:
            result["reread"] = self._reread_diagnosis(prior, result, moment)
            result["unchanged"] = result["reread"].get("state") == "unchanged"
            result["changed"] = not result["unchanged"]
        return result

    def _historical_basis(self, name: str, tenant: str, at: int, current_authority: dict[str, Any] | None) -> dict[str, Any] | None:
        catalog = self.catalogs.get(name)
        old_endpoints = []
        if catalog:
            for ep in catalog["endpoints"].values():
                if current_authority and ep.get("generation") == current_authority["generation"]:
                    continue
                if not _visible(ep.get("tenants", []), tenant):
                    continue
                item = copy.deepcopy(ep)
                item["historical"] = True
                item["start_eligible"] = False
                old_endpoints.append(item)
        old_covers = [
            copy.deepcopy(c) for c in self.covers
            if prefix_matches(c["prefix"], name)
            and (not current_authority or c.get("generation") != current_authority["generation"])
        ]
        old_covers.sort(key=lambda c: c.get("received_at", 0), reverse=True)
        if not old_endpoints and not old_covers:
            return None
        basis = {
            "meaning": "historical_basis_only",
            "usable": False,
            "can_start": False,
            "start_allowed": False,
            "reason": "authority_generation_no_longer_current",
            "endpoints": old_endpoints,
            "covers": old_covers[:3],
            "cover": old_covers[0] if old_covers else None,
            "note": "这些内容只能解释过去看到的结果；委托代次已变化，不能作为启动新调用的资格。",
        }
        return basis

    # ------------------------------------------------------------------
    # 资格、版本重读和失效
    # ------------------------------------------------------------------
    def consistency_token(self) -> dict[str, Any]:
        authorities = {p: {"holder": d["holder"], "epoch": d["epoch"], "generation": d["generation"], "active": d["active"]}
                      for p, d in sorted(self.delegations.items())}
        return {"view_seq": self.seq, "authority_revision": self.authority_revision, "authorities": authorities}

    def _issue_qualification(self, result: dict[str, Any], at: int, *, kind: str = "start_call", client: str | None = None) -> dict[str, Any]:
        qid = self._new_id("qual")
        qual = {
            "id": qid,
            "token": qid,
            "lease_id": qid,
            "capability_id": qid,
            "kind": kind,
            "eligible_for_new_calls": kind == "start_call",
            "start_eligible": kind == "start_call",
            "result_id": result["result_id"],
            "result_version": result["version"],
            "tenant": result["tenant"],
            "name": result["name"],
            "scope": result.get("scope", "exact"),
            "authority": copy.deepcopy(result.get("authority")),
            "authority_generation": (result.get("authority") or {}).get("generation"),
            "view_seq": result["view_seq"],
            "issued_at": at,
            "until": result.get("until"),
            "expires_at": result.get("until"),
            "valid": True,
            "client": client,
        }
        self.qualifications[qid] = qual
        if client:
            self.clients.setdefault(client, {"id": client, "subscriptions": [], "qualifications": []})
            self.clients[client]["qualifications"].append(qid)
        return qual

    def _associate_result_to_client(self, client: str, result: dict[str, Any]) -> None:
        record = self.clients.setdefault(client, {"id": client, "subscriptions": [], "qualifications": []})
        q = result.get("qualification")
        if q and q["id"] not in record["qualifications"]:
            record["qualifications"].append(q["id"])
            self.qualifications[q["id"]]["client"] = client

    def _invalidate_matching_results(self, *, name: str, tenant: str | None, at: int, seq: int, reason: str,
                                     tenants: list[str] | None = None, all_tenants: bool = False) -> None:
        for result in list(self.results.values()):
            if not isinstance(result, dict) or result.get("name") != name or result.get("scope") != "exact":
                continue
            if result.get("invalidated"):
                continue
            applies = all_tenants or tenant is None and (
                tenants is None or _visible(tenants, result["tenant"]) or "*" in tenants
            )
            if tenant is not None and result.get("tenant") != tenant:
                applies = False
            if not applies:
                continue
            # 对新端点而言，不可见租户的缺失结论不被该端点“适用”地失效。
            if reason == "endpoint_registered" and tenants is not None and not _visible(tenants, result["tenant"]):
                continue
            result["invalidated"] = True
            result["invalidated_at"] = at
            result["invalidated_by"] = seq
            result["invalidated_reason"] = reason
            q = result.get("qualification")
            if q and q.get("id") in self.qualifications:
                self.qualifications[q["id"]].update({"valid": False, "invalidated_by": seq, "reason": reason})

    def get_result(self, ref: Any) -> dict[str, Any] | None:
        return self.resolve_result_ref(ref)

    def read_result(self, tenant: str, name: str, version: Any, **kwargs: Any) -> dict[str, Any]:
        return self.query(tenant, name, prior=version, **kwargs)

    def resolve_result_ref(self, ref: Any) -> dict[str, Any] | None:
        if isinstance(ref, dict):
            if ref.get("result_id"):
                return self.results.get(ref["result_id"])
            if ref.get("id") and str(ref["id"]).startswith("res-"):
                return self.results.get(ref["id"])
            if ref.get("result_version") is not None:
                ref = ref["result_version"]
            elif ref.get("version") is not None:
                ref = ref["version"]
            elif ref.get("query_id") or ref.get("query"):
                return self.results.get(f"query:{ref.get('query_id') or ref.get('query')}")
        if isinstance(ref, str) and ref in self.results:
            return self.results[ref]
        if isinstance(ref, int) and ref in self.results_by_version:
            return self.results.get(self.results_by_version[ref])
        if isinstance(ref, str) and ref.isdigit():
            return self.resolve_result_ref(int(ref))
        return None

    def revalidate_result(self, result_or_ref: Any, *, at: int | None = None) -> dict[str, Any]:
        moment = self.now if at is None else at
        old = self.resolve_result_ref(result_or_ref)
        if old is None:
            return {"valid": False, "state": "unknown_version", "reason": "result_version_not_retained_or_unknown"}
        diagnosis = self._stored_result_diagnosis(old, moment)
        current = self.query(old["tenant"], old["name"], scope=old.get("scope", "exact"), at=moment)
        diagnosis["current"] = current
        diagnosis["replacement"] = current
        return diagnosis

    def _stored_result_diagnosis(self, old: dict[str, Any], at: int) -> dict[str, Any]:
        reasons = []
        state = "current"
        valid = True
        if old.get("invalidated"):
            valid = False
            state = "invalidated"
            reasons.append(old.get("invalidated_reason") or "invalidated_by_event")
        until = old.get("until")
        if until is not None and at >= int(until):
            valid = False
            state = "expired" if state == "current" else state
            reasons.append("ttl_expired")
        current_authority = self.authority_for(old["name"])
        old_gen = (old.get("authority") or {}).get("generation")
        current_gen = (current_authority or {}).get("generation")
        if old_gen != current_gen:
            valid = False
            state = "authority_changed"
            reasons.append("authority_generation_changed")
        if not valid and state == "current":
            state = "stale"
        return {
            "valid": valid,
            "state": state,
            "reason": reasons[0] if reasons else None,
            "reasons": reasons,
            "old_result_id": old.get("result_id"),
            "old_version": old.get("version"),
            "old_view_seq": old.get("view_seq"),
            "current_authority": current_authority,
        }

    def _reread_diagnosis(self, prior: Any, current: dict[str, Any], at: int) -> dict[str, Any]:
        old = self.resolve_result_ref(prior)
        if old is None:
            return {"state": "unknown_version", "can_replace": True, "message": "未保留该结果版本，返回当前一致视图"}
        diag = self._stored_result_diagnosis(old, at)
        unchanged = (
            diag["valid"]
            and old.get("status") == current.get("status")
            and old.get("endpoints") == current.get("endpoints")
            and old.get("proof", {}).get("revision") == (current.get("proof") or {}).get("revision")
        )
        diag["state"] = "unchanged" if unchanged else ("changed" if diag["state"] == "current" else diag["state"])
        diag["replacement"] = current
        return diag

    def require_start_qualification(self, token_or_result: str | dict[str, Any], *, at: int | None = None) -> dict[str, Any]:
        moment = self.now if at is None else at
        qid = token_or_result
        if isinstance(token_or_result, dict):
            qid = token_or_result.get("start_token") or (token_or_result.get("qualification") or {}).get("id") or token_or_result.get("id")
        qual = self.qualifications.get(str(qid))
        if qual is None:
            diag = {"valid": False, "reason": "unknown_qualification"}
            raise StaleQualification(diag)
        current_authority = self.authority_for(qual["name"])
        if (current_authority or {}).get("generation") != qual.get("authority_generation"):
            qual["valid"] = False
            qual["reason"] = "authority_generation_changed"
        if qual.get("until") is not None and moment >= int(qual["until"]):
            qual["valid"] = False
            qual["reason"] = "ttl_expired"
        if not qual.get("valid", True):
            diag = {"valid": False, "reason": qual.get("reason", "stale"), "qualification": copy.deepcopy(qual)}
            raise StaleQualification(diag)
        return copy.deepcopy(qual)

    def can_start(self, token_or_result: str | dict[str, Any], *, at: int | None = None) -> bool:
        try:
            self.require_start_qualification(token_or_result, at=at)
            return True
        except StaleQualification:
            return False

    # ------------------------------------------------------------------
    # Watch、游标保留和一致重同步
    # ------------------------------------------------------------------
    def handle_watch_message(self, record: dict[str, Any], *, at: int) -> dict[str, Any]:
        client = record.get("client") or record.get("client_id")
        tenant = record.get("tenant") or record.get("tenant_id")
        name = record.get("name", record.get("prefix", record.get("scope_prefix")))
        after = record.get("after", record.get("cursor", record.get("last_seq", record.get("offset", 0))))
        if isinstance(after, str) and after.isdigit():
            after = int(after)
        if not client or not tenant or name is None:
            raise DiscoveryError("watch 需要 client、tenant、name")
        if not isinstance(after, int) or isinstance(after, bool) or after < 0:
            raise DiscoveryError("watch.after 必须是非负整数")
        scope = record.get("scope") or ("prefix" if "prefix" in record and record.get("name") is None else None)
        target, scope = parse_query_target(name, scope)
        return self.watch(
            str(client), str(tenant), target, after, at=at, scope=scope,
            snapshot_token=record.get("snapshot_token") or record.get("consistency_token"),
        )

    def watch(
        self,
        client: str,
        tenant: str,
        name: str | None = None,
        after: int = 0,
        *,
        prefix: str | None = None,
        at: int | None = None,
        scope: str | None = "exact",
        snapshot_token: Any = None,
    ) -> dict[str, Any]:
        if name is None:
            name = prefix
        if name is None:
            raise DiscoveryError("watch 需要 name 或 prefix")
        moment = self.now if at is None else at
        self._set_time(moment)
        target, parsed_scope = parse_query_target(name, scope or ("prefix" if prefix is not None else "exact"))
        key = f"{client}:{tenant}:{parsed_scope}:{target}"
        sub = self.subscriptions.get(key)
        if sub is None:
            self._sub_counter += 1
            sub = {
                "id": f"sub-{self._sub_counter}",
                "key": key,
                "client": client,
                "tenant": tenant,
                "name": target,
                "scope": parsed_scope,
                "after": after,
                "created_at": moment,
                "last_watch_at": moment,
                "last_delivered_seq": after,
                "watch_count": 0,
                "known_results": [],
                "snapshot_tokens": [],
                "status": "streaming",
            }
            self.subscriptions[key] = sub
            self.clients.setdefault(client, {"id": client, "subscriptions": [], "qualifications": []})
            if key not in self.clients[client]["subscriptions"]:
                self.clients[client]["subscriptions"].append(key)
        sub["watch_count"] += 1
        sub["last_watch_at"] = moment
        sub["after"] = after

        cursor = self.diagnose_cursor(after)
        token_conflict = self._snapshot_token_conflict(snapshot_token)
        must_resync = not cursor["can_resume"] or token_conflict is not None

        if must_resync:
            snapshot = self.query(tenant, target, scope=parsed_scope, at=moment, client=client)
            sub["status"] = "resync_required"
            sub["last_snapshot_seq"] = snapshot["view_seq"]
            sub["last_snapshot_version"] = snapshot["version"]
            sub["snapshot_tokens"].append(snapshot["consistency_token"])
            if snapshot["result_id"] not in sub["known_results"]:
                sub["known_results"].append(snapshot["result_id"])
            invalidated = self._client_invalidations(client, sub, moment)
            response = {
                "ok": True,
                "subscription_id": sub["id"],
                "client": client,
                "tenant": tenant,
                "name": target,
                "scope": parsed_scope,
                "status": "resync_required",
                "state": "snapshot_required",
                "can_resume": False,
                "must_resync": True,
                "resync_required": True,
                "reason": (token_conflict or {}).get("reason") if token_conflict else cursor.get("reason"),
                "cursor": cursor,
                "snapshot_token_conflict": token_conflict,
                "snapshot": snapshot,
                "view": snapshot,
                "result": snapshot,
                "replacement": snapshot,
                "changes": [],
                "events": [],
                "notifications": [],
                "invalidated_qualifications": invalidated,
                "invalidated": invalidated,
                "consistency_token": snapshot["consistency_token"],
                "seq": self.seq,
            }
            sub["last_response"] = {k: response[k] for k in ("status", "reason", "seq")}
            return response

        events = self._relevant_events(after, tenant, target, parsed_scope)
        notifications = []
        for event in events:
            note = self._redact_event_for_tenant(event, tenant)
            # 最新一条相关变更附带可整体替换旧发现结果的一致视图。
            if event is events[-1]:
                replacement = self.query(tenant, target, scope=parsed_scope, at=moment, client=client)
                note["replacement"] = replacement
                note["replace_with"] = replacement
                if replacement["result_id"] not in sub["known_results"]:
                    sub["known_results"].append(replacement["result_id"])
            notifications.append(note)
        sub["status"] = "streaming"
        if events:
            sub["last_delivered_seq"] = events[-1]["seq"]
        response = {
            "ok": True,
            "subscription_id": sub["id"],
            "client": client,
            "tenant": tenant,
            "name": target,
            "scope": parsed_scope,
            "status": "changes" if notifications else "caught_up",
            "can_resume": True,
            "must_resync": False,
            "resync_required": False,
            "reason": cursor.get("reason"),
            "cursor": cursor,
            "changes": notifications,
            "events": notifications,
            "notifications": notifications,
            "latest_seq": self.seq,
            "seq": self.seq,
            "consistency_token": self.consistency_token(),
        }
        if notifications and "replacement" in notifications[-1]:
            response["replacement"] = notifications[-1]["replacement"]
            response["current"] = notifications[-1]["replacement"]
            response["view"] = notifications[-1]["replacement"]
        else:
            current_view = self.query(tenant, target, scope=parsed_scope, at=moment, client=client)
            response["current"] = current_view
            response["view"] = current_view
        sub["last_response"] = {"status": response["status"], "latest_delivered_seq": sub["last_delivered_seq"]}
        return response

    def watch_prefix(self, client: str, tenant: str, prefix: str, after: int = 0, **kwargs):
        return self.watch(client, tenant, prefix, after, scope="prefix", **kwargs)

    def diagnose_cursor(self, after: int) -> dict[str, Any]:
        oldest = self.retained_from()
        if after < self.trim_through:
            return {
                "after": after,
                "trim_through": self.trim_through,
                "retained_from": oldest,
                "latest_seq": self.seq,
                "can_resume": False,
                "must_resync": True,
                "reason": "cursor_before_retained_range",
                "explanation": f"客户端处理到 {after}，但服务只保留 {oldest} 之后；缺少已压缩通知，必须取一致快照。",
            }
        if after > self.seq:
            return {
                "after": after,
                "trim_through": self.trim_through,
                "retained_from": oldest,
                "latest_seq": self.seq,
                "can_resume": False,
                "must_resync": True,
                "reason": "cursor_ahead_of_log",
                "explanation": "游标比服务最新序号还新，服务无法证明其视图来源。",
            }
        return {
            "after": after,
            "trim_through": self.trim_through,
            "retained_from": oldest,
            "latest_seq": self.seq,
            "can_resume": True,
            "must_resync": False,
            "reason": "within_retained_range",
            "explanation": "所需通知仍在保留区间，可只补与该订阅相关的变更。",
        }

    def _snapshot_token_conflict(self, token: Any) -> dict[str, Any] | None:
        if not token:
            return None
        current = self.consistency_token()
        if isinstance(token, dict):
            if token.get("authority_revision") is not None and token.get("authority_revision") != current["authority_revision"]:
                return {
                    "reason": "snapshot_generation_changed_during_resync",
                    "requested_token": token,
                    "current_token": current,
                    "explanation": "重同步期间委托代次再次变化；旧快照与新目录不能拼接，必须重新取原子快照。",
                }
            if token.get("view_seq") is not None and int(token["view_seq"]) < self.seq:
                # view 变化不一定是委托代次拼接风险；若 authority_revision 未变仍可续读。
                return None
        return None

    def _redact_event_for_tenant(self, event: dict[str, Any], tenant: str) -> dict[str, Any]:
        note = copy.deepcopy(event)
        if note.get("kind") not in {"service_changed", "endpoint_expired"}:
            return note
        view = note.get("endpoint_view")
        if view and not _visible(view.get("tenants", []), tenant):
            for key in ("endpoint", "endpoint_id", "until", "expires_at", "endpoint_view"):
                note.pop(key, None)
            note["redacted"] = True
        visible_views = [
            ep for ep in note.get("affected_views", [])
            if _visible(ep.get("tenants", []), tenant)
        ]
        if "affected_views" in note:
            note["affected_views"] = copy.deepcopy(visible_views)
            note["affected_endpoints"] = [ep["id"] for ep in visible_views]
            if len(note["affected_endpoints"]) != len(event.get("affected_endpoints", [])):
                note["redacted"] = True
        withdrawal = note.get("withdrawal")
        if isinstance(withdrawal, dict):
            withdrawal.pop("tenants", None)
            if withdrawal.get("target_endpoint") and not visible_views:
                withdrawal.pop("target_endpoint", None)
                note.pop("endpoint_id", None)
        return note

    def _relevant_events(self, after: int, tenant: str, target: str, scope: str) -> list[dict[str, Any]]:
        relevant = []
        for event in self._events_after(after):
            if event["seq"] <= self.trim_through:
                continue
            event_scope = event.get("scope") or ("prefix" if event["kind"] == "delegation_changed" or event["kind"] == "cover_updated" else "exact")
            event_name = event.get("name") or event.get("prefix")
            if scope == "exact":
                name_match = event_name == target or (event.get("prefix") and prefix_matches(event["prefix"], target))
            else:
                # 前缀订阅：事件名字位于子树，或委托/cover 前缀与订阅子树相交。
                name_match = bool(event_name and (prefix_matches(target, event_name) or prefix_matches(event_name, target)))
            if not name_match:
                continue
            if event.get("all_tenants"):
                relevant.append(event)
            elif event.get("tenants") is not None:
                if _visible(event["tenants"], tenant):
                    relevant.append(event)
            else:
                relevant.append(event)
        return relevant

    def _client_invalidations(self, client: str, sub: dict[str, Any], at: int) -> list[dict[str, Any]]:
        client_record = self.clients.get(client, {})
        qids = list(client_record.get("qualifications", []))
        rows = []
        for qid in qids:
            qual = self.qualifications.get(qid)
            if not qual:
                continue
            if qual.get("name") != sub["name"] and not prefix_matches(sub["name"], qual.get("name", "")):
                continue
            current_authority = self.authority_for(qual["name"])
            reasons = []
            if qual.get("authority_generation") != (current_authority or {}).get("generation"):
                reasons.append("authority_generation_changed")
            if qual.get("until") is not None and at >= int(qual["until"]):
                reasons.append("ttl_expired")
            q = self.qualifications[qid]
            if not q.get("valid", True):
                reasons.append(q.get("reason", "invalidated"))
            if reasons:
                rows.append({
                    "qualification_id": qid,
                    "result_id": qual.get("result_id"),
                    "name": qual.get("name"),
                    "tenant": qual.get("tenant"),
                    "kind": qual.get("kind"),
                    "valid": False,
                    "usable_for_new_calls": False,
                    "reasons": list(dict.fromkeys(reasons)),
                    "historical_note": "可保留为历史依据，但不能据此启动新调用。",
                })
        # 即使 query 没带 client，订阅自身发过的快照也明确列出版本失效。
        for rid in sub.get("known_results", []):
            old = self.results.get(rid)
            if not old:
                continue
            diag = self._stored_result_diagnosis(old, at)
            if not diag["valid"] and not any(r.get("result_id") == rid for r in rows):
                rows.append({
                    "result_id": rid,
                    "old_version": old.get("version"),
                    "name": old.get("name"),
                    "tenant": old.get("tenant"),
                    "valid": False,
                    "usable_for_new_calls": False,
                    "reasons": diag["reasons"],
                })
        return rows

    # ------------------------------------------------------------------
    # 运维控制
    # ------------------------------------------------------------------
    def handle_trim(self, record: dict[str, Any], *, at: int) -> dict[str, Any]:
        through = record.get("through", 0)
        if not isinstance(through, int) or isinstance(through, bool) or through < 0:
            raise DiscoveryError("trim.through 必须是非负整数")
        if through < self.trim_through:
            return {"ok": True, "idempotent": True, "trim_through": self.trim_through}
        before = len(self.events)
        self.events = [e for e in self.events if e["seq"] > through]
        self.trim_through = through
        return {"ok": True, "trim_through": through, "retained_from": through + 1, "removed_events": before - len(self.events), "at": at}

    def trim(self, through: int, at: int | None = None):
        return self.handle_trim({"through": through}, at=self.now if at is None else at)

    def handle_restart(self, record: dict[str, Any], *, at: int) -> dict[str, Any]:
        # 已提交目录、代次和通知保留点视为持久状态；瞬态连接由 watch 重建。
        self.restart_count += 1
        if not record.get("keep_unreachable", False):
            self.unreachable_holders.clear()
            self.unreachable_prefixes.clear()
        for sub in self.subscriptions.values():
            sub["transport_state"] = "reconnected_required"
        return {
            "ok": True,
            "restart_count": self.restart_count,
            "durable_state_retained": True,
            "subscriptions": len(self.subscriptions),
            "trim_through": self.trim_through,
            "retained_from": self.retained_from(),
            "latest_seq": self.seq,
        }

    def restart(self, at: int | None = None, **record):
        return self.handle_restart(record, at=self.now if at is None else at)

    def handle_inspect_message(self, record: dict[str, Any], *, at: int) -> dict[str, Any]:
        subscription_id = record.get("subscription") or record.get("subscription_id")
        if subscription_id:
            return self.inspect_subscription(str(subscription_id), at=at)
        kind = str(record.get("type", record.get("view", ""))).lower()
        client = record.get("client") or record.get("client_id")
        name = record.get("name")
        if not client and not name:
            target = record.get("target") or record.get("id")
            if target and kind in {"client", "subscription", "agent"}:
                client = target
            elif target and kind in {"name", "prefix", "domain"}:
                name = target
        return self.inspect(client=client, name=name, at=at)

    def inspect(self, *, client: str | None = None, name: str | None = None,
                subscription_id: str | None = None, at: int | None = None,
                include_fenced: bool = True, **extra) -> dict[str, Any]:
        moment = self.now if at is None else at
        if subscription_id or extra.get("subscription"):
            return self.inspect_subscription(str(subscription_id or extra.get("subscription")), at=moment)
        if client:
            return self.inspect_client(client, at=moment, name=name)
        if name is not None:
            return self.inspect_name(name, at=moment, include_fenced=include_fenced)
        return self.desk_overview(at=moment)

    def inspect_name(self, name: str, *, at: int | None = None, include_fenced: bool = True) -> dict[str, Any]:
        moment = self.now if at is None else at
        normalized = normalize_name(name) if not str(name).endswith("*") else normalize_prefix(str(name).rstrip("*").rstrip("."))
        authority = self.authority_for(normalized)
        coverage = self._coverage_diagnosis(normalized, authority, moment) if authority else {"complete": False, "gaps": [{"code": "no_authority"}]}
        delegations = [copy.deepcopy(d) for p, d in sorted(self.delegations.items()) if prefix_matches(p, normalized) or prefix_matches(normalized, p)]
        catalog = self.catalogs.get(normalized)
        endpoints = copy.deepcopy(list(catalog["endpoints"].values())) if catalog else []
        response = {
            "ok": True,
            "view": "name",
            "name": normalized,
            "at": moment,
            "authority": authority,
            "who_can_answer": (authority or {}).get("holder"),
            "authority_epoch": (authority or {}).get("epoch"),
            "delegations": delegations,
            "coverage": coverage,
            "coverage_gaps": coverage.get("gaps", []),
            "missing_coverage_evidence": [g for g in coverage.get("gaps", []) if g.get("code") in {"cover_missing", "cover_expired", "cover_behind", "no_authority"}],
            "endpoints": endpoints,
            "current_generation_endpoints": [e for e in endpoints if authority and e.get("generation") == authority["generation"]],
            "consistency_token": self.consistency_token(),
        }
        if include_fenced:
            response["fenced_reports"] = copy.deepcopy([r for r in self.fenced_reports if normalized in json.dumps(r, ensure_ascii=False)][-10:])
        return response

    def coverage_gaps(self, at: int | None = None) -> list[dict[str, Any]]:
        moment = self.now if at is None else at
        gaps = []
        for prefix, delegation in sorted(self.delegations.items()):
            if not delegation.get("active"):
                continue
            diagnosis = self._coverage_diagnosis(prefix, delegation, moment)
            for gap in diagnosis.get("gaps", []):
                gaps.append({"name": prefix, "holder": delegation["holder"], "epoch": delegation["epoch"], **gap})
        for name in sorted(self.catalogs):
            authority = self.authority_for(name)
            if not authority:
                gaps.append({"name": name, "code": "no_authority"})
                continue
            diagnosis = self._coverage_diagnosis(name, authority, moment)
            for gap in diagnosis.get("gaps", []):
                gaps.append({"name": name, "holder": authority["holder"], "epoch": authority["epoch"], **gap})
        # 去重
        dedup = {}
        for gap in gaps:
            key = (gap.get("name"), gap.get("code"), gap.get("prefix"), gap.get("covered_revision"), gap.get("latest_revision"))
            dedup[key] = gap
        return list(dedup.values())

    def inspect_client(self, client: str, *, at: int | None = None, name: str | None = None) -> dict[str, Any]:
        moment = self.now if at is None else at
        record = self.clients.get(client)
        if record is None:
            return {"ok": True, "view": "client", "client": client, "found": False, "subscriptions": [], "qualifications": []}
        subs = []
        for key in record.get("subscriptions", []):
            sub = self.subscriptions[key]
            if name and sub["name"] != normalize_name(name):
                continue
            diagnosis = self.diagnose_cursor(sub["after"])
            invalidations = self._client_invalidations(client, sub, moment)
            subs.append({
                "subscription_id": sub["id"],
                "tenant": sub["tenant"],
                "name": sub["name"],
                "scope": sub["scope"],
                "after": sub["after"],
                "cursor": diagnosis,
                "can_resume": diagnosis["can_resume"],
                "must_resync": diagnosis["must_resync"] or sub.get("status") == "resync_required",
                "why": diagnosis.get("explanation"),
                "status": sub.get("status"),
                "last_delivered_seq": sub.get("last_delivered_seq"),
                "last_snapshot_seq": sub.get("last_snapshot_seq"),
                "invalidated_qualifications": invalidations,
                "watch_count": sub.get("watch_count"),
            })
        quals = []
        for qid in record.get("qualifications", []):
            q = copy.deepcopy(self.qualifications.get(qid))
            if q:
                diag = self._stored_result_diagnosis(self.results.get(q["result_id"], {}), moment) if q.get("result_id") in self.results else {}
                q["current_diagnosis"] = diag
                quals.append(q)
        return {
            "ok": True,
            "view": "client",
            "client": client,
            "found": True,
            "subscriptions": subs,
            "qualifications": quals,
            "retention": {"trim_through": self.trim_through, "retained_from": self.retained_from(), "latest_seq": self.seq},
        }

    def inspect_subscription(self, identifier: str, *, at: int | None = None) -> dict[str, Any]:
        moment = self.now if at is None else at
        sub = self.subscriptions.get(identifier)
        if sub is None:
            sub = next((candidate for candidate in self.subscriptions.values() if candidate.get("id") == identifier), None)
        if sub is None:
            return {"ok": True, "view": "subscription", "subscription_id": identifier, "found": False}
        diagnosis = self.diagnose_cursor(sub["after"])
        return {
            "ok": True,
            "view": "subscription",
            "found": True,
            "subscription_id": sub["id"],
            "client": sub["client"],
            "tenant": sub["tenant"],
            "name": sub["name"],
            "scope": sub["scope"],
            "after": sub["after"],
            "cursor": diagnosis,
            "can_resume": diagnosis["can_resume"],
            "must_resync": diagnosis["must_resync"] or sub.get("status") == "resync_required",
            "why": diagnosis.get("explanation"),
            "invalidated_qualifications": self._client_invalidations(sub["client"], sub, moment),
        }

    def diagnose_subscription(self, client: str, name: str | None = None, at: int | None = None) -> dict[str, Any]:
        return self.inspect_client(client, at=at, name=name)

    def desk_overview(self, *, at: int | None = None) -> dict[str, Any]:
        moment = self.now if at is None else at
        return {
            "ok": True,
            "view": "desk",
            "at": moment,
            "seq": self.seq,
            "restart_count": self.restart_count,
            "retention": {"trim_through": self.trim_through, "retained_from": self.retained_from()},
            "authorities": [copy.deepcopy(d) for d in sorted(self.delegations.values(), key=lambda d: d["prefix"])],
            "coverage_gaps": self.coverage_gaps(moment),
            "subscription_count": len(self.subscriptions),
            "client_count": len(self.clients),
            "subscriptions": [self.inspect_client(c, at=moment) for c in sorted(self.clients)],
            "consistency_token": self.consistency_token(),
        }


# 常见命名别名，降低不同调用方的导入猜测成本。
FederatedDiscoveryService = DiscoveryService
ServiceDiscovery = DiscoveryService
DiscoveryEngine = DiscoveryService
FederatedDiscovery = DiscoveryService
JointDiscoveryService = DiscoveryService
Federation = DiscoveryService
Discovery = DiscoveryService
Registry = DiscoveryService
Simulator = DiscoveryService
Cache = DiscoveryCache
ControlledCache = DiscoveryCache
LocalCache = DiscoveryCache


class DiscoveryAgent:
    """仿真代理：维护租户隔离缓存和每个订阅实际处理到的游标。"""

    def __init__(self, service: "DiscoveryService", client_id: str, tenant: str, *, cache: DiscoveryCache | None = None):
        self.service = service
        self.client_id = client_id
        self.tenant = tenant
        self.cache = cache or DiscoveryCache(service)
        self.processed_cursors: dict[tuple[str, str], int] = {}
        self.applied_snapshots: list[dict[str, Any]] = []

    def _cursor_key(self, name: str, scope: str = "exact") -> tuple[tuple[str, str], str]:
        target, parsed_scope = parse_query_target(name, scope)
        return (parsed_scope, target), parsed_scope

    def query(self, name: str, *, at: int | None = None, mode: str = "start", cache: bool = True, **kwargs: Any) -> dict[str, Any]:
        result = self.service.query(
            self.tenant, name, at=at, mode=mode, client=self.client_id, **kwargs
        )
        if cache:
            self.cache.put(result)
        return result

    def watch(self, name: str, *, after: int | None = None, scope: str = "exact", at: int | None = None,
             acknowledge: bool = False, **kwargs: Any) -> dict[str, Any]:
        key, parsed_scope = self._cursor_key(name, scope)
        cursor = self.processed_cursors.get(key, 0) if after is None else after
        response = self.service.watch(
            self.client_id, self.tenant, name, cursor, scope=parsed_scope, at=at, **kwargs
        )
        self.cache.apply_notification(response)
        if response.get("snapshot"):
            self.applied_snapshots.append(copy.deepcopy(response["snapshot"]))
        if acknowledge:
            self.ack(name, int(response["seq"]), scope=parsed_scope)
        return response

    def poll_and_apply(self, name: str, **kwargs: Any) -> dict[str, Any]:
        """读取并应用通知，然后把服务最新序号记为“实际已处理”。"""
        response = self.watch(name, acknowledge=False, **kwargs)
        self.ack(name, int(response["seq"]), scope=response.get("scope", "exact"))
        return response

    def ack(self, name: str, seq: int, *, scope: str = "exact") -> None:
        key, parsed_scope = self._cursor_key(name, scope)
        self.processed_cursors[key] = max(int(seq), self.processed_cursors.get(key, 0))

    def reconnect(self, name: str, *, at: int | None = None, scope: str = "exact") -> dict[str, Any]:
        key, parsed_scope = self._cursor_key(name, scope)
        return self.watch(name, after=self.processed_cursors.get(key, 0), scope=parsed_scope, at=at)

    def get_cached(self, name: str, *, at: int | None = None, revalidate: bool = True):
        return self.cache.get(self.tenant, name, at=at, revalidate=revalidate)

    def can_start(self, token_or_result: str | dict[str, Any], *, at: int | None = None) -> bool:
        return self.service.can_start(token_or_result, at=at)

    def require_start(self, token_or_result: str | dict[str, Any], *, at: int | None = None) -> dict[str, Any]:
        return self.service.require_start_qualification(token_or_result, at=at)


ClientAgent = DiscoveryAgent
Agent = DiscoveryAgent


def create_service(**kwargs: Any) -> DiscoveryService:
    return DiscoveryService(**kwargs)


def process_messages(rows: Iterable[dict[str, Any]], **kwargs: Any) -> list[dict[str, Any]]:
    return DiscoveryService(**kwargs).process_records(rows)


def run_scenario(path: str | Path) -> list[dict[str, Any]]:
    """便捷 API：运行 JSONL 并返回每条输入的回执。"""
    return DiscoveryService().run_file(path)


def solve(messages: str | Path | Iterable[dict[str, Any]], **kwargs: Any) -> list[dict[str, Any]]:
    """统一入口：接受消息列表、可迭代对象或 JSONL 路径。"""
    if isinstance(messages, (str, Path)):
        return run_scenario(messages)
    service = DiscoveryService(**kwargs)
    return service.process_records(messages)


# 常见方法名别名。
DiscoveryService.submit = DiscoveryService.ingest
DiscoveryService.subscribe = DiscoveryService.watch
DiscoveryService.read_again = DiscoveryService.revalidate_result
DiscoveryService.dashboard = DiscoveryService.desk_overview
DiscoveryService.desk = DiscoveryService.desk_overview


if __name__ == "__main__":
    from scenario_runner import main

    raise SystemExit(main())
