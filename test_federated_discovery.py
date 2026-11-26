"""联合发现服务核心不变量的回归测试。"""

import json
import unittest

from federated_discovery import (
    Agent,
    DiscoveryCache,
    DiscoveryService,
    StaleQualification,
    prefix_matches,
)


class NamingTests(unittest.TestCase):
    def test_longest_prefix_match_is_label_aware(self):
        self.assertTrue(prefix_matches("tools.hand", "tools.hand.joint"))
        self.assertTrue(prefix_matches("tools", "tools"))
        self.assertFalse(prefix_matches("tools.h", "tools.hand"))

    def test_longest_active_delegation_wins_and_revocation_falls_back(self):
        svc = DiscoveryService()
        svc.delegate("tools", "parent", 1, at=0)
        svc.delegate("tools.hand", "team-hand", 1, at=1)
        self.assertEqual(svc.authority_for("tools.hand.joint")["holder"], "team-hand")

        svc.revoke_prefix("tools.hand", 2, at=2)
        authority = svc.authority_for("tools.hand.joint")
        self.assertEqual(authority["prefix"], "tools")
        self.assertEqual(authority["holder"], "parent")

    def test_old_epoch_delegation_is_fenced(self):
        svc = DiscoveryService()
        svc.delegate("tools", "a", 2, at=1)
        old = svc.delegate("tools", "old", 1, at=2)
        self.assertFalse(old["accepted"])
        self.assertEqual(svc.authority_for("tools")["holder"], "a")


class MissingProofTests(unittest.TestCase):
    def test_missing_is_unknown_without_cover_and_proven_with_cover(self):
        svc = DiscoveryService()
        svc.delegate("tools", "A", 1, at=0)

        pending = svc.query("lab", "tools.pose", at=1)
        self.assertEqual(pending["status"], "coverage_pending")
        self.assertFalse(pending["cacheable"])
        self.assertFalse(pending["negative_cacheable"])
        self.assertIsNone(pending["until"])

        svc.cover_prefix("tools", holder="A", epoch=1, revision=1, until=16, at=2)
        missing = svc.query("lab", "tools.pose", at=3)
        self.assertEqual(missing["status"], "missing")
        self.assertTrue(missing["proven_absent"])
        self.assertTrue(missing["cacheable"])
        self.assertEqual(missing["until"], 16)
        self.assertEqual(missing["ttl"], 13)

    def test_expired_cover_cannot_authorize_negative_cache(self):
        svc = DiscoveryService()
        svc.delegate("tools", "A", 1, at=0)
        svc.cover_prefix("tools", holder="A", epoch=1, revision=1, until=5, at=1)
        result = svc.query("lab", "tools.pose", at=5)
        self.assertIn(result["status"], {"coverage_pending", "upstream_unreachable"})
        self.assertFalse(result["cacheable"])
        self.assertTrue(result["coverage"]["gaps"][0]["code"] == "cover_expired")

    def test_upstream_unreachable_is_distinct_from_missing(self):
        svc = DiscoveryService()
        svc.delegate("tools", "A", 1, at=0)
        svc.set_source_reachable(False, holder="A")
        result = svc.query("lab", "tools.pose", at=2)
        self.assertEqual(result["status"], "upstream_unreachable")
        self.assertEqual(result["meaning"], "upstream_connection_lost")
        self.assertFalse(result["may_close_job"])

    def test_explicit_withdrawal_is_distinct_from_unproven_absence(self):
        svc = DiscoveryService()
        svc.delegate("tools", "A", 1, at=0)
        svc.register_service("tools.pose", "p1", holder="A", epoch=1, revision=1,
                             tenants=["lab"], until=20, at=1)
        svc.withdraw_service("tools.pose", holder="A", epoch=1, revision=2, at=2)
        result = svc.query("lab", "tools.pose", at=3)
        self.assertEqual(result["status"], "explicit_empty")
        self.assertTrue(result["explicit_withdrawal"])
        self.assertFalse(result["cacheable"])
        self.assertTrue(result["may_close_job"])


class EndpointAndTenantTests(unittest.TestCase):
    def test_endpoint_requires_current_generation_and_tenant_visibility(self):
        svc = DiscoveryService()
        svc.delegate("tools", "A", 1, at=0)
        svc.register_service("tools.pose", "p", holder="A", epoch=1, revision=1,
                             tenants=["lab"], until=20, at=1)

        lab = svc.query("lab", "tools.pose", at=2)
        self.assertEqual(lab["status"], "found")
        self.assertEqual([e["id"] for e in lab["endpoints"]], ["p"])
        self.assertTrue(lab["can_start"])

        guest = svc.query("guest", "tools.pose", at=2)
        self.assertEqual(guest["endpoints"], [])
        self.assertFalse(guest["can_start"])

        fenced = svc.register_service("tools.pose", "old", holder="A", epoch=9, revision=2,
                                      tenants=["guest"], until=30, at=3)
        self.assertFalse(fenced["accepted"])
        guest_after_fence = svc.query("guest", "tools.pose", at=4)
        self.assertEqual(guest_after_fence["endpoints"], [])

    def test_expired_endpoint_is_not_returned(self):
        svc = DiscoveryService()
        svc.delegate("tools", "A", 1, at=0)
        svc.register_service("tools.pose", "p", holder="A", epoch=1, revision=1,
                             tenants=["lab"], until=5, at=1)
        self.assertEqual(svc.query("lab", "tools.pose", at=4)["endpoints"][0]["id"], "p")
        result = svc.query("lab", "tools.pose", at=5)
        self.assertEqual(result["endpoints"], [])
        self.assertFalse(result["can_start"])

    def test_withdrawal_does_not_leave_revoked_endpoint_in_cache(self):
        svc = DiscoveryService()
        cache = DiscoveryCache(svc)
        svc.delegate("tools", "A", 1, at=0)
        found = svc.register_service("tools.pose", "p", holder="A", epoch=1, revision=1,
                                     tenants=["lab"], until=20, at=1)
        first = svc.query("lab", "tools.pose", at=2)
        cache.put(first)
        self.assertEqual(cache.get("lab", "tools.pose", at=3)["endpoints"][0]["id"], "p")

        svc.withdraw_service("tools.pose", holder="A", epoch=1, revision=2, at=4)
        watch = svc.watch("c", "lab", "tools.pose", after=0, at=4)
        cache.apply_notification(watch)
        self.assertIsNone(cache.get("lab", "tools.pose", at=5, revalidate=False))

    def test_tenant_caches_are_isolated(self):
        cache = DiscoveryCache()
        result_lab = {"tenant": "lab", "name": "tools.pose", "scope": "exact", "until": 20, "issued_at": 1, "endpoints": ["p"]}
        result_guest = {"tenant": "guest", "name": "tools.pose", "scope": "exact", "until": 20, "issued_at": 1, "endpoints": []}
        cache.put(result_lab)
        cache.put(result_guest)
        self.assertEqual(cache.get("lab", "tools.pose", at=2, revalidate=False)["endpoints"], ["p"])
        self.assertEqual(cache.get("guest", "tools.pose", at=2, revalidate=False)["endpoints"], [])

    def test_withdrawal_notification_does_not_leak_other_tenant_endpoint_id(self):
        svc = DiscoveryService()
        svc.delegate("tools", "A", 1, at=0)
        svc.register_service("tools.shared", "lab-ep", holder="A", epoch=1, revision=1,
                             tenants=["lab"], until=30, at=1)
        svc.register_service("tools.shared", "guest-ep", holder="A", epoch=1, revision=2,
                             tenants=["guest"], until=30, at=2)
        svc.watch("glab", "lab", "tools.shared", after=0, at=3)
        svc.withdraw_service("tools.shared", holder="A", epoch=1, revision=3, at=4)
        watch = svc.watch("glab", "lab", "tools.shared", after=3, at=5)
        raw = json.dumps(watch, ensure_ascii=False)
        self.assertIn("lab-ep", raw)
        self.assertNotIn("guest-ep", raw)
        self.assertEqual(watch["replacement"]["endpoints"], [])


class InvalidationAndWatchTests(unittest.TestCase):
    def test_new_endpoint_invalidates_missing_and_watch_has_replacement(self):
        svc = DiscoveryService()
        cache = DiscoveryCache(svc)
        svc.delegate("tools", "A", 1, at=0)
        svc.cover_prefix("tools", holder="A", epoch=1, revision=1, until=16, at=1)
        missing = svc.query("lab", "tools.pose", query_id="q", at=2)
        cache.put(missing)
        svc.watch("c", "lab", "tools.pose", after=0, at=3)

        svc.register_service("tools.pose", "p", holder="A", epoch=1, revision=2,
                             tenants=["lab"], until=20, at=4)
        reread = svc.query("lab", "tools.pose", prior=missing["version"], at=5)
        self.assertFalse(reread["reread"]["valid"])
        self.assertIn(reread["reread"]["state"], {"invalidated", "changed"})
        self.assertEqual(reread["status"], "found")

        watch = svc.watch("c", "lab", "tools.pose", after=0, at=6)
        self.assertEqual(watch["status"], "changes")
        replacement = watch.get("replacement") or watch["notifications"][-1]["replacement"]
        self.assertEqual(replacement["status"], "found")
        self.assertEqual(replacement["endpoints"][0]["id"], "p")

        cache.apply_notification(watch)
        cached = cache.get("lab", "tools.pose", at=6, revalidate=False)
        self.assertEqual(cached["status"], "found")

    def test_agent_stores_actually_processed_cursor(self):
        svc = DiscoveryService()
        agent = Agent(svc, "agent-1", "lab")
        svc.delegate("tools", "A", 1, at=0)
        svc.cover_prefix("tools", holder="A", epoch=1, revision=1, until=20, at=1)
        agent.query("tools.pose", at=2)
        agent.poll_and_apply("tools.pose", at=3)
        self.assertEqual(agent.processed_cursors[("exact", "tools.pose")], svc.seq)

        svc.register_service("tools.pose", "p", holder="A", epoch=1, revision=2,
                             tenants=["lab"], until=30, at=4)
        reconnect = agent.reconnect("tools.pose", at=5)
        self.assertEqual(reconnect["status"], "changes")
        self.assertEqual(reconnect["replacement"]["status"], "found")

    def test_cursor_within_retention_gets_only_relevant_changes(self):
        svc = DiscoveryService()
        svc.delegate("tools", "A", 1, at=0)
        svc.delegate("other", "B", 1, at=1)
        svc.register_service("tools.pose", "p", holder="A", epoch=1, revision=1,
                             tenants=["lab"], until=20, at=2)
        svc.register_service("other.svc", "o", holder="B", epoch=1, revision=1,
                             tenants=["lab"], until=20, at=3)
        watch = svc.watch("c", "lab", "tools.pose", after=2, at=4)
        names = [e["name"] for e in watch["events"]]
        self.assertIn("tools.pose", names)
        self.assertNotIn("other.svc", names)

    def test_trimmed_cursor_requires_consistent_snapshot(self):
        svc = DiscoveryService()
        svc.delegate("tools.hand", "old", 1, at=0)
        svc.register_service("tools.hand.joint", "aa", holder="old", epoch=1, revision=1,
                             tenants=["lab"], until=22, at=1)
        svc.watch("c", "lab", "tools.hand.joint", after=0, at=2)
        svc.trim(through=1, at=3)

        ok_cursor = svc.watch("c2", "lab", "tools.hand.joint", after=1, at=4)
        self.assertTrue(ok_cursor["can_resume"])

        stale = svc.watch("c", "lab", "tools.hand.joint", after=0, at=5)
        self.assertTrue(stale["must_resync"])
        self.assertEqual(stale["reason"], "cursor_before_retained_range")
        self.assertIn("snapshot", stale)
        self.assertEqual(stale["events"], [])

    def test_delegation_during_resync_forces_another_atomic_snapshot(self):
        svc = DiscoveryService()
        svc.delegate("tools.hand", "old", 1, at=0)
        svc.trim(through=1, at=1)
        first = svc.watch("c", "lab", "tools.hand.joint", after=0, at=2)
        token = first["consistency_token"]
        self.assertTrue(first["must_resync"])

        svc.delegate("tools.hand", "new", 2, at=3)
        second = svc.watch(
            "c", "lab", "tools.hand.joint", after=first["snapshot"]["view_seq"],
            snapshot_token=token, at=4,
        )
        self.assertTrue(second["must_resync"])
        self.assertEqual(second["reason"], "snapshot_generation_changed_during_resync")
        self.assertEqual(second["snapshot"]["authority"]["holder"], "new")
        self.assertEqual(second["events"], [])


class DelegationTransferQualificationTests(unittest.TestCase):
    def test_old_result_is_historical_but_not_start_qualification(self):
        svc = DiscoveryService()
        svc.delegate("tools.hand", "old", 1, at=0)
        svc.register_service("tools.hand.joint", "aa", holder="old", epoch=1, revision=1,
                             tenants=["lab"], until=22, at=1)
        old = svc.query("lab", "tools.hand.joint", at=2, client="agent")
        self.assertTrue(old["can_start"])
        self.assertTrue(svc.can_start(old["start_token"], at=2))

        svc.delegate("tools.hand", "new", 2, at=3)
        after = svc.query("lab", "tools.hand.joint", at=5)
        self.assertEqual(after["status"], "authority_pending")
        self.assertFalse(after["can_start"])
        self.assertEqual(after["endpoints"], [])
        self.assertEqual(after["historical_basis"]["endpoints"][0]["id"], "aa")
        self.assertFalse(svc.can_start(old["start_token"], at=5))
        with self.assertRaises(StaleQualification):
            svc.require_start_qualification(old["start_token"], at=5)

        reread = svc.revalidate_result(old, at=5)
        self.assertFalse(reread["valid"])
        self.assertEqual(reread["state"], "authority_changed")

    def test_new_authority_endpoint_replaces_old_generation(self):
        svc = DiscoveryService()
        svc.delegate("h", "old", 1, at=0)
        svc.register_service("h.j", "aa", holder="old", epoch=1, revision=1, tenants=["lab"], until=30, at=1)
        svc.delegate("h", "new", 2, at=2)
        fenced = svc.register_service("h.j", "old-late", holder="old", epoch=1, revision=2,
                                      tenants=["lab"], until=30, at=3)
        self.assertFalse(fenced["accepted"])
        svc.register_service("h.j", "bb", holder="new", epoch=2, revision=1, tenants=["lab"], until=31, at=4)
        result = svc.query("lab", "h.j", at=5)
        self.assertEqual([e["id"] for e in result["endpoints"]], ["bb"])
        self.assertEqual(result["authority"]["epoch"], 2)


class DeskAndPrefixTests(unittest.TestCase):
    def test_desk_reports_authority_coverage_gap_and_subscription_reason(self):
        svc = DiscoveryService()
        svc.delegate("tools", "A", 1, at=0)
        svc.watch("c", "lab", "tools.pose", after=0, at=1)
        inspection = svc.inspect(name="tools.pose", at=2)
        self.assertEqual(inspection["who_can_answer"], "A")
        self.assertTrue(any(g["code"] == "cover_missing" for g in inspection["coverage_gaps"]))

        client = svc.inspect(client="c", at=2)
        self.assertTrue(client["subscriptions"][0]["can_resume"])
        self.assertIn("保留区间", client["subscriptions"][0]["why"])

    def test_prefix_query_contains_only_matching_visible_endpoints(self):
        svc = DiscoveryService()
        svc.delegate("tools", "A", 1, at=0)
        svc.register_service("tools.pose", "p", holder="A", epoch=1, revision=1, tenants=["lab"], until=20, at=1)
        svc.register_service("tools.hand.joint", "j", holder="A", epoch=1, revision=2, tenants=["lab"], until=20, at=2)
        svc.register_service("billing.api", "b", holder="B", epoch=1, revision=1, tenants=["lab"], until=20, at=3)
        result = svc.query("lab", "tools.*", at=4)
        self.assertEqual(result["scope"], "prefix")
        self.assertEqual({e["name"] for e in result["endpoints"]}, {"tools.pose", "tools.hand.joint"})

    def test_restart_keeps_retention_and_allows_client_diagnosis(self):
        svc = DiscoveryService()
        svc.delegate("tools", "A", 1, at=0)
        svc.trim(through=0, at=1)
        svc.restart(at=2)
        report = svc.inspect(client="missing", at=3)
        self.assertFalse(report["found"])
        self.assertEqual(svc.restart_count, 1)
        self.assertEqual(svc.retained_from(), 1)


if __name__ == "__main__":
    unittest.main()
