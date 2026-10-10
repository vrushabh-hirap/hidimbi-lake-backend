import unittest
import json
from pathlib import Path

from cache_invalidator import TaggedCache
from metrics_exporter import MetricsRegistry
from rolling_window_limiter import RollingWindowLimiter
from webhook_dispatcher import HookEvent, WebhookDispatcher


class DecoyInfrastructureTests(unittest.TestCase):
    def test_local_ops_config_is_demo_scoped(self):
        config = json.loads((Path(__file__).parents[1] / "ops_config.json").read_text())
        self.assertEqual(config["metrics_namespace"], "hidimbi_demo")
        self.assertGreater(config["window_limit"], 0)

    def test_window_limit_and_expiration(self):
        now = [0.0]
        limiter = RollingWindowLimiter(2, 5, clock=lambda: now[0])
        self.assertTrue(limiter.allow("demo"))
        self.assertTrue(limiter.allow("demo"))
        self.assertFalse(limiter.allow("demo"))
        now[0] = 6
        self.assertTrue(limiter.allow("demo"))

    def test_metrics_render_deterministically(self):
        registry = MetricsRegistry(clock=lambda: 1.0)
        registry.observe("town_requests", 2, route="market")
        self.assertEqual(registry.render(), 'town_requests{route="market"} 2\n')

    def test_tag_invalidation(self):
        cache = TaggedCache(clock=lambda: 1.0)
        cache.put("notice", "hello", {"town"})
        self.assertEqual(cache.get("notice"), "hello")
        self.assertEqual(cache.invalidate("town"), 1)
        self.assertIsNone(cache.get("notice"))

    def test_webhook_retry(self):
        attempts = []
        dispatcher = WebhookDispatcher(lambda event: attempts.append(event.event_id) or len(attempts) > 1)
        dispatcher.enqueue(HookEvent("e1", "demo", b"{}", "https://hooks.invalid/town"))
        self.assertFalse(dispatcher.deliver_next().delivered)
        self.assertTrue(dispatcher.deliver_next().delivered)
        self.assertEqual(dispatcher.pending(), 0)


if __name__ == "__main__":
    unittest.main()
