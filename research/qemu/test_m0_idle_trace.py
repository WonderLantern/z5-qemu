import unittest

from m0_idle_trace import wait_before_target


class IdleTraceTest(unittest.TestCase):
    def test_wait_before_route_target_is_counterexample(self):
        events = [dict(name='trace_10467bbe', guest_ms=10),
                  dict(name='trace_1047897a', guest_ms=11, native_page={'page_id': 18, 'row': 0}),
                  dict(name='trace_1047897a', guest_ms=30, native_page={'page_id': 1, 'row': 0})]
        self.assertEqual(wait_before_target(events, (1, 0)), (10, 30))

    def test_target_first_or_missing_evidence_is_not_counterexample(self):
        target = dict(name='trace_1047897a', guest_ms=5, native_page={'page_id': 1, 'row': 0})
        wait = dict(name='trace_10467bbe', guest_ms=10)
        self.assertIsNone(wait_before_target([target, wait], (1, 0)))
        self.assertIsNone(wait_before_target([wait], (1, 0)))
        self.assertIsNone(wait_before_target([wait, target], (1, 0)))
        self.assertIsNone(wait_before_target([wait, dict(name='trace_1047897a')], (1, 0)))
