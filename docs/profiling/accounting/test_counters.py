"""Discontinuities must survive interval subtraction and per-CPU summation."""

from copy import deepcopy
import unittest

from counters import difference


class CounterDeltaTest(unittest.TestCase):
    def setUp(self):
        self.a = dict(identity=["boot", 123, 4, "dev", "mac"], start_ns=20, end_ns=21,
                      counts={"link.rx.packets": 12, "driver.rx_no_buffer_count": 6,
                              "driver.rx_queue_0_packets": 100, "softnet.dropped": {"0": 4, "1": 2},
                              "tc.ipv4.submitted": {"0": 10, "1": 2},
                              "tc.ipv4.ring_drop": {"0": 0, "1": 0}},
                      tc_epochs={"tc.ipv4.submitted": [12, 18], "tc.ipv4.ring_drop": [12, 19]},
                      issues=[])
        self.b = deepcopy(self.a)
        self.b.update(start_ns=34, end_ns=38)

    def test_missing_and_zero(self):
        del self.b["counts"]["driver.rx_queue_0_packets"]
        result = difference(self.a, self.b)
        self.assertEqual(result["elapsed_bounds_ns"], [13, 18])
        d = result["deltas"]
        self.assertIsNone(d["driver.rx_queue_0_packets"])
        self.assertIsNone(d["driver.rx_missed_errors"])
        self.assertEqual((d["driver.rx_no_buffer_count"], d["tc.ipv4.matched"]), (0, 0))
        self.assertIsNone(d["tc.ipv6.matched"])

    def test_driver_reset_can_be_hidden_in_companion_counter(self):
        self.b["counts"].update({"driver.rx_no_buffer_count": 1, "driver.rx_queue_0_packets": 105})
        d = difference(self.a, self.b)["deltas"]
        self.assertIsNone(d["driver.rx_no_buffer_count"])
        self.assertIsNone(d["driver.rx_queue_0_packets"])
        self.assertEqual(d["link.rx.packets"], 0)

    def test_per_cpu_reset_hidden_by_rising_total(self):
        self.b["counts"]["tc.ipv4.submitted"] = {"0": 1, "1": 900}
        d = difference(self.a, self.b)["deltas"]
        self.assertIsNone(d["tc.ipv4.submitted"])
        self.assertIsNone(d["tc.ipv4.matched"])

    def test_map_replacement_and_hotplug(self):
        self.b["tc_epochs"]["tc.ipv4.ring_drop"] = [12, 25]
        del self.b["counts"]["softnet.dropped"]["1"]
        d = difference(self.a, self.b)["deltas"]
        self.assertIsNone(d["tc.ipv4.ring_drop"])
        self.assertIsNone(d["softnet.dropped"])

    def test_interleaved_reads_bound_rx_delta_and_reject_intra_sample_reset(self):
        self.a["rx_end"] = 18
        self.b["counts"]["link.rx.packets"] = 32
        self.b["rx_end"] = 37
        self.assertEqual(difference(self.a, self.b)["link_rx_delta_bounds"], [14, 25])
        self.b["rx_end"] = 2
        result = difference(self.a, self.b)
        self.assertIsNone(result["link_rx_delta_bounds"])
        self.assertIsNone(result["deltas"]["link.rx.packets"])

    def test_incomparable_snapshots(self):
        self.b["start_ns"] = 20
        with self.assertRaises(ValueError):
            difference(self.a, self.b)
        self.b["start_ns"] = 30
        self.b["identity"][1] += 1
        with self.assertRaises(ValueError):
            difference(self.a, self.b)
