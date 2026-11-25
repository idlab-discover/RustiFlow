from copy import deepcopy
import unittest

from ledger import explain


class BoundaryTest(unittest.TestCase):
    def setUp(self):
        self.interval = {"deltas": {"link.rx.packets": 29, "softnet.dropped": 17,
                                    "driver.rx_queue_0_packets": 29, "driver.rx_queue_1_drops": 0}}
        self.kernel = {f: dict(matched=n, submitted=n, ring_drop=0) for f, n in (("4", 20), ("6", 7))}
        self.evidence = dict(scope="isolated", reference_frames={"4": 20, "6": 7}, other_link_units=2,
                             drained=True, decoded={"4": 20, "6": 7}, exported={"4": 20, "6": 7})

    def test_unequal_families_and_global_noise(self):
        result = explain(self.interval, self.evidence, self.kernel)
        self.assertEqual(result["observations"], [])
        self.assertIsNone(result["reported_queue_packet_sum"])

    def test_unmatched_scopes_cannot_locate_link_loss(self):
        self.interval["deltas"]["link.rx.packets"] = 15
        self.evidence["scope"] = "mixed"
        self.assertEqual(explain(self.interval, self.evidence, self.kernel)["observations"], [])
        self.evidence["scope"] = "isolated"
        self.assertIn("fewer units", explain(self.interval, self.evidence, self.kernel)["first_observation"])

    def test_positive_reserve_failure_without_ground_truth(self):
        self.kernel["6"].update(submitted=6, ring_drop=1)
        result = explain(self.interval, {}, self.kernel)
        self.assertEqual(result["observations"], ["TC ring reservation loss"])

    def test_only_compare_drained_consumers_in_pipeline_order(self):
        self.evidence["decoded"]["6"] = 5
        self.evidence["exported"] = {"4": 10, "6": 5}
        self.assertEqual(explain(self.interval, self.evidence, self.kernel)["observations"], [
            "IPv6 submitted versus decoded mismatch", "IPv4 decoded versus exported mismatch"])
        self.evidence["drained"] = False
        self.assertEqual(explain(self.interval, self.evidence, self.kernel)["observations"], [])

    def test_localize_remaining_stages_when_submission_missing(self):
        kernel = deepcopy(self.kernel)
        kernel["6"].update(submitted=None, matched=None)
        self.evidence["exported"]["6"] = 0
        self.assertEqual(explain(self.interval, self.evidence, kernel)["observations"],
                         ["IPv6 decoded versus exported mismatch"])
