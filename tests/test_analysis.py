"""python -m unittest discover tests"""
import os
import sys
import time
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from ied_inspector.analysis import analyze, ied_name_from_domains  # noqa: E402


def conn(ip, model, domains, vlan, appid):
    dom = domains[0]
    return {"ip": ip, "ok": True, "started": time.time(), "finished": time.time(), "domains": domains,
            "identity": {"vendor": "ABB", "model": model, "revision": "x"},
            "gocbs": [{"ref": f"{dom}/LLN0$GO$gcbTrip", "kind": "GOOSE", "name": "gcbTrip", "vlanId": vlan,
                       "appId": appid, "mac": "01-0C-CD-01-00-01", "confRev": 1, "members": []}],
            "svcbs": [], "supervision": [], "vendorSupervision": []}


class DeviceNamingTest(unittest.TestCase):
    def test_same_model_different_ips_are_separate_devices(self):
        a = analyze(None, [conn("127.0.0.61", "RED670", ["RED670_ALD0", "RED670_ACTRL"], 103, 0x1001),
                           conn("127.0.0.62", "RED670", ["RED670_BLD0", "RED670_BCTRL"], 101, 0x1002),
                           conn("127.0.0.66", "REF615", ["REF615LD0"], 102, 0x2001)])
        names = sorted(d["name"] for d in a["devices"])
        self.assertEqual(len(names), 3, names)
        self.assertIn("RED670_A", names)
        self.assertIn("RED670_B", names)

    def test_identical_ld_names_on_two_ips_stay_separate(self):
        # two simulators loaded from the same CID: same LD names, different IPs
        a = analyze(None, [conn("127.0.0.61", "RED670", ["AA1LD0"], 103, 0x1001),
                           conn("127.0.0.62", "RED670", ["AA1LD0"], 101, 0x1002)])
        self.assertEqual(len(a["devices"]), 2, [d["name"] for d in a["devices"]])
        self.assertEqual(len(a["controlBlocks"]), 2)
        self.assertEqual(sorted(r["effective"]["vlanId"] for r in a["controlBlocks"]), [101, 103])

    def test_name_from_domains(self):
        self.assertEqual(ied_name_from_domains(["AA1J1Q01A1LD0", "AA1J1Q01A1CTRL"]), "AA1J1Q01A1")
        self.assertEqual(ied_name_from_domains(["REF615LD0"]), "REF615")


if __name__ == "__main__":
    unittest.main()
