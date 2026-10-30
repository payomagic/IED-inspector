"""Regression tests: python -m unittest discover tests"""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from ied_inspector.scl import SclModel  # noqa: E402

PCM600_STYLE = b"""<?xml version="1.0" encoding="utf-8"?>
<SCL xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns="http://www.iec.ch/61850/2003/SCL" version="2007" revision="B">
  <Header id="t"/>
  <Communication><SubNetwork name="WA1" type="8-MMS">
    <ConnectedAP iedName="R1" apName="AP1">
      <Address><P type="IP" xsi:type="tP_IP">10.0.0.5</P></Address>
      <GSE ldInst="LD0" cbName="gcb1"><Address>
        <P type="MAC-Address" xsi:type="tP_MAC-Address">01-0C-CD-01-05-46</P>
        <P type="APPID" xsi:type="tP_APPID">0546</P>
        <P type="VLAN-ID" xsi:type="tP_VLAN-ID">2D4</P>
        <P type="VLAN-PRIORITY" xsi:type="tP_VLAN-PRIORITY">4</P>
      </Address></GSE>
    </ConnectedAP></SubNetwork></Communication>
  <IED name="R1"><AccessPoint name="AP1"><Server><LDevice inst="LD0">
    <LN0 lnClass="LLN0" inst="" lnType="T"><DataSet name="DS"/>
      <GSEControl name="gcb1" appID="R1LD0/LLN0.gcb1" datSet="DS" confRev="1"/></LN0>
  </LDevice></Server></AccessPoint></IED>
</SCL>"""


class SclAddressTest(unittest.TestCase):
    def test_xsi_type_does_not_hide_address_parameters(self):
        m = SclModel.load(PCM600_STYLE, "pcm600.scd")
        cb = m.all_gocbs()[0]
        self.assertEqual(cb["vlanId"], 0x2D4)          # 724 decimal
        self.assertEqual(cb["vlanPriority"], 4)
        self.assertEqual(cb["appId"], 0x0546)
        self.assertEqual(cb["mac"], "01-0C-CD-01-05-46")
        self.assertEqual(m.ieds["R1"]["ip"], "10.0.0.5")

    def test_pcm600_mac_range_is_not_a_warning(self):
        m = SclModel.load(PCM600_STYLE, "pcm600.scd")
        self.assertFalse([f for f in m.validate() if f["severity"] in ("warning", "error") and "MAC" in f["message"]])


if __name__ == "__main__":
    unittest.main()
