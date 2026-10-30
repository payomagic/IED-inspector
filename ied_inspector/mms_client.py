"""Built-in read-only MMS client (own implementation, no third-party code).

Only these MMS services exist here: Initiate, Identify, GetNameList,
GetVariableAccessAttributes, Read, GetNamedVariableListAttributes, Conclude.
"""
import socket

from .ber import tlv, ber_uint, ber_parse, first, decode_data, decode_type
from .iso import (IsoTransport, MmsError, spdu, spdu_param, session_params, wrap_data, unwrap_data,
                  MMS_AC_OID, ACSE_AS_OID, MMS_AS_OID, BER_TS_OID)

OBJ_NAMED_VARIABLE = 0
OBJ_NAMED_VARIABLE_LIST = 2
OBJ_DOMAIN = 9


class BuiltinMmsClient:
    backend_name = "builtin"

    def __init__(self, host, port=102, timeout=5.0, local_ip=None):
        self.host, self.port, self.timeout, self.local_ip = host, port, timeout, local_ip
        self.sock = None
        self.iso = None
        self.invoke_id = 0
        self.log = []

    def _log(self, msg):
        self.log.append(msg)

    def connect(self):
        src = (self.local_ip, 0) if self.local_ip else None
        self.sock = socket.create_connection((self.host, self.port), timeout=self.timeout, source_address=src)
        self.sock.settimeout(self.timeout)
        self.iso = IsoTransport(self.sock)
        self._log(f"TCP connected to {self.host}:{self.port}")

        cr = b"\xE0\x00\x00\x00\x01\x00" + b"\xC0\x01\x0A" + b"\xC1\x02\x00\x01" + b"\xC2\x02\x00\x01"
        self.iso.send_tpkt(bytes([len(cr)]) + cr)
        cc = self.iso.recv_tpkt()
        if cc[1] & 0xF0 != 0xD0:
            raise MmsError("COTP connection refused")
        self._log("COTP connection confirmed")

        init_detail = (tlv(0x80, b"\x01") + tlv(0x81, b"\x05\xF1\x00")
                       + tlv(0x82, bytes.fromhex("03EE1C00000408000079EF18")))
        mms_init = tlv(0xA8, ber_uint(0x80, 65000) + ber_uint(0x81, 5) + ber_uint(0x82, 5)
                       + ber_uint(0x83, 10) + tlv(0xA4, init_detail))
        aarq = tlv(0x60,
                   tlv(0xA1, tlv(0x06, MMS_AC_OID))
                   + tlv(0xA2, tlv(0x06, bytes.fromhex("2901876701")))
                   + tlv(0xA3, tlv(0x02, b"\x0C"))
                   + tlv(0xA6, tlv(0x06, bytes.fromhex("29018767")))
                   + tlv(0xA7, tlv(0x02, b"\x0C"))
                   + tlv(0xBE, tlv(0x28, tlv(0x02, b"\x03") + tlv(0xA0, mms_init))))
        ctx_list = tlv(0xA4,
                       tlv(0x30, tlv(0x02, b"\x01") + tlv(0x06, ACSE_AS_OID) + tlv(0x30, tlv(0x06, BER_TS_OID)))
                       + tlv(0x30, tlv(0x02, b"\x03") + tlv(0x06, MMS_AS_OID) + tlv(0x30, tlv(0x06, BER_TS_OID))))
        user_data = tlv(0x61, tlv(0x30, tlv(0x02, b"\x01") + tlv(0xA0, aarq)))
        cp = tlv(0x31, tlv(0xA0, tlv(0x80, b"\x01"))
                 + tlv(0xA2, tlv(0x81, b"\x00\x00\x00\x01") + tlv(0x82, b"\x00\x00\x00\x01") + ctx_list + user_data))
        params = (b"\x05\x06\x13\x01\x00\x16\x01\x02" + b"\x14\x02\x00\x02"
                  + b"\x33\x02\x00\x01" + b"\x34\x02\x00\x01" + spdu_param(0xC1, cp))
        self.iso.send_cotp_data(spdu(0x0D, params))

        resp = self.iso.recv_cotp_data()
        if resp[0] != 0x0E:
            raise MmsError(f"association rejected (session SPDU 0x{resp[0]:02X})")
        pres = session_params(resp).get(0xC1)
        if pres is None:
            raise MmsError("no user data in session accept")
        normal = first(ber_parse(first(ber_parse(pres), 0x31)), 0xA2)
        pdv = first(ber_parse(first(ber_parse(normal), 0x61)), 0x30)
        aare = first(ber_parse(first(ber_parse(pdv), 0xA0)), 0x61)
        aare_items = ber_parse(aare)
        result = first(aare_items, 0xA2)
        if result is None or first(ber_parse(result), 0x02) != b"\x00":
            raise MmsError("ACSE association rejected")
        mms = first(ber_parse(first(ber_parse(first(aare_items, 0xBE)), 0x28)), 0xA0)
        if not mms or mms[0] != 0xA9:
            raise MmsError("MMS Initiate rejected")
        self._log("MMS association established")

    def _request(self, service):
        self.invoke_id = (self.invoke_id + 1) & 0x7FFFFFFF
        self.iso.send_cotp_data(wrap_data(tlv(0xA0, ber_uint(0x02, self.invoke_id) + service)))
        mms = unwrap_data(self.iso.recv_cotp_data())
        tag, body = ber_parse(mms)[0]
        if tag == 0xA2:
            raise MmsError("MMS confirmed-error")
        if tag == 0xA4:
            raise MmsError("MMS reject")
        if tag != 0xA1:
            raise MmsError(f"unexpected MMS PDU 0x{tag:02X}")
        return ber_parse(body)[1]

    def close(self):
        try:
            if self.iso:
                self.iso.send_cotp_data(b"\x09\x00")
        except OSError:
            pass
        finally:
            if self.sock:
                self.sock.close()
            self.sock = self.iso = None

    # ---- read-only services -------------------------------------------------
    def identify(self):
        _, body = self._request(tlv(0x82))
        items = ber_parse(body)
        g = lambda t: (first(items, t) or b"").decode("utf-8", "replace")
        return {"vendor": g(0x80), "model": g(0x81), "revision": g(0x82)}

    def get_name_list(self, object_class, domain=None):
        names, after = [], None
        while True:
            scope = tlv(0xA1, tlv(0x81, domain.encode()) if domain else tlv(0x80))
            req = tlv(0xA0, tlv(0x80, bytes([object_class]))) + scope
            if after:
                req += tlv(0x82, after.encode())
            _, body = self._request(tlv(0xA1, req))
            items = ber_parse(body)
            batch = [c.decode() for _, c in ber_parse(first(items, 0xA0) or b"")]
            names += batch
            more = first(items, 0x81)
            more = True if more is None else more != b"\x00"
            if not more or not batch:
                return names
            after = batch[-1]

    def domains(self):
        return self.get_name_list(OBJ_DOMAIN)

    def variables(self, domain):
        return self.get_name_list(OBJ_NAMED_VARIABLE, domain)

    def datasets(self, domain):
        return self.get_name_list(OBJ_NAMED_VARIABLE_LIST, domain)

    @staticmethod
    def _obj(domain, item):
        return tlv(0xA1, tlv(0x1A, domain.encode()) + tlv(0x1A, item.encode()))

    def read(self, domain, item):
        spec = tlv(0xA1, tlv(0xA0, tlv(0x30, tlv(0xA0, self._obj(domain, item)))))
        _, body = self._request(tlv(0xA4, spec))
        tag, c = ber_parse(first(ber_parse(body), 0xA1))[0]
        return decode_data(tag, c)

    def get_type(self, domain, item):
        _, body = self._request(tlv(0xA6, tlv(0xA0, self._obj(domain, item))))
        ts = first(ber_parse(body), 0xA2)
        return decode_type(ts) if ts else None

    def dataset_directory(self, domain, name):
        _, body = self._request(tlv(0xAC, self._obj(domain, name)))
        members = []
        for _, entry in ber_parse(first(ber_parse(body), 0xA1) or b""):
            vs = first(ber_parse(entry), 0xA0)
            dom_spec = first(ber_parse(vs), 0xA1)
            if dom_spec:
                parts = ber_parse(dom_spec)
                members.append((parts[0][1].decode(), parts[1][1].decode()))
        return members

    def read_dataset(self, domain, name):
        spec = tlv(0xA1, tlv(0xA1, self._obj(domain, name)))
        _, body = self._request(tlv(0xA4, spec))
        return [decode_data(t, c) for t, c in ber_parse(first(ber_parse(body), 0xA1) or b"")]
