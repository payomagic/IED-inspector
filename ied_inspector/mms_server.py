"""Read-only MMS server used by the simulator. Write requests are always refused."""
import socket
import socketserver
import threading

from .ber import tlv, ber_uint, ber_parse, first, enc_uint
from .iso import (IsoTransport, MmsError, spdu, spdu_param, session_params, MMS_AC_OID, BER_TS_OID, MMS_AS_OID)

ERR_OBJECT_NON_EXISTENT = 10
ERR_ACCESS_DENIED = 3


class _Handler(socketserver.BaseRequestHandler):
    def handle(self):
        srv = self.server.owner
        srv._client_event(self.client_address, "connected")
        iso = IsoTransport(self.request)
        self.request.settimeout(600)
        mms_pcid = 3
        max_pdu = 65000
        try:
            cr = iso.recv_tpkt()
            if cr[1] & 0xF0 != 0xE0:
                return
            src_ref = cr[4:6]
            cc = b"\xD0\x00\x01" + src_ref + b"\x00" + b"\xC0\x01\x0A"
            iso.send_tpkt(bytes([len(cc)]) + cc)

            con = iso.recv_cotp_data()
            if con[0] != 0x0D:
                return
            pres = session_params(con).get(0xC1, b"")
            normal = first(ber_parse(first(ber_parse(pres), 0x31) or b""), 0xA2) or b""
            nitems = ber_parse(normal)
            for _, ctx in ber_parse(first(nitems, 0xA4) or b""):
                parts = ber_parse(ctx)
                if first(parts, 0x06) == MMS_AS_OID:
                    mms_pcid = int.from_bytes(first(parts, 0x02), "big")
            pdv = first(ber_parse(first(nitems, 0x61) or b""), 0x30) or b""
            aarq = first(ber_parse(first(ber_parse(pdv), 0xA0) or b""), 0x60) or b""
            ext = first(ber_parse(first(ber_parse(aarq), 0xBE) or b""), 0x28) or b""
            init = first(ber_parse(ext), 0xA0) or b""
            init_items = ber_parse(first(ber_parse(init), 0xA8) or b"")
            ld = first(init_items, 0x80)
            if ld:
                max_pdu = max(1000, min(65000, int.from_bytes(ld, "big")))
            self.max_pdu = max_pdu

            init_resp = tlv(0xA9, ber_uint(0x80, max_pdu) + ber_uint(0x81, 5) + ber_uint(0x82, 5)
                            + ber_uint(0x83, 10)
                            + tlv(0xA4, tlv(0x80, b"\x01") + tlv(0x81, b"\x05\xF1\x00")
                                  + tlv(0x82, bytes.fromhex("03EE1C00000408000079EF18"))))
            aare = tlv(0x61, tlv(0xA1, tlv(0x06, MMS_AC_OID)) + tlv(0xA2, tlv(0x02, b"\x00"))
                       + tlv(0xA3, tlv(0xA1, tlv(0x02, b"\x00")))
                       + tlv(0xBE, tlv(0x28, tlv(0x02, bytes([mms_pcid])) + tlv(0xA0, init_resp))))
            cpa = tlv(0x31, tlv(0xA0, tlv(0x80, b"\x01"))
                      + tlv(0xA2, tlv(0x83, b"\x00\x00\x00\x01")
                            + tlv(0xA5, tlv(0x30, tlv(0x80, b"\x00") + tlv(0x81, BER_TS_OID))
                                  + tlv(0x30, tlv(0x80, b"\x00") + tlv(0x81, BER_TS_OID)))
                            + tlv(0x61, tlv(0x30, tlv(0x02, b"\x01") + tlv(0xA0, aare)))))
            params = b"\x05\x06\x13\x01\x00\x16\x01\x02" + b"\x14\x02\x00\x02" + spdu_param(0xC1, cpa)
            iso.send_cotp_data(spdu(0x0E, params))
            srv._client_event(self.client_address, "associated")

            while True:
                req = iso.recv_cotp_data()
                if req[0] in (0x09, 0x19):           # FINISH / ABORT
                    if req[0] == 0x09:
                        iso.send_cotp_data(b"\x0A\x00")
                    return
                pres = req[4:] if req[:2] == b"\x01\x00" else req
                pdv = first(ber_parse(first(ber_parse(pres), 0x61) or b""), 0x30) or b""
                mms = first(ber_parse(pdv), 0xA0)
                if not mms:
                    continue
                resp = self.dispatch(srv, mms)
                if resp is not None:
                    out = tlv(0x61, tlv(0x30, tlv(0x02, bytes([mms_pcid])) + tlv(0xA0, resp)))
                    iso.send_cotp_data(b"\x01\x00\x01\x00" + out)
        except (MmsError, OSError, IndexError, ValueError, TypeError):
            pass
        finally:
            srv._client_event(self.client_address, "disconnected")

    # --------------------------------------------------------------
    def dispatch(self, srv, mms):
        tag, body = ber_parse(mms)[0]
        if tag == 0x8B:                                   # conclude
            return tlv(0x8C)
        if tag != 0xA0:
            return None
        items = ber_parse(body)
        invoke = items[0][1]
        stag, sbody = items[1]
        model = srv.model
        srv.requests += 1

        def ok(service):
            return tlv(0xA1, tlv(0x02, invoke) + service)

        def err():
            return tlv(0xA2, tlv(0x80, invoke) + tlv(0xA2, tlv(0xA0, tlv(0x85, b"\x00"))))

        if stag == 0x82:                                  # identify
            return ok(tlv(0xA2, tlv(0x80, srv.vendor.encode()) + tlv(0x81, srv.model_name.encode())
                          + tlv(0x82, srv.revision.encode())))

        if stag == 0xA1:                                  # getNameList
            p = ber_parse(sbody)
            cls = int.from_bytes(first(ber_parse(first(p, 0xA0)), 0x80), "big")
            scope = ber_parse(first(p, 0xA1))[0]
            after = first(p, 0x82)
            after = after.decode() if after else None
            if cls == 9:
                names = list(model.domains.keys())
            elif scope[0] == 0x81:
                dom = scope[1].decode()
                if dom not in model.domains:
                    return err()
                if cls == 0:
                    names = model.name_lists[dom]
                elif cls == 2:
                    names = [it for (d, it) in model.datasets if d == dom]
                else:
                    names = []
            else:
                names = []
            start = 0
            if after:
                try:
                    start = names.index(after) + 1
                except ValueError:
                    start = len(names)
            budget = self.max_pdu - 64
            out, size = [], 0
            for n in names[start:]:
                enc = tlv(0x1A, n.encode())
                if size + len(enc) > budget:
                    break
                out.append(enc)
                size += len(enc)
            more = start + len(out) < len(names)
            return ok(tlv(0xA1, tlv(0xA0, b"".join(out)) + tlv(0x81, b"\xFF" if more else b"\x00")))

        if stag == 0xA4:                                  # read
            p = ber_parse(sbody)
            vas = first(p, 0xA1)
            choice = ber_parse(vas)[0]
            results = []
            if choice[0] == 0xA0:                         # listOfVariable
                for _, entry in ber_parse(choice[1]):
                    results.append(self._read_one(model, entry))
            elif choice[0] == 0xA1:                       # dataset
                dparts = ber_parse(first(ber_parse(choice[1]), 0xA1) or b"")
                key = (dparts[0][1].decode(), dparts[1][1].decode()) if len(dparts) == 2 else None
                members = model.datasets.get(key)
                if members is None:
                    return err()
                for d, it in members:
                    node = model.lookup(d, it)
                    results.append(node.encode() if node else tlv(0x80, bytes([ERR_OBJECT_NON_EXISTENT])))
            return ok(tlv(0xA4, tlv(0xA1, b"".join(results))))

        if stag == 0xA6:                                  # getVariableAccessAttributes
            name = first(ber_parse(sbody), 0xA0)
            parts = ber_parse(first(ber_parse(name), 0xA1) or b"")
            if len(parts) != 2:
                return err()
            node = model.lookup(parts[0][1].decode(), parts[1][1].decode())
            if node is None:
                return err()
            return ok(tlv(0xA6, tlv(0x80, b"\x00") + tlv(0xA2, node.type_spec())))

        if stag == 0xAC:                                  # getNamedVariableListAttributes
            parts = ber_parse(first(ber_parse(sbody), 0xA1) or b"")
            if len(parts) != 2:
                return err()
            members = model.datasets.get((parts[0][1].decode(), parts[1][1].decode()))
            if members is None:
                return err()
            lst = b"".join(tlv(0x30, tlv(0xA0, tlv(0xA1, tlv(0x1A, d.encode()) + tlv(0x1A, it.encode()))))
                           for d, it in members)
            return ok(tlv(0xAC, tlv(0x80, b"\x00") + tlv(0xA1, lst)))

        if stag == 0xA5:                                  # write -> always refused (read-only)
            p = ber_parse(sbody)
            vas = ber_parse(first(p, 0xA0) or b"")
            n = max(1, len(vas[0:1] and ber_parse(vas[0][1])))
            srv._client_event(None, "write refused (simulator is read-only)")
            return ok(tlv(0xA5, b"".join(tlv(0x80, bytes([ERR_ACCESS_DENIED])) for _ in range(n))))

        return err()

    @staticmethod
    def _read_one(model, entry):
        vs = first(ber_parse(entry), 0xA0)
        parts = ber_parse(first(ber_parse(vs or b""), 0xA1) or b"")
        if len(parts) != 2:
            return tlv(0x80, bytes([ERR_OBJECT_NON_EXISTENT]))
        node = model.lookup(parts[0][1].decode(), parts[1][1].decode())
        return node.encode() if node else tlv(0x80, bytes([ERR_OBJECT_NON_EXISTENT]))


class _TCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class MmsServer:
    def __init__(self, model, ip, port=102, vendor="IED Inspector", model_name="Simulator", revision="0.2"):
        self.model, self.ip, self.port = model, ip, port
        self.vendor, self.model_name, self.revision = vendor, model_name, revision
        self.server = None
        self.thread = None
        self.clients = []
        self.events = []
        self.requests = 0

    def _client_event(self, addr, what):
        self.events.append({"client": f"{addr[0]}:{addr[1]}" if addr else "", "event": what})
        self.events = self.events[-50:]
        if addr and what == "associated":
            self.clients.append(f"{addr[0]}:{addr[1]}")
        if addr and what == "disconnected":
            c = f"{addr[0]}:{addr[1]}"
            if c in self.clients:
                self.clients.remove(c)

    def start(self):
        self.server = _TCPServer((self.ip, self.port), _Handler)
        self.server.owner = self
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def stop(self):
        if self.server:
            self.server.shutdown()
            self.server.server_close()
            self.server = None
