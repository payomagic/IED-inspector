"""Optional MMS backend using libiec61850 (https://libiec61850.com, GPLv3 / commercial)
through ctypes. Nothing from libiec61850 is bundled; the user points the app to a
shared library (libiec61850.so / iec61850.dll) in Settings."""
import ctypes
import os
import sys
import time

from .ber import BitString, UtcTime, FailedAccess
from .iso import MmsError

MMS_ARRAY, MMS_STRUCTURE, MMS_BOOLEAN, MMS_BIT_STRING, MMS_INTEGER, MMS_UNSIGNED, MMS_FLOAT, \
    MMS_OCTET_STRING, MMS_VISIBLE_STRING, MMS_GENERALIZED_TIME, MMS_BINARY_TIME, MMS_BCD, \
    MMS_OBJ_ID, MMS_STRING, MMS_UTC_TIME, MMS_DATA_ACCESS_ERROR = range(16)

_libs = {}


class _Identity(ctypes.Structure):
    _fields_ = [("vendorName", ctypes.c_char_p), ("modelName", ctypes.c_char_p), ("revision", ctypes.c_char_p)]


class _VarAccessSpec(ctypes.Structure):
    _fields_ = [("domainId", ctypes.c_char_p), ("itemId", ctypes.c_char_p),
                ("arrayIndex", ctypes.c_int32), ("componentName", ctypes.c_char_p)]


def default_lib_names():
    if sys.platform.startswith("win"):
        return ["iec61850.dll", "libiec61850.dll"]
    if sys.platform == "darwin":
        return ["libiec61850.dylib"]
    return ["libiec61850.so"]


def load_lib(path=None):
    key = path or ""
    if key in _libs:
        return _libs[key]
    candidates = [path] if path else default_lib_names()
    last = None
    for c in candidates:
        try:
            lib = ctypes.CDLL(c)
            break
        except OSError as e:
            last = e
    else:
        raise MmsError(f"cannot load libiec61850: {last}")
    vp, cp, i, b = ctypes.c_void_p, ctypes.c_char_p, ctypes.c_int, ctypes.c_bool
    err = ctypes.POINTER(ctypes.c_int)
    sig = {
        "MmsConnection_create": (vp, []),
        "MmsConnection_setRequestTimeout": (None, [vp, ctypes.c_uint32]),
        "MmsConnection_setConnectTimeout": (None, [vp, ctypes.c_uint32]),
        "MmsConnection_connect": (b, [vp, err, cp, i]),
        "MmsConnection_conclude": (None, [vp, err]),
        "MmsConnection_close": (None, [vp]),
        "MmsConnection_destroy": (None, [vp]),
        "MmsConnection_identify": (ctypes.POINTER(_Identity), [vp, err]),
        "MmsServerIdentity_destroy": (None, [ctypes.POINTER(_Identity)]),
        "MmsConnection_getDomainNames": (vp, [vp, err]),
        "MmsConnection_getDomainVariableNames": (vp, [vp, err, cp]),
        "MmsConnection_getDomainVariableListNames": (vp, [vp, err, cp]),
        "MmsConnection_readVariable": (vp, [vp, err, cp, cp]),
        "MmsConnection_getVariableAccessAttributes": (vp, [vp, err, cp, cp]),
        "MmsConnection_readNamedVariableListValues": (vp, [vp, err, cp, cp, b]),
        "MmsConnection_readNamedVariableListDirectory": (vp, [vp, err, cp, cp, ctypes.POINTER(b)]),
        "LinkedList_getNext": (vp, [vp]),
        "LinkedList_getData": (vp, [vp]),
        "LinkedList_destroy": (None, [vp]),
        "MmsVariableSpecification_getType": (i, [vp]),
        "MmsVariableSpecification_getName": (cp, [vp]),
        "MmsVariableSpecification_getSize": (i, [vp]),
        "MmsVariableSpecification_getChildSpecificationByIndex": (vp, [vp, i]),
        "MmsVariableSpecification_destroy": (None, [vp]),
        "MmsValue_getType": (i, [vp]),
        "MmsValue_getArraySize": (ctypes.c_uint32, [vp]),
        "MmsValue_getElement": (vp, [vp, i]),
        "MmsValue_getBoolean": (b, [vp]),
        "MmsValue_toInt64": (ctypes.c_int64, [vp]),
        "MmsValue_toUint32": (ctypes.c_uint32, [vp]),
        "MmsValue_toDouble": (ctypes.c_double, [vp]),
        "MmsValue_toString": (cp, [vp]),
        "MmsValue_getOctetStringSize": (ctypes.c_uint16, [vp]),
        "MmsValue_getOctetStringBuffer": (ctypes.POINTER(ctypes.c_uint8), [vp]),
        "MmsValue_getBitStringSize": (i, [vp]),
        "MmsValue_getBitStringBit": (b, [vp, i]),
        "MmsValue_getUtcTimeInMs": (ctypes.c_uint64, [vp]),
        "MmsValue_getDataAccessError": (i, [vp]),
        "MmsValue_delete": (None, [vp]),
        "LibIEC61850_getVersionString": (cp, []),
    }
    for name, (res, args) in sig.items():
        fn = getattr(lib, name, None)
        if fn is None:
            continue
        fn.restype, fn.argtypes = res, args
    _libs[key] = lib
    return lib


def lib_version(path=None):
    lib = load_lib(path)
    try:
        return lib.LibIEC61850_getVersionString().decode()
    except Exception:
        return "unknown"


class LibIec61850Client:
    backend_name = "libiec61850"

    def __init__(self, host, port=102, timeout=5.0, lib_path=None):
        self.lib = load_lib(lib_path)
        self.host, self.port, self.timeout = host, port, timeout
        self.con = None
        self.log = [f"using libiec61850 {lib_version(lib_path)}"]

    def _err(self):
        return ctypes.c_int(0)

    def _check(self, e, what):
        if e.value != 0:
            raise MmsError(f"{what} failed (MmsError {e.value})")

    def connect(self):
        L = self.lib
        last = 0
        for attempt in range(2):          # first connect after library load is occasionally refused
            self.con = L.MmsConnection_create()
            L.MmsConnection_setRequestTimeout(self.con, int(self.timeout * 1000))
            if hasattr(L, "MmsConnection_setConnectTimeout"):
                L.MmsConnection_setConnectTimeout(self.con, int(self.timeout * 1000))
            e = self._err()
            ok = L.MmsConnection_connect(self.con, ctypes.byref(e), self.host.encode(), self.port)
            if ok and e.value == 0:
                self.log.append(f"MMS association established with {self.host}:{self.port}")
                return
            last = e.value
            L.MmsConnection_destroy(self.con)
            self.con = None
            time.sleep(0.2)
        raise MmsError(f"connect failed (MmsError {last})")

    def close(self):
        if self.con:
            L = self.lib
            e = self._err()
            try:
                L.MmsConnection_conclude(self.con, ctypes.byref(e))
            except Exception:
                pass
            L.MmsConnection_destroy(self.con)
            self.con = None

    def _strings(self, ll):
        out = []
        L = self.lib
        if not ll:
            return out
        el = L.LinkedList_getNext(ll)
        while el:
            d = L.LinkedList_getData(el)
            if d:
                out.append(ctypes.cast(d, ctypes.c_char_p).value.decode())
            el = L.LinkedList_getNext(el)
        return out

    def identify(self):
        e = self._err()
        p = self.lib.MmsConnection_identify(self.con, ctypes.byref(e))
        self._check(e, "identify")
        if not p:
            return {}
        r = p.contents
        g = lambda x: x.decode(errors="replace") if x else ""
        out = {"vendor": g(r.vendorName), "model": g(r.modelName), "revision": g(r.revision)}
        return out

    def domains(self):
        e = self._err()
        ll = self.lib.MmsConnection_getDomainNames(self.con, ctypes.byref(e))
        self._check(e, "getDomainNames")
        return self._strings(ll)

    def variables(self, domain):
        e = self._err()
        ll = self.lib.MmsConnection_getDomainVariableNames(self.con, ctypes.byref(e), domain.encode())
        self._check(e, "getDomainVariableNames")
        return self._strings(ll)

    def datasets(self, domain):
        e = self._err()
        ll = self.lib.MmsConnection_getDomainVariableListNames(self.con, ctypes.byref(e), domain.encode())
        self._check(e, "getDomainVariableListNames")
        return self._strings(ll)

    def _conv(self, v):
        L = self.lib
        t = L.MmsValue_getType(v)
        if t in (MMS_ARRAY, MMS_STRUCTURE):
            return [self._conv(L.MmsValue_getElement(v, i)) for i in range(L.MmsValue_getArraySize(v))]
        if t == MMS_BOOLEAN:
            return bool(L.MmsValue_getBoolean(v))
        if t == MMS_INTEGER:
            return int(L.MmsValue_toInt64(v))
        if t == MMS_UNSIGNED:
            return int(L.MmsValue_toUint32(v))
        if t == MMS_FLOAT:
            return float(L.MmsValue_toDouble(v))
        if t == MMS_BIT_STRING:
            n = L.MmsValue_getBitStringSize(v)
            return BitString("".join("1" if L.MmsValue_getBitStringBit(v, i) else "0" for i in range(n)))
        if t == MMS_OCTET_STRING:
            n = L.MmsValue_getOctetStringSize(v)
            return bytes(L.MmsValue_getOctetStringBuffer(v)[:n])
        if t in (MMS_VISIBLE_STRING, MMS_STRING):
            s = L.MmsValue_toString(v)
            return s.decode(errors="replace") if s else ""
        if t == MMS_UTC_TIME:
            return UtcTime(L.MmsValue_getUtcTimeInMs(v) / 1000.0)
        if t == MMS_DATA_ACCESS_ERROR:
            return FailedAccess(L.MmsValue_getDataAccessError(v))
        return None

    def read(self, domain, item):
        e = self._err()
        v = self.lib.MmsConnection_readVariable(self.con, ctypes.byref(e), domain.encode(), item.encode())
        self._check(e, f"read {domain}/{item}")
        try:
            return self._conv(v)
        finally:
            self.lib.MmsValue_delete(v)

    def _spec_tree(self, spec):
        L = self.lib
        t = L.MmsVariableSpecification_getType(spec)
        if t == MMS_STRUCTURE:
            out = []
            for i in range(L.MmsVariableSpecification_getSize(spec)):
                c = L.MmsVariableSpecification_getChildSpecificationByIndex(spec, i)
                out.append((L.MmsVariableSpecification_getName(c).decode(), self._spec_tree(c)))
            return out
        return None

    def get_type(self, domain, item):
        e = self._err()
        spec = self.lib.MmsConnection_getVariableAccessAttributes(self.con, ctypes.byref(e), domain.encode(), item.encode())
        self._check(e, "getVariableAccessAttributes")
        try:
            return self._spec_tree(spec)
        finally:
            self.lib.MmsVariableSpecification_destroy(spec)

    def dataset_directory(self, domain, name):
        e = self._err()
        dele = ctypes.c_bool(False)
        ll = self.lib.MmsConnection_readNamedVariableListDirectory(self.con, ctypes.byref(e), domain.encode(),
                                                                    name.encode(), ctypes.byref(dele))
        self._check(e, "readNamedVariableListDirectory")
        out = []
        el = self.lib.LinkedList_getNext(ll) if ll else None
        while el:
            d = self.lib.LinkedList_getData(el)
            if d:
                s = ctypes.cast(d, ctypes.POINTER(_VarAccessSpec)).contents
                out.append((s.domainId.decode() if s.domainId else domain, s.itemId.decode()))
            el = self.lib.LinkedList_getNext(el)
        return out

    def read_dataset(self, domain, name):
        e = self._err()
        v = self.lib.MmsConnection_readNamedVariableListValues(self.con, ctypes.byref(e), domain.encode(), name.encode(), False)
        self._check(e, "readNamedVariableListValues")
        try:
            return self._conv(v)
        finally:
            self.lib.MmsValue_delete(v)
