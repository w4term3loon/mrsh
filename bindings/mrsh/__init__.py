import os
import ctypes

from collections import namedtuple
Match = namedtuple('Match', ['hash1', 'hash2', 'score'])
Meta = namedtuple('Meta', ['name', 'size', 'filters'])

lib_path = os.path.join(os.path.dirname(__file__), "_native.so")
lib = ctypes.CDLL(lib_path)

# define C signatures
class Fingerprint(ctypes.Structure):
    pass
Fingerprint._fields_ = [
        ("bf_list", ctypes.c_void_p),
        ("bf_list_last_element", ctypes.c_void_p),
        ("next", ctypes.POINTER(Fingerprint)),
        ("amount_of_BF", ctypes.c_uint32),
        ("file_name", ctypes.c_char * 200),
        ("filesize", ctypes.c_uint32),
    ]

lib.fp_init.restype = ctypes.POINTER(Fingerprint)
lib.fp_destroy.argtypes = [ctypes.POINTER(Fingerprint)]

lib.fp_add_file.restype = ctypes.c_int32
lib.fp_add_file.argtypes = [ctypes.POINTER(Fingerprint), ctypes.c_char_p, ctypes.c_char_p]

lib.fp_add_bytes.restype = ctypes.c_int32
lib.fp_add_bytes.argtypes = [ctypes.POINTER(Fingerprint), ctypes.c_char_p, ctypes.c_ulong, ctypes.c_char_p]

lib.fp_fp_compare.restype = ctypes.c_uint8
lib.fp_fp_compare.argtypes = [ctypes.POINTER(Fingerprint), ctypes.POINTER(Fingerprint)]

lib.fp_get.argtypes = [ctypes.POINTER(Fingerprint), ctypes.c_char_p, ctypes.c_long]

class FingerprintList(ctypes.Structure):
    _fields_ = [
        ("list", ctypes.POINTER(Fingerprint)),
        ("last_element", ctypes.POINTER(Fingerprint)),
        ("size", ctypes.c_long)
    ]

lib.fpl_init.restype = ctypes.POINTER(FingerprintList)
lib.fpl_destroy.argtypes = [ctypes.POINTER(FingerprintList)];

lib.fpl_add_path.argtypes = [ctypes.POINTER(FingerprintList), ctypes.c_char_p, ctypes.c_char_p]
lib.fpl_add_bytes.argtypes = [ctypes.POINTER(FingerprintList), ctypes.c_char_p, ctypes.c_ulong, ctypes.c_char_p]

lib.fpl_get.argtypes = [ctypes.POINTER(FingerprintList), ctypes.c_char_p, ctypes.c_long]

class _MRSH_fp:
    def __init__(self):
        self.fp = lib.fp_init()

    def __del__(self):
        lib.fp_destroy(self.fp)

    def __call__(self):
        # TODO: find an intuitive use case
        pass

    def add(self, data):
        err = 0
        if isinstance(data, str):
            err = lib.fp_add_file(self.fp, data.encode(), None)
        elif isinstance(data, bytes):
            err = lib.fp_add_bytes(self.fp, data, len(data), b"n/a")

        elif isinstance(data, tuple):
            d = data[0]
            label = data[1].encode()
            if isinstance(d, str):
                err = lib.fp_add_file(self.fp, d.encode(), label)

            if isinstance(d, bytes):
                err = lib.fp_add_bytes(self.fp, d, len(d), label)

        if (err != 0):
            return None
        return self

    def __str__(self):
        buf = ctypes.create_string_buffer(self.fp.contents.amount_of_BF+1 * 512 + 256)
        lib.fp_get(self.fp, buf, len(buf))
        return buf.value.decode()

class _MRSH_fpl:
    def __init__(self):
        self.fpl = lib.fpl_init()

    def __del__(self):
        lib.fpl_destroy(self.fpl)

    def __call__(self):
        # TODO: find an intuitive use case
        pass

    def add(self, elem):
        if isinstance(elem, str):
            lib.fpl_add_path(self.fpl, elem.encode(), None)

        elif isinstance(elem, bytes):
            lib.fpl_add_bytes(self.fpl, elem, len(elem), b"n/a")

        elif isinstance(elem, tuple):
            data = elem[0]
            label = elem[1].encode()
            if isinstance(data, str):
                lib.fpl_add_path(self.fpl, data.encode(), label)

            if isinstance(data, bytes):
                lib.fpl_add_bytes(self.fpl, data, len(data), label)

        elif isinstance(elem, list):
            for e in elem:
                self.add(e)
        else:
            raise TypeError("Unsupported input type")
        return self

    def __iadd__(self, other):
        self.add(other)
        return self

    def __str__(self):
        # TODO: calculate every bloom filter for every fp:
        # fp*(fp_x*fp_x_bf_num*512) {+additional headers}
        buf = ctypes.create_string_buffer(self.fpl.contents.size+1 * 512 + 256) # placeholder
        lib.fpl_get(self.fpl, buf, len(buf))
        return buf.value.decode()

    # could be moved to C for performance
    # TODO: rework this into new comparison
    def compare_all(self, threshold=None):
        results = []
        fpl = ctypes.cast(self.fpl, ctypes.POINTER(FingerprintList)).contents

        tmp1 = fpl.list
        while tmp1:
            tmp2 = tmp1.contents.next
            while tmp2:
                score = lib.fp_fp_compare(tmp1, tmp2)
                name1 = tmp1.contents.file_name.decode()
                name2 = tmp2.contents.file_name.decode()

                if threshold is None:
                    results.append(Match(name1, name2, score))
                elif threshold <= score:
                    results.append(Match(name1, name2, score))

                tmp2 = tmp2.contents.next
            tmp1 = tmp1.contents.next

        return results

def fp(data=None) -> _MRSH_fp:
    obj = _MRSH_fp()
    if data is not None:
        obj.add(data)
    return obj

def fpl(data=None) -> _MRSH_fpl:
    obj = _MRSH_fpl()
    if data is not None:
        obj.add(data)
    return obj

def hash(data=None) -> str:
    obj = _MRSH_fp()
    if data is not None:
        obj.add(data)
    return obj.__str__()

# TODO: rework comparison
def compare(hash1, hash2, mode='default') -> Match:
    _ = mode
    score = lib.fp_fp_compare(hash1.fp, hash2.fp)
    return Match(hash1.fp.contents.file_name.decode(), hash2.fp.contents.file_name.decode(), score)

def meta(fingerprint:_MRSH_fp) -> Meta:
    fp = fingerprint.fp
    return Meta(fp.contents.file_name, fp.contents.filesize, fp.contents.amount_of_BF)
