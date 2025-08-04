import os
import ctypes

from collections import namedtuple

lib_path = os.path.join(os.path.dirname(__file__), "libmrsh.so")
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

Metadata = namedtuple('Metadata', ['name', 'size', 'filters'])

lib.fp_init.restype = ctypes.POINTER(Fingerprint)

lib.fp_destroy.restype = None
lib.fp_destroy.argtypes = [ctypes.POINTER(Fingerprint)]

lib.fp_add_file.restype = ctypes.c_int32
lib.fp_add_file.argtypes = [ctypes.POINTER(Fingerprint), ctypes.c_char_p, ctypes.c_char_p]

lib.fp_add_bytes.restype = ctypes.c_int32
lib.fp_add_bytes.argtypes = [ctypes.POINTER(Fingerprint), ctypes.c_char_p, ctypes.c_ulong, ctypes.c_char_p]

lib.fp_fp_compare.restype = ctypes.c_uint8
lib.fp_fp_compare.argtypes = [ctypes.POINTER(Fingerprint), ctypes.POINTER(Fingerprint)]

lib.fp_str.restype = ctypes.c_void_p
lib.fp_str.argtypes = [ctypes.POINTER(Fingerprint)]

class FingerprintList(ctypes.Structure):
    _fields_ = [
        ("list", ctypes.POINTER(Fingerprint)),
        ("last_element", ctypes.POINTER(Fingerprint)),
        ("size", ctypes.c_long)
    ]

lib.fpl_init.restype = ctypes.POINTER(FingerprintList)

lib.fpl_destroy.restype = None
lib.fpl_destroy.argtypes = [ctypes.POINTER(FingerprintList)];

lib.fpl_add_path.argtypes = [ctypes.POINTER(FingerprintList), ctypes.c_char_p, ctypes.c_char_p]
lib.fpl_add_bytes.argtypes = [ctypes.POINTER(FingerprintList), ctypes.c_char_p, ctypes.c_ulong, ctypes.c_char_p]

lib.fpl_str.restype = ctypes.c_void_p
lib.fpl_str.argtypes = [ctypes.POINTER(FingerprintList)]

lib.str_free.restype = None
lib.str_free.argtypes = [ctypes.c_void_p]

class Compare(ctypes.Structure):
    _fields_ = [
        ("name1", ctypes.c_char_p),
        ("name2", ctypes.c_char_p),
        ("score", ctypes.c_uint8)
    ]

class CompareList(ctypes.Structure):
    _fields_ = [
        ("list", ctypes.POINTER(Compare)),
        ("size", ctypes.c_long)
    ]

Comparison = namedtuple('Comparison', ['hash1', 'hash2', 'score'])
def cl_to_list(cl_ptr) -> list:
    cl = cl_ptr.contents
    return [
        Comparison(cl.list[i].name1.decode(), cl.list[i].name2.decode(), cl.list[i].score)
        for i in range(cl.size)
    ]

lib.cl_fpl_all.restype = ctypes.POINTER(CompareList)
lib.cl_fpl_all.argtypes = [ctypes.POINTER(FingerprintList), ctypes.c_uint8]

lib.cl_free.restype = None
lib.cl_free.argtypes = [ctypes.POINTER(CompareList)]
# TODO: class, and desctructor for gc-ability

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
        raw = lib.fp_str(self.fp)
        if not raw:
            return ""

        data = ctypes.string_at(raw)
        lib.str_free(raw)
        return data.decode('utf-8', errors='replace')

    def meta(self) -> Metadata:
        fp = self.fp
        return Metadata(fp.contents.file_name.rstrip(b'\0').decode(),
                        fp.contents.filesize, fp.contents.amount_of_BF)

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

            elif isinstance(data, bytes):
                lib.fpl_add_bytes(self.fpl, data, len(data), label)
            else:
                raise TypeError("Unsupported data type in tuple")

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
        raw = lib.fpl_str(self.fpl)
        if not raw:
            return ""

        data = ctypes.string_at(raw)
        lib.str_free(raw)
        return data.decode('utf-8', errors='replace')

    def compare_all(self, threshold=0):
        cl_ptr = lib.cl_fpl_all(self.fpl, threshold);
        result = cl_to_list(cl_ptr)
        lib.cl_free(cl_ptr)
        return result

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

# TODO: other types
def compare(hash1, hash2, mode='default') -> Comparison:
    _ = mode
    score = lib.fp_fp_compare(hash1.fp, hash2.fp)
    return Comparison(hash1.fp.contents.file_name.decode(), hash2.fp.contents.file_name.decode(), score)

