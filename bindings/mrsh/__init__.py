import os
import sys
import ctypes

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

lib.fingerprint_compare.argtypes = [ctypes.POINTER(Fingerprint), ctypes.POINTER(Fingerprint)]
lib.fingerprint_compare.restype = ctypes.c_uint8

class FingerprintList(ctypes.Structure):
    _fields_ = [
        ("list", ctypes.POINTER(Fingerprint)),
        ("last_element", ctypes.POINTER(Fingerprint)),
        ("size", ctypes.c_long)
    ]

lib.init_empty_fingerprintList.restype = ctypes.POINTER(FingerprintList)
lib.fingerprintList_destroy.argtypes = [ctypes.POINTER(FingerprintList)];

lib.addPathToFingerprintList.argtypes = [ctypes.POINTER(FingerprintList), ctypes.c_char_p]
lib.addBytesToFingerprintList.argtypes = [ctypes.POINTER(FingerprintList), ctypes.c_char_p, ctypes.c_ulong]

lib.get_fingerprintList.argtypes = [ctypes.POINTER(FingerprintList), ctypes.c_char_p, ctypes.c_long]

class _MRSH_fpl:
    def __init__(self):
        self.fpl = lib.init_empty_fingerprintList()

    def __del__(self):
        lib.fingerprintList_destroy(self.fpl)

    def __call__(self, data):
        if isinstance(data, str):
            lib.addPathToFingerprintList(self.fpl, data.encode())
        elif isinstance(data, bytes):
            lib.addBytesToFingerprintList(self.fpl, data, len(data))
        elif isinstance(data, list):
            for elem in data:
                self.__call__(elem)
        else:
            raise TypeError("Unsupported input type")
        return self

    def __str__(self):
        # fp*512 {+additional headers}
        buf = ctypes.create_string_buffer(2048)
        lib.get_fingerprintList(self.fpl, buf, len(buf))
        return buf.value.decode()

    def compare(self):
        results = []
        fpl = ctypes.cast(self.fpl, ctypes.POINTER(FingerprintList)).contents

        tmp1 = fpl.list
        while tmp1:
            tmp2 = tmp1.contents.next
            while tmp2:
                score = lib.fingerprint_compare(tmp1, tmp2)
                name1 = tmp1.contents.file_name.decode()
                name2 = tmp2.contents.file_name.decode()
                results.append((name1, name2, score))
                tmp2 = tmp2.contents.next
            tmp1 = tmp1.contents.next

        return results

class _MRSHmodule:
    def __call__(self, data=None) -> _MRSH_fpl:
        obj = _MRSH_fpl()
        if data is not None:
            obj(data)
        return obj

sys.modules[__name__] = _MRSHmodule() # type: ignore
