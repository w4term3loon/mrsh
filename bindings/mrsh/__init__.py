import os
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

lib.addPathToFingerprintList.argtypes = [ctypes.POINTER(FingerprintList), ctypes.c_char_p, ctypes.c_char_p]
lib.addBytesToFingerprintList.argtypes = [ctypes.POINTER(FingerprintList), ctypes.c_char_p, ctypes.c_ulong, ctypes.c_char_p]

lib.get_fingerprintList.argtypes = [ctypes.POINTER(FingerprintList), ctypes.c_char_p, ctypes.c_long]

class _MRSH_fpl:
    def __init__(self):
        self.fpl = lib.init_empty_fingerprintList()

    def __del__(self):
        lib.fingerprintList_destroy(self.fpl)

    def __call__(self):
        pass

    def add(self, elem):
        if isinstance(elem, str):
            lib.addPathToFingerprintList(self.fpl, elem.encode(), None)

        elif isinstance(elem, bytes):
            na_label = ctypes.c_char_p("n/a".encode("utf-8"))
            lib.addBytesToFingerprintList(self.fpl, elem, len(elem), na_label)

        elif isinstance(elem, tuple):
            data = elem[0]
            label = ctypes.c_char_p(elem[1].encode("utf-8"))
            if isinstance(data, str):
                lib.addPathToFingerprintList(self.fpl, data.encode(), label)

            if isinstance(data, bytes):
                lib.addBytesToFingerprintList(self.fpl, data, len(data), label)

        elif isinstance(elem, list):
            for e in elem:
                self.add(e)
        else:
            raise TypeError("Unsupported input type")
        return self

    def __str__(self):
        # fp*512 {+additional headers}
        buf = ctypes.create_string_buffer(2048)
        lib.get_fingerprintList(self.fpl, buf, len(buf))
        return buf.value.decode()

    def compare(self, threshold=None):
        results = []
        fpl = ctypes.cast(self.fpl, ctypes.POINTER(FingerprintList)).contents

        tmp1 = fpl.list
        while tmp1:
            tmp2 = tmp1.contents.next
            while tmp2:
                score = lib.fingerprint_compare(tmp1, tmp2)
                name1 = tmp1.contents.file_name.decode()
                name2 = tmp2.contents.file_name.decode()

                if threshold is None:
                    results.append((name1, name2, score))
                elif threshold <= score:
                    results.append((name1, name2, score))

                tmp2 = tmp2.contents.next
            tmp1 = tmp1.contents.next

        return results

def new(data=None) -> _MRSH_fpl:
    obj = _MRSH_fpl()
    if data is not None:
        obj.add(data)
    return obj

