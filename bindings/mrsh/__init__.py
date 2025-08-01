import os
import sys
import ctypes

lib_path = os.path.join(os.path.dirname(__file__), "_native.so")
lib = ctypes.CDLL(lib_path)

# define C signatures
lib.init_empty_fingerprintList.restype = ctypes.c_void_p
lib.addPathToFingerprintList.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
lib.addBytesToFingerprintList.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_ulong]
lib.print_fingerprintList.argtypes = [ctypes.c_void_p]
lib.fingerprintList_destroy.argtypes = [ctypes.c_void_p];

def fp_print(filename: str):
    if not filename:
        print("Please provide a filename.")
        return

    fpl = lib.init_empty_fingerprintList()
    lib.addPathToFingerprintList(fpl, filename.encode());
    lib.print_fingerprintList(fpl)
    lib.fingerprintList_destroy(fpl)

def fp_print_bytes(data:bytes):
    if not data:
        print("Please provide data.")
        return

    fpl = lib.init_empty_fingerprintList()
    lib.addBytesToFingerprintList(fpl, data, len(data));
    lib.print_fingerprintList(fpl)
    lib.fingerprintList_destroy(fpl)

class _CallableMRSH:
    def __call__(self, data):
        return fp_print(data)

    def fp_print_bytes(self, data):
        return fp_print_bytes(data)

sys.modules[__name__] = _CallableMRSH() # type: ignore
