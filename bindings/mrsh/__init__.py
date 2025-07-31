import ctypes
import os

lib_path = os.path.join(os.path.dirname(__file__), "_native.so")
_native = ctypes.CDLL(lib_path)

def init_fplist():
    _native.init_empty_fingerprintList()
    print("inited successfully")

