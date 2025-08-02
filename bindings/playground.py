import mrsh
import random

myhash = mrsh.new()

rng = random.Random(1337)
haystack = bytes(rng.getrandbits(8) for _ in range(4096))

start = 512
needle = bytes(haystack[start:start + 919])

myhash.add([haystack, needle])

print(myhash)
print(f"Score is {myhash.compare()}")

