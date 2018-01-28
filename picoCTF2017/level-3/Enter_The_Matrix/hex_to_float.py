'''
Python2
usage: hex_to_float.py <hex>
        the <hex> is the hex value when view as 32-bit dword on little-endian computer
'''
import struct
import sys

h = sys.argv[1]
print(struct.unpack('>f', h.decode('hex'))[0])

# reverse: hex to float
# f = 1
# print(hex(struct.unpack('<I', struct.pack('<f', f))[0]))
