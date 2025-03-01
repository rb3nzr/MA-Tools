#!/usr/bin/env python3

import sys
import pefile
from Crypto.Cipher import ARC4

if len(sys.argv) < 2:
    print("Usage: python plugx_config_extractor.py <sample>")
    sys.exit(1)

f = sys.argv[1]
pe = pefile.PE(f)
print(f"======= SAMPLE: {f} =======")

data_section = pe.sections[2]
data = data_section.get_data()

key_bytes = data[24:28]
key = f"{int.from_bytes(key_bytes, 'little'):X}"
print(f">>> DECRYPTION KEY: {key}")

enc_config = data[32:].split(b'\x00\x00', 1)[0]

rc4 = ARC4.new(key.encode())
config = rc4.decrypt(enc_config)

fields = config.split(b'\x00\x00')
fields = [f for f in fields if f]
fields = [f.decode('utf-8', errors='ignore') for f in fields]
print(f">>> Mutex: {fields[1]}")
print(f">>> Domain 1: {fields[4]}")
print(f">>> Domain 2: {fields[5]}")
print(f">>> Domain 3: {fields[6]}")
print(f">>> Document: {fields[3]}")
print(f">>> Possible campaign ID: {fields[2]}")
print(f">>> Possible campaign ID: {fields[2]}")
