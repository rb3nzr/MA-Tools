from Crypto.Cipher import ARC4
import base64
import pefile
import re
import sys

'''
Extracts and decrypts config data and the URL for downloading of the main module

Usage: python3 redosdru_config_ex.py <sample>

Sample used: 79c061e457eae6fe5e1ed54eb37e968e8d49d130b8723e2bd8fa8ce4329f81db
'''

def decrypt_config(enc_config):
    config_len = len(enc_config)
    enc_config = bytearray(base64.urlsafe_b64decode(enc_config + b'=' * (-len(enc_config) % 4)))

    # replace values (119 and 0x56)
    for i in range(min(config_len, len(enc_config))):
        enc_config[i] = (enc_config[i] + 119) % 256
        enc_config[i] ^= 0x56

    # replace key
    key = b"Strong798"
    cipher = ARC4.new(key)
    dec_config = bytearray(cipher.encrypt(bytes(enc_config))) 

    return bytes(dec_config)  

def decrypt_url(enc_url):
    url_len = len(enc_url)
    enc_url = bytearray(base64.urlsafe_b64decode(enc_url + b'=' * (-len(enc_url) % 4)))

    # replace values (122 and 0x59)
    for i in range(min(url_len, len(enc_url))):
        enc_url[i] = (enc_url[i] + 122) % 256
        enc_url[i] ^= 0x59

    # replace key
    key = b"Getong538"
    cipher = ARC4.new(key)
    dec_url = bytearray(cipher.encrypt(bytes(enc_url))) 

    return bytes(dec_url)

def get_url(sample):
    pattern = re.compile(b"[A-Za-z0-9+/]{54}")
    data = sample.get_memory_mapped_image()

    config = []
    matches = [match.group(0).decode(errors='replace') for match in pattern.finditer(data)]
    config = ''.join(matches)
    url = config[:54]

    return url

def get_config(sample):
    pattern = re.compile(b"[A-Za-z0-9+/=]{69}")
    data = sample.get_memory_mapped_image()

    config = []
    matches = [match.group(0).decode(errors='replace') for match in pattern.finditer(data)]
    config = ''.join(matches)

    return config

def main():
    sample = pefile.PE(sys.argv[1])

    config = get_config(sample)
    decrypted_config = decrypt_config(config.encode())
    decoded_hex = decrypted_config.hex()
    config_data = bytes.fromhex(decoded_hex)
    cleaned_config = config_data.decode('utf-8', errors='ignore').replace(' ', '\n')

    url = get_url(sample)
    decrypted_url = decrypt_url(url.encode())
    decrypted_url_hex = decrypted_url.hex()
    url_data = bytes.fromhex(decrypted_url_hex)
    cleaned_url = url_data.decode('utf-8', errors='ignore').replace(' ', '\n')

    print(f" ========== Config data ========== \n")
    print(f"{cleaned_config}\n")
    print(f" ======== NetSyst DLL URL ======== \n")
    print(f"{cleaned_url}\n")

if __name__ == '__main__':
    main()


     

