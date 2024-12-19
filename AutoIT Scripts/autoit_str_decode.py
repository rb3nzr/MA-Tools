

import re 
import os 
import sys
import argparse 

"""
Example sample: 05d9a6b5ca04a3fb6392e36c27915575740e711991f2300cf31e82fa7b8cd5d0
Example function call on encoded string: AMENDRANGES("89[82[70[68[69[88[79[68[85[92[35[35[35[35", 0x4 + 0xffffffff)

[!] Changes that will need to be made depending on the .au3 script:
    - The delimiter that splits the encoded strings ('[' is used here)
    - The starting literal (name of the static string enc function) on the regex patterns (AMENDRANGES is used here)
"""

def decode_str(enc_str, val):
    res = ""
    split = [int(x) for x in enc_str.split("[")] # Edit delimiter 
        decoded = (b - val) & 0xFFFF
        res += chr(decoded)
    return res 

def unsigned_to_signed(num, bits=32):
    u_max = 2**bits 
    s_max = 2**(bits - 1)
    return num - u_max if num >= s_max else num 

def print_strs(file_path, pattern):
    with open(file_path, 'r') as f:
        contents = f.read()

    ro_pattern = r'AMENDRANGES\([^)]*\)' # Edit starting literal (ex: AMENDRANGES)
    matches = re.findall(ro_pattern, contents)
    for ro_call in matches:
        match = re.match(pattern, ro_call)
        if match:
            enc_str, val, mask = match.groups()
            val = int(val, 16)
            mask = int(mask, 16)
            signed_mask = unsigned_to_signed(mask)
            val_res = val + signed_mask
            print(decode_str(enc_str, val_res))

def comment_script(file_path, pattern):
    with open(file_path, 'r') as f:
        lines = f.readlines()
    
    modified_lines = []
    for line in lines:
        match = re.search(pattern, line)
        if match:
            enc_str, val, mask = match.groups()
            val = int(val, 16)
            mask = int(mask.split(')')[0].strip(), 16)
            signed_mask = unsigned_to_signed(mask)
            val_res = val + signed_mask
            decoded_str = decode_str(enc_str, val_res)

            comment = f"  ; Decodes to: {decoded_str}"
            line = line.rstrip() + comment + '\n'
        modified_lines.append(line)
    
    with open("modified_script", 'w') as f:
        f.writelines(modified_lines)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("-f", "--file-path", required=True, help="Path to AutoIT script file")
    parser.add_argument("-p", "--print", action="store_true", help="Print the decoded strings")
    parser.add_argument("-c", "--set-comments", action="store_true", help="Write out a new file with comments for the decoded strings")
    args = parser.parse_args

    # Edit the starting literal (RO in this case) as it's probably different in the .au3
    pattern = r'AMENDRANGES\(\s*"([^"]+)"\s*,\s*([^+]+)\s*\+\s*([^,]+)\s*\)'

    if not os.path.exists(args.file_path):
        print("Could not find file from given path")
        sys.exit()
    
    file_path = args.file_path 
    if args.print:
        print_strs(file_path, pattern)
    if args.set_comments:
        comment_script(file_path, pattern)



