import os
import pefile
from binaryninja import BinaryViewType, InstructionTextTokenType

def rotr32(value, shift):
	value &= 0xffffffff
	return ((value >> shift) | (value << (32 - shift))) & 0xffffffff

def routine(func_name_bytes):
	state = 0xc0de1337 
	for b in func_name_bytes:
		tmp = rotr32(state, 8)
		tmp = (tmp + b) & 0xffffffff
		state = state ^ tmp
	return state & 0xffffffff

def generate_hash_dict(dll_paths):
	hash_dict = {}
	for entry in dll_paths:
		if isinstance(entry, tuple):
			module_name, dll_path = entry
		else:
			dll_path = entry
			module_name = os.path.splitext(os.path.basename(dll_path))[0]
		
		pe = pefile.PE(dll_path)
		for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
			if exp.name is None:
				continue
			func_name_bytes = list(exp.name)
			h = routine(func_name_bytes)
			hash_dict[h] = f"{module_name}!{exp.name.decode('ascii', 'ignore')}"
	
	return hash_dict

dll_list = [
	("ntdll.dll", "/home/rb3nzr/Desktop/ntdll.dll"),
	("kernel32.dll", "/home/rb3nzr/Desktop/kernel32.dll"),
	("user32.dll", "/home/rb3nzr/Desktop/user32.dll")
]

hashes = generate_hash_dict(dll_list)

def annotate_hashed_imports():
	for fn in bv.functions:
		for block in fn.basic_blocks:
			for line in block.get_disassembly_text():
				addr = line.address
				for token in line.tokens:
					if token.type in [
						InstructionTextTokenType.IntegerToken,
						InstructionTextTokenType.PossibleAddressToken,
						InstructionTextTokenType.DataSymbolToken
					]:
					
					try:
						imm_val = int(token.text, 0)
					except ValueError:
						pass
					
					if imm_val in hashes:
						comment_str = f"import => {hashes[imm_val]}"
						fn.set_comment_at(addr, comment_str)
						print(f"=> 0x{addr:x}: Found 0x{imm_val:08x} => {hashes[imm_val]}")

annotate_hashed_imports()