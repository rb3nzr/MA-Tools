#!/usr/bin/env python3

import sys
import re
import pefile
import struct
from capstone import *
from capstone.x86 import *
from colorama import Fore 

# Tested on:
# > packed:   1155d7ffbc9830d364310cf794b77f638df24218a4278b48754266dd8c50a823 2025-01-04
# > unpacked: a883940150a872c5ac33249ca8523e75ee98f4ace0bf1ad17d9d16c7edd78f8c
# > packed:   7e0f61d7f03f394f4dd1eaa7d5c9b19e0aa7e422a7527d3a345827473f123089 2025-01-02
# > unpacked: 9a5a61de316d081f4ab63cb945d602ffada90aaea4ce0aa3b8fd99e664b496cf

XOR_KEY = 0x2a

def is_prologue(instruction):
    if instruction.mnemonic == "push" and instruction.op_str == "ebp":
        return True
    return False

def is_epilogue(instruction):
    if instruction.mnemonic == "pop" and instruction.op_str == "ebp":
        return True
    return False

def pack_immediate(imm_value, imm_size):
    if imm_size == 1:
        return struct.pack("<B", imm_value & 0xFF)
    elif imm_size == 2:
        return struct.pack("<H", imm_value & 0xFFFF)
    elif imm_size == 4:
        return struct.pack("<I", imm_value & 0xFFFFFFFF)
    else:
        return b""

def read_bytes_from_pe(pe, va, size):
    image_base = pe.OPTIONAL_HEADER.ImageBase

    # Convert VA to an offset from the image base
    offset_from_base = va - image_base

    for section in pe.sections:
        start = section.VirtualAddress
        end = section.VirtualAddress + section.SizeOfRawData
        if start <= offset_from_base < end:
            section_offset = offset_from_base - start
            file_offset = section.PointerToRawData + section_offset
            pe.__data__.seek(file_offset, 0)
            return pe.__data__.read(size)
    return None

# For original stack string building with immediates
def parse_mov_imm_to_stack(instruction):
    """
    If the instruction is something like:
      mov dword ptr [ebp - 0x64], 0x12345678
    or
      mov word ptr [ebp - 0x66], 0x1234
    or
      mov byte ptr [ebp - 0x2], 0x12

    Returns (offset, size, value)
    """
    if instruction.mnemonic != "mov":
        return None

    if len(instruction.operands) != 2:
        return None

    dest, src = instruction.operands[0], instruction.operands[1]

    if dest.type != X86_OP_MEM:
        return None
    
    if src.type != X86_OP_IMM:
        return None

    # Get the offset (displacement) from [ebp + disp]
    disp = dest.value.mem.disp

    offset = disp if disp < 0 else None
    if offset is None:
        return None

    src_size = src.size 
    imm_value = src.imm

    return (offset, src_size, imm_value)

# For xmm based absolute memory loads 
def parse_movaps_xmm0(instruction, pe):
    """
    Checks if `instruction` is something like:
        movaps xmm0, [0x403000]
    or
        movaps xmm0, ds:[0x403000]
    Returns the 16 bytes found at that address
    """
    if instruction.mnemonic != "movaps":
        return None

    if len(instruction.operands) != 2:
        return None

    dest = instruction.operands[0]
    if dest.type != CS_OP_REG:
        return None

    if dest.reg != X86_REG_XMM0:
        return None

    src = instruction.operands[1]
    if src.type != X86_OP_MEM:
        return None

    if src.value.mem.base != 0:
        return None
    
    # Displacement is the absolute VA to read from
    disp = src.value.mem.disp
    # Read 16 bytes from that VA
    data = read_bytes_from_pe(pe, disp, 16)
    return data

def dump_stack_strs(stack_map):
    """
    Given a dict: offset -> byte ( e.g. { -0x64: 0x41, -0x63: 0x42, ... } ),
    produce a contiguous byte array for each region. Then print them.
    """
    if not stack_map:
        return

    sorted_offsets = sorted(stack_map.keys())

    blocks = []
    current_block = []
    prev_offset = None 
    for offset in sorted_offsets:
        if prev_offset is None or offset == (prev_offset + 1):
            current_block.append(offset)
        else:
            blocks.append(current_block)
            current_block = [offset]
        prev_offset = offset 
    if current_block:
        blocks.append(current_block)
    
    res = b''
    for block in blocks:
        data = bytes(stack_map[o] for o in block)
        #ascii_str = "".join(chr(b) if 32 <= b < 127 else "." for b in data)
        #print(f"[>] Offset {block[0]}..{block[-1]} => hex: {data.hex()} => ascii-ish: '{ascii_str}'")
        res += data 
    return res

def xor_decode(data: bytes):
    return bytes(b ^ XOR_KEY for b in data)
    
if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python gc_strings.py <sample>")
        sys.exit(1)

    filename = sys.argv[1]
    pe = pefile.PE(filename)

    text_section = pe.sections[0]
    text_section_addr = pe.OPTIONAL_HEADER.ImageBase + text_section.VirtualAddress
    text_data = text_section.get_data()

    cs = Cs(CS_ARCH_X86, CS_MODE_32)
    cs.detail = True
    cs.skipdata = True 
    in_function = False 
    func_start_ea = None 

    stack_map = {}
    string_res = []
    xmm_strings = []  

    instr_iter = cs.disasm(text_data, text_section_addr)

    for instruction in instr_iter:
        if is_prologue(instruction):
            # If already in function, dump the old map
            if in_function:
                #print(f">> Nested function prologue? Dumping partial stack")
                data = dump_stack_strs(stack_map)
                if data != None:
                    dec_bytes = xor_decode(data)
                    if len(dec_bytes) != 0:
                        res = dec_bytes.strip(b'\x00')
                        string_res.append(res)
                stack_map.clear()
            
            in_function = True 
            func_start_ea = instruction.address 
            #print(f">> Function start at 0x{instruction.address:X}")
            continue 
        
        if in_function:
            if is_epilogue(instruction):
                #print(f"[-] Function end at 0x{instruction.address:X}")
                data = dump_stack_strs(stack_map)
                if data != None:
                    dec_bytes = xor_decode(data)
                    if len(dec_bytes) != 0:
                        res = dec_bytes.strip(b'\x00')
                        string_res.append(res)
                
                stack_map.clear()
                in_function = False 
                func_start_ea = None 
                continue

        xmm_data = parse_movaps_xmm0(instruction, pe)
        if xmm_data:
            dec_bytes = xor_decode(xmm_data)
            if len(dec_bytes) != 0:
                res = dec_bytes.strip(b'\x00')
                xmm_strings.append(res)
        
        # Try to parse instructions that move imm -> [ebp-offset]
        result = parse_mov_imm_to_stack(instruction)
        if result:
            offset, size, value = result 
            packed = pack_immediate(value, size)
            # Place thse bytes into the stack_map 
            # e.g. offset == -0x64 => positions -100..-97
            base = offset 
            for i, bval in enumerate(packed):
                stack_map[base + i] = bval 

    if in_function:
        #print("[!] Reached end of .text while still in a function. Dumping partial stack.")
        data = dump_stack_strs(stack_map)
        if data != None:
            dec_bytes = xor_decode(data)
            if len(dec_bytes) != 0:
                res = dec_bytes.strip(b'\x00')
                string_res.append(res)
    
    print(Fore.MAGENTA + "==== IMM AM Loads ====")
    for i, st in enumerate(xmm_strings):
        print(Fore.CYAN + f"{st}")

    print(Fore.BLUE + "===== SS Immediates =====")
    for st in string_res:
        print(Fore.WHITE + f"{st}")
    


