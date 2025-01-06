from binaryninja import BinaryView, LowLevelILOperation

# Tested on:
# > packed:   1155d7ffbc9830d364310cf794b77f638df24218a4278b48754266dd8c50a823 2025-01-04
# > unpacked: a883940150a872c5ac33249ca8523e75ee98f4ace0bf1ad17d9d16c7edd78f8c
# > packed:   7e0f61d7f03f394f4dd1eaa7d5c9b19e0aa7e422a7527d3a345827473f123089 2025-01-02
# > unpacked: 9a5a61de316d081f4ab63cb945d602ffada90aaea4ce0aa3b8fd99e664b496cf

XOR_KEY = 0x2A

def xor_decode(data, key, stop_at_null=True):
    out = []
    for b in data:
        dec = b ^ key
        if stop_at_null and dec == 0:
            break
        out.append(dec)
    return bytes(out)

def is_probably_hexstring(data):
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError:
        return False

    if len(text) % 2 != 0:
        return False
    hex_chars = "0123456789abcdefABCDEF"
    return all(ch in hex_chars for ch in text)

def maybe_decode_hex(data: bytes) -> bytes:
    if is_probably_hexstring(data):
        return bytes.fromhex(data.decode("ascii"))
    else:
        return data

def process_data_block(raw_data, xor_key):
    data_bytes = maybe_decode_hex(raw_data)
    decoded = xor_decode(data_bytes, xor_key, stop_at_null=False)

    try:
        decoded_str = decoded.decode("ascii")
    except UnicodeDecodeError:
        decoded_str = repr(decoded)
    return decoded_str

def find_xmm_data():
    for func in bv.functions:
        llil = func.low_level_il
        if not llil:
            continue
        
        for block in llil:
            for instr in block:
                if instr.operation == LowLevelILOperation.LLIL_SET_REG:
                    # operands[0] => numeric register ID
                    # operands[1] => expression being assigned
                    reg_name = instr.operands[0]
                    src_expr   = instr.operands[1]
                    
                    if reg_name == "xmm0":
                        # Is LOAD from a constant pointer?
                        if src_expr.operation == LowLevelILOperation.LLIL_LOAD:
                            addr_expr = src_expr.operands[0]
                            if addr_expr.operation == LowLevelILOperation.LLIL_CONST_PTR:
                                # Addr that data is loaded at 
                                data_addr = addr_expr.operands[0]
                                data_bytes = bv.read(data_addr, 32)
                                instr_addr = instr.address 
                                dec = process_data_block(data_bytes, XOR_KEY)
                                bv.set_comment_at(instr_addr, f"value: {dec}")
                                print(f"XMM load at 0x{instr_addr:08X} | value => {dec}")
                                print(f"    => Loads from 0x{data_addr:08X}")

def find_stack_immediates():
    for func in bv.functions:
        llil = func.low_level_il
        if not llil:
            continue

        for block in llil:
            for instr in block:
                if instr.operation == LowLevelILOperation.LLIL_STORE:
                    mem_expr = instr.operands[0]
                    val_expr = instr.operands[1]

                    if val_expr.operation != LowLevelILOperation.LLIL_CONST:
                        continue

                    if mem_expr.operation not in (LowLevelILOperation.LLIL_SUB,LowLevelILOperation.LLIL_ADD):
                        continue

                    base_expr = mem_expr.operands[0]
                    offset_expr = mem_expr.operands[1]
                    if base_expr.operation != LowLevelILOperation.LLIL_REG:
                        continue

                    base_reg = base_expr.operands[0]  
                    if base_reg not in ("ebp", "esp"):
                        continue

                    if offset_expr.operation != LowLevelILOperation.LLIL_CONST:
                        continue

                    offset = offset_expr.operands[0]
                    if mem_expr.operation == LowLevelILOperation.LLIL_SUB:
                        offset = -offset

                    imm_value = val_expr.operands[0]
                    byte_size = 4

                    try:
                        raw_bytes = imm_value.to_bytes(byte_size, byteorder='little', signed=False)
                    except OverflowError:
                        continue
                    
                    instr_addr = instr.address
                    dec = xor_decode(raw_bytes, XOR_KEY)
                    bv.set_comment_at(instr_addr, f"ss value: {dec}")
                    print(f"SS at 0x{instr_addr:08X} | value => {dec}") 

find_stack_immediates()
find_xmm_data()
