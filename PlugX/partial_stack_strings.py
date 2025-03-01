import struct
from binaryninja import *
from binaryninja.lowlevelil import LowLevelILInstruction, LowLevelILOperation

# single general decoding routine from the sample
# decodes a handful of API names
def test_routine(buff):
    return ''.join(
        chr((((i & 0xFF) & 0x6E | ((~i) & 0xFF) & 0x91) ^
             ((buff[i] & 0x6E) | ((~buff[i]) & 0xFF) & 0x91)))
        for i in range(len(buff))
    )

# check if the instruction is a constant store to the stack
def is_store_of_constant(instr) -> bool:
    if instr.operation != LowLevelILOperation.LLIL_STORE:
        return False
    mem_expr = instr.operands[0]
    val_expr = instr.operands[1]

    if val_expr.operation != LowLevelILOperation.LLIL_CONST:
        return False

    if mem_expr.operation not in (LowLevelILOperation.LLIL_SUB, LowLevelILOperation.LLIL_ADD):
        return False

    base_expr = mem_expr.operands[0]
    offset_expr = mem_expr.operands[1]

    if base_expr.operation != LowLevelILOperation.LLIL_REG:
        return False

    if offset_expr.operation != LowLevelILOperation.LLIL_CONST:
        return False

    return True

# extract the raw bytes, stack offset, and addr from the stack store location
def get_stack_store_immediate(instr):
    mem_expr = instr.operands[0]
    val_expr = instr.operands[1]
    imm_value = val_expr.operands[0]

    byte_size = 4
    try:
        raw_bytes = imm_value.to_bytes(byte_size, byteorder='little', signed=False)
    except OverflowError:
        return None

    base_op = mem_expr.operation  
    offset_val = mem_expr.operands[1].operands[0]
    if base_op == LowLevelILOperation.LLIL_SUB:
        offset_val = -offset_val

    return (raw_bytes, offset_val, instr.address)

def resolve_xmm_and_stores(all_instrs):
    str_results = []

    for i in range(len(all_instrs)):
        instr = all_instrs[i]

        # build buffer for the XMM loads + extra stores
        if instr.operation == LowLevelILOperation.LLIL_SET_REG:
            reg = instr.operands[0]
            src_expr = instr.operands[1]

            if reg in ("xmm0", "xmm1", "xmm2", "xmm3"):
                if src_expr.operation == LowLevelILOperation.LLIL_LOAD:
                    addr_expr = src_expr.operands[0]
                    if addr_expr.operation == LowLevelILOperation.LLIL_CONST_PTR:
                        data_addr = addr_expr.operands[0]
                        xmm_data = bv.read(data_addr, 32)  # Read XMM data
                        instr_addr = instr.address

                        # backtrack to find stack stores related to this XMM load
                        stack_extra_bytes = b''
                        for fwd in range(1, 13):  # look ahead at most 12 instructions
                            idx_fwd = i + fwd
                            if idx_fwd >= len(all_instrs):
                                break
                            next_instr = all_instrs[idx_fwd]

                            if is_store_of_constant(next_instr):
                                value = get_stack_store_immediate(next_instr)
                                if value:
                                    raw_bytes, offset_val, addr = value
                                    stack_extra_bytes += raw_bytes 

                        full_encrypted_data = xmm_data + stack_extra_bytes
                        dec_str = test_routine(full_encrypted_data)  
                        if dec_str:
                            str_results.append((instr_addr, dec_str))

    for (addr, dec_bytes) in str_results:
        final_str = dec_bytes.strip('\x00')
        if len(final_str) > 4:
            print(f"=> {final_str} ::: 0x{addr:08X}")

def resolve_just_stores(all_instrs):
    str_results = []

    # build a buffer for only immediate stores
    for i in range(len(all_instrs)):
        enc_bytes = b''
        for bkwd in range(1, 13):
            idx_back = i - bkwd
            if idx_back < 0:
                break
            prev_instr = all_instrs[idx_back]
            if is_store_of_constant(prev_instr):
                value = get_stack_store_immediate(prev_instr)
                if value is None:
                    continue
                raw_bytes, offset_val, addr = value
                if raw_bytes is None:
                    continue
                if raw_bytes[-1] == 0x00:
                    continue
                if offset_val == -4:
                    continue

                enc_bytes = raw_bytes + enc_bytes

        if enc_bytes:
            dec_str = test_routine(enc_bytes)
            dec_bytes = dec_str.encode('utf-8', errors='ignore')
            if dec_bytes:
                current_addr = all_instrs[i].address
                str_results.append((current_addr, dec_bytes))

    for (addr, dec_bytes) in str_results:
        final_str = dec_bytes.decode('utf-8', errors='ignore').strip('\x00')
        if len(final_str) > 4:
            print(f"=> {final_str} ::: 0x{addr:08X}")

# start
all_instrs = []
for func in bv.functions:
    try:
        llil = func.low_level_il
    except ILException:
        continue
    if not llil:
        continue
    for block in llil:
        for instr in block:
            all_instrs.append(instr)

resolve_just_stores(all_instrs)
resolve_xmm_and_stores(all_instrs)
