import json
from binaryninja import BinaryView

# floss -j sample.exe > floss_out.json
output_path = "/home/rb3nzr/Desktop/floss_out.json"

# Just pulling from decoded_strings 
def annotate_floss_output(output_path):
    with open(output_path, "r") as f:
        data = json.load(f)

    floss_imagebase = data.get("metadata", {}).get("imagebase", 0x10000000)
    bn_imagebase = bv.start

    decoded_strings = data.get("strings", {}).get("decoded_strings", [])
    if not decoded_strings:
        print("No 'decoded_strings' found in the output file.")
        return

    count_annotated = 0
    for ds in decoded_strings:
        floss_decoded_at    = ds.get("decoded_at")
        floss_decoder_addr  = ds.get("decoding_routine")
        dec_string          = ds.get("string", "")
        enc_type            = ds.get("encoding", "")

        if not floss_decoded_at:
            continue

        # Rebase addresses
        bn_decoded_at = (floss_decoded_at - floss_imagebase) + bn_imagebase
        bn_decoder = None
        if floss_decoder_addr:
            bn_decoder = (floss_decoder_addr - floss_imagebase) + bn_imagebase

        # Set comments 
        funcs = bv.get_functions_containing(bn_decoded_at)
        if funcs:
            for fn in funcs:
                existing = fn.get_comment_at(bn_decoded_at)
                if existing is None:
                    existing = ""
    
                new_note = f"'{dec_string}'"
                if bn_decoder is not None:
                    new_note += f" (decoded in 0x{bn_decoder:X})"
    
                combined = (existing + "\n" + new_note).strip()
                print(f"[{enc_type}] '{dec_string}' used in: 0x{bn_decoded_at:08X}")
                fn.set_comment_at(bn_decoded_at, combined)
                count_annotated += 1

        if bn_decoder is not None:
            func_decoder = bv.get_function_at(bn_decoder)
            if func_decoder:
                existing_decoder_cmt = func_decoder.comment or ""
                note_decoder = f"[decoded here]: '{dec_string}' [{enc_type}]"
                if existing_decoder_cmt:
                    note_decoder = existing_decoder_cmt + "\n" + note_decoder
                func_decoder.comment = note_decoder
        
    print(f"Done. Annotated {count_annotated} decoded string locations")

annotate_floss_output(output_path)
