from argparse import ArgumentParser, ArgumentDefaultsHelpFormatter
import sys

from bindiff_no_func_addr import IdaBinDiff

if __name__ == "__main__":
    parser = ArgumentParser(description='Get the patch affected functions', formatter_class=ArgumentDefaultsHelpFormatter)
    parser.add_argument('--original_path', type=str, help='original binary path')
    parser.add_argument('--patched_path', type=str, help='patched binary path')
    parser.add_argument('--bits', type=int, default=64, required=False, help='bits of the binary')
    parser.add_argument('--base_addr', type=str, default='0x400000', required=False, help='base address of the binary, hex')

    args = parser.parse_args()
    original_path = args.original_path
    patched_path = args.patched_path
    bits = args.bits
    # Convert base address to int, raise an error if not in hex format
    try:
        base_addr = int(args.base_addr, 16)
    except:
        print(f"Error: base address {args.base_addr} is not in hex format")
        sys.exit(1)

    ida_bindiff = IdaBinDiff(original_path, patched_path, bits, base_addr=base_addr)
    infos = ida_bindiff.get_patch_affected_functions()
    if infos:
        # Infos: [(address1, address2, name1, name2, similarity), ...]
        for info in infos:
            address1, address2, name1, name2, similarity = info
            print(f"{hex(address1)} {hex(address2)} {name1} {name2} {similarity}")
