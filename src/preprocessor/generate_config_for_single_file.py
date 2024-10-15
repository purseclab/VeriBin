from argparse import ArgumentParser, ArgumentDefaultsHelpFormatter, ArgumentTypeError
import os

# Custom objects
from function_info_extractor import FuncInfoExtractor
from config_generator import ConfigGenerator

def str2bool(v):
    if isinstance(v, bool):
        return v
    if v.lower() in ('yes', 'true', 't', 'y', '1'):
        return True
    elif v.lower() in ('no', 'false', 'f', 'n', '0'):
        return False
    else:
        raise ArgumentTypeError('Boolean value expected.')

if __name__ == "__main__":
    parser = ArgumentParser(description='Generate the config file from binary', formatter_class=ArgumentDefaultsHelpFormatter)
    parser.add_argument('--original_path', required=True, help='Original binary file path')
    parser.add_argument('--patched_path', required=True, help='Patched binary file path')
    parser.add_argument('--func_addr_original', required=True, help='Function address in the original binary, to be compared')
    parser.add_argument('--func_addr_patched', required=True, help='Function address in the patched binary, to be compared')
    parser.add_argument('--version', type=str, required=False, default='angr', help='Select the tools to use: [ida, angr, bindiff]')
    parser.add_argument('--out_dir', type=str, help='output directory')
    parser.add_argument('--force_run', type=str2bool, default=False, help='Force to run the tools even if the output files already exist')
    parser.add_argument('--max_process', type=int, default=4, help='Maximum number of processes to run concurrently')

    args = parser.parse_args()
    original_path = args.original_path
    patched_path = args.patched_path
    # If address is hex, convert to int
    original_func_addr = int(args.func_addr_original, 16) if args.func_addr_original.startswith("0x") else int(args.func_addr_original)
    patched_func_addr = int(args.func_addr_patched, 16) if args.func_addr_patched.startswith("0x") else int(args.func_addr_patched)

    # output dir, use realpath and join path to get the absolute path
    out_dir = os.path.realpath(os.path.join(os.getcwd(), args.out_dir))

    # versions
    version = args.version.lower().replace(' ', '')
    selected_versions = version.split(',')

    # Check the existence of the output directory
    if not os.path.exists(out_dir):
        print(f"Output directory {out_dir} does not exist!")
        print("Creating the output directory...")
        os.makedirs(out_dir)

    # Extract function information, store to the output directory
    func_info_extractor = FuncInfoExtractor(original_path, patched_path, original_func_addr, patched_func_addr, selected_versions, out_dir, force_run=args.force_run, max_process=args.max_process)
    log_paths = func_info_extractor.log_paths

    #  Generate the configuration file
    config_generator = ConfigGenerator(selected_versions=selected_versions, out_dir=out_dir, log_paths=log_paths)
    print(f"Generating the configuration file to {out_dir}/config_preprocessed.json")