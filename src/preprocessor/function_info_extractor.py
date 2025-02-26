import os
from bindiff_helper import IdaBinDiff
import concurrent.futures
import traceback
from argparse import ArgumentParser, ArgumentDefaultsHelpFormatter, ArgumentTypeError

# GLOBALS
IDA_SCRIPT_PATH = os.path.join(os.path.dirname(os.path.realpath(__file__)), "ida_func.py")
IDA_PATH = os.path.join(os.path.dirname(os.path.realpath(__file__)),
                        "../../../ida8.3/idat64")
ANGR_FUNC_PATH = os.path.join(os.path.dirname(os.path.realpath(__file__)), "angr_func.py")
TIMEOUT = 600

class FuncInfoExtractor(object):
    def __init__(self, original_path, patched_path, original_func_addr, patched_func_addr, selected_versions, out_dir, force_run=False, max_process=4):
        self.original_path = original_path
        self.patched_path = patched_path
        self.original_func_addr = original_func_addr
        self.patched_func_addr = patched_func_addr
        self.selected_versions = selected_versions
        self.out_dir = out_dir
        self.force_run = force_run

        # Init some other arguments
        self.output_dir_angr = self.generate_output_path("angr") if "angr" in self.selected_versions else None
        self.output_dir_ida = self.generate_output_path("ida") if "ida" in self.selected_versions else None
        self.output_dir_bindiff = self.generate_output_path("bindiff") if "bindiff" in self.selected_versions else None

        self.angr_log_path_original = os.path.join(self.output_dir_angr, f"angr_{self.original_func_addr:x}_original.txt") if "angr" in self.selected_versions else None
        self.angr_log_path_patched = os.path.join(self.output_dir_angr, f"angr_{self.patched_func_addr:x}_patched.txt") if "angr" in self.selected_versions else None
        self.ida_log_path_original = os.path.join(self.output_dir_ida, f"ida_{self.original_func_addr:x}_original.txt") if "ida" in self.selected_versions else None
        self.ida_log_path_patched = os.path.join(self.output_dir_ida, f"ida_{self.patched_func_addr:x}_patched.txt") if "ida" in self.selected_versions else None
        self.bindiff_log_path = os.path.join(self.output_dir_bindiff, "bindiff.txt") if "bindiff" in self.selected_versions else None

        self.log_paths = [self.angr_log_path_original, self.angr_log_path_patched, self.ida_log_path_original, self.ida_log_path_patched, self.bindiff_log_path]

        tasks = self.get_tasks()

        # Run the tasks
        self.concurrent_run_tasks(tasks, max_process=max_process, timeout=TIMEOUT)

    def generate_output_path(self, target):
        output_dir_target =  os.path.join(self.out_dir, target)
        if not os.path.exists(output_dir_target):
            os.makedirs(output_dir_target, exist_ok=True)
        return output_dir_target

    def get_tasks(self):
        """
        Concurrently run the selected tools to extract function information, store the running scripts into a list of tasks
        """
        tasks = []

        # Run each selected tools
        if 'angr' in self.selected_versions:
            if not os.path.exists(self.angr_log_path_original) or self.force_run:
                args = (self.original_path, self.original_func_addr, self.angr_log_path_original)
                tasks.append(('angr', args))
            else:
                print(f"Angr log already exists at {self.angr_log_path_original}, skipping...")
            if not os.path.exists(self.angr_log_path_patched) or self.force_run:
                args = (self.patched_path, self.patched_func_addr, self.angr_log_path_patched)
                tasks.append(('angr', args))
            else:
                print(f"Angr log already exists at {self.angr_log_path_patched}, skipping...")

        if 'ida' in self.selected_versions:
            original_script = '%s -c -A -S"%s %s %s %s" %s' % (IDA_PATH, IDA_SCRIPT_PATH, hex(self.original_func_addr),
                                                        self.ida_log_path_original, True, self.original_path)
            patched_script = '%s -c -A -S"%s %s %s %s" %s' % (IDA_PATH, IDA_SCRIPT_PATH, hex(self.patched_func_addr),
                                                            self.ida_log_path_patched, True, self.patched_path)

            if not os.path.exists(self.ida_log_path_original) or self.force_run:
                tasks.append(('ida', original_script))
            else:
                print(f"IDA log already exists at {self.ida_log_path_original}, skipping...")
            if not os.path.exists(self.ida_log_path_patched) or self.force_run:
                tasks.append(('ida', patched_script))
            else:
                print(f"IDA log already exists at {self.ida_log_path_patched}, skipping...")

        if 'bindiff' in self.selected_versions:
            if not os.path.exists(self.bindiff_log_path) or self.force_run:
                args = (self.original_path, self.patched_path, self.original_func_addr, self.patched_func_addr, self.bindiff_log_path)
                tasks.append(('bindiff', args))
            else:
                print(f"Bindiff log already exists at {self.bindiff_log_path}, skipping...")

        return tasks

    def handle_single_task(self, task):
        version, args = task
        if version == 'angr':
            self.handle_angr(args)
        elif version == 'ida':
            self.handle_ida(args)
        elif version == 'bindiff':
            self.handle_bindiff(args)
        else:
            raise ValueError(f"Unknown version: {version}")

    def handle_angr(self, args):
        try:
            binary_path, func_addr, output_path = args
            print(f"Running angr for {binary_path} at {hex(func_addr)}")
            cmd_str = f"timeout {TIMEOUT} python {ANGR_FUNC_PATH} --file_path {binary_path} --func_addr {hex(func_addr)} --output_log_path {output_path}"
            print(f"Running command: {cmd_str}")
            os.system(cmd_str)
        except Exception as e:
            print(traceback.format_exc())

    def handle_ida(self, script):
        print(f"Running IDA script: {script}")
        os.system("bash -c '{}'".format(script))

    def handle_bindiff(self, args):
        original_path, patched_path, original_func_addr, patched_func_addr, output_path = args
        base_addr = None
        if self.original_func_addr < 0x400000:
            base_addr = 0x0
        elif self.original_func_addr < 0x800000:
            base_addr = 0x400000
        else:
            base_addr = 0x800000

        print(f"Running bindiff for {original_path} and {patched_path} at {hex(original_func_addr)} and {hex(patched_func_addr)}")
        try:
            bindiff_result = IdaBinDiff(primary=original_path, secondary=patched_path,
                                        func_addr_original=original_func_addr, func_addr_patched=patched_func_addr,
                                        size=64, base_addr=base_addr, debug=False)

            # Save the bindiff result
            with open(output_path, 'w') as f:
                all_matching_func_info = bindiff_result.all_matching_func_info
                if all_matching_func_info:
                    for o_func_addr, p_func_addr in all_matching_func_info:
                        f.write('%s, %s\n' % (hex(o_func_addr), hex(p_func_addr)))
        except Exception as e:
            print(traceback.format_exc())

    def concurrent_run_tasks(self, tasks, max_process, timeout):
        """
        Concurrently run the tasks
        """
        with concurrent.futures.ProcessPoolExecutor(max_workers=max_process) as executor:
                print("Starting to submit scripts...")

                # Dictionary to keep track of futures and their arguments
                future_to_args = {}

                # Submit each script to the executor and store in dictionary
                for task in tasks:
                    future = executor.submit(self.handle_single_task, task)
                    future_to_args[future] = task
                print("All scripts have been submitted.")

                # Iterate through the futures and wait for each with a timeout
                for future in concurrent.futures.as_completed(future_to_args):
                    try:
                        # Get the result of the future with the specified timeout
                        future.result(timeout=timeout)
                    except Exception as e:
                        # Retrieve the arguments for this future
                        args = future_to_args[future]
                        print(f"A task with args {args} raised an exception: {e}")
                        print(traceback.format_exc())

if __name__ == "__main__":
    parser = ArgumentParser(description='Extract the function information and store into output dir', formatter_class=ArgumentDefaultsHelpFormatter)
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
