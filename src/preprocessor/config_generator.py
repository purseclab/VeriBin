import re
import os
import json
from argparse import ArgumentParser, ArgumentDefaultsHelpFormatter, ArgumentTypeError


PARTITION = ";;"

class ConfigGenerator(object):
    def __init__(self, selected_versions, out_dir, log_paths=None):
        self.selected_versions = selected_versions
        self.out_dir = out_dir
        self.log_paths = log_paths

        # Extract log paths
        if log_paths is not None:
            angr_original, angr_patched, ida_original, ida_patched, bindiff = log_paths
            self.angr_original_log_path = angr_original
            self.angr_patched_log_path = angr_patched
            self.ida_original_log_path = ida_original
            self.ida_patched_log_path = ida_patched
            self.bindiff_log_path = bindiff
        else:
            print("No log paths provided, please provide the log paths")
            return


        # Init some variables
        self.function_info_map = {
            'angr': {},
            'ida': {},
            'combined': {}
        }
        self.symbol_table = {
            'original_angr': {},
            'patched_angr': {},
            'original_ida': {},
            'patched_ida': {},
            'original_combined': {},
            'patched_combined': {}
        }
        self.function_info_map_bindiff = {}
        self.combined_config_info = None
        self.out_file_path = os.path.join(self.out_dir, 'config_preprocess.json')

        # Start the process
        self.run()

    def run(self):
        # Extract the function info from angr, ida, and bindiff
        self.extract_func_info()
        # Combine the results between angr and ida, will update self.combined_config_info
        self.combine_result()
        # Generate the config file
        self.generate_config_file()

    def extract_func_info(self):
        if 'angr' in self.selected_versions and self.angr_original_log_path and self.angr_patched_log_path:
            self.function_info_map['angr'], self.symbol_table['original_angr'] = self.extract_signature_file(self.angr_original_log_path,
                                                                                                             self.function_info_map['angr'])
            self.function_info_map['angr'], self.symbol_table['patched_angr'] = self.extract_signature_file(self.angr_patched_log_path,
                                                                                                            self.function_info_map['angr'])
        if 'ida' in self.selected_versions and self.ida_original_log_path and self.ida_patched_log_path:
            self.function_info_map['ida'], self.symbol_table['original_ida'] = self.extract_signature_file(self.ida_original_log_path,
                                                                                                           self.function_info_map['ida'])
            self.function_info_map['ida'], self.symbol_table['patched_ida'] = self.extract_signature_file(self.ida_patched_log_path,
                                                                                                         self.function_info_map['ida'])
        if 'bindiff' in self.selected_versions and self.bindiff_log_path:
            self.function_info_map_bindiff = self.extract_bindiff_data(self.bindiff_log_path)

    def extract_signature_file(self, log_path, function_info_map):
        symbol_table = {}
        with open(log_path, 'r') as f:
            for line in f.readlines():
                line = line.strip()
                if PARTITION in line:
                    # The first part is the address, if not a valid address, skip
                    try:
                        addr = int(line.split(PARTITION)[0], 16)
                        parts = line.split(PARTITION)
                        addr = func_name = prototype = ida_func_size = angr_func_size = None
                        if len(parts) == 5:
                            # IDA results: addr, func_name, prototype, return_value_used, func_size
                            addr, func_name, prototype, _, ida_func_size = parts
                        elif len(parts) == 4:
                            # Angr results: addr, func_name, prototype, func_size
                            addr, func_name, prototype, angr_func_size = parts

                        info = self.parse_function_prototype(prototype)
                        if info is not None:
                            if func_name not in function_info_map:
                                function_info_map[func_name] = {
                                    'num_of_args': info['num_of_args'],
                                    'output_args_index': info['output_args_index'],
                                    'is_variadic': info['is_variadic'],
                                    'return_value_used': info['return_value_used'],
                                    'ida_func_size': ida_func_size if ida_func_size is not None else None,
                                    'angr_func_size': angr_func_size if angr_func_size is not None else None
                                }

                            symbol_table[addr] = func_name
                    except Exception:
                        continue
        return function_info_map, symbol_table

    def extract_bindiff_data(self, log_path):
        matching_functions = {}
        with open(log_path, 'r') as f:
            for line in f.readlines():
                # Get rid of ' ' and '\n'
                line = line.strip().replace(' ', '')
                # There are also 'affected functions' info, and some comments
                try:
                    addresses = line.split(',')
                    if len(addresses) != 2:
                        continue
                except Exception:
                    continue
                original_addr, patched_addr = addresses
                matching_functions[original_addr] = patched_addr
        return matching_functions

    def parse_function_prototype(self, prototype):
        # Return None if the prototype is empty
        if len(prototype) == 0 or prototype == 'None':
            return None
        # print(prototype)
        prototype_type = "angr" if "->" in prototype else "ida"
        # print(prototype_type)

        if prototype_type == "angr":
            pattern = r"\s*\((?P<arguments>.*)\)\s*->(?P<return_value>.*)"
        else:
            pattern = r"\s*(?P<return_value>.*?)\((?P<arguments>.*?)\)"

        match = re.search(pattern, prototype)
        if match is not None:
            return_value = match.group("return_value")
            function_args = match.group("arguments")

            num_of_args, output_args_index, is_variadic = 0, [], False

            if '...' in function_args:
                is_variadic = True
                function_args = function_args.split(', ...', 1)[0]  # Only consider args before '...'

            return_value_used = True
            if len(return_value) > 0:
                if 'void' in return_value and 'void *' not in return_value:
                    return_value_used = False
                elif 'None' in return_value:
                    return_value_used = False
                else:
                    return_value_used = True


            if len(function_args) == 0:
                num_of_args = 0
            else:
                args = function_args.split(',')
                num_of_args = len(args)
                if prototype_type == "ida":
                    for i, arg in enumerate(args):
                        if '*' in arg and 'const' not in arg:
                            output_args_index.append(i)

            info = {
                'num_of_args': num_of_args,
                'output_args_index': output_args_index,
                'is_variadic': is_variadic,
                'return_value_used': return_value_used
            }
            # print(info)
            return info
        else:
            print(f"Failed to parse function prototype: {prototype}")
            import IPython; IPython.embed()
            assert(False and "Failed to parse function prototype")

    def combine_result(self):
        """
        Combine the func info results from ida and angr for one benchmark
        - Add ida results before angr results
        - If the address is the same, keep the ida result
        - If the ida's prototype is None, replace it with angr's prototype
        - Keep both ida/angr function sizes
        """
        # 1. func info
        combined_func_info = {}
        for func_name, ida_info in self.function_info_map['ida'].items():
            if func_name in self.function_info_map['angr']:
                # Update angr_func_size in ida_info
                angr_func_size = self.function_info_map['angr'][func_name]['angr_func_size']
                ida_info['angr_func_size'] = angr_func_size
            combined_func_info[func_name] = ida_info

        # Add angr func info only if it's not in ida's results
        # No need to get ida_func_size since it does not exist in ida's results
        for func_name, angr_info in self.function_info_map['angr'].items():
            if func_name not in combined_func_info:
                combined_func_info[func_name] = angr_info


        # 2. symbol table
        symbol_table_original_combined = self.symbol_table['original_ida'].copy()
        symbol_table_patched_combined = self.symbol_table['patched_ida'].copy()
        # Add angr's symbol table
        for addr, func_name in self.symbol_table['original_angr'].items():
            if addr not in symbol_table_original_combined:
                symbol_table_original_combined[addr] = func_name
        for addr, func_name in self.symbol_table['patched_angr'].items():
            if addr not in symbol_table_patched_combined:
                symbol_table_patched_combined[addr] = func_name


        # 3. Filter bindiff results, only keep the functions that are in the combined_func_info
        matching_functions = {}
        for original_addr, patched_addr in self.function_info_map_bindiff.items():
            # Add if original OR patched addr is in combined_func_info
            if original_addr in symbol_table_original_combined and patched_addr in symbol_table_patched_combined:
                matching_functions[original_addr] = patched_addr

        # 4. Update self.combined_config_info
        self.combined_config_info = {
            'symbol_table': {
                'original': symbol_table_original_combined,
                'patched': symbol_table_patched_combined
            },
            'func_info_map': combined_func_info,
            'matching_functions': matching_functions
        }

    def generate_config_file(self):
        """
        Write the combined config info to the output file
        """
        with open(self.out_file_path, 'w+') as f:
            f.write(json.dumps(self.combined_config_info, indent=4))
        print(f"Generated config file: {self.out_file_path}")
