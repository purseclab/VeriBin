import json


class ConfigFile(object):
    def __init__(self, filepath):
        self.binary_info = None
        self.filepath = filepath
        self.load_from_file()

    def load_from_file(self):
        if self.filepath:
            f = open(self.filepath)
            data = json.load(f)
            self.parse_data(data)
            f.close()
        else:
            data = {}
            self.parse_data(data)

    def parse_data(self, data):
        symbol_table = {'original': {}, 'patched': {}}
        func_info_map = {}
        matching_functions = {}
        exit_edges = {'original': {}, 'patched': {}}
        cfgfast_options = {'original': {},
                           'patched': {}
                           }
        patcherex_added_functions = []

        # Register initial values
        # Example: "rax": "0x0"
        register_initial_values = {}

        # Invalid return values
        # Example: ["0x0", "0x1"]
        invalid_ret_values = []

        if 'symbol_table' in data:
            for tag in ['original', 'patched']:
                for func_addr_str, func_name in data['symbol_table'][tag].items():
                    # func_addr: from str(hex) to int
                    func_addr = int(func_addr_str, 16)
                    symbol_table[tag][func_addr] = func_name

        if 'func_info_map' in data:
            func_info_map = data['func_info_map']

        if 'matching_functions' in data:
            for k, v in data['matching_functions'].items():
                func_addr_original = int(k, 16)
                func_addr_patched = int(v, 16)
                if func_addr_original in symbol_table['original'].keys():
                    func_name_original = symbol_table['original'][func_addr_original]
                else:
                    # Upper case X means hex with uppercase letters, e.g., sub_4EC9C0
                    func_name_original = "sub_%X" % func_addr_original

                if func_addr_patched in symbol_table['patched'].keys():
                    func_name_patched = symbol_table['patched'][func_addr_patched]
                else:
                    # Upper case X
                    func_name_patched = "sub_%X" % func_addr_patched
                matching_functions["Func_%s" % func_name_original] = {
                    'addr_original': func_addr_original,
                    'addr_patched': func_addr_patched,
                    'func_name_patched': "Func_%s" % func_name_patched}


        if 'exit_edges' in data:
            for tag in ['original', 'patched']:
                exit_edges[tag] = []

                # Check if the item is a list (newer format) or a dictionary (older format)
                if isinstance(data['exit_edges'][tag], list):
                    # This is the newer format
                    for edge in data['exit_edges'][tag]:
                        addr_from = int(edge[0], 16)
                        addr_to = int(edge[1], 16)
                        exit_edges[tag].append((addr_from, addr_to))
                elif isinstance(data['exit_edges'][tag], dict):
                    # This is the older format
                    for func_addr, edges in data['exit_edges'][tag].items():
                        for edge in edges:
                            addr_from = int(edge[0], 16)
                            addr_to = int(edge[1], 16)
                            exit_edges[tag].append((addr_from, addr_to))

        if 'cfgfast_options' in data:
            skip_ummapped_addrs = True
            for tag in ['original', 'patched']:
                try:
                    skip_unmapped_addrs = data['cfgfast_options'][tag]['skip_unmapped_addrs']
                except Exception:
                    try:
                        regions = [(int(r[0], 16), int(r[1], 16)) for r in data['cfgfast_options'][tag]['regions']]
                        if len(regions) > 0:
                            skip_unmapped_addrs = False
                        else:
                            skip_unmapped_addrs = True
                    except Exception:
                        pass
                function_starts = [int(func_addr, 16) for func_addr in data['cfgfast_options'][tag]['function_starts']]
                if len(function_starts) == 0:
                    function_starts = None

                cfgfast_options[tag] = {"skip_unmapped_addrs": skip_unmapped_addrs, "function_starts": function_starts}

        if 'patcherex_added_functions' in data:
            patcherex_added_functions = [int(addr_str, 16) for addr_str in data['patcherex_added_functions']]

        if 'register_initial_values' in data:
            for reg_name, reg_value in data['register_initial_values'].items():
                register_initial_values[reg_name] = int(reg_value, 16)

        # invalid_ret_values
        if 'invalid_ret_values' in data:
            try:
                invalid_ret_values = [int(x, 16) for x in data['invalid_ret_values']]
            except:
                invalid_ret_values = []


        self.binary_info = {'symbol_table': symbol_table,
                            'func_info_map': func_info_map,
                            'matching_functions': matching_functions,
                            'exit_edges': exit_edges,
                            'cfgfast_options': cfgfast_options,
                            'patcherex_added_functions': patcherex_added_functions,
                            'register_initial_values': register_initial_values,
                            'invalid_ret_values': invalid_ret_values}

        if 'exit_keywords' in data:
            self.binary_info['exit_keywords'] = data['exit_keywords']
