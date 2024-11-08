import copy
from typing import List, Any
import claripy
RECURSIVE_LIMIT = 20

class Path(object):
    """
        Description: todo
    """

    def __init__(self, project, invalid_exit_edges: List[Any], state, debug=False):
        # init arguments
        self.project = project
        self.invalid_exit_edges = invalid_exit_edges
        self.state = state

        # Path constraint of the path.
        self.path_constraint = None

        # Map from symbolic value to its contents.
        # This map contains symbolic memory unique to this path i.e., only the writes made in this path.
        self.symbolic_memory = {}

        # Function arguments map: Map from function address to a corresponding list of arguments list
        # Format: {func_name: {bb_addr: [args]}}
        self.func_args_map = {}

        # Status
        #   1. representing whether the constraint is false or not
        self.is_false_constraint = False
        #   2. representing whether the path is a invalid exit path
        self.is_invalid_exit_path = False

        # New items for angr state
        self.replacement_dict = {}
        self.replacement_dict_reg = {}
        self.angr_path_info = self.state.sypy_path
        self.visited_blocks = self.angr_path_info.bb_addrs
        self.return_value = None

        # Debug flag
        self._debug = debug

        self.construct()

    def _dprint(self, *args, **kwargs):
        if self._debug:
            # print('[+] {}'.format(msg))
            print('[+]', *args, **kwargs)

    def construct(self):
        # Create a basic replacement dict with infor from angr
        self._init_replacement_dict()

        # Get replaced values as well as updating the replacement dict
        self._handle_constraints()
        self._handle_memory_writes()
        self._handle_return_value()
        self._handle_func_args_map()

        # Validate the path:
        # - whether it contains false path constraint
        # - whether it contains any invalid exit edges provided in configuration file
        self._check_if_valid()

    def _init_replacement_dict(self):
        replacement_dict = {}
        replacement_dict_reg = {}

        # Memory replacement dict: update from address_concretization, need to generate MemLoad obj
        for k,v in self.angr_path_info.address_concretization.items():
            if k not in replacement_dict:
                size = k.ast.size()
                mem_obj = self.generate_memory_load(v, size=size)
                replacement_dict[k] = mem_obj

        # No need to do this, since we already returns MemLoad obj in angr
        # # Memory replacement dict: update from memory_reads, need to generate MemLoad obj
        # for k,v in self.angr_path_info.memory_reads.items():
        #     if k not in replacement_dict:
        #         size = k.ast.size()
        #         mem_obj = self.generate_memory_load(v, size=size)
        #         replacement_dict[k] = mem_obj

        # No need to do this, since we already returns Func obj in angr
        # # Function replacement dict
        # replacement_dict.update(self.angr_path_info.function_call_replacement)

        # Naming replacement dict: eliminate register indexes
        replaced_leaf_asts = []
        for r_ast in replacement_dict.values():
            replaced_leaf_asts.extend(list(r_ast.leaf_asts()))

        # self._dprint(replaced_leaf_asts)
        self._get_leaf_replacements_reg(replaced_leaf_asts, replacement_dict_reg)

        self._dprint("init replacement_dict", replacement_dict)
        self._dprint("init replacement_dict_reg", replacement_dict_reg)
        self.replacement_dict = replacement_dict
        self.replacement_dict_reg = replacement_dict_reg

    @staticmethod
    def _get_leaf_replacements_reg(leaf_asts, replacement_dict_reg):
        for ast in leaf_asts:
            if ast.op == 'BVS' and ast.depth == 1:
                name = ast.args[0]
                # Case 1.  reg
                # e.g.: 'reg_rdi_12_64{UNINITIALIZED}
                # Case 2. unresolvable mem
                # e.g.: 'mem_fe00000000001350_114_64'
                if  ('reg_' in name or 'mem_' in name or 'symbolic_read_unconstrained_' in name)\
                        and ast.cache_key not in replacement_dict_reg:
                    id = name.split('_')[2]
                    new_name = name.replace('_' + id + '_', '_')
                    args = list(ast.args)
                    args[0] = new_name
                    new_ast = ast.make_like(ast.op, tuple(args))
                    replacement_dict_reg[ast.cache_key] = new_ast


    def _handle_constraints(self):
        constraint = claripy.And(*self.angr_path_info.constraints)
        constraint_updated = self._replace_ast(constraint)
        self._dprint("\npath constraints")
        self._dprint("old constraint:", constraint)
        self._dprint("updated constraint:", constraint_updated)
        self.path_constraint = claripy.simplify(constraint_updated)

    def _handle_memory_writes(self):
        symbolic_memory = {}
        for addr_key, ast in self.angr_path_info.global_memory_writes.items():
            # addr_key: (addr.cache_key, size)
            (addr_cache, size) = addr_key
            new_addr = self._replace_ast(addr_cache.ast)
            new_ast = self._replace_ast(ast)
            new_key = (new_addr.cache_key, size)
            symbolic_memory[new_key] = new_ast

        self._dprint("Symbolic memory")
        self._dprint(symbolic_memory)
        self.symbolic_memory = symbolic_memory

    def _handle_return_value(self):
        if self.angr_path_info.return_value is not None:
            updated_return_value =  self._replace_ast(self.angr_path_info.return_value)
            self._dprint("\noriginal return value:", self.angr_path_info.return_value, "\n")
            self._dprint("updated return value:", updated_return_value)
            self.return_value = updated_return_value

    def _handle_func_args_map(self):
        func_args_map = {}
        # Copy from function_calls, only keep the function calls that are in visited blocks
        for func_name, args_map in self.angr_path_info.function_calls.items():
            new_args_map = {}
            for bb_addr, args_list in args_map.items():
                # If bb_addr is  not in visited blocks, there is an error
                if bb_addr not in self.visited_blocks:
                    continue
                # Replace args
                new_args_map[bb_addr] = []
                for args in args_list:
                    new_args = list(self._replace_ast(arg) for arg in args)
                    # print(new_args)
                    func_obj = self.generate_symbolic_func(func_name, new_args, self.project.arch.bits)
                    # print("handle func args map", func_obj)
                    new_args_map[bb_addr].append(func_obj)
            func_args_map[func_name] = new_args_map

        # print(func_args_map)
        self.func_args_map = func_args_map

    def _replace_ast(self, ast):
        # if ast is not None:
        #     curr_ast = ast

        #     # No need to do this, since we already returns MemLoad obj in angr
        #     # # 1. Replace with replace_dict recursively, until no mem object or fake_return object is found
        #     # count = 0
        #     # while count < RECURSIVE_LIMIT:
        #     #     count += 1
        #     #     curr_leaf_asts_str = ' '.join(str(i) for i in list(curr_ast.leaf_asts()))
        #     #     if count == RECURSIVE_LIMIT:
        #     #         print("Reach recursive limit %s, will keep the object and eliminate index" % count)
        #     #         break
        #     #     if 'mem_' in curr_leaf_asts_str or \
        #     #             'fake_ret_value_' in curr_leaf_asts_str or \
        #     #             'symbolic_read_unconstrained_' in curr_leaf_asts_str:
        #     #         print(curr_leaf_asts_str)
        #     #         new_ast = curr_ast.replace_dict(self.replacement_dict.copy())
        #     #         self._dprint("Found replacement, old:", curr_ast)
        #     #         self._dprint("Found replacement, new:", new_ast, "\n")
        #     #         curr_ast = new_ast
        #     #     else:
        #     #         break

        #     # 2. Replace registers
        #     # 2.1 Update replacement_dict_reg
        #     leaf_asts = list(curr_ast.leaf_asts())
        #     self._get_leaf_replacements_reg(leaf_asts, self.replacement_dict_reg)
        #     self._dprint("replace ast, replacement_dict_reg", self.replacement_dict_reg)
        #     # 2.2 Replace dict
        #     replaced_ast = curr_ast.replace_dict(self.replacement_dict_reg.copy())

        #     self._dprint("Replacement, old:", ast)
        #     self._dprint("Replacement, new", replaced_ast)
        #     return replaced_ast
        # else:
        #     return None
        return ast

    def _check_if_valid(self):
        # 1. False constraint
        if self.is_false_constraint is not True and claripy.is_false(self.path_constraint):
            self.is_false_constraint = True

        # 2. Invalid exit edge
        # If it's already been marked as invalid, do nothing
        if self.is_invalid_exit_path is not True:
            # Iterate all edges, see if there is any invalid exit edges
            for i in range(len(self.visited_blocks) - 1):
                # edge: (current_bb_addr, next_bb_addr)
                edge = (self.visited_blocks[i], self.visited_blocks[i+1])
                if edge in self.invalid_exit_edges:
                    self.is_invalid_exit_path = True
                    break

    ### Static methods ###

    @staticmethod
    def generate_memory_load(addr_symbolic, size):
        args = [addr_symbolic]
        MemoryLoad_decl = claripy.ast.func.MemoryLoad(op='MemoryLoad', args=args,
                                                      _ret_size=size)
        new_value = MemoryLoad_decl.op(*args)
        return new_value

    @staticmethod
    def generate_symbolic_func(func_name, args, size):
        # print("generate_symbolic_func", func_name, args, size)
        modified_func_name = "Func_%s" % func_name if not func_name.startswith('Func_') else func_name
        func_args = [modified_func_name]
        func_args.extend(args)
        Func_decl = claripy.ast.func.Func(op=modified_func_name, args=func_args, _ret_size=size)
        new_func = Func_decl.func_op(*func_args)
        # print("generate_symbolic_func, new_func", new_func)

        if len(new_func.args)  == len(args) + 1:
            print("generate_symbolic_func, remove first arg", new_func.args[0])
            new_func.args = new_func.args[1:]

        # print("generate_symbolic_func, done", new_func)
        assert(len(new_func.args) == len(args))
        return new_func
