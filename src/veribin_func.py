import angr
import os
import pickle
from queue import Queue
# from typing import List, Set, Any, Dict
import time
import angrutils
import copy
import claripy

from veribin_path import Path
from veribin_hooks import install_arch_hooks
from ppc_helper import get_p_and_cfg


VISIT_LIMIT = 2
INDIRECT_CALL_NUM_OF_ARGS = 0

my_options = {
    # angr.options.CALLLESS,
              angr.options.SYMBOLIC,
              angr.options.SYMBOLIC_INITIAL_VALUES,
              # angr.options.SYMBOLIC_WRITE_ADDRESSES,
              angr.options.CONSERVATIVE_READ_STRATEGY,
              angr.options.CONSERVATIVE_WRITE_STRATEGY,
              angr.options.SUPPORT_FLOATING_POINT,
              # angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
              # angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS

              # Add LAZY_SOLVES option to avoid angr from solving constraints using BackendConcrete
              # Which will cause angr to fail due to BackendConcrete not supporting added operations
              angr.options.LAZY_SOLVES,

              # Use cache-less solver to avoid angr from using BackendConcrete
              angr.options.CACHELESS_SOLVER,

              angr.options.BYPASS_ERRORED_IRCCALL, # Added by Antonio
              angr.options.CONSTRAINT_TRACKING_IN_SOLVER, # Added by Antonio,

              # cpuid
              angr.options.CPUID_SYMBOLIC
              }

CFG_ARGS = {
            "show_progressbar":True,
            "normalize":True,
            # Copy same default options from angr-management
            "resolve_indirect_jumps":True,
            "data_references":True,
            "cross_references":False,
            "skip_unmapped_addrs":True,
            "exclude_sparse_regions":True,
            "force_complete_scan":False,
            "force_smart_scan":True,
            # End of angr-management options
            }

def get_block(p, cfg, addr):
    try:
        _node = cfg.model.get_node(addr)
        return p.factory.block(addr, _node.size)
    except AttributeError:
        return p.factory.block(addr)

class PathPlugin(angr.SimStatePlugin):
    debug = False
    def __init__(self, loop_info, debug=False, symbolic_memory_read_zero=False):
        super(PathPlugin, self).__init__()
        self.constraints = []
        self.memory_writes = {}
        self.global_memory_writes = {}
        self.memory_reads = {}
        self.function_calls = {}
        self.function_info = {}
        self.function_addr_to_name = {}
        self.function_call_replacement = {}
        self.address_concretization = {}
        self.return_value = None
        self.bb_addrs = []
        self.output_args_memory_addrs = {}
        self.symbolic_memory_read_zero = symbolic_memory_read_zero

        # Store loop_info from loop finder
        self.loop_info = loop_info

        # Loop: breaking addr to loop addr
        # Format: 'breaking_edge_from_addr': 'loop_addr'
        breaking_addr_to_loop_addr = {}
        for loop_addr, single_loop_info in self.loop_info.items():
            for breaking_addr in single_loop_info['break_edges'].keys():
                breaking_addr_to_loop_addr[breaking_addr] = loop_addr
                PathPlugin._dprint(f"Breaking_addr_to_loop_addr: {hex(breaking_addr)} -> {hex(loop_addr)}")
        self.breaking_addr_to_loop_addr = breaking_addr_to_loop_addr

        # Update debug
        PathPlugin.debug = debug

    @classmethod
    def _dprint(cls, msg, n=5000):
        # n: Number of characters to print
        msg_str = str(msg)
        if cls.debug:
            # If msg is too long, print the first N characters
            if len(msg_str) > n:
                msg_str = msg_str[:n] + "\t[...] (message is too long)"
            print('{}'.format(msg_str))

    @angr.SimStatePlugin.memo
    def copy(self, memo):
        new_path_plugin = PathPlugin(loop_info=self.loop_info, debug=self.debug, symbolic_memory_read_zero=self.symbolic_memory_read_zero)

        # Shallow copy
        new_path_plugin.function_info = self.function_info.copy()
        new_path_plugin.function_addr_to_name = self.function_addr_to_name.copy()
        new_path_plugin.function_call_replacement = self.function_call_replacement.copy()
        new_path_plugin.address_concretization = self.address_concretization.copy()

        # Still shallow copy
        new_path_plugin.constraints = copy.copy(self.constraints)
        new_path_plugin.memory_writes = copy.copy(self.memory_writes)
        new_path_plugin.global_memory_writes = copy.copy(self.global_memory_writes)
        new_path_plugin.memory_reads = copy.copy(self.memory_reads)
        new_path_plugin.function_calls = copy.copy(self.function_calls)
        new_path_plugin.bb_addrs = copy.copy(self.bb_addrs)
        new_path_plugin.output_args_memory_addrs = copy.copy(self.output_args_memory_addrs)


        # Left blank
        # self.return_value

        return new_path_plugin

    @staticmethod
    def handle_memory_write(state):
        PathPlugin._dprint('\n[+] Handling memory write in state %s' % state)
        addr = state.solver.simplify(state.inspect.mem_write_address)
        is_global_flag = True

        content = state.inspect.mem_write_expr
        length = state.inspect.mem_write_length
        # addr_str = hex(state.solver.eval(addr))
        key = (addr.cache_key, length)

        # If is local write, only add to memory_writes
        # stack address : between sp and bp
        # sp and bp contains the most updated values
        if state.solver.is_true(addr == state.regs.sp) or \
            (state.solver.is_true(addr > state.regs.sp - 0x100) and state.solver.is_true(addr <= state.regs.sp + 0x100)):
            PathPlugin._dprint('[-] Skip stack address: addr %s between sp - 0x100 %s and sp + 0x100 %s.' %
                  (addr, state.regs.sp - 0x100, state.regs.sp + 0x100))
            PathPlugin._dprint(f"\tMemory write addr: {key}")
            PathPlugin._dprint(f"\tMemory write content: {content}")
            PathPlugin._dprint('[+] Done handling memory write in state %s' % state)
            is_global_flag = False

        if is_global_flag:
            # print("key:", key)
            state.sypy_path.global_memory_writes[key] = content

        # Add all writes to memory_writes
        state.sypy_path.memory_writes[key] = content

    @staticmethod
    def handle_memory_read(state):
        addr = state.inspect.mem_read_address
        PathPlugin._dprint('\n[+] Handling memory read in state %s %s' % (state, addr))
        # stack address : between sp and bp
        # sp and bp contains the most updated values
        # if state.solver.is_true(addr == state.regs.sp) or \
        #     (state.solver.is_true(addr > state.regs.sp) and state.solver.is_true(addr <= state.regs.bp)):
        #     print('[-] Skip stack address: addr %s between sp %s and bp %s.' %
        #           (addr, state.regs.sp, state.regs.bp))
        #     return
        content = state.solver.simplify(state.inspect.mem_read_expr)
        # addr_str = hex(state.solver.eval(addr))
        # If content is a symcolic_read_unconstrainted value
        # example: <BV64 symbolic_read_unconstrained_1842_64{UNINITIALIZED}>
        # OR: <BV8 mem_7fffffffffeffc1_11_8{UNINITIALIZED}>
        assert(8*state.inspect.mem_read_length == content.size())

        # Only when 'symbolic_memory_read' is found state options, we need to assign a symbolic value to it
        if hasattr(state.sypy_path, 'symbolic_memory_read_zero') and state.sypy_path.symbolic_memory_read_zero:

            # If content is 0, assign a symbolic value to it
            if state.solver.is_true(content == 0):
                # mem_{addr}_{state.inspect.mem_read_length * 8}
                # generate a name: if memory_read_addr is symbolic, use it as name Mem_{addr}
                # otherwise, use symbolic_0 as name, avoid name conflict
                if addr.symbolic:
                    name = f"Mem_{addr}"
                    explicit_name_flag = True
                elif addr.concrete:
                    name = f"Mem_{hex(addr.concrete_value)}_zero"
                    explicit_name_flag = False
                else:
                    name = "Mem_symbolic_zero"
                    explicit_name_flag = True
                content = state.solver.BVS(name,
                                        size=state.inspect.mem_read_length * 8,
                                        explicit_name=explicit_name_flag)
                # print(content)

                # reassign memory read content
                state.inspect.mem_read_expr = content

        # if content.op == 'BVS' and content.depth == 1:
        #     state.sypy_path.memory_reads[content.cache_key] = addr

        state.sypy_path.memory_reads[content.cache_key] = addr
        PathPlugin._dprint(f"\tMemory read addr: {addr}")
        PathPlugin._dprint(f"\tMemory read content: {content}")
        PathPlugin._dprint(f"\tMemory read length: {state.inspect.mem_read_length}")

        PathPlugin._dprint('[+] Done handling memory reads in state %s' % state)

    @staticmethod
    def handle_indirect_function_call(state):

        # Return a fake signature using num_of_args to generate prototype
        # Format: "void *x(void *, ...)"
        def generate_fake_signature_str(num_of_args, output_args_index=[]):
            if num_of_args == 0:
                return "void *x()"
            else:
                args_str = ", ".join(["int" if i not in output_args_index else "void *" for i in range(num_of_args)])
                return f"void *x({args_str})"

        PathPlugin._dprint('\n[+] Handling function call in state %s' % state)
        function_address_bv = state.inspect.function_address

        try:
            function_addr = state.solver.eval_atmost(function_address_bv, 1)[0]

            # Handling patcherex added functions: remove 'CALLLESS' option
            # If is patcherex added function, do not consider it as a 'real' function call
            if function_addr in state.globals['veribin_func'].patcherex_added_functions:
                state.options['CALLLESS'] = False
                PathPlugin._dprint("Patcherex added function, do not consider it as a 'real' function call")
                return

            if function_addr not in state.sypy_path.function_info:
                tic = time.perf_counter()

                func = state.project.kb.functions.get_by_addr(function_addr)


                func_name = "Func_" + func.demangled_name
                PathPlugin._dprint(f"func info in kb functions: {func_name}, {func.prototype}")

                if func.calling_convention is None:
                    func.calling_convention = angr.calling_conventions.DEFAULT_CC[state.project.arch.name] \
                        ["Linux"](state.project.arch)

                # Method 1
                # if the func info is in configuration, manually create a prototype
                if func.prototype is None:
                    if func_name in state.globals['veribin_func'].function_info_map:
                        num_of_args = state.globals['veribin_func'].function_info_map[func_name]["num_of_args"]
                        try:
                            output_args_index = state.globals['veribin_func'].function_info_map[func_name]["output_args_index"]
                        except KeyError:
                            output_args_index = []
                        fake_signature = generate_fake_signature_str(num_of_args, output_args_index)
                        func.prototype = angr.sim_type.parse_signature(fake_signature).with_arch(state.arch)
                        PathPlugin._dprint(f"func info method 1 (ida): {func_name}, {func.prototype}")

                # Method 2: Variable Recovery + Calling Convention
                if func.prototype is None:
                    _ = state.project.analyses.VariableRecoveryFast(func)
                    cc_analysis = state.project.analyses.CallingConvention(func, analyze_callsites=True)
                    if func.prototype is None:
                        func.prototype = cc_analysis.prototype
                    PathPlugin._dprint(f"func info method 2 (Variable Recovery): {func_name},\
                                       {func.prototype}, {cc_analysis.prototype}")

                # Method 3: (ref: angr tests) DEFAULT_CC + find_declaration
                if func.prototype is None:
                    # func.calling_convention = angr.calling_conventions.DEFAULT_CC[state.project.arch.name]\
                    #     (state.project.arch)
                    func.find_declaration()
                    PathPlugin._dprint(f"func info method 3 (find declaration): {func_name}, {func.prototype}")

                # Method 4: otherwise, the function argument should be empty (create a default prototype with 0 arg)
                if func.prototype is None:
                    # func.arguments should be empty, thus prototype is expected to be () -> char*
                    func.prototype = func.calling_convention.guess_prototype(func.arguments).with_arch(state.arch)
                    PathPlugin._dprint(f"func info method 4 (empty): {func_name}, {func.prototype}")

                if func.prototype is None:
                    assert False and  "Function prototype is None"

                if func.prototype is not None and func.prototype._arch is None:
                    func.prototype = func.prototype.with_arch(state.arch)

                toc = time.perf_counter()
                PathPlugin._dprint("===== Time elapse for CallingConvention: %.4f seconds\n" % (toc - tic))

                # Store function info into sypy_path
                PathPlugin._dprint(f"func info store into map: {func_name}, {func.prototype}")
                state.sypy_path.function_info[function_addr] = {'func_name': func_name, 'func_obj': func}
            else:
                func_name = state.sypy_path.function_info[function_addr]['func_name']
                func = state.sypy_path.function_info[function_addr]['func_obj']

            try:
                func_variables = func.calling_convention.get_args(state, func.prototype)
            except:
                func_variables = []
            PathPlugin._dprint(f"func_name: {func_name}, prototype: {func.prototype}, variables: {func_variables}")

            # Update output arguments (if any), in "Func_Arg#index" format
            if func_name in state.globals['veribin_func'].function_info_map and \
                "output_args_index" in state.globals['veribin_func'].function_info_map[func_name]:
                output_args_index = state.globals['veribin_func'].function_info_map[func_name]["output_args_index"]
                # print("output_args_index:", output_args_index)
            else:
                output_args_index = []
            # Skip for now, because angr cannot distinguish between 'const void *' and 'void *'
            # else:
            #     # If output_args_index is not specified, assume all pointer arguments are output arguments
            #     output_args_index = []
            #     for i, arg in enumerate(func.prototype.args):
            #         print("arg", arg, "arg_type", type(arg))
            #         if isinstance(arg, angr.sim_type.SimTypePointer):
            #             output_args_index.append(i)
            #             print("arg:", arg, "output_args_index:", i)

            if len(output_args_index) > 0:
                for output_arg_index in output_args_index:
                    # the output arg is a pointer, we need to assign new value to it
                    output_arg = func_variables[output_arg_index]
                    # print("output_arg:", output_arg)
                    # we select content size as default architecure size, e.g., 32-bit or 64-bit
                    new_output_arg_content = state.solver.BVS(f"{func_name}_Arg#{output_arg_index}",
                                                    size=state.arch.bits,
                                                    explicit_name=True)
                    PathPlugin._dprint(f"new_output_arg: {new_output_arg_content}")
                    # Assign new_output_arg value to mem[output_arg]
                    state.memory.store(output_arg, new_output_arg_content,
                                    new_output_arg_content.size()>>3,
                                    endness=state.arch.memory_endness)
                    # print("After setting arg, get:", state.memory.load(output_arg,
                    #                                                 new_output_arg_content.size()>>3,
                    #                                                 endness=state.arch.memory_endness))

        except Exception as e:
            if isinstance(e, KeyError) or isinstance(e, angr.errors.SimUnsatError) or \
                isinstance(e, angr.errors.SimValueError):
                    print("Handling indirect call")
                    # 1. name
                    func_name = "Func_indirect_call" + str(function_address_bv)
                    # 2. calling convention
                    calling_convention = angr.calling_conventions.DEFAULT_CC[state.project.arch.name]['Linux'](state.project.arch)
                    # =. prototype
                    fake_signature = generate_fake_signature_str(INDIRECT_CALL_NUM_OF_ARGS)
                    prototype = angr.sim_type.parse_signature(fake_signature).with_arch(state.project.arch)
                    # 3. variables
                    func_variables = calling_convention.get_args(state, prototype)
            else:
                print(f"Error! in function {function_address_bv}: {e}")
                raise NotImplementedError("Something wrong in function call handler.")

        # Store into sypy_path
        if func_name not in state.sypy_path.function_calls:
            state.sypy_path.function_calls[func_name] = {}
        bb_addr = list(state.history.bbl_addrs)[-1]
        if bb_addr not in state.sypy_path.function_calls[func_name]:
            state.sypy_path.function_calls[func_name][bb_addr] = []
        state.sypy_path.function_calls[func_name][bb_addr].append(func_variables)

    @staticmethod
    def handle_new_constraint(state):
        PathPlugin._dprint('\n[+] Handling new constraint in state %s' % state)
        added_constraints = state.inspect.added_constraints
        PathPlugin._dprint(f"added constraints: {added_constraints}")
        assert(len(added_constraints) == 1)
        if state.solver.is_true(added_constraints[-1]) or state.solver.is_false(added_constraints[-1]):
            PathPlugin._dprint("\t Ignore the condition for conditional jump")
            PathPlugin._dprint("\t added constraint: %s" % added_constraints[-1])
            # TODO: discard this state
            return
        state.sypy_path.constraints.append(claripy.simplify(added_constraints[-1]))
        PathPlugin._dprint(f"constraints: {state.sypy_path.constraints}")
        PathPlugin._dprint('[+] Done handling new constraint in state %s' % state)

    @staticmethod
    def handle_indirect_jump(state):
        PathPlugin._dprint("TODO: handle indirect jump")
        # succs = state.inspect.sim_successors.successors

    @staticmethod
    def handle_address_concretization(state):
        PathPlugin._dprint("\n[+] Handling address concretization.")
        PathPlugin._dprint(f"\tstrategy: {state.inspect.address_concretization_strategy}")
        PathPlugin._dprint(f"\taction: {state.inspect.address_concretization_action}")
        PathPlugin._dprint(f"\tmemory: {state.inspect.address_concretization_memory}")
        PathPlugin._dprint(f"\texpr: {state.inspect.address_concretization_expr}")
        PathPlugin._dprint(f"\tadded_constraints: {state.inspect.address_concretization_add_constraints}")
        PathPlugin._dprint(f"\tresult: {state.inspect.address_concretization_result}")
        if state.inspect.address_concretization_result is not None:
            # TODO: handle multiple results
            for i in range(len(state.inspect.address_concretization_result)):
                concrete_addr = state.inspect.address_concretization_result[i]
                size = int((state.inspect.address_concretization_expr.size())/8)
                addr_ast = state.memory.load(concrete_addr, size=size, endness='Iend_LE')
                state.sypy_path.address_concretization[addr_ast.cache_key] = state.inspect.address_concretization_expr
                PathPlugin._dprint(f"Current AC: {state.sypy_path.address_concretization}")
        state.inspect.address_concretization_add_constraints = False
        PathPlugin._dprint("[+] Done handling address concretization in state %s" % state)

    @staticmethod
    def handle_fake_return_value(state):
        # func_addr = state.addr
        # bb_addr = list(state.history.bbl_addrs)[-1]

        # assert func_addr in state.sypy_path.function_info
        # func_name = state.sypy_path.function_info[func_addr]['func_name']

        # # Last one argument list
        # assert bb_addr in state.sypy_path.function_calls[func_name]
        # func_args = state.sypy_path.function_calls[func_name][bb_addr][-1]

        # old_value = state.inspect.reg_write_expr
        # new_value = Path.generate_symbolic_func(func_name=func_name, args=func_args, size=state.arch.bits)
        # if old_value.cache_key not in state.sypy_path.function_call_replacement.keys():
        #     state.sypy_path.function_call_replacement[old_value.cache_key] = new_value
        # print(old_value, new_value)
        PathPlugin._dprint(f"Fake return value handler, skipped {state.inspect.reg_write_expr}")

    @staticmethod
    def handle_fake_return_value_cond(state):
        # We want to catch only 'fake_return_value' writing to returning register
        # state with 'CALLLESS' function will not store default return value to returning register
        return state.solver.eval(state.inspect.reg_write_offset) == state.arch.ret_offset and \
            state.history.jumpkind == 'Ijk_Call' and state.options['CALLLESS']

class VeriBinFunc(object):
    def __init__(self, p, func_addr, binary_info, exit_edges_info, tag, graph_format='dot', is_ppc=False, debug=False, use_cache=True, symbolic_memory_read_zero=False):
        # Arguments
        self.p = p
        self.func_addr = func_addr
        self.exit_edges_info = exit_edges_info
        self.tag = tag
        self.is_ppc = is_ppc
        self.debug = debug
        self.use_cache = use_cache
        self.symbolic_memory_read_zero = symbolic_memory_read_zero

        # self.function_info_map = binary_info['func_info_map']
        # Add 'Func_' prefix before function name
        self.function_info_map = {'Func_' + k: v for k, v in binary_info['func_info_map'].items()}

        self.patcherex_added_functions = binary_info['patcherex_added_functions']
        self.symbol_table = binary_info['symbol_table'][tag]
        # Get the initial values of registers from config file
        self.register_initial_values = binary_info['register_initial_values']
        tic = time.perf_counter()
        try:
            # Load cfg and project from pickle file
            # If explicitly set use_cache to False, skip loading from cache
            if not use_cache:
                assert False
            if self.is_ppc:
                # When the binary is ppc, pickling will cause an error, so we need to load it from file
                assert False
            self.cfg = pickle.load(open(p.filename + ".cfg.p", "rb"))
            self.p = pickle.load(open(p.filename + ".project.p", "rb"))
        except:
            if self.is_ppc == "PowerPC:BE:32:MPC8270":
                self.p, self.cfg = get_p_and_cfg(self.p)
            else:
                try:
                    self.cfg = self.p.analyses.CFGFast(**CFG_ARGS,
                                                        # Add function_starts to force angr to analyze the function
                                                        function_starts=[self.func_addr],
                                                        **binary_info['cfgfast_options'][tag]
                                                    )

                    # Try to load func, if not found, re-load project and re-generate cfg,
                    self.func = self.cfg.kb.functions.get_by_addr(self.func_addr)
                except KeyError:
                    # KeyError could happens when: 1) the function is not found in the cfg
                    # 2) during the CFGFast analysis, some other functions are not found

                    # Re-load the project with 'load_debug_info' set to True
                    self.p = angr.Project(p.filename, load_options={'auto_load_libs': False, 'load_debug_info': True})
                    # Re-generate the cfg
                    self.cfg = self.p.analyses.CFGFast(**CFG_ARGS,
                                                    #    function_starts=[self.func_addr],
                                                        **binary_info['cfgfast_options'][tag]
                                                    )
            self.p.analyses.Flirt()
            pickle.dump(self.cfg, open(p.filename + ".cfg.p", "wb"))
            pickle.dump(self.p, open(p.filename + ".project.p", "wb"))
        toc = time.perf_counter()
        print("Time elapse for angr CFG: %.4f seconds\n" % (toc - tic))

        # Add exception handler to handle cases when angr cannot find the function
        try:
            self.func = self._get_func_by_addr(self.func_addr)
        except KeyError:
            print("Error! Cannot find patch affected function at address %s" % hex(self.func_addr))
            # Print all functions
            print("All functions:")
            print(self.cfg.kb.functions._function_map.values())
            raise KeyError("Cannot find patch affected function at address %s" % hex(self.func_addr))

        # Fix a NoneType error
        self.func._project = self.p

        # Get function size
        print("Function size:", self.func.size)

        self.graph = self._get_func_graph()
        # generate graph, format can be 'png' or 'dot'
        # If target path is incorrect(doesn't exist, caused by pickling), skip
        try:
            # Skip if already exist
            if not os.path.exists(os.path.join(os.path.dirname(self.p.filename),
                                               "%s_%s_funcgraph_asm.%s" % (self.tag, hex(self.func_addr), graph_format))):
                angrutils.plot_func_graph(self.p,
                                        self.graph,
                                        asminst=True,
                                        fname=os.path.join(os.path.dirname(self.p.filename),
                                                            "%s_%s_funcgraph_asm" % (self.tag, hex(self.func_addr))),
                                        format=graph_format)
                # angrutils.plot_func_graph(self.p,
                #                           self.graph,
                #                           asminst=True,
                #                           vexinst=True,
                #                           fname=os.path.join(os.path.dirname(self.p.filename),
                #                                              "%s_%s_funcgraph_vex" % (self.tag, hex(self.func_addr))),
                #                           format=graph_format)
        except Exception as e:
            print("Error in generating graph:", e)
            pass

        self.paths = []
        self.ended_states = []
        self.end_points_bb_addr = [node.addr for node in self.graph.nodes if self.graph.out_degree(node) == 0]
        # Get last instrucntion addrs from end nodes
        self.end_points_instr_addr = [self.get_block(addr).instruction_addrs[-1] for addr in self.end_points_bb_addr]

        # Get all instructions addrs this function from the function graph
        self.all_instrs_addr = []
        for node in self.graph.nodes:
            bb = self.get_block(node.addr)
            self.all_instrs_addr += bb.instruction_addrs

        # # get all end points of the function
        # self.end_instrs_addr = []
        # for node in self.graph.nodes:
        #     bb = self.p.factory.block(node.addr, node.size)
        #     bb.pp()

        #     # Case 1: End of function, no successor
        #     if self.graph.out_degree(node) == 0:
        #         bb.pp()
        #         print("End of function")
        #         end_instruction_addr = bb.instruction_addrs[-1]
        #         self.end_instrs_addr.append(end_instruction_addr)

        self.calling_convention = angr.calling_conventions.DEFAULT_CC[self.p.arch.name]['Linux'](self.p.arch)

        self.return_value_used = self._is_return_value_used()

        # Store loop finder object
        self.loop_finder = self.p.analyses.LoopFinder(functions=[self.func])

        # Loop_info, in format of 'loop_addr': 'break_edges' (dict)
        self.loop_info = {}

        for loop in self.loop_finder.loops:
            # Store 'break_edges' from LoopFinder,
            # in format of 'last ins addr of from_block': 'first ins addr of to_block'
            break_edges = {}
            for from_block, to_block in loop.break_edges:
                # Type of 'from_block' and 'to_block' is 'angr.analyses.cfg.cfg_node.CFGNode',
                # Use 'get_block' to get the block object
                from_edge_addr = self.get_block(from_block.addr).instruction_addrs[-1]
                to_edge_addr = self.get_block(to_block.addr).instruction_addrs[0]
                self._dprint(f"break edge: {hex(from_edge_addr)} -> {hex(to_edge_addr)}")
                if from_edge_addr not in break_edges:
                    break_edges[from_edge_addr] = []
                break_edges[from_edge_addr].append(to_edge_addr)

            # Store into loop_info
            self.loop_info[loop.entry.addr] = {'break_edges': break_edges}

        self._construct()

    def _dprint(self, msg, n=5000):
        # n: Number of characters to print
        msg_str = str(msg)
        if self.debug:
            # If msg is too long, print the first N characters
            if len(msg_str) > n:
                msg_str = msg_str[:n] + "\t[...] (message is too long)"
            print('[+] {}'.format(msg_str))

    def _construct(self):
        self._interprete_function()


    def _interprete_function(self):

        state = self.p.factory.blank_state(addr=self.func_addr,
                                     cc=self.calling_convention,
                                     add_options=my_options,
                                     mode='symbolic')

        # Set registers to initial values
        for reg_name, reg_value in self.register_initial_values.items():
            setattr(state.regs, reg_name, reg_value)

        # Add costumized plugin VeriBinPath
        state.register_plugin('sypy_path', PathPlugin(loop_info=self.loop_info, debug=self.debug, symbolic_memory_read_zero=self.symbolic_memory_read_zero))

        # inspections (breakpoints):
        #   1. memory write
        state.inspect.b('mem_write', when=angr.BP_AFTER, action=state.sypy_path.handle_memory_write)
        #   1.1. mem_read
        state.inspect.b('mem_read', when=angr.BP_AFTER, action=state.sypy_path.handle_memory_read)
        #   2. function call
        state.inspect.b('call', when=angr.BP_BEFORE, action=state.sypy_path.handle_indirect_function_call)
        #   3. new constraints
        state.inspect.b('constraints', when=angr.BP_BEFORE, action=state.sypy_path.handle_new_constraint)
        #   4. indirect jump constraint
        # state.inspect.b('engine_process', when=angr.BP_AFTER, action=state.sypy_path.handle_indirect_jump)
        #   5. Address concretization
        state.inspect.b('address_concretization', when=angr.BP_AFTER,
                        action=state.sypy_path.handle_address_concretization)
        #   6. fake_return_value
        # state.inspect.b('reg_write', when=angr.BP_AFTER, action=state.sypy_path.handle_fake_return_value,
        #                 condition=state.sypy_path.handle_fake_return_value_cond)

        simgr = self.p.factory.simulation_manager(state)

        # Store some global information
        state.globals['simgr'] = simgr

        # Get all end instructions addr(last instruction from basic blocks with out degree 0) from self.func.graph
        state.globals['end_points_addr'] = self.end_points_instr_addr

        state.globals['veribin_func'] = self

        # Init output_arg_memory_addrs
        # state.globals['output_args_memory_addrs'] = []

        while True:
            self._dprint(simgr)
            for k, v in simgr.stashes.items():
                if k == 'active' or k == 'pruned':
                    self._dprint(f"{k}, {v}")

            # Multiple tasks
            # 1. Filter states split from evil addrs
            # 2. Add back CALLLESS option if not in state.options
            for s in simgr.active:

                # TASK 0: Install hooks
                install_arch_hooks(self.p, s, self.patcherex_added_functions, debug=self.debug)

                # TASK 1:Filter states split from evil addrs
                bbl_addrs = list(s.history.bbl_addrs)

                # Move to stashed if current state is from end points addrs
                if len(bbl_addrs) > 0 and bbl_addrs[-1] in state.globals['end_points_addr']:
                    # Skip if current binary is using pcode engine,
                    # because we're not able to get the correct function graph
                    # (a whole function graph including patcherex added functions)
                    if self.is_ppc:
                        continue

                    print("\n\n#####See evil addr %s at state %s\n\n" % (hex(bbl_addrs[-1]), hex(s.addr)))
                    simgr.move("active", "stashed", filter_func=lambda _s: _s.addr == s.addr)

                # Move to errored if reach loop limitation (an instruction is executed more than twice)
                if bbl_addrs.count(s.addr) == 2:
                    print("Found loop at %s" % hex(s.addr))
                    simgr.move("active", "loop", filter_func=lambda _s: _s.addr == s.addr)

                # TASK 2: Add back CALLLESS option if not in state.options
                if s.options['CALLLESS'] is False:
                    s.options['CALLLESS'] = True

            simgr.step(num_inst=1, opt_level=2)

            if len(simgr.active) == 0:
                break
        self._handle_all_paths(simgr)

    def _handle_all_paths(self, simgr):
        print(simgr)
        all_paths = []
        for single_type_path_list in simgr.stashes.values():
            all_paths += single_type_path_list
        for state in all_paths:
            state.sypy_path.bb_addrs = list(state.history.bbl_addrs)
            # print('BB addrs: [{}]'.format(', '.join(hex(x) for x in state.sypy_path.bb_addrs)))
            # print(state.simplify())
            if self.return_value_used:
                state.sypy_path.return_value = getattr(state.regs, self.calling_convention.RETURN_VAL.reg_name)

            # print("constraints", state.sypy_path.constraints)
            # print("memory writes", state.sypy_path.memory_writes)
            # print("return value", state.sypy_path.return_value)
            # print("function args", state.sypy_path.function_calls)
            # print("*****************************************")
            self.ended_states.append(state)
            path = Path(self.p, self.exit_edges_info, state, debug=self.debug)
            self.paths.append(path)

    def _label_function(self):
        return 'f_%s_%s' % (self.func.name, hex(self.func.addr))

    @staticmethod
    def _label_block(block):
        return 'bb_%x' % block.addr

    def get_veribin_func(self):
        if self.veribin_func is None:
            self._construct()
        return self.veribin_func

    def _get_func_by_addr(self, addr):
        # Check whether func addr is in the function map
        if self.cfg.kb.functions.contains_addr(addr):
            func = self.cfg.kb.functions.get_by_addr(addr)
        else:
            # Get floor function
            func = self.cfg.kb.functions.floor_func(addr)

        func.normalize()
        return func

    def _is_return_value_used(self):
        if self.func_addr in self.symbol_table:
            func_name = self.symbol_table[self.func_addr]
            if not func_name.startswith('Func_'):
                func_name = 'Func_' + func_name
            if func_name in self.function_info_map:
                func_info = self.function_info_map[func_name]
                if 'return_value_used' in func_info:
                    return func_info['return_value_used']
        try:
            result = self.calling_convention.prototype.returnty is not None
        except AttributeError:
            # prototype is None, has no attribute 'returnty'
            result = True
        return result


    def get_block(self, addr):
        try:
            _node = self.cfg.model.get_node(addr)
            return self.p.factory.block(addr, _node.size)
        except AttributeError:
            return self.p.factory.block(addr)

    def _get_func_graph(self):
        # If the function doesn't use vex engine, return the original graph
        if self.is_ppc:
            # TODO: get jump targets using pcode engine
            return self.func.graph.copy()

        if self.tag == 'original' or len(self.patcherex_added_functions) == 0:
            return self.func.graph.copy()

        graph = self.func.graph.copy()
        extra_edges_queue = Queue()
        for node in graph.nodes:
            # Re-lift, to get more accurate vex jumpkind info
            block = self.get_block(node.addr)
            for jump_target_addr, jumpkind in block.vex.constant_jump_targets_and_jumpkinds.items():
                if jumpkind == 'Ijk_Boring':
                    # If target_bb not in graph
                    if jump_target_addr not in list(b.addr for b in graph.nodes):
                        extra_edges_queue.put((block.addr, jump_target_addr))

                # Step into patcherex added functions
                elif jumpkind == 'Ijk_Call' and jump_target_addr in self.patcherex_added_functions:
                    func_addr = jump_target_addr
                    target_func = self.cfg.kb.functions.get_by_addr(func_addr)
                    # Add edge (dst_addr -> func_start_addr)
                    extra_edges_queue.put((block.addr, func_addr))

                    # Add edges (func_end_points -> dst_addr + dst_block.size)
                    for end_point_block in target_func.endpoints:
                        extra_edges_queue.put((end_point_block.addr, block.addr + block.size))

                    # Remove edge from src_block to (src_addr + src.size)
                    next_node = self.get_block(block.addr + block.size)
                    graph.remove_edge(block.codenode, next_node.codenode)

        while not extra_edges_queue.empty():
            src_addr, dst_addr = extra_edges_queue.get()
            src_block = self.get_block(src_addr)
            dst_block = self.get_block(dst_addr)
            # Add dst_block's successors if dst_block is not in the graph
            if dst_addr not in list(b.addr for b in graph.nodes):
                jump_targets_and_jumpkinds = list(dst_block.vex.constant_jump_targets_and_jumpkinds.items())
                func_addrs = [addr for addr, jumpkind in jump_targets_and_jumpkinds if jumpkind == 'Ijk_Call']

                # For special functions given by patcherex, add the whole function graph into the current graph
                # Turning a "Call" into a "Jump"
                if len(func_addrs) == 1 and func_addrs[0] in self.patcherex_added_functions:
                    func_addr = func_addrs[0]
                    target_func = self.cfg.kb.functions.get_by_addr(func_addr)
                    # Add edge (dst_addr -> func_start_addr)
                    extra_edges_queue.put((dst_addr, func_addr))

                    # Add edges (func_end_points -> dst_addr + dst_block.size)
                    for end_point_block in target_func.endpoints:
                        extra_edges_queue.put((end_point_block.addr, dst_addr + dst_block.size))

                else:
                    # Add all jump edges
                    for jump_target_addr, jumpkind in jump_targets_and_jumpkinds:
                        if jumpkind == 'Ijk_Boring':
                            extra_edges_queue.put((dst_addr, jump_target_addr))
                    # Fix for call but without nest block
                    if len(jump_targets_and_jumpkinds) == 1 and len(func_addrs) == 1:
                        # Add the next block as a jump target
                        extra_edges_queue.put((dst_addr, dst_addr + dst_block.size))

            # Add edge to graph
            if not graph.has_edge(src_block.codenode, dst_block.codenode):
                # print("Add edge: %s-%s" % (hex(src_block.addr), hex(dst_block.addr)))
                graph.add_edge(src_block.codenode, dst_block.codenode)

        return graph
