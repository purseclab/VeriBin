
import angr
import re
import claripy
from angr.calling_conventions import DEFAULT_CC, SimRegArg
from utils import is_rodata_addr, load_string_content_from_binary

# Customized modules
from parse_spec_string import parse_spec_string
from veribin_path import Path

INDIRECT_CALL_NUM_OF_ARGS = 2
DEBUG = False

SPECIAL_PHP_VARIADIC_FUNCTIONS = {
    "Func_zend_parse_parameters": 1,
    "Func_zend_parse_parameters_ex": 2,
    "Func_zend_parse_method_parameters": 2
}
def _dprint(msg):
    if DEBUG:
        print('[+] {}'.format(msg))

def is_fakefloat(reg_value):
    for a in reg_value.annotations:
        if hasattr(a, "fakefloat") and a.fakefloat:
            return True
    return False

def annotate_as_fakefloat(reg_value):
    aa=claripy.annotation.Annotation()
    aa.fakefloat = True
    new_reg_value = reg_value.append_annotation(aa)
    return new_reg_value

def update_pointer_variable(p, old_variables):
    """
    Iterate through all variables, if the variable is a pointer and is rodata addr,
    replace it with the content of the rodata addr
    Return a new list of variables
    """
    new_variables = []
    for var in old_variables:
        # If var is a pointer and is rodata addr, replace it with the content of the rodata addr
        if isinstance(var, claripy.ast.bv.BV) and is_rodata_addr(p, var):
            new_var = load_string_content_from_binary(p, var)
            if new_var is not None:
                new_variables.append(new_var)
                continue
        new_variables.append(var)
    return new_variables

def install_arch_hooks(p, state, patcherex_added_functions, debug=False):
    # Set global debug flag
    global DEBUG
    DEBUG = debug

    def get_insn_by_state(s):
        ip = s.solver.eval_one(s.ip)
        instr = state.project.factory.block(ip).disassembly.insns[0]
        return instr

    def efscfui_hook(state):
        # HACK this converts a register from int to float
        # we do not do anything, but we set the float as a fakefloat
        i = get_insn_by_state(state)
        _dprint(f"RUNNING efscfui, {hex(i.address)}")
        r1, r2 = i.op_str.split(",")
        rsource = getattr(state.regs, r2)
        rdestval = rsource
        #import IPython; IPython.embed()
        rdestval = annotate_as_fakefloat(rdestval)
        setattr(state.regs, r1, rdestval)

    def efsdiv_hook(state):
        def convert(reg_value):
            import struct
            if is_fakefloat(reg_value):
                # this is a fake float, we don't need to do anything
                return reg_value
            if reg_value.symbolic == False:
                # in this case we convert a float constant to int
                vv = state.solver.eval_one(reg_value)
                ivv = int(struct.unpack('>f',struct.pack(">I", vv))[0])
                return state.solver.BVV(ivv,32)
            raise angr.AngrError("fakefloat scenario not supported in efsdiv")

        i = get_insn_by_state(state)
        _dprint(f"RUNNING efsdiv, {hex(i.address)}")
        r1, r2, r3 = i.op_str.split(",")
        r2v = getattr(state.regs, r2)
        r3v = getattr(state.regs, r3)
        #result = convert(r2v)/convert(r3v)
        import claripy
        # HACK I implement x//y as int(ceil(x/y)), where // is integer division
        # an alternative "cleaner" implementation would be to store the remainder
        # in some register and then check this register in ceil and add +1 if !=0
        r2vc = convert(r2v)
        r3vc = convert(r3v)
        result = claripy.If(r2vc%r3vc==0,r2vc/r3vc,(r2vc/r3vc)+1)
        result = annotate_as_fakefloat(result)
        setattr(state.regs, r1, result)

    # Hook for rep stosq OR rep stosd
    def rep_stos_hook(state):
        i = get_insn_by_state(state)
        _dprint(f"RUNNING {i.mnemonic}, {hex(i.address)}")

        pattern = r'\[(\w+)\],\s*(\w+)'
        # example: rep stosq qword prt [rdi], rax
        match = re.search(pattern, i.op_str)
        if match:
            dest = match.group(1)
            src = match.group(2)
            _dprint(f"dest, {dest}, src, {src}")

        func_name = "Func_memset"
        args = [dest, src, 'rcx']
        func_variables = [getattr(state.regs, reg_name) for reg_name in args]
         # Update pointer variable
        func_variables = update_pointer_variable(p, func_variables)
        call_result = Path.generate_symbolic_func(func_name, func_variables, size=state.arch.bits)
        _dprint(f"rep_stos_hook, call result:, {call_result}")

        # store to return register
        state.registers.store(state.arch.ret_offset, call_result)

        # store into sypy_path
        if func_name not in state.sypy_path.function_calls:
            state.sypy_path.function_calls[func_name] = {}
        bb_addr = state.addr
        if bb_addr not in state.sypy_path.function_calls[func_name]:
            state.sypy_path.function_calls[func_name][bb_addr] = []
        state.sypy_path.function_calls[func_name][bb_addr].append(func_variables)

    # Hook for rep movsq OR rep movsd
    def rep_movs_hook(state):
        i = get_insn_by_state(state)
        _dprint(f"RUNNING {i.mnemonic}, {hex(i.address)}")

        pattern = r'\[(\w+)\],.*\[(\w+)\]'
        # example: rep movsq qword ptr [rdi], qword ptr [rsi]
        match = re.search(pattern, i.op_str)
        if match:
            dest = match.group(1)
            src = match.group(2)
            _dprint(f"dest, {dest}, src, {src}")

        func_name = "Func_memcpy"
        args = [dest, src, 'rcx']
        func_variables = [getattr(state.regs, reg_name) for reg_name in args]
         # Update pointer variable
        func_variables = update_pointer_variable(p, func_variables)
        call_result = Path.generate_symbolic_func(func_name, func_variables, size=state.arch.bits)
        _dprint(f"rep_movs_hook, call result:, {call_result}")

        # store to return register
        state.registers.store(state.arch.ret_offset, call_result)

        # store into sypy_path
        if func_name not in state.sypy_path.function_calls:
            state.sypy_path.function_calls[func_name] = {}
        bb_addr = state.addr
        if bb_addr not in state.sypy_path.function_calls[func_name]:
            state.sypy_path.function_calls[func_name][bb_addr] = []
        state.sypy_path.function_calls[func_name][bb_addr].append(func_variables)

    # Hook for movaps
    def movaps_hook(state):
        i = get_insn_by_state(state)
        _dprint(f"RUNNING {i.mnemonic}, {hex(i.address)}")

        pattern = r'(\w+|\[(.*?)\]),\s*(\w+)'
        # example 1, memory destination: movaps xmmword prt [rsp+0x20], xmm0
        # 240123: Found new movaps formats
        # example 2, register destination: movaps xmm2, xmm0
        match = re.search(pattern, i.op_str)
        if not match:
            return
        dest_operand = match.group(1)
        src_register = match.group(3)
        _dprint(f"dest, {dest_operand}, src, {src_register}")

        dest_location = None

        # Check if the destination is a memory location or a register
        if "[" in dest_operand and "]" in dest_operand:
            # Handle memory destination
            memory_location = match.group(2)
            _dprint(f"memory_location: {memory_location}")

            # Extract memory offset, assume the format is [reg + offset] or [reg]
            parts = memory_location.split(" ")
            if len(parts) == 1:
                dest_reg_name = parts[0]
                offset = 0
            elif len(parts) == 3:
                dest_reg_name = parts[0]
                offset = int(parts[2], 16)
            else:
                raise NotImplementedError("movaps_hook: memory_location format not supported")

            # Get memory address
            dest_reg = getattr(state.regs, dest_reg_name)
            dest_location = dest_reg + offset
            _dprint(f"dest_location: {dest_location}")

        elif hasattr(state.regs, dest_operand):
            # Handle register destination
            _dprint(f"dest, {dest_operand}, src, {src_register}")
            dest_location = getattr(state.regs, dest_operand)
        else:
            raise NotImplementedError("movaps_hook: destination operand format not supported")

        # Copy src_register to dest_location
        src_reg = getattr(state.regs, src_register)

        func_name = "Func_movaps"
        args = [dest_location, src_reg]
        call_result = Path.generate_symbolic_func(func_name, args, size=state.arch.bits)
        _dprint(f"movaps_hook, call result:, {call_result}")

        # store to return register
        state.registers.store(state.arch.ret_offset, call_result)

        # store into sypy_path
        if func_name not in state.sypy_path.function_calls:
            state.sypy_path.function_calls[func_name] = {}
        bb_addr = state.addr

        if bb_addr not in state.sypy_path.function_calls[func_name]:
            state.sypy_path.function_calls[func_name][bb_addr] = []
        state.sypy_path.function_calls[func_name][bb_addr].append(args)

    def function_call_hook(state):
        # Return a fake signature using num_of_args to generate prototype
        # Format: "void *x(void *, ...)"
        def generate_fake_signature_str(num_of_args, output_args_index=[]):
            if num_of_args == 0:
                return "void *x()"
            else:
                args_str = ", ".join(["int" if i not in output_args_index else "void *" for i in range(num_of_args)])
                return f"void *x({args_str})"

        i = get_insn_by_state(state)
        _dprint(f"RUNNING call hook, {hex(i.address)}")

        call_target_str = i.op_str
        _dprint(f"call target, {call_target_str}")

        try:
            # get concreate value of call target
            try:
                # Normal C call target: "0x401800"
                if call_target_str.startswith("0x"):
                    function_addr = int(call_target_str, 16)
                # CPP call target: "#0x401800"
                elif call_target_str.startswith("#0x"):
                    function_addr = int(call_target_str[1:], 16)
                # When call target is a hex sting ending with 'h', e.g., 401800h
                elif call_target_str.endswith("h"):
                    function_addr = int(call_target_str[:-1], 16)
                else:
                    raise KeyError("call target is not a concreate value")
            except:
                raise KeyError("call target is not a concreate value")

            # Handling patcherex added functions: remove 'CALLLESS' option
            # If is patcherex added function, do not consider it as a 'real' function call
            if function_addr in state.globals['veribin_func'].patcherex_added_functions:
                state.options['CALLLESS'] = False
                _dprint("Patcherex added function, do not consider it as a 'real' function call")
                return

            if function_addr not in state.sypy_path.function_info:

                func = state.project.kb.functions.get_by_addr(function_addr)

                # If addr already in ['veribin_func'].symbol_table, use the name in symbol table
                if function_addr in state.globals['veribin_func'].symbol_table:
                    func_name = "Func_" + state.globals['veribin_func'].symbol_table[function_addr]
                else:
                    func_name = "Func_" + func.demangled_name
                _dprint(f"func info in kb functions: {func_name, func.prototype}")
                if func.calling_convention is None:
                    func.calling_convention = angr.calling_conventions.DEFAULT_CC[state.project.arch.name] \
                        ['Linux'](state.project.arch)

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
                        _dprint(f"func info method 1 (ida): {func_name}, {func.prototype}")

                # Method 2: Variable Recovery + Calling Convention
                if func.prototype is None:
                    _ = state.project.analyses.VariableRecoveryFast(func)
                    try:
                        cc_analysis = state.project.analyses.CallingConvention(func, analyze_callsites=True)
                        if func.prototype is None:
                            func.prototype = cc_analysis.prototype
                        _dprint(f"func info method 2 (Variable Recovery): {func_name}, {func.prototype},\
                                {cc_analysis.prototype}")
                    except:
                        pass

                # Method 3: (ref: angr tests) DEFAULT_CC + find_declaration
                if func.prototype is None:
                    # func.calling_convention = angr.calling_conventions.DEFAULT_CC[state.project.arch.name]\
                    #     (state.project.arch)
                    func.find_declaration()
                    _dprint(f"func info method 3 (find declaration): {func_name}, {func.prototype}")

                # Method 4: otherwise, the function argument should be empty (create a default prototype with 0 arg)
                if func.prototype is None:
                    # func.arguments should be empty, thus prototype is expected to be () -> char*
                    func.prototype = func.calling_convention.guess_prototype(func.arguments).with_arch(state.arch)
                    _dprint(f"func info method 4 (empty): {func_name}, {func.prototype}")

                if func.prototype is None:
                    assert False and  "Function prototype is None"

                if func.prototype is not None and func.prototype._arch is None:
                    func.prototype = func.prototype.with_arch(state.arch)

                # Store function info into sypy_path
                _dprint(f"func info store into map: {func_name}, {func.prototype}")
                state.sypy_path.function_info[function_addr] = {'func_name': func_name, 'func_obj': func}
            else:
                func_name = state.sypy_path.function_info[function_addr]['func_name']
                func = state.sypy_path.function_info[function_addr]['func_obj']

            # For some variadic function from PHP, parse the spec string to get the number of arguments
            if func_name in SPECIAL_PHP_VARIADIC_FUNCTIONS.keys():
                _dprint(f"Parse spec string for {func_name}")
                # Get the offset of the spec string in the argument list
                spec_str_offset = SPECIAL_PHP_VARIADIC_FUNCTIONS[func_name]
                # Get register name of the 3rd argument from the calling convention
                reg_name = func.calling_convention.ARG_REGS[spec_str_offset]
                reg_content = getattr(state.regs, reg_name)
                # Load the content of the string from binary
                spec_str = load_string_content_from_binary(state.project, reg_content)
                _dprint(f"spec_str: {spec_str}")
                if spec_str is not None:
                    num_of_args, output_args_index = parse_spec_string(spec_str.args[0], initial_argument_number=spec_str_offset+1)
                    # Update num_of_args into function_info_map, which will be used to compare different call objects arguments
                    # TODO: Fix potential bug when the same function is called with different number of arguments
                    state.globals['veribin_func'].function_info_map[func_name]['num_of_args'] = num_of_args

                    # Use special_entry instead of only the func_name, because different spec_str may have different number of arguments
                    special_entry = f"{func_name}_{spec_str.args[0]}"
                    if special_entry not in state.globals['veribin_func'].function_info_map:
                        # Set the number of arguments and output_args_index
                        state.globals['veribin_func'].function_info_map[special_entry] = {"num_of_args": num_of_args,
                                                                                 "output_args_index": output_args_index}

                    _dprint(f"num_of_args: {num_of_args}, output_args_index: {output_args_index}")
                fake_signature = generate_fake_signature_str(num_of_args, output_args_index)
                func.prototype = angr.sim_type.parse_signature(fake_signature).with_arch(state.arch)
                _dprint(f"Parse spec string for {func_name}, {func.prototype}")

            # Handle some avio_xx functions, treat the 1st argument as an output argument
            elif func_name.startswith("Func_avio_"):
                # If 0 not in output_args_index, append it
                try:
                    output_args_index = state.globals['veribin_func'].function_info_map[func_name]["output_args_index"]
                except KeyError:
                    output_args_index = []
                if 0 not in output_args_index:
                    output_args_index = [0] + output_args_index
                    # Update output_args_index into function_info_map
                    state.globals['veribin_func'].function_info_map[func_name]["output_args_index"] = output_args_index

                    # Update function prototype
                    fake_signature = generate_fake_signature_str(len(func.prototype.args), output_args_index)
                    func.prototype = angr.sim_type.parse_signature(fake_signature).with_arch(state.arch)
                    _dprint(f"Update output_args_index for {func_name}, {func.prototype}")

            try:
                func_variables = func.calling_convention.get_args(state, func.prototype)

                # Only for PowerPC:BE:32:MPC8270
                if state.project.arch.name == 'PowerPC:BE:32:MPC8270':
                    # Replace floating point value
                    for i in range(len(func_variables)):
                        old_value = func_variables[i]
                        # if is a oncrete value, range: 0x1000 - 0xf0000000
                        if old_value.concrete and (0x1000 < old_value.args[0] < 0xf0000000):
                            new_value = old_value.raw_to_fp()
                            _dprint(f"replace floating point value, {old_value}, {new_value}")
                            func_variables[i] = new_value
            except:
                func_variables = []

            # Update pointer variable
            func_variables = update_pointer_variable(p, func_variables)

            # Update function arguments (reload memory content if necessary)
            # Fix for case_054
            func_variables_memory_addrs = [None] * len(func_variables)
            # If any of the argument is 'MemoryLoad', try to reload the memory because we may have modified it
            for i, variable in enumerate(func_variables):
                if not state.solver.symbolic(variable):
                    continue
                read_key = state.solver.simplify(variable).cache_key
                variable_memory_addr = None
                print("read_key:", read_key)
                # Check from memory_reads
                if read_key in state.sypy_path.memory_reads:
                    variable_memory_addr = state.solver.simplify(state.sypy_path.memory_reads[read_key])

                # If can be 'MemoryLoad' but not in memory_reads, try to reload with first argument as addr
                elif variable.op == "MemoryLoad":
                    variable_memory_addr = state.solver.simplify(variable.args[0])

                # Cases when variable is uninitialized register
                else:
                    variable_memory_addr = state.solver.simplify(variable)

                _dprint(f"variable:, {variable}")
                _dprint(f"func_variables_memory_addr:, {variable_memory_addr}")

                if variable_memory_addr is not None:
                    # Store into memory addrs
                    func_variables_memory_addrs[i] = variable_memory_addr
                    write_key = (variable_memory_addr.cache_key, variable.size()>>3)
                    # If memory_addr is in output_args_memory_addrs, reload the memory content because we may have modified it
                    if write_key in state.sypy_path.output_args_memory_addrs:
                        # Only continue if content is different
                        if variable.cache_key != state.sypy_path.output_args_memory_addrs[write_key]:
                            print("\nReload memory content from memory_writes", variable_memory_addr)
                            # Reload memory content from memory_writes
                            assert write_key in state.sypy_path.memory_writes
                            func_variables[i] = state.memory.load(variable_memory_addr, variable.size()>>3,
                                                                    endness=state.arch.memory_endness)

            _dprint(f"func_name: {func_name}, prototype: {func.prototype}, variables: {func_variables}")

            # Update output arguments (if any), in "Func_Arg#index" format
            if func_name not in SPECIAL_PHP_VARIADIC_FUNCTIONS and func_name in state.globals['veribin_func'].function_info_map and \
                "output_args_index" in state.globals['veribin_func'].function_info_map[func_name]:
                output_args_index = state.globals['veribin_func'].function_info_map[func_name]["output_args_index"]
                # print("output_args_index:", output_args_index)
            elif func_name in SPECIAL_PHP_VARIADIC_FUNCTIONS:
                spec_str_offset = SPECIAL_PHP_VARIADIC_FUNCTIONS[func_name]
                spec_str_arg = func_variables[spec_str_offset]
                spec_str = spec_str_arg.args[0]
                special_entry = f"{func_name}_{spec_str}"
                assert special_entry in state.globals['veribin_func'].function_info_map
                output_args_index = state.globals['veribin_func'].function_info_map[special_entry]["output_args_index"]
                _dprint(f"Getting output_args_index from spec string: {special_entry} {output_args_index}")
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

            # Handle incorrect locs get from calling_convention
            # (e.g., [<x0>, None, <x1>])
            try:
                if len(output_args_index) > 0:
                    for output_arg_index in output_args_index:
                        # the output arg is a pointer, we need to assign new value to it
                        output_arg = func_variables[output_arg_index]
                        output_arg_memory_addr = func_variables_memory_addrs[output_arg_index]
                        # If memory_addr is None, set addr to be itself
                        if output_arg_memory_addr is None:
                            print("Potential error: output_arg_memory_addr is None")
                            output_arg_memory_addr = output_arg
                        _dprint(f"output_arg_addr:, {output_arg_memory_addr}")
                        # we select content size as default architecure size, e.g., 32-bit or 64-bit
                        new_output_arg_content = state.solver.BVS(f"{func_name}_Arg#{output_arg_index}_{output_arg}",
                        # new_output_arg_content = state.solver.BVS(f"{func_name}_Arg#{output_arg_index}",
                                                        size=state.arch.bits,
                                                        explicit_name=True)
                        _dprint(f"new_output_arg: {new_output_arg_content}")
                        # Assign new_output_arg value to mem[output_arg]


                        state.memory.store(output_arg_memory_addr, new_output_arg_content,
                                        new_output_arg_content.size()>>3,
                                        endness=state.arch.memory_endness)
                        print("After setting arg, get:", state.memory.load(output_arg_memory_addr,
                                                                        new_output_arg_content.size()>>3,
                                                                        endness=state.arch.memory_endness))

                        # Store the output_arg_memory_addr into sypy_path
                        # if output_arg_memory_addr.cache_key not in state.sypy_path.output_args_memory_addrs:
                        #     print("Add output_arg_memory_addr:", output_arg_memory_addr)
                        #     state.sypy_path.output_args_memory_addrs.append(output_arg_memory_addr.cache_key)
                        print("Add output_arg_memory_addr:", output_arg_memory_addr)
                        write_key = (output_arg_memory_addr.cache_key, new_output_arg_content.size()>>3)
                        state.sypy_path.output_args_memory_addrs[write_key] = new_output_arg_content.cache_key

            except Exception as e:
                pass

        except Exception as e:
            print(f"Error! in function {call_target_str}: {e}")
            return
            # raise NotImplementedError("Something wrong in function call handler.")

        # Store into sypy_path
        if func_name not in state.sypy_path.function_calls:
            state.sypy_path.function_calls[func_name] = {}
        bb_addr = list(state.history.bbl_addrs)[-1]
        if bb_addr not in state.sypy_path.function_calls[func_name]:
            state.sypy_path.function_calls[func_name][bb_addr] = []
        state.sypy_path.function_calls[func_name][bb_addr].append(func_variables)

        # Return a Function object
        call_result = Path.generate_symbolic_func(func_name, func_variables, size=state.arch.bits)
        _dprint("function call %s, call result: %s" % (func_name, call_result))

        # store to return register
        # state.registers.store(state.arch.ret_offset, call_result)
        if state.arch.name in DEFAULT_CC:
           cc = DEFAULT_CC[state.arch.name]['Linux']
           ret_reg = cc.RETURN_VAL
           if isinstance(ret_reg, SimRegArg):
               ret_offset = state.arch.registers[ret_reg.reg_name][0]
        else:
           ret_offset = state.arch.ret_offset
        ret_reg_name = state.arch.register_names[ret_offset]
        setattr(state.regs, ret_reg_name, call_result)

    # Get assembly instructions
    try:
        i = get_insn_by_state(state)
    except Exception as e:
        print("Error! in get_insn_by_state:", e)
        return

    print("get_insn_by_state:", i)
    if i.mnemonic.startswith("rep stos"):
        _dprint(f"INSTALLING 'rep stos' hook, {hex(i.address)}, {i.size}")
        p.hook(i.address, rep_stos_hook, length=i.size)
    elif i.mnemonic.startswith("rep movs"):
        _dprint(f"INSTALLING 'rep movs' hook, {hex(i.address)}, {i.size}")
        p.hook(i.address, rep_movs_hook, length=i.size)
    elif i.mnemonic.startswith("movaps"):
        _dprint(f"INSTALLING 'movaps' hook, {hex(i.address)}, {i.size}")
        p.hook(i.address, movaps_hook, length=i.size)
    elif i.mnemonic in ["call", "bl", "e_bl"]:
        _dprint(f"INSTALLING call, {hex(i.address)}, {i.size}")
        call_target_str = i.op_str
        _dprint(f"call target, {call_target_str}")
        # get concreate value of call target
        try:
            # Normal C call target: "0x401800"
            if call_target_str.startswith("0x"):
                function_addr = int(call_target_str, 16)
            # CPP call target: "#0x401800"
            elif call_target_str.startswith("#0x"):
                function_addr = int(call_target_str[1:], 16)
            # When call target is a hex sting ending with 'h', e.g., 401800h
            elif call_target_str.endswith("h"):
                function_addr = int(call_target_str[:-1], 16)
            # Indirect call target: "[rax*8 + 0x97fee0]; rdx"
            else:
                raise ValueError("Indirect call target")
            # Skip if the call is to a function that has been added by patcherex
            # Instead, we let angr to symbolic execute into that function
            if function_addr in patcherex_added_functions:
                return
        except:
            _dprint("skip, call target is not a concreate value")
            return
        p.hook(i.address, function_call_hook, length=i.size)
    elif p.arch.name == "PowerPC:BE:32:e200" and i.mnemonic == "efscfui":
        _dprint(f"INSTALLING efscfui, {hex(i.address)}, {i.size}")
        #import IPython; IPython.embed()
        p.hook(i.address, efscfui_hook, length=i.size)
    elif p.arch.name == "PowerPC:BE:32:e200" and i.mnemonic == "efsdiv":
        _dprint(f"INSTALLING efsdiv, {hex(i.address)}, {i.size}")
        p.hook(i.address, efsdiv_hook, length=i.size)
