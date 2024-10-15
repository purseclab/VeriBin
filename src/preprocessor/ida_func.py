import ida_auto
import idautils
import idc
import ida_xref
import ida_idp
import ida_funcs
import ida_segment
import ida_nalt
import ida_hexrays
import ida_lines
import ida_pro
import os
import sys
LAYERS = 2

def get_calls(func_addr):
    call_addrs = []
    for ea in idautils.FuncItems(func_addr):
        for code_ref_ea in idautils.CodeRefsFrom(ea, True):
            # see if a valid function address
            temp_func = ida_funcs.get_func(code_ref_ea)
            if temp_func is None or temp_func.start_ea != code_ref_ea:
                # print("Not a valid function address, continue")
                continue
            if ida_funcs.get_func(code_ref_ea):
                call_addr = code_ref_ea
                if call_addr not in call_addrs:
                    call_addrs.append(call_addr)
                    # print(hex(call_addr), called_func_name)
                break
    print(f"Get all calls for {hex(func_addr)}")
    print(', '.join([hex(x) for x in call_addrs]))
    return call_addrs

def decompile_callee_funcs_with_layers(func_addr, layer=0):
    """
    Given a target func_addr, recursively:
    - Get all calls, call this function for each call with layer-1
    - Decompile the target function when layer=0
    """
    print(f"\nDecompile callee functions with layers for {hex(func_addr)}")
    # Handle arm address
    # If provided address is an odd number -->thumb
    is_thumb = func_addr % 2 == 1
    if is_thumb:
        func_addr -= 1

    # Collect callee function addrs
    call_addrs = get_calls(func_addr)

    if layer > 0:
        # Recursively decompile the callee functions
        for call_addr in call_addrs:
            decompile_callee_funcs_with_layers(call_addr, layer-1)

    # After decompiling the callee functions, decompile the target function
    # Update function
    ida_funcs.update_func(func_addr)
    ida_hexrays.decompile(func_addr)
    ida_funcs.update_func(func_addr)
    func_name = ida_funcs.get_func_name(func_addr)
    print(f"\tDecompiling {func_name} , {hex(func_addr)}")

    prototype = idc.get_type(func_addr)
    print(f"\t\t{func_name}: {prototype}")

    return None

"""
Get all called functions' information, including prototype
"""
def get_funcs_info(func_addr, decompile_flag=False):
    print(f"\nGet functions' prototypes for {hex(func_addr)}")
    # Handle arm address
    # If provided address is an odd number -->thumb
    is_thumb = func_addr % 2 == 1
    if is_thumb:
        func_addr -= 1

    # decompile function
    if decompile_flag:
        decompile_callee_funcs_with_layers(func_addr, layer=LAYERS)

    # ida_hexrays.decompile(func_addr)
    call_addrs = [func_addr]
    funcs_info = {}
    call_addrs += get_calls(func_addr)

    print("All call addrs" + ', '.join([hex(x) for x in call_addrs]))

    for call_addr in call_addrs:
        # print(ida_lines.tag_remove(ida_hexrays.decompile(call_addr).print_dcl()))
        target_func = ida_funcs.get_func(call_addr)
        if target_func:
            func_size = target_func.size()
            func_name = ida_funcs.get_func_name(call_addr)
            # remove '.' from func_name
            func_name = func_name.replace('.', '')
            # print(hex(call_addr), func_name)
            if func_name not in funcs_info or funcs_info[func_name] is None:
                # prototype
                func_prototype = idc.get_type(call_addr)
                print(f"\t{func_name}: {func_prototype}")

                return_value_used = None
                if func_prototype:
                    ret_type = func_prototype[0:func_prototype.find('(')]
                    return_value_used = not ('void' in ret_type and '*' not in ret_type)
                # If thumb, update call_addr
                if is_thumb:
                    call_addr += 1
                funcs_info[func_name] = {"prototype": func_prototype, "return_value_used": return_value_used,
                                        "addr": call_addr, "size": func_size}
    # print(funcs_info)
    return funcs_info

"""
For the given target function, get the decompiled code of the caller functions
Then, check if the return value is used
Return: True if the return value is used, False otherwise
"""
def check_is_ret_value_used(func_addr, target_func_name, f):

    f.write(f"\nCheck if return value is used for {hex(func_addr)}\n")
    is_return_value_used = None
    psudeocode_codes_for_func = []

    if target_func_name is None:
        return None, []

    # Handle arm address
    # If provided address is an odd number -->thumb
    is_thumb = func_addr % 2 == 1
    if is_thumb:
        func_addr -= 1

    # Get all callers
    callers = list(idautils.CodeRefsTo(func_addr, flow=True))

    f.write(f"Get all callers for {hex(func_addr)}\n")
    f.write(', '.join([hex(x) for x in callers]))
    f.write("\n")

    # Only analyze the first 3 callers
    if len(callers) > 3:
        callers = callers[:3]

    # Decompile the caller functions
    for caller in callers:
        # Update function
        ida_funcs.update_func(caller)
        caller_name = ida_funcs.get_func_name(caller)
        f.write(f"\tDecompiling {caller_name} , {hex(caller)}\n")

        # Get the decompiled code
        cfunc = ida_hexrays.decompile(caller)

        # Get lines of
        if cfunc:
            psudeocode = cfunc.__str__().split('\n')
            for line in psudeocode:
                if target_func_name in line:
                    psudeocode_codes_for_func.append(line)
                    f.write(f"\t\t{line}\n")

    # Check if the return value is used
    if len(psudeocode_codes_for_func) > 0:
        import re
        re_pattern = re.compile(rf'^\s*{re.escape(target_func_name)}\s*\(.*?\)\s*;?\s*$')
        for line in psudeocode_codes_for_func:
            if target_func_name in line:
                temp_is_used = not(bool(re_pattern.match(line)))
                f.write(f"\t\t{line}, {temp_is_used}\n")
                if temp_is_used is True:
                    is_return_value_used = True
                    break

        is_return_value_used = False if is_return_value_used is None else is_return_value_used


    return is_return_value_used, psudeocode_codes_for_func


if __name__ == "__main__":
    ida_auto.auto_wait()

    if len(idc.ARGV) > 3:
        func_addr = int(idc.ARGV[1], 16)
        output_file_path = str(idc.ARGV[2])
        decompile_flag = str(idc.ARGV[3]) == 'True'
    else:
        sys.stdout("ARGV[0]: path to script\nARGV[1]: func_addr\nARGV[2]: output_file_name\nARGV[3]: decompile_flag\n")
        ida_pro.qexit(0)

    # create output file
    f = open(output_file_path, "w+")
    f.write("decompile_flag: %s\n" % decompile_flag)

    try:
        # There are 3 possible base addresses: 0x0, 0x400000, 0x8000000
        if func_addr < 0x400000:
            base_addr = 0x0
        elif func_addr < 0x8000000:
            base_addr = 0x400000
        else:
            base_addr = 0x8000000
        ida_segment.rebase_program(base_addr - ida_nalt.get_imagebase(), base_addr)
        func_info = get_funcs_info(func_addr, decompile_flag=decompile_flag)

        # Update func prototype for target function, regarding the return value

        target_func_name = ida_funcs.get_func_name(func_addr)

        if target_func_name:
            target_func_name = target_func_name.replace('.', '')
            # If the target name is knwon, skip because we assume the prototype is accurate with symbol (by flirt)
            if target_func_name in func_info and target_func_name.startswith('sub_'):
                old_value = func_info[target_func_name]['return_value_used']
                f.write(f"\tOld return_value_used for {target_func_name} is {old_value}\n")
                if old_value is not False:
                    is_ret_value_used, psudeocode_codes_for_func = check_is_ret_value_used(func_addr, target_func_name=target_func_name, f=f)
                    for line in psudeocode_codes_for_func:
                        f.write(line + '\n')
                if old_value is not False and is_ret_value_used is False:
                    func_info[target_func_name]['return_value_used'] = is_ret_value_used
                    f.write(f"\tUpdate return_value_used for {target_func_name} to {is_ret_value_used}\n")
                    # Update prototype
                    old_prototype = func_info[target_func_name]['prototype']
                    if old_prototype is not None:
                        ret_type = old_prototype[0:old_prototype.find('(')]
                        # replace
                        new_prototype = old_prototype.replace(ret_type, 'void ')
                        func_info[target_func_name]['prototype'] = new_prototype
                        f.write(f"\tUpdate prototype for {target_func_name} to {new_prototype}\n")

        # func prototype
        # f.write("###Start of function prototypes###\n")
        # for func_name, info in func_info.items():
        #     str = "\t%s;;%s;;%s\n" % (hex(info['addr']),func_name, info['prototype'])
        #     f.write(str)
        # f.write("###End of function prototypes###\n")

        # Write function info
        f.write("###Start of function info###\n")
        f.write("\tAddress;;Function Name;;Prototype;;Return_value_used;;Size\n")
        for func_name, info in func_info.items():
            str = "\t%s;;%s;;%s;;%s;;%s\n" % (hex(info['addr']),func_name, info['prototype'], info['return_value_used'], info['size'])
            f.write(str)
        f.write("###End of function info###\n")

    except Exception as e:
        import traceback
        f.write(traceback.format_exc())

    f.close()
    ida_pro.qexit(0)