"""
Z3 based symbolic compiler.
"""

import z3
import logging
import claripy
import re
from difflib import ndiff
from colorama import Fore, Style
from typing import Any, Optional

# Custom modules
from utils import COLOR, print, similar

def get_bool(ob: object) -> object:
    if not isinstance(ob, claripy.ast.bool.Bool):
        return ob != 0
    return ob


def adjust_ops(op1: object, op2: object) -> object:
    """
    Adjust and return op1 corresponding to op2.
    :param op1: Operand 1
    :param op2: Operand 2
    :return: Bit size adjusted operand 1
    """
    if isinstance(op1, claripy.ast.bv.BV) and isinstance(op2, claripy.ast.bv.BV):
        # print("adjust_ops, before, size of op1: ", op1.size(), " size of op2: ", op2.size())
        sz1 = op1.size()
        sz2 = op2.size()
        if sz1 < sz2:
            op1 = claripy.ZeroExt(sz2 - sz1, op1)
        elif sz1 > sz2:
            op2 = claripy.ZeroExt(sz1 - sz2, op2)
        # print("adjust_ops, after, size of op1: ", op1.size(), " size of op2: ", op2.size())
    return op1, op2


def adjust_ops_signed(op1: object, op2: object) -> object:
    """
    Adjust and return op1 corresponding to op2.
    :param op1: Operand 1
    :param op2: Operand 2
    :return: Bit size adjusted operand 1
    """
    if isinstance(op1, claripy.ast.bv.BV) and isinstance(op2, claripy.ast.bv.BV):
        # print("adjust_ops_signed, before, size of op1: ", op1.size(), " size of op2: ", op2.size())
        sz1 = op1.size()
        sz2 = op2.size()
        if sz1 < sz2:
            op1 = claripy.SignExt(sz2 - sz1, op1)
        elif sz1 > sz2:
            op2 = claripy.SignExt(sz1 - sz2, op2)
        # print("adjust_ops_signed, after, size of op1: ", op1.size(), " size of op2: ", op2.size())
    return op1, op2


def handle_eq(op1: object, op2: object) -> object:
    op1, op2 = adjust_ops(op1, op2)
    return op1 == op2


def handle_neq(op1: object, op2: object) -> object:
    op1, op2 = adjust_ops(op1, op2)
    return op1 != op2


# unary op handlers
def handle_unary_not(op: object) -> object:
    return claripy.Not(get_bool(op))


def is_builtin_class_instance(obj):
    return obj.__class__.__module__ == 'builtins'


class Z3ConstraintGenerator(object):
    """
        Z3 based backend.
    """
    def __init__(self, project):
        self.project = project
        self.DEFAULT_SIZE = project.arch.bits
        self.generated_new_symbol_store = {}
        self.common_symbolic_memory = {}
        self.comparison_map = {}
        self.assumption_map = {}
        self.constant_map = {}
        self.true_val = None

    def get_constant(self, val: int, size=None):
        if size is None:
            size = self.DEFAULT_SIZE
        return claripy.BVV(val, size)


    def handle_call(self, func_name: str, args: Optional[Any] = None) -> Any:
        # Convert args into z3 BV
        args_z3 = claripy._backend_z3.convert_list(args)

        if not self.z3_func_handler.has_function(func_name):
            # We are seeing this function for the first time.
            # setup the function.
            # Get argument sort.
            args_sort = []

            if len(args_z3) > 0:
                args_sort = list(map(lambda x: x.sort(), args_z3))

            # Add the function.
            self.z3_func_handler.add_function(func_name, args_sort, self.z3_func_handler.default_ret_sort)
        return self.z3_func_handler.handle_call(func_name, args_z3)

    def combine_vals(self, old_val: Any, cond: Any, new_val: Any, is_signed: Any = None) -> Any:
        if is_signed:
            old_val, new_val = adjust_ops_signed(old_val, new_val)
        else:
            old_val, new_val = adjust_ops(old_val, new_val)
        assert(old_val.size() == new_val.size())
        ret = claripy.If(cond, new_val, old_val)
        assert(ret.size() == old_val.size())
        return claripy.simplify(ret)

    def pretty_print_symbolic_value(self, sym):
        sym_str = str(sym).replace("<", "").replace(">", "")
        bv_pattern = r"BV\d+ "
        sym_str = re.sub(bv_pattern, "", sym_str)
        return sym_str


    def negate_cond(self, val: Any) -> Any:
        return handle_unary_not(get_bool(val))

    def ask_user_about_function(self, original_func_name, patched_func_name, original_func_args_count,
                                patched_func_args_count, original_out_args, patched_out_args):
        answer = None
        count = None
        while True:
            answer = input(f"{COLOR['red']}\n[StA_matching_func] Do you consider the Function \n\t{original_func_name} \nequivalent to Function\n\t{patched_func_name}\n? (Y/N){COLOR['reset']}").lower()
            if answer == 'y':
                print(f"{COLOR['red']}You confirmed that {original_func_name} and {patched_func_name} are equivalent{COLOR['reset']}")
                break
            elif answer == 'n':
                print(f"{COLOR['red']}You confirmed that {original_func_name} and {patched_func_name} are not equivalent{COLOR['reset']}")
                break
            else:
                print(f"{COLOR['red']}You have to answer Y or N{COLOR['reset']}")

        if answer == 'y':

            if original_func_args_count != patched_func_args_count:
                min_count = min(original_func_args_count, patched_func_args_count)

                non_output_args_list_old = []
                for i in range(original_func_args_count):
                    if i not in original_out_args:
                        non_output_args_list_old.append(i)
                non_output_args_list_new = []
                for i in range(original_func_args_count):
                    if i not in patched_out_args:
                        non_output_args_list_new.append(i)
                for c, (o, n) in enumerate(zip(non_output_args_list_old, non_output_args_list_new)):
                    if o != c or n != c:
                        break
                min_count_non_output = c + 1

                print(f"{COLOR['red']}[StA_matching_func_num_of_args] The two matching functions have different arguments length{COLOR['reset']}")
                print(f"{original_func_name} has {original_func_args_count} arguments (arguments {str([i + 1 for i in non_output_args_list_old])} are non-output arguments)")
                print(f"{patched_func_name} has {patched_func_args_count} arguments (arguments {str([i + 1 for i in non_output_args_list_new])} are non-output arguments)")

                while True:
                    answer2 = input(f"{COLOR['red']}\nDo you want to only compare the common non-output arguments (the first {min_count_non_output} arguments)? (Y/N){COLOR['reset']}" ).lower()
                    if answer2 == 'y':
                        print(f"{COLOR['red']}I will only compare the first {min_count_non_output} arguments{COLOR['reset']}")
                        break
                    elif answer2 == 'n':
                        break
                    else:
                        print(f"{COLOR['red']}You have to answer Y or N{COLOR['reset']}")

                if answer2 == 'n':
                    while True:
                        user_input = input(f"{COLOR['red']}Please input the number of arguments you want to compare (0 ~ {min_count}):{COLOR['reset']}")
                        try:
                            count = int(user_input)
                        except ValueError:
                            print(f"{COLOR['red']}Please input a valid integer from 0 ~ {min_count}{COLOR['reset']}")
                            continue

                        if 0 <= count <= min_count:
                            print(f"{COLOR['red']}You entered {count}{COLOR['reset']}")
                            break
                        else:
                            print(f"{COLOR['red']}Please input a valid integer from 0 ~ {min_count}{COLOR['reset']}")
                elif answer2 == 'y':
                    count = min_count_non_output

            else:
                count = original_func_args_count
        return answer, count

    def create_function_with_new_name(self, new_func_name, old_func):
        new_func_args = [new_func_name]
        # Get all the rest from the p_func
        new_func_args.extend(old_func.args)
        new_func = claripy.ast.func.Func(op=new_func_name, args=new_func_args, _ret_size=old_func.size())
        new_func_result = new_func.func_op(*new_func_args)

        # Remove dummy argument
        if len(new_func_result.args) > 0 and new_func_name in str(new_func_result.args[0]):
            new_func_result.args = new_func_result.args[1:]
        return new_func_result

    def create_replacement_func(self, o_func, p_func, count):
        # If the two functions already share the same name, no need to replace
        if o_func.op == p_func.op:
            if len(o_func.args) == len(p_func.args) == count:
                return o_func, p_func
            else:
                o_func.args = o_func.args[:count]
                p_func.args = p_func.args[:count]
                return o_func, p_func

        new_func_name = o_func.op
        new_func_result = self.create_function_with_new_name(new_func_name, p_func)

        # Deal with args count
        if len(o_func.args) > count:
            o_func.args = o_func.args[:count]
        if len(new_func_result.args) > count:
            new_func_result.args = new_func_result.args[:count]
        return o_func, new_func_result

    def update_matching_funcs(self, o_funcs_args_map, p_funcs_args_map, matching_funcs, function_info_old,
                              function_info_new, interactive=False):
        # Maintain a list of original function names that cannot find args_count
        # Delete from the matching funcs after the iteration
        deleted_matching_funcs_names_o = []

        # For functions already in matching_funcs, if the args_count is not set, set it as min(o_count, p_count)
        for o_func_name, matching_info in matching_funcs.items():
            p_func_name = matching_info['func_name_patched']
            if 'args_count' not in matching_info:
                if o_func_name in function_info_old and p_func_name in function_info_new:
                    o_func_args_count = function_info_old[o_func_name]['num_of_args']
                    p_func_args_count = function_info_new[p_func_name]['num_of_args']
                else:
                    try:
                        # If the function is not in the function_info_old, use the number of arguments in the function args map
                        o_func_args_count = len(list(o_funcs_args_map[o_func_name].values())[0][0].ast.args)
                        p_func_args_count = len(list(p_funcs_args_map[p_func_name].values())[0][0].ast.args)
                        print("update_matching_funcs, func_name, %s, %s, args_count %d,  %d" %
                              (o_func_name, p_func_name, o_func_args_count, p_func_args_count))
                    except KeyError:
                        # Remove the function from matching_funcs if it is not in the function args map
                        deleted_matching_funcs_names_o.append(o_func_name)
                        print("update_matching_funcs,func_name, %s, %s KeyError" % (o_func_name, p_func_name))
                        continue

                matching_funcs[o_func_name]['args_count'] = min(o_func_args_count, p_func_args_count)

        # Delete functions from matching_funcs with deleted_matching_funcs_names_o
        for func_name in deleted_matching_funcs_names_o:
            matching_funcs.pop(func_name)

        # Deal with functions not in matching function list: Match two functions with the same function address
        o_unmatched_functions = list(
            func_name for func_name in o_funcs_args_map.keys() if func_name not in matching_funcs.keys())
        p_matching_funcs_names = list(v['func_name_patched'] for v in matching_funcs.values())
        p_unmatched_functions = list(func_name for func_name in p_funcs_args_map.keys()
                                     if func_name not in p_matching_funcs_names)
        for o_func_name in o_unmatched_functions.copy():
            # Set o_func_args_count as the number of arguments for the first function call
            o_func_args_count = len(list(o_funcs_args_map[o_func_name].values())[0][0].ast.args)

            for p_func_name in p_unmatched_functions.copy():
                # Set p_func_args_count as the number of arguments for the first function call
                p_func_args_count = len(list(p_funcs_args_map[p_func_name].values())[0][0].ast.args)
                # Match two functions with the same function address/ name
                if o_func_name == p_func_name and o_func_args_count == p_func_args_count:
                    print("Adding matching information: Function <%s> in the original binary matches with Function \
                          <%s> in the patched binary." % (o_func_name, p_func_name))
                    matching_funcs[o_func_name] = {'func_name_patched': p_func_name, 'args_count': o_func_args_count}
                    # Remove the two func objs from the unmatched list
                    o_unmatched_functions.remove(o_func_name)
                    p_unmatched_functions.remove(p_func_name)
                    break

        # Deal with functions not in matching function list: Ask the user
        o_unmatched_functions = list(
            func_name for func_name in o_funcs_args_map.keys() if func_name not in matching_funcs.keys())
        p_unmatched_functions = list(
            func_name for func_name in p_funcs_args_map.keys() if
            func_name not in list(v['func_name_patched'] for v in matching_funcs.values()))

        for o_func_name in o_unmatched_functions.copy():
            # Set o_func_args_count as the number of arguments for the first function call
            o_func_args_count = len(list(o_funcs_args_map[o_func_name].values())[0][0].ast.args)
            o_out_args_index = []
            if o_func_name in function_info_old:
                o_func_info = function_info_old[o_func_name]
                if 'output_args_index' in o_func_info:
                    o_out_args_index = o_func_info['output_args_index']

            # When UI mode is enabled
            if interactive:
                for p_func_name in p_unmatched_functions.copy():
                    # Set p_func_args_count as the number of arguments for the first function call
                    p_func_args_count = len(list(p_funcs_args_map[p_func_name].values())[0][0].ast.args)

                    p_out_args_index = []
                    if p_func_name in function_info_new:
                        p_func_info = function_info_new[p_func_name]
                        if 'output_args_index' in p_func_info:
                            p_out_args_index = p_func_info['output_args_index']

                    # We don't have this function in the dict, ask the user
                    answer, args_count = self.ask_user_about_function(o_func_name, p_func_name, o_func_args_count,
                                                                      p_func_args_count, o_out_args_index,
                                                                      p_out_args_index)

                    if answer == 'n':
                        logging.debug(
                            "The two functions do not match, do nothing. Continue querying other possible functions.")
                    else:
                        print("Adding matching information: Function <%s> in the original binary matches with Function \
                              <%s> in the patched binary." % (o_func_name, p_func_name))
                        matching_funcs[o_func_name] = {'func_name_patched': p_func_name, 'args_count': args_count}
                        # Remove the two func objs from the unmatched list
                        o_unmatched_functions.remove(o_func_name)
                        p_unmatched_functions.remove(p_func_name)
                        break
        return

    def replace_matching_funcs(self, patched_constraint, original_constraint, matching_funcs):
        def replace_and_update_function_map(result, func, new_func, funcs_maps):
            result = result.replace(old=func, new=new_func)
            # Update the dictionary
            for func_addr in funcs_maps.keys():
                for i in range(len(funcs_maps[func_addr])):
                    func_temp = funcs_maps[func_addr][i]
                    funcs_maps[func_addr][i] = func_temp.replace(old=func, new=new_func)
            return result

        # If there is no matching function, return the original constraint
        if len(matching_funcs) == 0:
            return original_constraint, patched_constraint

        result_o = original_constraint
        result_p = patched_constraint
        # Check the ast's children asts
        p_funcs = list(set(i for i in list(patched_constraint.recursive_children_asts) if i.op.startswith('Func_')))
        o_funcs = list(set(i for i in list(original_constraint.recursive_children_asts) if i.op.startswith('Func_')))

        # Check the ast itself
        if patched_constraint.op.startswith('Func_'):
            p_funcs.append(patched_constraint)
        if original_constraint.op.startswith('Func_'):
            o_funcs.append(original_constraint)
        # if len(p_funcs) > 0: print("\nPatched functions: %s" % ', '.join(map(str, p_funcs)))
        # if len(o_funcs) > 0: print("\nOriginal functions: %s" % ', '.join(map(str, o_funcs)))

        # Generate funcs maps
        p_funcs_maps = dict()
        o_funcs_maps = dict()
        for func in p_funcs:
            # func_addr = func.op.replace('Func_', '')
            func_addr = func.op
            if func_addr not in p_funcs_maps.keys():
                p_funcs_maps[func_addr] = list()
            p_funcs_maps[func_addr].append(func)

        for func in o_funcs:
            # func_addr = func.op.replace('Func_', '')
            func_addr = func.op
            if func_addr not in o_funcs_maps.keys():
                o_funcs_maps[func_addr] = list()
            o_funcs_maps[func_addr].append(func)

        # Compare matching functions
        for (o_func_addr, o_func_list) in o_funcs_maps.items():
            # Init matching_func_addr
            matching_func_addr = None
            # Set o_func to be the first function object
            o_func = o_func_list[0]

            # 1. Get matching_func_name/addr
            # Check if it has a marked matching function
            if o_func_addr in matching_funcs:
                matching_func_addr = matching_funcs[o_func_addr]['func_name_patched']
                matching_func_count = matching_funcs[o_func_addr]['args_count']
            # Function name with argument index
            elif o_func_addr.split('_')[-1].startswith('Arg#'):
                # Remove the index str
                o_func_name = '_'.join(o_func_addr.split('_')[:-1])

                # Get the index str
                arg_index_str = o_func_addr.replace(o_func_name, '')

                # Check if it has a marked matching function
                if o_func_name in matching_funcs:
                    matching_func_addr = matching_funcs[o_func_name]['func_name_patched']
                    matching_func_count = matching_funcs[o_func_name]['args_count']
                    matching_func_addr = matching_func_addr + arg_index_str
            else:
                logging.debug("o_func_addr %s not in matching_funcs\n" % o_func_addr)
                continue

            # 2. Replace each matching function name
            if matching_func_addr in p_funcs_maps:
                # Replace only if: (1) function names are different; (2) function args length are different
                for p_func in p_funcs_maps[matching_func_addr]:
                    new_o_func, new_p_func = self.create_replacement_func(o_func, p_func, count=matching_func_count)

                    # If the o_func gets updated, also update the related information
                    if not (hash(o_func) == hash(new_o_func)):
                        result_o = replace_and_update_function_map(result_o, o_func, new_o_func, o_funcs_maps)

                    if not (hash(p_func) == hash(new_p_func)):
                        result_p = replace_and_update_function_map(result_p, p_func, new_p_func, p_funcs_maps)
                    logging.debug(
                        "Replacing %s with %s in the patched constraint" % (matching_func_addr, o_func_addr))
                    logging.debug("Result(original): " + str(result_o) + "\n")
                    logging.debug("Result(patched): " + str(result_p) + "\n")
            else:
                logging.debug("Matching_func_addr %s not in p_funcs_maps\n" % matching_func_addr)

        # Update func output args
        result_o, result_p = self.replace_func_output_args(patched_constraint=result_p, original_constraint=result_o,
                                                           matching_funcs=matching_funcs)
        return result_o, result_p

    def replace_func_output_args(self, patched_constraint, original_constraint, matching_funcs):
        """
        Iterate through each function names in the BVS, and replace the patched func names with the corresponding original func name
        (only in the patched_constraint)
        - Added replacement: should also replace strings in the assumption map (if found in the leaf_asts)
        Example input 1: <BV64 Func_sub_4ECA20_Arg#0_<BV64 MemoryLoad(0x28 + Func_zend_object_store_get_object(Func_zend_parse_method_parameters_Arg#3_<BV64 0x7fffffffffeffb0>[31:0]))>>
        Example input 2: <BV64 Func_memset_Arg#0_<BV64 Func_sub_49C2D0(reg_rcx_64{UNINITIALIZED}[31:0] * reg_rdx_64{UNINITIALIZED}[31:0])>>
        """

        # If there is no matching function, return the original constraint
        if len(matching_funcs) == 0:
            return original_constraint, patched_constraint

        result_p = patched_constraint
        # Check the ast's children asts
        p_output_args = list(set(i for i in list(patched_constraint.recursive_children_asts) if i.op == 'BVS' and i.args[0].startswith('Func_')))

        # Check the ast itself
        if patched_constraint.op == 'BVS' and patched_constraint.args[0].startswith('Func_'):
            p_output_args.append(patched_constraint)

        # if len(p_output_args) > 0: print("\nPatched functions: %s" % ', '.join(map(str, p_output_args)))

        # Prepare a list of matching function names
        # Key, value: patched_func_name, original_func_name
        replacement_func_names = {matching_info['func_name_patched']: original_func_name \
                                  for original_func_name, matching_info in matching_funcs.items()}

        # Use regex pattern to extract the function name
        # pattern = r'(Func_[a-zA-Z_][a-zA-Z0-9_]*)_Arg#\d+'
        pattern = r'Func_[a-zA-Z0-9_]+(?=(?:_Arg#|[(]))'

        for expression in p_output_args:
            replacement_str = {}

            expression_str = expression.args[0]
            matches = re.findall(pattern, expression_str)
            for patched_func_name in matches:
                # Get the original function name
                original_func_name = replacement_func_names.get(patched_func_name, None)
                if original_func_name is None:
                    # Not a matching function,
                    print("Function %s not in replacement_func_names\n" % patched_func_name)
                    continue

                # Replace if original_func_name is different from patched_func_name
                # Replace the patched_func_name with the original_func_name
                if original_func_name != patched_func_name:
                    replacement_str[patched_func_name] = original_func_name

            for o_value, p_value in self.assumption_map.values():
                # check if str(p_value) is in the expression_str
                if expression_str.find(str(p_value)) != -1:
                    print("Found %s in the patched constraint" % str(p_value))
                    # add to replacement_str
                    replacement_str[str(p_value)] = str(o_value)

            # Generate a new BVS with the replaced function names
            new_expression_str = expression_str
            for old_str, new_str in replacement_str.items():
                new_expression_str = new_expression_str.replace(old_str, new_str)
                print("Replacing %s with %s in the patched constraint" % (old_str, new_str))

            new_expression = claripy.BVS(new_expression_str, expression.size(), explicit_name=True)

            result_p = result_p.replace(old=expression, new=new_expression)
            # print("Result(patched): " + str(result_p) + "\n")

        return original_constraint, result_p

    def check_implies(self, patched_constraint, original_constraint, output=False, update_assumption_map=False) -> bool:
        patched_constraint_copy = patched_constraint
        ret_val = None

        for o_value, p_value in self.assumption_map.values():
            if hash(p_value) in [hash(v) for v in list(patched_constraint_copy.leaf_asts())]:
                patched_constraint = patched_constraint.replace(p_value, o_value)

        # Check implication without updating assumptions
        check_cond = self.negate_cond(claripy.Or(self.negate_cond(patched_constraint), original_constraint))
        check_cond_z3 = self._convert_claripy_to_z3(check_cond)
        s = z3.Solver()
        s.add(check_cond_z3)
        pure_ret_val = s.check() == z3.unsat
        logging.debug("Result: \n (%s \n implies \n %s) == %s", str(patched_constraint), str(original_constraint), str(ret_val))

        # Only update the assumption map if pure result is False
        if pure_ret_val is False and update_assumption_map:
            new_assumption_map = self.get_assumption_map(original_constraint, patched_constraint)
            for o_value, p_value in new_assumption_map.values():
                if hash(p_value) in [hash(v) for v in list(patched_constraint_copy.leaf_asts())]:
                    patched_constraint = patched_constraint.replace(p_value, o_value)

            if len(new_assumption_map) > 0:
                # Check implication with assumptions
                check_cond = self.negate_cond(claripy.Or(self.negate_cond(patched_constraint), original_constraint))
                check_cond_z3 = self._convert_claripy_to_z3(check_cond)
                s = z3.Solver()
                s.add(check_cond_z3)
                ret_val = s.check() == z3.unsat
                logging.debug("Result: \n (%s \n implies \n %s) == %s", str(patched_constraint),
                              str(original_constraint), str(ret_val))

            # If pure_ret_val is False, ret_val is True, add assumption map into self.assumption_map
            if update_assumption_map and not pure_ret_val and ret_val and len(new_assumption_map) > 0:
                print("Add to assumption_map:", new_assumption_map)
                for _hash, value in new_assumption_map.items():
                    if _hash not in self.assumption_map:
                        self.assumption_map[_hash] = value

        final_ret_val = ret_val if ret_val is not None else pure_ret_val
        if output:
            self.output_with_assumptions(original_constraint, patched_constraint_copy)
            print("\nResult for check_implies: %s\n" % (str(final_ret_val)))
        return final_ret_val

    def check_equals_only(self, original_value, patched_value, original_valid_pc, patched_valid_pc,
                          output=False, update_assumption_map=False):
        if is_builtin_class_instance(original_value) and is_builtin_class_instance(patched_value):
            # print("ERROR: builtin class", original_value, patched_value)
            return original_value == patched_value
        original_value = claripy.simplify(original_value)
        patched_value = claripy.simplify(patched_value)

        patched_value_copy = patched_value
        patched_valid_pc_copy = patched_valid_pc
        if update_assumption_map:
            assumption_map = {**self.get_assumption_map(original_value, patched_value), **self.assumption_map}
        else:
            assumption_map = {**self.assumption_map}
        for o_value, p_value in assumption_map.values():
            if hash(p_value) in [hash(v) for v in list(patched_value_copy.leaf_asts())]:
                patched_value = patched_value.replace(p_value, o_value)
            if hash(p_value) in [hash(v) for v in list(patched_valid_pc_copy.leaf_asts())]:
                patched_valid_pc = patched_valid_pc.replace(p_value, o_value)

        # Check if the value is in the comparison map (compared before)
        key = (hash(original_value), hash(patched_value))
        if key in self.comparison_map.keys():
            if output:
                self.output_with_assumptions(original_value, patched_value_copy)
                print("\nResult for check_equals_only: %s\n" % (str(self.comparison_map[key])))
            return self.comparison_map[key]

        logging.debug("Original value:\n %s\n", original_value)
        logging.debug("Patched value:\n %s\n", patched_value)
        logging.debug("Checking \n %s \n equals to \n %s" % (str(original_value), str(patched_value)))

        # ret_val = False
        ret_val = str(original_value) == str(patched_value)
        '''
        # For ITE expression, check the true_value and false_value, and whether the constraint implies?
        if original_value.op == 'If' and patched_value.op == 'If':
            o_cons, o_T_value, o_F_value = original_value.args
            p_cons, p_T_value, p_F_value = patched_value.args
            if self.check_equals_only(o_T_value, p_T_value) and self.check_equals_only(o_F_value, p_F_value):
                ret_val = self.check_implies(p_cons, o_cons)

        # original: ITE, patched: BVV (remove extra condition in the patched value, enlarging scope)
        elif original_value.op == 'If':
            ret_val = False

        # original: BVV, patched: ITE (add extra condition in the patched value, restricting)
        elif patched_value.op == 'If':
            p_cons, p_T_value, p_F_value = patched_value.args
            ret_val = self.check_equals_only(original_value, p_T_value)
        else:
            ret_val = str(original_value) == str(patched_value)
        '''

        # If strcmp not equal, use canonicalize
        if ret_val is False:
            original_value_temp = original_value.canonicalize(rename=False)
            patched_value_temp = patched_value.canonicalize(rename=False)
            ret_val = str(original_value_temp) == str(patched_value_temp)

        # If still false, use z3 solver
        if ret_val is False:
            original_value_z3 = self._convert_claripy_to_z3(original_value)
            patched_value_z3 = self._convert_claripy_to_z3(patched_value)
            original_valid_pc_true_z3 = self._convert_claripy_to_z3(handle_eq(original_valid_pc, claripy.true))
            patched_valid_pc_true_z3 = self._convert_claripy_to_z3(handle_eq(patched_valid_pc, claripy.true))
            check_cond = self.negate_cond(handle_eq(original_value, patched_value))
            check_cond_z3 = self._convert_claripy_to_z3(check_cond)
            s = z3.Solver()
            s.add(check_cond_z3)
            # set valid path constraints to be true
            s.add(original_valid_pc_true_z3)
            s.add(patched_valid_pc_true_z3)
            check_result = s.check()

            ret_val = check_result == z3.unsat
            # Counter Example
            if output and ret_val is False:
                if check_result == z3.sat:
                    model = s.model()
                    print("\t counter example model:", model)
                    original_value_evaluate = model.evaluate(original_value_z3)
                    patched_value_evaluate = model.evaluate(patched_value_z3)
                    print("\toriginal value evaluate:", original_value_evaluate)
                    print("\tpatched value evaluate:", patched_value_evaluate)
                elif check_result == z3.unknown:
                    print("Check result: unknown")

        self.comparison_map[key] = ret_val
        # If ret_val is True, add assumption map into self.assumption_map
        if update_assumption_map and ret_val:
            for _hash, value in assumption_map.items():
                if _hash not in self.assumption_map:
                    self.assumption_map[_hash] = value
        if output:
            self.output_with_assumptions(original_value, patched_value_copy)
            print("\nResult for check_equals_only: %s\n" % (str(ret_val)))
        return ret_val

    def check_equals_without_constraint(self, original_value, patched_value, output=False, update_assumption_map=False):
        def compare_two_value(original_arg, patched_arg):
            # Both are builtin class, directly compare
            if is_builtin_class_instance(original_arg) and is_builtin_class_instance(patched_arg):
                return str(original_arg) == str(patched_arg)
            # Only one is builtin class, won't be the same, return False
            elif is_builtin_class_instance(original_arg) or is_builtin_class_instance(patched_arg):
                return False
            # For ITE expression, check the true_value and false_value, and whether the constraint implies?
            if original_arg.op == 'If' and patched_arg.op == 'If':
                o_cons, o_T_value, o_F_value = original_arg.args
                p_cons, p_T_value, p_F_value = patched_arg.args
                if self.check_equals_without_constraint(o_T_value, p_T_value) and \
                        self.check_equals_without_constraint(o_F_value, p_F_value):
                    return True

            # original: ITE, patched: BVV (remove extra condition in the patched value, enlarging scope)
            elif original_arg.op == 'If':
                return False

            # original: BVV, patched: ITE (add extra condition in the patched value, restricting)
            elif patched_arg.op == 'If':
                p_cons, p_T_value, p_F_value = patched_arg.args
                return self.check_equals_without_constraint(original_arg, p_T_value)
            else:
                return self.check_equals_without_constraint(original_arg, patched_arg)

            return False

        patched_value_copy = patched_value
        if update_assumption_map:
            assumption_map = {**self.get_assumption_map(original_value, patched_value), **self.assumption_map}
        else:
            assumption_map = self.assumption_map
        # Update the patched value with assumption map
        for o_value, p_value in assumption_map.values():
            if hash(p_value) in [hash(v) for v in list(patched_value_copy.leaf_asts())]:
                patched_value = patched_value.replace(p_value, o_value)

        # If the values are compared before, return the result
        key = (hash(original_value), hash(patched_value))
        if key in self.comparison_map.keys():
            if output:
                self.output_with_assumptions(original_value, patched_value_copy)
                print("\nResult for check_equals_without_constraint: %s\n" % (str(self.comparison_map[key])))
            return self.comparison_map[key]

        logging.debug("Original value:\n %s\n", original_value)
        logging.debug("Patched value:\n %s\n", patched_value)
        logging.debug("Checking \n %s \n equals to \n %s" % (str(original_value), str(patched_value)))

        # string compare
        ret_val = str(original_value) == str(patched_value)

        # If false, compare in details (child arg)
        if ret_val is False:
            if hasattr(original_value, 'op') and hasattr(patched_value, 'op'):
                if original_value.op == patched_value.op and original_value.op != 'If':
                    if len(original_value.args) == len(patched_value.args):
                        ret_flag = True
                        for i in range(len(original_value.args)):
                            original_arg = original_value.args[i]
                            patched_arg = patched_value.args[i]
                            ret_flag &= compare_two_value(original_arg, patched_arg)
                            # Early termination
                            if ret_flag is False:
                                break
                        ret_val = ret_flag
                # 0x1 V.S. (if a then 0x1 else 0x2)
                elif patched_value.op == 'If':
                    ret_val = compare_two_value(original_value, patched_value)
                # 0x1 V.S. 0x0 .. (if a then 0x1 else 0x2)
                elif patched_value.op == 'Concat':
                    ret_val = compare_two_value(original_value, patched_value.args[1])

        # If (1) strcmp not equal, (2) children args not equal, (3) try canonicalize, (4) Z3 solver
        if ret_val is False:
            if hasattr(original_value, 'canonicalize') and hasattr(patched_value, 'canonicalize'):
                original_value_temp = original_value.canonicalize(rename=False)
                patched_value_temp = patched_value.canonicalize(rename=False)
                ret_val = str(original_value_temp) == str(patched_value_temp)

        if ret_val is False:
            original_value_z3 = self._convert_claripy_to_z3(original_value)
            patched_value_z3 = self._convert_claripy_to_z3(patched_value)
            check_cond = self.negate_cond(handle_eq(original_value, patched_value))
            check_cond_z3 = self._convert_claripy_to_z3(check_cond)
            s = z3.Solver()
            s.add(check_cond_z3)
            check_result = s.check()

            ret_val = check_result == z3.unsat
            # Counter Example
            if output and ret_val is False:
                if check_result == z3.sat:
                    model = s.model()
                    print("\t counter example model:", model)
                    original_value_evaluate = model.evaluate(original_value_z3)
                    patched_value_evaluate = model.evaluate(patched_value_z3)
                    print("\toriginal value evaluate:", original_value_evaluate)
                    print("\tpatched value evaluate:", patched_value_evaluate)
                elif check_result == z3.unknown:
                    print("Check result: unknown")

        self.comparison_map[key] = ret_val
        # If ret_val is True, add assumption map into self.assumption_map
        if update_assumption_map and ret_val:
            for _hash, value in assumption_map.items():
                if _hash not in self.assumption_map:
                    self.assumption_map[_hash] = value
        if output:
            self.output_with_assumptions(original_value, patched_value_copy)
            print("\nResult for check_equals_without_constraint: %s\n" % (str(ret_val)))
        return ret_val

    def check_equals(self, _original_value, _patched_value, original_valid_pc, patched_valid_pc,
                          output=False, update_assumption_map=False, args=None, N=256, pkey=None):
        def compress_vlist(vlist):
            olist = []
            if len(vlist) == 0:
                return []
            if len(vlist) == 1:
                return [(vlist[0], vlist[0])]
            b = vlist[0]
            olist = []
            vlist.append(vlist[-1] + 1)
            for o, v in zip(vlist, vlist[1:]):
                if v == o + 1:
                    continue
                else:
                    olist.append((b, o))
                    b = v
            olist.append((b, o))
            return olist

        def prettyprint_variable(var):
            # print("var", str(var))
            t = str(var).replace("<", "").replace(">", "").replace("(", "").replace(")", "")
            pattern = r"BV\d+ "
            t = re.sub(pattern, "", t)
            # print("t", t)
            a, b = t.split(" + ", maxsplit=1)
            return "[%s + %s]" % (b, a)

        original_value = claripy.simplify(_original_value)
        patched_value = claripy.simplify(_patched_value)
        # patched_value_replaced = self.replace_matching_funcs(patched_value, original_value, matching_functions)

        logging.debug("Original value:\n %s\n", original_value)
        logging.debug("Patched value:\n %s\n", patched_value)
        patch_related_var_map = {}
        constraint_related_var_map = {}
        logging.debug("Checking \n %s \n equals to \n %s" % (str(original_value), str(patched_value)))

        check_cond = handle_eq(original_value, patched_value)
        logging.debug("Checking condition:\n %s\n", check_cond)


        check_cond = self.negate_cond(check_cond)

        check_cond_z3 = self._convert_claripy_to_z3(check_cond)
        # s = claripy.Solver()
        s = z3.Solver()
        s.add(check_cond_z3)

        if s.check() != z3.unsat:

            # 1. Constraint related variables
            model = s.model()

            # Generate an input that leads to different global write values
            if args is not None: self.generate_input(original_value, patched_value, model, args)

            constraint_related_var_map = {d(): [int(model[d()].as_string())] for d in model if d.arity() == 0}

            for var in list(constraint_related_var_map.keys()):
                s.reset()
                s.add(check_cond_z3)
                s.add(var != model[var])
                for other_var in list(constraint_related_var_map.keys()):
                    if other_var is not var:
                        s.add(other_var == model[other_var])

                while len(constraint_related_var_map[var]) < N and s.check() != z3.unsat:
                    new_model = s.model()
                    new_var_value = int(new_model[var].as_string())
                    # logging.debug("%s: %d" , str(var), new_var_value)
                    constraint_related_var_map[var].append(new_var_value)
                    s.add(var != new_var_value)

            # 2. Patch related variables
            s.reset()

            different_parts = []
            self.get_different_parts(original_value, patched_value, different_parts)
            # simpler_check_cond = check_cond
            for (value_1, value_2) in different_parts:
                simpler_check_cond = self.negate_cond(value_1 == value_2)
                simpler_check_cond_z3 = self._convert_claripy_to_z3(simpler_check_cond)
                s.add(simpler_check_cond_z3)
                if s.check() != z3.unsat:
                    model = s.model()
                    # patch_related_var_map = {d(): [int(model[d()].as_string())] for d in model}
                    for d in model:
                        if d.arity() == 0:
                            var = d()
                            var_value = int(model[d()].as_string())
                            if var not in patch_related_var_map:
                                patch_related_var_map[var] = [var_value]
                            else:
                                patch_related_var_map[var].append(var_value)
                    for var in list(patch_related_var_map.keys()):
                        s.reset()
                        s.add(simpler_check_cond_z3)
                        s.add(var != model[var])
                        for other_var in list(patch_related_var_map.keys()):
                            if other_var is not var:
                                s.add(other_var == model[other_var])

                        while len(patch_related_var_map[var]) < N and s.check() != z3.unsat:
                            new_model = s.model()
                            new_var_value = int(new_model[var].as_string())
                            # logging.debug("%s: %d" , str(var), new_var_value)
                            patch_related_var_map[var].append(new_var_value)
                            s.add(var != new_var_value)

        # Print out the results
        # 1. Constraint related variables
        # if len(constraint_related_var_map) > 0: print("\nFull-constraints related variables:")
        for var in constraint_related_var_map:
            value_list = constraint_related_var_map[var]
            value_list.sort()
            if 0 < len(value_list) < N:
                print("Variable %s is relevant, Length: %d" % (str(var), len(value_list)))
                # print("Variable %s is relevant, Length: %d" % (prettyprint_variable(var), len(value_list)))
                print(value_list)
                # binary_list = [format(i, '08b') for i in value_list]
                # print("Bit-wise representation:\n", binary_list, "\n")

        # 2. Patch related variables
        if len(patch_related_var_map) > 0: print("\nPatch related variables:")
        for var in patch_related_var_map:
            value_list = patch_related_var_map[var]
            value_list.sort()
            if 0 < len(value_list) < N:
                print("Variable %s is relevant, Length: %d" % (str(var), len(value_list)))
                # print("Variable %s is relevant, Length: %d" % (prettyprint_variable(var), len(value_list)))
                print(value_list)
                # binary_list = [format(i, '08b') for i in value_list]
                # print("Bit-wise representation:\n", binary_list, "\n")

        s = z3.Solver()
        s.add(check_cond_z3)
        if s.check() != z3.unsat:
            model = s.model()
            if args is not None:
                print("")
            # if args is not None: self.generate_input(original_value, patched_value, model, args)

        ret_val = len(constraint_related_var_map) == 0 and len(patch_related_var_map) == 0
        logging.debug("Result: \n (%s \n equals to \n %s) == %s", str(original_value), str(patched_value), str(ret_val))
        return ret_val

    def get_different_parts(self, original_value, patched_value, result):
        if is_builtin_class_instance(original_value) and is_builtin_class_instance(patched_value):
            # print("ERROR: builtin class", original_value, patched_value)
            return

        # original_value = original_value.canonicalize(rename=False)
        # patched_value = patched_value.canonicalize(rename=False)

        # If the two expressions are the same, skip
        if self.compare(original_value, patched_value):
            return

        if original_value.op != patched_value.op or \
                (original_value.op != 'If' and original_value.depth != patched_value.depth):
            result.append((original_value, patched_value))
            return

        # Specially handle ITE
        if original_value.op == 'If':
            self._compare_if(original_value, patched_value, result)

        # If the two exprs are BVV, directly compare them
        elif original_value.op == 'BVV':
            result.append((original_value, patched_value))

        # If the two exprs are BVS, directly compare them
        # 'BVS': MemoryLoad<...>, String<...>
        elif original_value.op == 'BVS':
            result.append((original_value, patched_value))

        # If the two parts have different args number, directly compare them
        elif len(original_value.args) != len(patched_value.args):
            result.append((original_value, patched_value))

        # Else, for other operators
        else:
            for i in range(len(original_value.args)):
                original_child_node = original_value.args[i]
                patched_child_node = patched_value.args[i]

                if self.compare(original_child_node, patched_child_node) is not True:
                    self.get_different_parts(original_child_node, patched_child_node, result)

        return

    # Comparing two asts, returns True if they are canonically the same
    def compare(self, expr_1, expr_2):
        # if is_builtin_class_instance(expr_1) and is_builtin_class_instance(expr_2):
        #     return expr_1 == expr_2
        # # return expr_1.canonical_hash() == expr_2.canonical_hash()
        return hash(expr_1) == hash(expr_2)

    def _compare_if(self, expr_1, expr_2, result):
        cond_1, then_1, else_1 = expr_1.args
        cond_2, then_2, else_2 = expr_2.args

        cond_imply = self.check_implies(original_constraint=cond_1, patched_constraint=cond_2)
        then_equal = self.compare(then_1, then_2)
        else_equal = self.compare(else_1, else_2)

        # cond2 !-> cond1, then_1 != then_2, else_1 != else_2
        if not (cond_imply or then_equal or else_equal):
            result.append((expr_1, expr_2))
            return

        if not cond_imply:
            self.get_different_parts(cond_1, cond_2, result)
        if not then_equal:
            self.get_different_parts(then_1, then_2, result)
        if not else_equal:
            self.get_different_parts(else_1, else_2, result)

    def get_assumption_map(self, original_value, patched_value):
        assumption_map = self.assumption_map.copy()

        # 1. For constraints (bool): (1) Leaf asts + (2) Structural similar parts
        if isinstance(original_value, claripy.ast.bool.Bool) and isinstance(patched_value, claripy.ast.bool.Bool):
            # (1). Leaf asts

            original_leaf_asts = list(original_value.leaf_asts()) if hasattr(original_value, 'leaf_asts') else []
            patched_leaf_asts = list(patched_value.leaf_asts()) if hasattr(original_value, 'leaf_asts') else []
            patched_leaf_asts_canonical_hash = {}
            for patched_leaf_ast in patched_leaf_asts:
                _hash = patched_leaf_ast.canonicalize().canonical_hash()
                if _hash not in patched_leaf_asts_canonical_hash:
                    patched_leaf_asts_canonical_hash[_hash] = []
                patched_leaf_asts_canonical_hash[_hash].append(patched_leaf_ast)

            # 1.1 use canonical hash -- not suitable for BVV
            for original_ast in original_leaf_asts:

                # For BVV (constant value), only accepts addrs (>0x400000)
                if original_ast.op == 'BVV' and not claripy.is_true(original_ast.UGT(0x400000)):
                    continue

                original_hash = hash(original_ast)
                hash_key = original_hash
                # If already has an assumption for current ast in the assumption map, skip
                if hash_key in assumption_map.keys():
                    continue

                canonical_hash = original_ast.canonicalize().canonical_hash()

                # Canonical_hash equals, hash not equals --> add in to assumption list
                if canonical_hash in patched_leaf_asts_canonical_hash.keys():
                    patched_asts = patched_leaf_asts_canonical_hash[canonical_hash]

                    # Select the most similar one
                    similarities = [similar(str(original_ast), str(patched_ast))
                                    if patched_ast.size() == original_ast.size() else 0 for patched_ast in patched_asts]
                    if len(similarities) > 0:
                        max_similarity = max(similarities)
                        patched_ast = patched_asts[similarities.index(max_similarity)]

                        patched_hash = hash(patched_ast)
                        if original_hash != patched_hash and original_ast.op == patched_ast.op and max_similarity > 0.9:
                            # If not in the map, add to the map
                            if hash_key not in assumption_map.keys():
                                assumption_map[hash_key] = (original_ast, patched_ast)
                                print("1.1.1 Found by canonical_hash:", assumption_map[hash_key])

            # 1.2 Handle remaining BVV
            original_leaf_asts = list(original_value.leaf_asts()) if hasattr(original_value, 'leaf_asts') else []
            patched_leaf_asts = list(patched_value.leaf_asts()) if hasattr(original_value, 'leaf_asts') else []
            # Remove duplication
            o_leaf_asts_hash = [hash(o) for o in original_leaf_asts]
            p_leaf_asts_hash = [hash(p) for p in patched_leaf_asts]

            o_leaf_asts_filtered = [o for o in original_leaf_asts if hash(o) not in p_leaf_asts_hash]
            p_leaf_asts_filtered = [p for p in patched_leaf_asts if hash(p) not in o_leaf_asts_hash]

            original_leaf_bvv_asts = [leaf_ast for leaf_ast in o_leaf_asts_filtered if leaf_ast.op == 'BVV'
                                      and claripy.is_true(leaf_ast.UGT(0x400000))
                                      and hash(leaf_ast) not in assumption_map.keys()]
            # No way to filter patched leaf bvv
            patched_leaf_bvv_asts = [leaf_ast for leaf_ast in p_leaf_asts_filtered if leaf_ast.op == 'BVV'
                                     and claripy.is_true(leaf_ast.UGT(0x400000))]

            # print(original_leaf_bvv_asts)
            # print(patched_leaf_bvv_asts)
            offset_dict = {}
            for o in original_leaf_bvv_asts:
                for p in patched_leaf_bvv_asts:
                    if o.size() == p.size() and hash(o) != hash(p):
                        # print(o, p, o - p)
                        offset = (o - p)
                        if str(offset) not in offset_dict:
                            offset_dict[str(offset)] = []
                        offset_dict[str(offset)].append((o, p))
            # print(offset_dict)

            if len(offset_dict) > 0:
                most_likely_offset = max(offset_dict, key=lambda x: len(offset_dict[x]))
                # Only use this method when length > 1
                if len(offset_dict[most_likely_offset]) > 1:
                    for (o, p) in offset_dict[most_likely_offset]:
                        hash_key = hash(o)
                        if hash_key not in assumption_map.keys():
                            assumption_map[hash_key] = (o, p)
                            print("1.1.2 Found by BVV:", assumption_map[hash_key])

            # (2). Structural similar parts
            original_args = list(original_value.args)
            patched_args = list(patched_value.args)
            patched_args_chosen = {_id: False for _id in range(len(patched_args))}
            different_parts = []
            for original_arg in original_args:
                # Only calculate the string similarity when two arguments share the same string length
                # (Assumes that the constant value replacement -- assumptions -- are in two ASTs with the same length)
                similarities_map = {_id: similar(original_arg, patched_arg) if len(str(original_arg)) ==
                                                                               len(str(patched_arg)) else 0
                                    for _id, patched_arg in enumerate(patched_args) if patched_args_chosen[_id] is False}
                if len(similarities_map) > 0:
                    max_similarity = max(similarities_map.values())
                    if max_similarity > 0.9:
                        patched_arg_id_with_max_similarity = max(similarities_map, key=similarities_map.get)
                        patched_args_chosen[patched_arg_id_with_max_similarity] = True
                        if max_similarity != 1:
                            patched_arg = patched_args[patched_arg_id_with_max_similarity]
                            self.get_different_parts(original_arg, patched_arg, different_parts)

            # Check different parts:
            for (value_1, value_2) in different_parts:
                hash_key = hash(value_1)
                # If not in the map, check
                if hash_key not in assumption_map.keys():
                    # Only assumes the Constant or String are equal,
                    # OR similarity is pretty high (> 0.9)
                    if (value_1.op == value_2.op and value_1.op in ['BVV', 'BVS']) and value_1.size() == value_2.size():
                        # For BVV (constant value):
                        # (1) only accepts addrs (>0x400000)
                        # (2) the offset is a multiple of 0x10
                        if value_1.op == 'BVV':
                            # (1) Size less than 32, skip
                            if value_1.size() < 32:
                                continue
                            # (2) Size greater or equal to 32, but value is less than 0x400000, skip
                            if not (claripy.is_true(value_1.UGT(0x400000)) and claripy.is_true(value_2.UGT(0x400000)) \
                                and (claripy.is_true((value_1 - value_2) & 0xF == 0))):
                                continue

                        # For BVS (string value):
                        # (1) skip if value refers to a register value
                        elif value_1.op == 'BVS':
                            if 'reg_' in str(value_1) or 'reg_' in str(value_2):
                                continue

                        assumption_map[hash_key] = (value_1, value_2)
                        print("1.2 Found by structural:", assumption_map[hash_key])

        # 2. For values (bv), just check structural similar parts
        else:
            # 2.1 Structural
            different_parts = []
            self.get_different_parts(original_value, patched_value, different_parts)
            # Check different parts:
            for (value_1, value_2) in different_parts:
                # Only assumes the Constant or String are equal,
                # OR similarity is pretty high (> 0.9)
                try:
                    if value_1.size() == value_2.size() and ((value_1.op == value_2.op and value_1.op in ['BVV', 'BVS'])
                                                             or similar(value_1, value_2) > 0.9):
                        # For BVV (constant value):
                        # (1) only accepts addrs (>0x400000)
                        # (2) the offset is a multiple of 0x10
                        if value_1.op == 'BVV':
                            # (1) Size less than 32, skip
                            if value_1.size() < 32:
                                continue
                            # (2) Size greater or equal to 32, but value is less than 0x400000, skip
                            if not (claripy.is_true(value_1.UGT(0x400000)) and claripy.is_true(value_2.UGT(0x400000)) \
                                and (claripy.is_true(claripy.Extract(0, 0, value_1 - value_2) == 0))):
                                continue
                        # For BVS (string value):
                        # (1) skip if value refers to a register value
                        elif value_1.op == 'BVS':
                            if 'reg_' in str(value_1) or 'reg_' in str(value_2):
                                continue
                            # Skip if value refers to a string value
                            if 'String' in str(value_1) or 'String' in str(value_2):
                                continue
                            # Skip for memory load
                            if 'MemoryLoad' in str(value_1) or 'MemoryLoad' in str(value_2):
                                continue
                            # Skip for 'Func_' value
                            if 'Func_' in str(value_1) or 'Func_' in str(value_2):
                                # If only more than 2 characters are different, skip
                                if list(x!=y for x,y in zip(str(value_1),str(value_2))).count(True) > 2:
                                    continue

                        hash_key = hash(value_1)
                        # If not in the map, add to the map
                        if hash_key not in assumption_map.keys():
                            assumption_map[hash_key] = (value_1, value_2)
                            print("2.1 Found by structural:", assumption_map[hash_key])
                except AttributeError:
                    # Skip boolean value
                    continue

            # 2.2 BVV
            original_leaf_asts = list(original_value.leaf_asts()) if hasattr(original_value, 'leaf_asts') else []
            patched_leaf_asts = list(patched_value.leaf_asts()) if hasattr(original_value, 'leaf_asts') else []
            # Remove duplication
            o_leaf_asts_hash = [hash(o) for o in original_leaf_asts]
            p_leaf_asts_hash = [hash(p) for p in patched_leaf_asts]

            o_leaf_asts_filtered = [o for o in original_leaf_asts if hash(o) not in p_leaf_asts_hash]
            p_leaf_asts_filtered = [p for p in patched_leaf_asts if hash(p) not in o_leaf_asts_hash]

            original_leaf_bvv_asts = [leaf_ast for leaf_ast in o_leaf_asts_filtered if leaf_ast.op == 'BVV'
                                      and claripy.is_true(leaf_ast.UGT(0x400000))
                                      and hash(leaf_ast) not in assumption_map.keys()]
            # No way to filter patched leaf bvv
            patched_leaf_bvv_asts = [leaf_ast for leaf_ast in p_leaf_asts_filtered if leaf_ast.op == 'BVV'
                                     and claripy.is_true(leaf_ast.UGT(0x400000))]

            # print(original_leaf_bvv_asts)
            # print(patched_leaf_bvv_asts)
            offset_dict = {}
            for o in original_leaf_bvv_asts:
                for p in patched_leaf_bvv_asts:
                    if o.size() == p.size() and hash(o) != hash(p):
                        # print(o, p, o - p)
                        offset = (o - p)
                        if str(offset) not in offset_dict:
                            offset_dict[str(offset)] = []
                        offset_dict[str(offset)].append((o, p))
            # print(offset_dict)
            if len(offset_dict) > 0:
                most_likely_offset = max(offset_dict, key=lambda x: len(offset_dict[x]))
                # Only use this method when length > 1
                if len(offset_dict[most_likely_offset]) > 1:
                    for (o, p) in offset_dict[most_likely_offset]:
                        hash_key = hash(o)
                        if hash_key not in assumption_map.keys():
                            assumption_map[hash_key] = (o, p)
                            print("2.2 Found by BVV:", assumption_map[hash_key])
        return assumption_map

    @staticmethod
    def coloring_assumptions(value_bv, differences_bv):
        value_str = str(value_bv)
        differences_str = []
        # remove '<TYPE >'
        for diff in differences_bv:
            diff_str = str(diff)
            space_index = diff_str.find(' ')
            diff_str = diff_str[space_index + 1: -1]
            differences_str.append(diff_str)

        for diff_str in differences_str:
            if value_str.find(diff_str) != -1:
                value_str = value_str.replace(diff_str,  Fore.BLUE + diff_str + Style.RESET_ALL)

        # print(value_str)
        return value_str

    def output_with_assumptions(self, original_value, patched_value):
        diffs_original = [a[0] for a in self.assumption_map.values()]
        diffs_patched = [a[1] for a in self.assumption_map.values()]
        original_str = self.coloring_assumptions(original_value, diffs_original)
        patched_str = self.coloring_assumptions(patched_value, diffs_patched)
        original_str_colorized, patched_str_colorized = self.colorize(original_str, patched_str)
        print("\t%s\n \tV.S.\n \t%s\n" % (original_str_colorized, patched_str_colorized))

    @staticmethod
    def colorize(input_1, input_2):
        # SKIP if length of input_1 and input_2 are greater than 1000
        if len(input_1) > 10000 or len(input_2) > 10000:
            return input_1, input_2

        # Colorize the diff output, merging into one string,
        # remove [+/-] and add color to the string
        # remove \n in each line

        input_1_split = input_1.split(" ")
        input_2_split = input_2.split(" ")

        diffs = ndiff(input_1_split, input_2_split)
        # print(diffs)
        input_1_output = ""
        input_2_output = ""
        for diff in diffs:
            # print(diff)
            # Elements in input_1 but not in input_2
            if diff[0] == "-":
                input_1_output += Fore.RED + diff[2:] + Style.RESET_ALL + " "
            # Elements in input_2 but not in input_1
            elif diff[0] == "+":
                input_2_output += Fore.GREEN + diff[2:] + Style.RESET_ALL + " "
            elif diff[0] == "?":
                pass
            else:
                input_1_output += diff[2:] + " "
                input_2_output += diff[2:] + " "

        return input_1_output, input_2_output

    def generate_input(self, original_value, patched_value, model, args):
        var_load_pattern = r"_\*\(\<BV\d+ (?P<offset>0x(\d|a|b|c|d|e|f)+)?\s?\+?\s?(?P<reg>\w+)\>\)"
        # Todo: add variable size

        original_value_z3 = self._convert_claripy_to_z3(original_value)
        patched_value_z3 = self._convert_claripy_to_z3(patched_value)
        arg_names = [arg.reg_name for arg in args]
        # Memory map: record the pointer arguments
        memory_map = {arg.reg_name: {} for arg in args}
        # Value map: record the value arguments
        value_map = {}

        # Collecting info
        for var in model:
            var_name = var.name()
            # For now skip the function that takes arguments
            if var.arity() > 0:
                continue
            value = int(model[var()].as_string())
            # memory data
            if '_*' in var_name:
                # print("var_name", var_name)
                m = re.match(var_load_pattern, var_name)
                if m is None:
                    continue
                try:
                    offset = int(m.groupdict()['offset'], base=16)
                # in the case of var_load(reg), won't find a match for offset
                except TypeError:
                    offset = 0

                reg = m.groupdict()['reg']

                if reg not in arg_names:
                    continue
                memory_map[reg][offset] = {'value': value, 'size': int(var.range().size() / 8)}
                # memory_map[reg][offset] = {'value': value}

            # normal values
            else:
                value_map[var_name] = value

        # Translate into a list and print out
        # print("\nThe following input values trigger the patch-introduced differences:")
        # Memory
        # print(memory_map)
        '''
        print("\nVersion 1: ")
        for (arg, arg_map) in memory_map.items():
            if len(arg_map) > 0:
                for (offset, data) in arg_map.items():
                    print("%s[%d] = %d, size: %d" % (arg, offset, data['value'], data['size']))
                    # print("%s[%d] = 0x%x, size: ?" % (arg, offset, data['value']))
        '''
        # print("\nVersion 2: ")
        for (arg, arg_map) in memory_map.items():
            if len(arg_map) > 0:
                max_offset = max(arg_map.keys())
                data_stored_at_arg = [arg_map[i]['value'] if i in arg_map.keys() else '?' for i in
                                      range(max_offset + 1)]
                print("Memory at %s: " % arg)
                print(data_stored_at_arg)

        # Normal values
        for (arg, value) in value_map.items():
            if value is not None:
                pass
                # print("%s = 0x%x" % (arg, value))

        logging.debug("\nOriginal value: %s" % (str(original_value_z3)))
        logging.debug("\nOriginal value = %s" % str(model.eval(original_value_z3)))

        logging.debug("\nPatched value: %s" % str(patched_value_z3))
        logging.debug("\nPatched value = %s" % str(model.eval(patched_value_z3)))

    def _convert_claripy_to_z3(self, expr):
        return z3.simplify(claripy._backend_z3.convert(expr))
