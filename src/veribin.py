from __future__ import print_function
import os
import sys
import logging
from argparse import ArgumentParser, ArgumentDefaultsHelpFormatter, ArgumentTypeError
import re
import time
import timeout_decorator

import angr
import claripy

# Custom objects
from load_config import ConfigFile
from veribin_func import VeriBinFunc
from veribin_path import Path
from typing import Any, Optional
from z3_syc import Z3ConstraintGenerator
from preprocessor.bindiff_helper import IdaBinDiff
from ppc_helper import run_project
from utils import COLOR, print, str2bool, similar, is_rodata_addr, load_string_content_from_binary

# Increase the recursion limit to avoid angr from failing due to recursion limit
import sys
sys.setrecursionlimit(5000)

logging.getLogger().setLevel(logging.ERROR)
angr.loggers.setall(logging.CRITICAL)

# Load the FLIRT signatures
flirt_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'flirt_signatures/')
angr.flirt.load_signatures(flirt_path)

EXIT_KEYWORDS = ['exit',
                 '__stack_chk_fail',
                 '__assert_fail',
                 'abort',
                 'err',
                 'png_error',
                 'php_error_docref0',
                 'php_error_docref',
                 'zend_throw_exception_ex',
                 'handleErrors',
                 'TIFFError'
                 ]

# @timeout_decorator.timeout(10, use_signals=True)
def ask_user_for_modification(msg=''):
    while True:
        answer = input(f"{COLOR['red']}[{msg}] Do you think this modification is safe to apply? (y/n){COLOR['reset']}")
        if answer.lower() == 'y':
            print(f"{COLOR['red']}You chose to accept the modification.{COLOR['reset']}")
            return True
        elif answer.lower() == 'n':
            print(f"{COLOR['red']}You chose not to accept the modification.{COLOR['reset']}")
            return False
        else:
            print(f"{COLOR['red']}Please answer y or n{COLOR['reset']}")

def ask_user_to_continue(msg=''):
    while True:
        answer = input(f"{COLOR['red']}[{msg}] Do you want to continue re-checking?(y/n){COLOR['reset']}")
        if answer.lower() == 'y':
            print(f"{COLOR['red']}You chose to continue the re-checking process.{COLOR['reset']}")
            return True
        elif answer.lower() == 'n':
            print(f"{COLOR['red']}You chose to terminate the re-checking process.{COLOR['reset']}")
            return False
        else:
            print(f"{COLOR['red']}Please answer y or n{COLOR['reset']}")

def warning_for_condition_1(msg=''):
    # If split_result is False, print out a warning message
    # Press 'y' to continue with merge all, 'n' to exit
    description = f"{COLOR['red']}[{msg}] Condition 1: Path constraint."\
                      "\nUnmapped paths (paths without a constraint implication relationship) were detected during the per-path matching process."\
                      "\VeriBin will proceed by merging all valid paths. Please press 'y' to continue."\
                      f"\nIf you prefer to ignore these unmapped paths, you can label them as 'exit edges' in the config file. Press 'n' if you wish to exit now.{COLOR['reset']}"
    print(description)
    while True:
        answer = input(f"{COLOR['red']}Do you want to continue with merge all?(y/n){COLOR['reset']}")
        if answer.lower() == 'y':
            print(f"{COLOR['red']}You chose to continue with merge all.{COLOR['reset']}")
            return True
        elif answer.lower() == 'n':
            print(f"{COLOR['red']}You chose to exit.{COLOR['reset']}")
            return False
        else:
            print(f"{COLOR['red']}Please answer y or n{COLOR['reset']}")

class AngrArchHook(object):
    """
    Architecture specific hook based on angr analysis.
    """

    def __init__(self, reg_name):
        """
        Create architecture hook
        :param reg_name: Return register name.
        """
        self.reg_name = reg_name

    def get_return_value(self, path: Any) -> Optional[Any]:
        # try:
        #     rax_value = claripy.simplify(path_compiler.sym_value_map[self.reg_name]['value'])
        #     return rax_value
        # except KeyError:
        #     return None
        return path.return_value


class VeriBin(object):

    # @timeout_decorator.timeout(7200, use_signals=False)
    def __init__(self, target_old, target_new, config_file_path, func_addr_old, func_addr_new, additional_params=None):
        # Get the additional parameters
        if additional_params:
            for key, value in additional_params.items():
                setattr(self, f"_{key}", value)

        tic = time.perf_counter()
        self.binary_info = ConfigFile(config_file_path).binary_info
        load_options = {'auto_load_libs': False, 'load_debug_info': self._load_debug_info}
        if self._is_ppc:
            if self._is_ppc == "PowerPC:BE:32:e200":
                import archinfo
                import pypcode
                arch = archinfo.ArchPcode("PowerPC:BE:32:e200")
                self.p_old = angr.Project(target_old, arch=arch, auto_load_libs=False, engine=angr.engines.UberEnginePcode)
                self.p_new = angr.Project(target_new, arch=arch, auto_load_libs=False, engine=angr.engines.UberEnginePcode)
            elif self._is_ppc == "PowerPC:BE:32:MPC8270":
                self.p_old = run_project(target_old)
                self.p_new = run_project(target_new)
        else:
            self.p_old = angr.Project(target_old, load_options=load_options)
            self.p_new = angr.Project(target_new, load_options=load_options)
        self.func_addr_old = func_addr_old
        self.func_addr_new = func_addr_new
        self.matching_functions = self.binary_info['matching_functions']
        matching_instruction_addrs = {}
        self.modified_addrs_original = []
        self.modified_addrs_patched = []

        if self._use_ida:
            try:
                bindiff_obj = IdaBinDiff(target_old, target_new, func_addr_old, func_addr_new,
                                                       self.p_old.arch.bits,
                                                       self.p_old.loader.min_addr, # base_addr
                                                       debug=False)
                matching_instruction_addrs = bindiff_obj.ins_matching_map

                del bindiff_obj
            except Exception as e:
                import traceback
                print(traceback.format_exc())

        toc = time.perf_counter()
        print("Time elapse for VeriBin init (preprocess): %.4f seconds\n" % (toc - tic))

        tic = time.perf_counter()

        exit_edges_info_old = self.binary_info['exit_edges']['original']
        exit_edges_info_new = self.binary_info['exit_edges']['patched']

        self.veribin_func_old = VeriBinFunc(self.p_old, self.func_addr_old, self.binary_info, exit_edges_info_old,
                                      tag='original', graph_format=self._graph_format, is_ppc=self._is_ppc,
                                      debug=self._debug, use_cache=self._use_cache,
                                      symbolic_memory_read_zero=self._symbolic_memory_read_zero,)
        self.veribin_func_new = VeriBinFunc(self.p_new, self.func_addr_new, self.binary_info, exit_edges_info_new,
                                      tag='patched', graph_format=self._graph_format, is_ppc=self._is_ppc,
                                      debug=self._debug, use_cache=self._use_cache,
                                      symbolic_memory_read_zero=self._symbolic_memory_read_zero)

        if len(matching_instruction_addrs) > 0:
            # Get the matching basic block addresses
            # (reason: IDA superblock V.S. angr basic block)
            # self.matching_bb_addrs = self.get_matching_block_addrs(matching_superblock_addrs)

            # Get the matching instructions address
            self.matching_bb_addrs = matching_instruction_addrs.copy()

            # Get the modified instruction addresses (all ins addresses - matching instruction addresses)
            all_ins_addrs_original = self.veribin_func_old.all_instrs_addr
            all_ins_addrs_patched = self.veribin_func_new.all_instrs_addr
            self.modified_addrs_original = [addr for addr in all_ins_addrs_original if addr not in
                                                  self.matching_bb_addrs.keys()]
            self.modified_addrs_patched = [addr for addr in all_ins_addrs_patched if addr not in
                                                    self.matching_bb_addrs.values()]
            if len(self.modified_addrs_original) > 0:
                print("Modified Instructions Original: %s" % ', '.join(hex(addr) for addr in self.modified_addrs_original))
            if len(self.modified_addrs_patched) > 0:
                print("Modified Instructions Patched: %s" % ', '.join(hex(addr) for addr in self.modified_addrs_patched))
        else:
            self.matching_bb_addrs = []

        toc = time.perf_counter()
        print("Time elapse for SpiderCheck Translator: %.4f seconds\n" % (toc - tic))

        self.symc_old = None
        self.symc_new = None
        self.cons_gen = None
        self.paths_mapping = None
        self.user_assumptions = None
        self.condition_1_result = None
        self.condition_2_result = None
        self.condition_3_result = None
        self.condition_4_result = None
        self.final_result = None

        # store merged valid path constraints
        self.merged_valid_pc_old = claripy.true
        self.merged_valid_pc_new = claripy.true

        self._exit_keywords = EXIT_KEYWORDS
        if'exit_keywords' in self.binary_info:
            # Extend the exit keywords list with the user provided exit keywords
            self._exit_keywords.extend(self.binary_info['exit_keywords'])

        # Check whether the function is not-supported (CFG error)
        # Will exit if the function is not supported
        self._check_cfg_error()

        self._analysis()

    def _dprint(self, msg, n=5000):
        # n: Number of characters to print
        msg_str = str(msg)
        if self._debug:
            # If msg is too long, print the first N characters
            if len(msg_str) > n:
                msg_str = msg_str[:n] + f"\t[...] (message is too long) {COLOR['reset']}"
            print('[+] {}'.format(msg_str))

    def _check_cfg_error(self):
        '''
        Check if the function is not supported (CFG error)
        Parameters:
        - func: angr function object
        Steps:
        - Get function name from symbol_table (config file), based on the target function address
        - Get the function info from the func_info_map (config file)
        - The func is not supported if
            - ida_func_size is None (IDA fail to identify the target function)
            - angr_func_size is not None, but the function has only 1 block (CFG error)
        '''
        # Initialize the results for the old and new functions
        func_not_supported_old = False
        func_not_supported_new = False

        # Original function
        try:
            # Get the function name from the symbol table
            original_func_name = self.binary_info['symbol_table']['original'][self.func_addr_old]
            original_func_info = self.binary_info['func_info_map'][original_func_name]
            # Check if the function is not supported
            ida_func_size_old = original_func_info.get('ida_func_size', None)
            angr_func_size_old = original_func_info.get('angr_func_size', None)
            number_of_blocks_old = len(self.veribin_func_old.func.block_addrs_set)
            if ida_func_size_old == 'None' and angr_func_size_old != 'None' and number_of_blocks_old == 1:
                print(f"The original target function {original_func_name}({hex(self.func_addr_old)}) is not supported (CFG error).")
                func_not_supported_old = True
        except KeyError:
            pass

        # Patched function
        try:
            # Get the function name from the symbol table
            patched_func_name = self.binary_info['symbol_table']['patched'][self.func_addr_new]
            patched_func_info = self.binary_info['func_info_map'][patched_func_name]
            # Check if the function is not supported
            ida_func_size_new = patched_func_info.get('ida_func_size', None)
            angr_func_size_new = patched_func_info.get('angr_func_size', None)
            number_of_blocks_new = len(self.veribin_func_new.func.block_addrs_set)
            if ida_func_size_new == 'None' and angr_func_size_new != 'None' and number_of_blocks_new == 1:
                print(f"The patched target function {patched_func_name}({hex(self.func_addr_new)}) is not supported (CFG error).")
                func_not_supported_new = True
        except KeyError:
            pass

        # Exit if any of the functions is not supported
        if func_not_supported_old or func_not_supported_new:
            print("Function is not supported (CFG error).")
            print("Exit...")
            exit()


    def _analysis(self):

        tic = time.perf_counter()

        self.cons_gen = Z3ConstraintGenerator(self.p_old)
        self.all_paths_old = self.veribin_func_old.paths
        self.all_paths_new = self.veribin_func_new.paths
        flag_skip_early_terminated_paths = True
        self.all_true_and_valid_paths_old = self._collect_true_and_valid_paths(
            self.all_paths_old, self.veribin_func_old.end_points_bb_addr,
            skip_early_terminated_paths=flag_skip_early_terminated_paths)
        self.all_true_and_valid_paths_new = self._collect_true_and_valid_paths(
            self.all_paths_new, self.veribin_func_new.end_points_bb_addr,
            skip_early_terminated_paths=flag_skip_early_terminated_paths)

        # If there is no valid path, we try without skipping early terminated paths
        if len(self.all_true_and_valid_paths_old) == 0 or len(self.all_true_and_valid_paths_new) == 0:
            flag_skip_early_terminated_paths = False
            print("No valid path found, try without skipping early terminated paths")
            self.all_true_and_valid_paths_old = self._collect_true_and_valid_paths(
                self.all_paths_old, self.veribin_func_old.end_points_bb_addr,
                skip_early_terminated_paths=flag_skip_early_terminated_paths)
            self.all_true_and_valid_paths_new = self._collect_true_and_valid_paths(
                self.all_paths_new, self.veribin_func_new.end_points_bb_addr,
                skip_early_terminated_paths=flag_skip_early_terminated_paths)

        self.selected_paths_old = self.all_true_and_valid_paths_old
        self.selected_paths_new = self.all_true_and_valid_paths_new
        print("Old function, total paths: %d, total valid paths: %d" % (
            len(self.all_paths_old), len(self.all_true_and_valid_paths_old)))
        print("New function, total paths: %d, total valid paths: %d" % (
            len(self.all_paths_new), len(self.all_true_and_valid_paths_new)))
        if self._debug:
            self.print_paths()

        assert len(self.all_true_and_valid_paths_old) > 0 and "0 valid path, something is wrong"
        assert len(self.all_true_and_valid_paths_new) > 0 and "0 valid path, something is wrong"

        self.old_funcs_args_map = self._get_funcs_args(self.all_true_and_valid_paths_old)
        self.new_funcs_args_map = self._get_funcs_args(self.all_true_and_valid_paths_new)

        self.cons_gen.update_matching_funcs(self.old_funcs_args_map, self.new_funcs_args_map,
                                            self.matching_functions, self.veribin_func_old.function_info_map,
                                            self.veribin_func_new.function_info_map,
                                            interactive=self._interactive)

        toc = time.perf_counter()
        print("Time elapse for SYMC compile_function: %.4f seconds\n" % (toc - tic))

        # Safe Patch conditions checking
        self.user_assumptions = {}
        round_1_total_time = self.SP_conditions_checking()
        print("Time elapse for round 1 SP checking: %.4f seconds" % round_1_total_time)

        # Recheck if the assumptions map is not empty, when merged is True
        # Because when merge_all, some user assumptions may not be applied during the first round
        if self.final_result is False and len(self.cons_gen.assumption_map) > 0:
            # If round_1 already took more than 10 minutes, skip the re-checking process
            if round_1_total_time > 600:
                print("Round 1 took more than 10 minutes, skip the re-checking process")
            else:
                round_2_total_time = self.SP_conditions_checking()
                print("Time elapse for round 2 SP checking: %.4f seconds" % round_2_total_time)

        # If there are user_assumptions, re-check the conditions
        if len(self.user_assumptions) > 0:
            # Print the user assumptions
            print(f"{COLOR['red']}Detect user accepted assumptions, re-checking condition 1 to 4...{COLOR['reset']}")
            print("\tUser assumptions:")
            for o_value, p_value in self.user_assumptions.values():
                print("\t%s == %s" % (o_value, p_value))
            _to_continue_flag = ask_user_to_continue(msg='StA_recheck')
            if _to_continue_flag == False:
                print("User terminated the re-checking process, exit...")
            elif _to_continue_flag == True:
                # Assign the user assumptions to the constraint generator
                self.cons_gen.assumption_map = self.user_assumptions
                self.SP_conditions_checking()
        print("Skip early terminated paths: %s" % flag_skip_early_terminated_paths)
        print("Old function, total paths: %d, total valid paths: %d" % (
            len(self.all_paths_old), len(self.all_true_and_valid_paths_old)))
        print("New function, total paths: %d, total valid paths: %d" % (
            len(self.all_paths_new), len(self.all_true_and_valid_paths_new)))

        self.check_modified_bb_visited()
        return

    # Check if the modified addrs are visited by any valid path
    # If not, print out a warning message
    def check_modified_bb_visited(self):
        print("\n" + "*" * 5 + " Checking if the modified blocks or instructions are visited by any valid path")

        # Skip if there is no modified addrs
        if len(self.modified_addrs_original) == 0 and len(self.modified_addrs_patched) == 0:
            print("==> No modified addresses, skip checking")
            return

        original_result = True
        patched_result = True
        original_visited_num = 0
        patched_visited_num = 0
        if len(self.modified_addrs_original) > 0:
            self._dprint("Modified Addrs Original: %s" % ', '.join(hex(addr) for addr in self.modified_addrs_original))
            original_result, original_visited_num = self._check_modified_bb_visited_helper(self.modified_addrs_original, self.all_paths_old)
        if len(self.modified_addrs_patched) > 0:
            self._dprint("Modified Addrs Patched: %s" % ', '.join(hex(addr) for addr in self.modified_addrs_patched))
            patched_result, patched_visited_num = self._check_modified_bb_visited_helper(self.modified_addrs_patched, self.all_paths_new)

        if original_result and patched_result:
            print("==> All modified blocks are visited by at least one valid path.")
        elif original_visited_num > 0 and patched_visited_num > 0:
            print("==> Warning: Some modified blocks are not visited by any valid path, please be aware that the result may not be accurate.")
        if original_visited_num == 0:
            print("==> Warning: No modified blocks are visited by any valid path in the original function.")
        if patched_visited_num == 0:
            print("==> Warning: No modified blocks are visited by any valid path in the patched function.")


    def _check_modified_bb_visited_helper(self, modified_addrs, all_paths):
        result = True
        num_of_visited_modified_addrs = 0
        for addr in modified_addrs:
            visited = False
            for path in all_paths:
                if addr in path.visited_blocks:
                    visited = True
                    num_of_visited_modified_addrs += 1
                    break
            if visited is False:
                self._dprint(f"{COLOR['red']}Warning: modified block {hex(addr)} is not visited by any valid path{COLOR['reset']}")
                result = False
        return result, num_of_visited_modified_addrs

    def SP_conditions_checking(self):
        total_time_tick = time.perf_counter()
        tic = time.perf_counter()
        self._check_condition_1()
        toc = time.perf_counter()

        print("Time elapse for Condition 1: %.4f seconds\n" % (toc - tic))

        tic = time.perf_counter()
        if self._merged:
            self._check_condition_2_merge_all()
        else:
            self._check_condition_2()
        toc = time.perf_counter()

        print("Time elapse for Condition 2: %.4f seconds\n" % (toc - tic))

        tic = time.perf_counter()
        if self._merged:
            self._check_condition_3_merge_all()
        else:
            self._check_condition_3()
        toc = time.perf_counter()
        print("Time elapse for Condition 3: %.4f seconds\n" % (toc - tic))

        tic = time.perf_counter()
        if self._merged:
            self._check_condition_4_merge_all()
        else:
            self._check_condition_4()
        toc = time.perf_counter()
        print("Time elapse for Condition 4: %.4f seconds\n" % (toc - tic))

        self.final_result = self.condition_1_result and self.condition_2_result and self.condition_3_result and self.condition_4_result
        print("\n\nCondition 1: %s, Condition 2: %s, Condition 3: %s , Condition 4: %s-- > Safe to Apply Patch? %s" %
              (self.colorizing_condition_result(self.condition_1_result),
               self.colorizing_condition_result(self.condition_2_result),
               self.colorizing_condition_result(self.condition_3_result),
               self.colorizing_condition_result(self.condition_4_result),
               self.colorizing_condition_result(self.final_result)))
        self.print_assumptions()
        # self.veribin_func_old.get_veribin_func().dump_dot("oldfunc_%s_%s.dot" % (self.ex, hex(self.func_addr_old)))
        # self.veribin_func_new.get_veribin_func().dump_dot("newfunc_%s_%s.dot" % (self.ex, hex(self.func_addr_new)))
        print("Merged: %s" % self._merged)
        print("Use ida: %s" % self._use_ida)

        total_time_toc = time.perf_counter()
        return total_time_toc - total_time_tick

    def colorizing_condition_result(self, result):
        # 1. Green: True
        if result is True:
            return f"{COLOR['green']}True{COLOR['reset']}"
        # 2. Red: False
        elif result is False:
            return f"{COLOR['red']}False{COLOR['reset']}"

    def get_matching_block_addrs(self, matching_superblock_addrs):
        matching_bb_addrs = matching_superblock_addrs.copy()
        for old_addr, new_addr in matching_superblock_addrs.items():
            while True:
                try:
                    old_successors = list(self.veribin_func_old.graph.successors(self.veribin_func_old.func.get_node(old_addr)))
                    new_successors = list(self.veribin_func_new.graph.successors(self.veribin_func_new.func.get_node(new_addr)))
                    # Proceed when the number of successors of both nodes are 1
                    if len(old_successors) == 1 and len(new_successors) == 1:
                        old_addr_to_add = old_successors[0].addr
                        new_addr_to_add = new_successors[0].addr
                        # Proceed when the addr_to_add not in matching_bb_addrs
                        # (There are cases when BinDiff is wrong, and the new_addr_to_add is already in the dict matching
                        # with another addr)
                        if old_addr_to_add not in matching_bb_addrs.keys() and \
                                new_addr_to_add not in matching_bb_addrs.values():
                            matching_bb_addrs[old_addr_to_add] = new_addr_to_add
                            old_addr = old_addr_to_add
                            new_addr = new_addr_to_add
                            continue
                except Exception as e:
                    import traceback
                    print(traceback.format_exc())
                    break
                break

        return matching_bb_addrs

    def print_paths(self):
        # original all paths
        self._dprint("\nOriginal: all paths")
        for path in self.all_paths_old:
            edges = '[{}]'.format(', '.join(hex(block_addr) for block_addr in path.visited_blocks))
            self._dprint("%s\n" % edges)
            self._dprint("%s\n" % path.path_constraint)
            # Print each constraint
            self._dprint("Detailed onstraints:")
            for constraint in path.angr_path_info.constraints:
                self._dprint("\t%s\n" % constraint)

        # original all true and valid paths
        self._dprint("Original: all true and valid paths")
        for path in self.all_true_and_valid_paths_old:
            edges = '[{}]'.format(', '.join(hex(block_addr) for block_addr in path.visited_blocks))
            self._dprint("%s\n" % edges)
            self._dprint("%s\n" % path.path_constraint_str)

        # Patched all paths
        self._dprint("\nPatched: all paths")
        for path in self.all_paths_new:
            edges = '[{}]'.format(', '.join(hex(block_addr) for block_addr in path.visited_blocks))
            self._dprint("%s\n" % edges)
            self._dprint("%s\n" % path.path_constraint)
            # Print each constraint
            self._dprint("Detailed onstraints:")
            for constraint in path.angr_path_info.constraints:
                self._dprint("\t%s\n" % constraint)

        # patched: all true and valid paths
        self._dprint("Patched: all true and valid paths")
        for path in self.all_true_and_valid_paths_new:
            edges = '[{}]'.format(', '.join(hex(block_addr) for block_addr in path.visited_blocks))
            self._dprint("%s\n" % edges)
            self._dprint("%s\n" % path.path_constraint_str)

    def print_assumptions(self):
        if len(self.cons_gen.assumption_map) > 0:
            print("\nAssumptions:\n")
            for o_value, p_value in self.cons_gen.assumption_map.values():
                print("\t%s\t==\t%s\n" % (o_value, p_value))

    def add_to_user_assumptions_map(self, o_value, p_value):
        if o_value.size() == p_value.size():
            key = (hash(o_value), hash(p_value))
            if key not in self.user_assumptions:
                self.user_assumptions[key] = (o_value, p_value)
            if key not in self.cons_gen.assumption_map:
                self.cons_gen.assumption_map[key] = (o_value, p_value)
        else:
            print(f"Warning: The size of the two values ({o_value} v.s. {p_value}) are different, cannot add to the assumption map")

    def _check_condition_1(self):
        print("\n" + "*" * 5 + " Checking Condition 1: Whether the function's valid input space is not increased by"
                               " the patch (i.e., for non-error exit paths, the patched constraints imply the original"
                               " constraints).")
        split_result = False
        merged_result = False
        # 1. First try split version (matching path pairs)
        if self._merged is False:
            try:
                split_result = self._check_condition_1_per_path()
                # If split_result is False, print out a warning message
                if not split_result and self._interactive:
                    answer = warning_for_condition_1(msg='P1_warning')
                    # If answer is False, exit
                    if not answer:
                        print("Exit...")
                        exit()
            except Exception as e:
                import traceback
                print(traceback.format_exc())
                print("Time out for per path condition 1 checking. Try merge all instead...\n")

        # 2. Merge all
        if split_result is False or self._merged is True:
            # Set thw strategy to be merged (for P2/P3/P4)
            self._merged = True
            # Selected paths should be all true and valid paths
            self.selected_paths_old = self.all_true_and_valid_paths_old
            self.selected_paths_new = self.all_true_and_valid_paths_new

            # Merge all the paths
            cumulative_valid_return_constraint_old = self._collect_valid_return_constraint(
                self.all_true_and_valid_paths_old)
            cumulative_valid_return_constraint_new = self._collect_valid_return_constraint(
                self.all_true_and_valid_paths_new)
            o_replaced, p_replaced = self.cons_gen.replace_matching_funcs(
                cumulative_valid_return_constraint_new, cumulative_valid_return_constraint_old, self.matching_functions)
            self.merged_valid_pc_old = o_replaced
            self.merged_valid_pc_new = p_replaced
            # print("Condition 1: Checking \n %s \n implies \n %s" % (str(p_replaced), str(o_replaced)))
            print("Condition 1: Checking patched_constraint implies original_constraint")
            merged_result = self.cons_gen.check_implies(
                original_constraint=o_replaced,
                patched_constraint=p_replaced,
                output=True, update_assumption_map=self._update_assumption)
            print("Condition 1 merge all result:", merged_result)

        if split_result or merged_result:
            self.condition_1_result = True
        else:
            self.condition_1_result = self.handle_interactive(curr_cond_res=False, msg='P1_false')

        if self.condition_1_result:
            print("==> Condition 1 is True.")
        else:
            print("==> Condition 1 is False")

    # Disable it, as it is conflicting with parallel testing
    # @timeout_decorator.timeout(5, use_signals=True)
    def _check_condition_1_per_path(self):
        def bindiff_similar(bb_list_old, bb_list_new):
            score = 0
            visited_old = []
            for addr_old in bb_list_old:
                if addr_old in self.matching_bb_addrs.keys() and self.matching_bb_addrs[addr_old] in bb_list_new:
                    if addr_old not in visited_old:
                        visited_old.append(addr_old)
                        score += 1
                    # addr_old occurs in bb_list_old twice, add score only if the corresponding addr_new also occurs
                    # in bb_list_new twice
                    elif bb_list_new.count(self.matching_bb_addrs[addr_old]) == 2:
                        score += 1
            similarity_score = 2 * score / (len(bb_list_old) + len(bb_list_new))
            return similarity_score

        # If total number of old paths is greater than total number of new paths,
        # obviously not all old paths have at least one matching new path
        # Thus return false
        if len(self.all_true_and_valid_paths_old) > len(self.all_true_and_valid_paths_new):
            print("\t Condition 1 per path: False. (old paths: %d > new paths: %d)\n"
                         % ((len(self.all_true_and_valid_paths_old)), len(self.all_true_and_valid_paths_new)))
            return False

        paths_mapping = {path: [] for path in self.all_true_and_valid_paths_old}
        average_length_old = sum(len(path.visited_blocks) for path in self.all_true_and_valid_paths_old) \
                                / len(self.all_true_and_valid_paths_old)
        average_length_new = sum(len(path.visited_blocks) for path in self.all_true_and_valid_paths_new) \
                             / len(self.all_true_and_valid_paths_new)

        paths_chosen_new = [False for _ in range(len(self.all_true_and_valid_paths_new))]
        max_count = 0

        # 1. Round 1: use string comparison to mark 'exactly the same' paths OR subsequence paths as chosen
        # In this way, we can reduce the times of calling z3.solver
        for new_path_id, new_path in enumerate(self.all_true_and_valid_paths_new):
            for old_path_id, old_path in enumerate(self.all_true_and_valid_paths_old):
                # String comparison: If new_path_cons == old_path_cons OR is subsequence (not !), mark as chosen,
                # add to paths_mapping dict, and break
                # Getting rid of '<Bool ' nd '>'
                new_path_constraint = new_path.path_constraint_str[6:-1]
                old_path_constraint = old_path.path_constraint_str[6:-1]
                if new_path_constraint == old_path_constraint or (
                        old_path_constraint in new_path_constraint and "!(" + old_path_constraint not in
                        new_path_constraint):
                    paths_chosen_new[new_path_id] = True
                    # Add to paths_mapping dict
                    paths_mapping[old_path].append(new_path)
                    print("Old path: %s" % ', '.join(hex(addr) for addr in old_path.visited_blocks))
                    print("New path: %s" % ', '.join(hex(addr) for addr in new_path.visited_blocks))
                    print("\t%s\n\tV.S.\n\t%s\n" % (old_path.path_constraint, new_path.path_constraint))
                    break

        print("Old, all paths: %d" % (len(self.all_true_and_valid_paths_old),))
        print("New, all paths: %d, un-chosen paths: %d" %
                     (len(paths_chosen_new), len([a for a in paths_chosen_new if a is False])))
        # Round 2: for un-chosen paths, check implications using z3
        for new_path_id, new_path in enumerate(self.all_true_and_valid_paths_new):
            # Skip current path if it has been chosen
            if paths_chosen_new[new_path_id]:
                continue

            # If BinDiff fails to get any matching BB addrs, use string similar function instead
            if len(self.matching_bb_addrs) > 0:
                # tic = time.perf_counter()
                sorted_unchosen_paths_old = sorted(self.all_true_and_valid_paths_old,
                                                   key=lambda x: bindiff_similar(x.visited_blocks,
                                                                                 new_path.visited_blocks))
                # toc = time.perf_counter()
                # print("\t Time elapse for BinDiff similar: %.4f seconds\n" % (toc - tic))
            else:
                # tic = time.perf_counter()
                sorted_unchosen_paths_old = sorted(self.all_true_and_valid_paths_old,
                                                   key=lambda x: similar(x.path_constraint_str,
                                                                         new_path.path_constraint_str))
                # toc = time.perf_counter()
                # print("\t Time elapse for str similar: %.4f seconds\n" % (toc - tic))
            sorted_unchosen_paths_old.reverse()

            count = 0
            for old_path in sorted_unchosen_paths_old:
                count += 1

                # Only check the first CHECK_CONSTRAINT_IMPLICATION_LIMIT paths, to save time
                if count > CHECK_CONSTRAINT_IMPLICATION_LIMIT:
                    self._dprint("Count reaches LIMITATION: %d\n" % CHECK_CONSTRAINT_IMPLICATION_LIMIT)
                    break

                if count > max_count:
                    max_count = count
                replaced_old_path_constraint, replaced_new_path_constraint = self.cons_gen.replace_matching_funcs(
                    new_path.path_constraint, old_path.path_constraint, self.matching_functions)

                constraint_implication = self.cons_gen.check_implies(
                    original_constraint=replaced_old_path_constraint,
                    patched_constraint=replaced_new_path_constraint,
                    output=False, update_assumption_map=self._update_assumption)
                if constraint_implication:
                    print("\tCount: %d" % count)
                    print("Old path: %s" % ', '.join(hex(addr) for addr in old_path.visited_blocks))
                    print("New path: %s" % ', '.join(hex(addr) for addr in new_path.visited_blocks))
                    print("\t%s\n \tV.S.\n \t%s\n" % (old_path.path_constraint_str,
                                                             new_path.path_constraint_str))
                    # Update paths_chosen_new
                    paths_chosen_new[new_path_id] = True

                    # Update paths_mapping dict
                    paths_mapping[old_path].append(new_path)
                    break

        # Heuristic C (asymmetric): If len(path) <  Proportion * AVR (all paths), skip
        # For old paths, remove from paths_mapping dict if both conditions are met:
        # - has 0 corresponding new path
        # - len(path) <  Proportion * AVR (all paths)

        # Use 'keys_to_remove' to avoid RuntimeError: dictionary changed size during iteration
        keys_to_remove = []

        for old_path, matching_new_paths in paths_mapping.items():
            if len(matching_new_paths) == 0 and len(old_path.visited_blocks) < 0.8 * average_length_old:
                print("Heuristic C: skip old path: %s" % ", ".join(hex(addr) for addr in old_path.visited_blocks))
                keys_to_remove.append(old_path)

        for key in keys_to_remove:
            assert key in paths_mapping
            del paths_mapping[key]


        # For new paths, mark as 'skip' in paths_chosen_new
        for new_path_id, flag in enumerate(paths_chosen_new):
            if flag is False:
                new_path = self.all_true_and_valid_paths_new[new_path_id]
                if len(new_path.visited_blocks) < 0.8 * average_length_new:
                    paths_chosen_new[new_path_id] = 'skip'
                    print("Heuristic C: Skip new path: %s" % ", ".join(hex(addr) for addr in new_path.visited_blocks))
                    continue

        # Store the paths_mapping dict
        self.paths_mapping = paths_mapping
        print([len(v) for _, v in self.paths_mapping.items()])
        print("Unmapped old paths:")
        for path, new_paths in self.paths_mapping.items():
            if len(new_paths) == 0:
                print("%s\n" % path.path_constraint_str)
                print("%s\n" % ", ".join(hex(addr) for addr in path.visited_blocks))

        # C1_result is True when all new path maps to corresponding old path AND
        # every old path maps to more than 1 new path
        split_result = all(paths_chosen_new) and min([len(x) for x in self.paths_mapping.values()]) > 0
        if split_result is False:
            # Print un-chosen new paths
            print("Unmapped new paths:")
            unchosen_path_ids_new = [_id for _id, flag in enumerate(paths_chosen_new) if flag is False]
            for new_path_id in unchosen_path_ids_new:
                new_path = self.all_true_and_valid_paths_new[new_path_id]
                print("%s\n" % new_path.path_constraint_str)
                print("%s\n" % ", ".join(hex(addr) for addr in new_path.visited_blocks))
        else:
            # Assign the selected paths variable
            self.selected_paths_old = [path for path, new_paths in self.paths_mapping.items() if len(new_paths) > 0]
            self.selected_paths_new = [self.all_true_and_valid_paths_new[_id] for _id, flag in
                                       enumerate(paths_chosen_new) if flag is True]

        self._dprint("\t Condition 1: MAX_COUNT is %d\n" % max_count)

        return split_result

    def _collect_valid_return_constraint(self, all_true_and_valid_paths):
        cumulative_valid_ret_constraint = claripy.false
        for path in all_true_and_valid_paths:
            if path.path_constraint is not None:
                # print("Path constraint", path.path_constraint)
                cumulative_valid_ret_constraint = claripy.simplify(claripy.Or(cumulative_valid_ret_constraint,
                                                             path.path_constraint))
                # print("Cumulative_constraint", cumulative_valid_ret_constraint)
        return claripy.simplify(cumulative_valid_ret_constraint)

    # Output Equivalence
    def _check_condition_2(self):

        print("\n" + "*" * 5 + " Checking Condition 2: Whether global memory writes remain the same or not.")
        result = True
        for old_path, new_paths in self.paths_mapping.items():
            self._dprint("Old path: %s" % ', '.join(hex(addr) for addr in old_path.visited_blocks))
            # skip if no mapping new paths
            if len(new_paths) == 0:
                continue
            old_global_writes_map = self._filter_global_writes(old_path)
            # Merge multiple paths' global writes into one map, store as list
            new_global_writes_map = {}
            addrs_hash = []
            for new_path in new_paths:
                self._dprint("New path: %s" % ', '.join(hex(addr) for addr in new_path.visited_blocks))
                new_global_writes_map = self._filter_global_writes(new_path)
                for addr, value in new_global_writes_map.items():
                    _hash = hash(addr)
                    if _hash not in addrs_hash:
                        new_global_writes_map[addr] = []
                    new_global_writes_map[addr].append(value)

            if len(old_global_writes_map) != len(new_global_writes_map):
                print("Global write map (original binary), length: %d" % (len(old_global_writes_map)))
                for addr, value in old_global_writes_map.items():
                    print("\tAddr: %s\n\tValue: %s\n" % (addr, value))
                print("Global write map (patched binary), length: %d" % (len(new_global_writes_map)))
                for addr, value in new_global_writes_map.items():
                    print("\tAddr: %s\n\tValue: %s\n" % (addr, value))

                print("Condition 2: The length of two global_writes_map is different, return False.")
                result &= self.handle_interactive(curr_cond_res=result, msg='P2_map_length_differs')
            elif len(old_global_writes_map) == 0:
                print("Condition 2: empty global_writes_map, return True.")
            else:
                new_global_writes_chosen = {addr: False for addr in new_global_writes_map.keys()}
                for (key, value) in old_global_writes_map.items():
                    chosen_key = None
                    if key in new_global_writes_map:
                        chosen_key = key
                    else:
                        # Pick the most similar one among all the non-chosen addresses
                        similarities_map = {addr: similar(key, addr) for addr, flag in new_global_writes_chosen.items()
                                            if flag is False}
                        addr_with_max_similarity = max(similarities_map, key=similarities_map.get)
                        new_global_writes_chosen[addr_with_max_similarity] = True
                        chosen_key = addr_with_max_similarity

                    if chosen_key is None:
                        print("Condition 2: %s in old_global_writes_map but not in new_global_writes_map." % (str(key)))
                        result &= self.handle_interactive(curr_cond_res=result, msg='P2_key_not_in_new')
                        continue
                    new_values = new_global_writes_map[chosen_key]
                    if len(new_values) > 1:
                        # When there are multiple values, check the hash
                        value_hash = [hash(val) for val in new_values]
                        if len(set(value_hash)) > 1:
                            print("Condition 2: New paths have multiple values, return False")
                            result &= self.handle_interactive(curr_cond_res=result, msg='P2_multiple_values_in_new')
                            continue
                    new_value = new_values[0]
                    print("Condition 2: Comparing the value stored at address %s." % str(key))
                    replaced_old_value, replaced_new_value = self.cons_gen.replace_matching_funcs(
                        new_value, value, self.matching_functions)
                    current_result = self.cons_gen.check_equals_without_constraint(
                        replaced_old_value, replaced_new_value,
                        output=True, update_assumption_map=self._update_assumption)

                    if current_result is False:
                        user_answer = self.handle_interactive(curr_cond_res=result, msg='P2_values_differs')
                        result &= user_answer

        self.condition_2_result = result
        if self.condition_2_result:
            print("==> Condition 2 is True")
        else:
            print("==> Condition 2 is False")

    def _check_condition_2_merge_all(self):
        def prettyprint_variable(var):
            '''
            t = str(var).replace("<", "").replace(">", "")
            pattern = r"BV\d+ "
            t = re.sub(pattern, "", t)
            a, b = t.split(" + ", maxsplit=1)
            return "[%s + %s]" % (b, a)
            '''
            return str(var)

        print("\n" + "*" * 5 + " Checking Condition 2: Whether global memory writes remain the same or not.")
        old_global_writes_map = self._merge_global_writes(self.all_true_and_valid_paths_old)
        new_global_writes_map = self._merge_global_writes(self.all_true_and_valid_paths_new)
        result = True

        if len(old_global_writes_map) != len(new_global_writes_map):
            print("Global write map (original binary), length: %d" % (len(old_global_writes_map)))
            for addr, value in old_global_writes_map.items():
                print("\tAddr: %s\n\tValue: %s\n" % (addr, value))
            print("Global write map (patched binary), length: %d" % (len(new_global_writes_map)))
            for addr, value in new_global_writes_map.items():
                print("\tAddr: %s\n\tValue: %s\n" % (addr, value))

            print("Condition 2: The length of two global_writes_map is different, return False.")
            result &= self.handle_interactive(curr_cond_res=result, msg='P2_map_length_differs')
        elif len(old_global_writes_map) == 0:
            print("Condition 2: empty global_writes_map, return True.")
        else:
            print("\nmemory-write variables:", ", ".join(
                [prettyprint_variable(k) for k, v in old_global_writes_map.items() if k in new_global_writes_map]))

            new_global_writes_chosen = {addr: False for addr in new_global_writes_map.keys()}
            for (key, value) in old_global_writes_map.items():
                chosen_key = None
                if key in new_global_writes_map:
                    chosen_key = key
                else:
                    # Pick the most similar one among all the non-chosen addresses
                    similarities_map = {addr: similar(key, addr) for addr, flag in new_global_writes_chosen.items()
                                        if flag is False}
                    addr_with_max_similarity = max(similarities_map, key=similarities_map.get)
                    new_global_writes_chosen[addr_with_max_similarity] = True
                    chosen_key = addr_with_max_similarity

                if chosen_key is None:
                    print("Condition 2: %s in old_global_writes_map but not in new_global_writes_map." % (str(key)))
                    result &= self.handle_interactive(curr_cond_res=result, msg='P2_key_not_in_new')
                    continue

                new_value = new_global_writes_map[chosen_key]
                print("Condition 2: Comparing the value stored at address %s." % str(key))
                replaced_old_value, replaced_new_value = self.cons_gen.replace_matching_funcs(
                    new_value, value, self.matching_functions)

                current_result = self.cons_gen.check_equals_only(replaced_old_value, replaced_new_value,
                                                                 self.merged_valid_pc_old, self.merged_valid_pc_new,
                                                                 output=True,
                                                                 update_assumption_map=self._update_assumption)
                for o_value, p_value in self.cons_gen.assumption_map.values():
                    replaced_new_value = replaced_new_value.replace(p_value, o_value)
                if current_result is False:
                    current_result = self.handle_interactive(curr_cond_res=result, msg='P2_values_differs')

                result &= current_result
                # if current_result is False:
                #     print("Condition 2: In address %s, the values in the old/new global_writes_map are different, return False. Details: \n\t%s\n\twith\n\t%s\n\t" % (
                #         str(key), str(value), str(replaced_new_value)))
                # break
        self.condition_2_result = result
        if self.condition_2_result:
            print("==> Condition 2 is True")
        else:
            print("==> Condition 2 is False")

    def _merge_global_writes(self, valid_paths):
        path_to_writes_map = {path: self._filter_global_writes(path) for path in valid_paths}
        addrs = []
        for _map in path_to_writes_map.values():
            addrs.extend(_map.keys())
        addrs = list(set(addrs))
        # print(addrs)
        all_paths_global_writes_map = {
            addr: {'value_constraints': {}, 'merged_value': None}
            for addr in addrs}

        # Collect all path global writes, and store the info into a map
        for (path, one_path_writes_map) in path_to_writes_map.items():
            for (addr, value) in one_path_writes_map.items():
                constraint = path.path_constraint
                if constraint is None:
                    raise Exception("Path constraint should not be None")

                # constraint is not None, add constraint and value into the list
                else:
                    # Format of 'value_constraint': {<value.cache_key>: merged_constraint}
                    value_key = value.cache_key
                    if value_key in all_paths_global_writes_map[addr]['value_constraints']:
                        existing_constraint = all_paths_global_writes_map[addr]['value_constraints'][value_key]
                        all_paths_global_writes_map[addr]['value_constraints'][value_key] = claripy.simplify(
                            claripy.Or(existing_constraint, constraint))
                    else:
                        all_paths_global_writes_map[addr]['value_constraints'][value_key] = constraint


        # Merge values
        for addr in all_paths_global_writes_map.keys():
            # Format of 'value_constraint': {<value.key>: merged_constraint}
            unique_value_constraints = all_paths_global_writes_map[addr]['value_constraints']

            self._dprint(f"Merged unique value constraints dict for, {addr}")
            for value_key, merged_constraint in unique_value_constraints.items():
                self._dprint("\t%s" % value_key.ast)
                # print constraint
                self._dprint("\t\t%s" % merged_constraint)

            # Get the size of all unique values, note that the key is .cache_key
            # Need to use .ast to get the AST
            unique_value_sizes = [value_key.ast.size() for value_key in unique_value_constraints.keys()]

            # Remove duplicate sizes
            unique_value_sizes_no_duplicate = list(set(unique_value_sizes))

            # Assert that all unique values have the same size
            # assert (len(unique_value_sizes_no_duplicate) == 1)

            # Create a default value with the same size as the unique values
            merged_value = claripy.BVS('default_value', max(unique_value_sizes_no_duplicate))

            # Merge all unique values
            for value_key, constraint in unique_value_constraints.items():
                merged_value = self.cons_gen.combine_vals(merged_value, constraint, value_key.ast)

            # Store the merged value
            all_paths_global_writes_map[addr]['merged_value'] = merged_value

        result = {addr: claripy.simplify(all_paths_global_writes_map[addr]['merged_value']) for addr in
                  all_paths_global_writes_map.keys()}
        self._dprint("Global writes map")
        self._dprint(result)
        return result

    def _collect_true_and_valid_paths(self, paths, func_end_points, skip_early_terminated_paths=False):
        all_true_and_valid_paths = []
        paths_after_filtering_names = []
        paths_after_filtering_ret_vals = []

        for path in paths:
            if path.is_false_constraint is not True and path.is_invalid_exit_path is not True:
                # Check whether the last visited block is one of the function's endpoints
                # if path.visited_blocks[-1] not in func_end_points:
                if not any(end_bb_addr in path.visited_blocks for end_bb_addr in func_end_points):
                    self._dprint("!!! Potential error !!! Last visited block %s not in function's end points"
                                 % hex(path.visited_blocks[-1]))
                    edges = '[{}]'.format(', '.join(hex(block_addr) for block_addr in path.visited_blocks))
                    self._dprint("%s\n" % edges)
                    self._dprint("%s\n" % path.path_constraint)
                    if skip_early_terminated_paths:
                        continue

                # Heuristic A: Function call/symbol name not containing error exiting keywords
                self._dprint("\tAll func_names in current path: %s\n" % list(path.func_args_map.keys()))
                if not any(key_word == func_name.replace("Func_", "") for func_name in list(path.func_args_map.keys())
                           for key_word in self._exit_keywords):
                    paths_after_filtering_names.append(path)
                else:
                    # keyword in func_name
                    self._dprint("\tHeuristic A: keyword in func_name\n")

        # Heuristic B: Return value is not negative
        # Collect all unique return values
        unique_return_values_keys = {}
        for path in paths_after_filtering_names:
            ret_value = path.return_value
            if ret_value is not None:
                if ret_value.cache_key not in unique_return_values_keys:
                    unique_return_values_keys[ret_value.cache_key] = []
                # Append the path length to the list
                unique_return_values_keys[ret_value.cache_key].append(len(path.visited_blocks))
        self._dprint("len(unique_return_values_keys): %d\n" % len(unique_return_values_keys))
        self._dprint(unique_return_values_keys)

        # Generate invalid return value list
        # Stores integer values, not BVs
        invalid_return_values = []
        number_of_unique_return_values = len(unique_return_values_keys.keys())
        # Case 1: when there is only two return values 0 and 1
        # Treat the one with shorter average path length as invalid

        if number_of_unique_return_values == 2:
            # Get two keys to a list
            unique_return_values_keys_list = list(unique_return_values_keys.keys())
            # Check if the two values have the same size, if not, skip
            if not (unique_return_values_keys_list[0].ast.size() == \
                unique_return_values_keys_list[1].ast.size()):
                pass

            size = unique_return_values_keys_list[0].ast.size()
            bv_0 = claripy.BVV(0, size)
            bv_1 = claripy.BVV(1, size)
            # The two values are 0 and 1
            if bv_0.cache_key in unique_return_values_keys and bv_1.cache_key in \
                unique_return_values_keys:
                # Get the average path length of the two values
                avg_path_len_0 = sum(unique_return_values_keys[bv_0.cache_key]) / len( \
                    unique_return_values_keys[bv_0.cache_key])
                avg_path_len_1 = sum(unique_return_values_keys[bv_1.cache_key]) / len( \
                    unique_return_values_keys[bv_1.cache_key])
                # The one with shorter average path length is invalid
                if avg_path_len_0 < avg_path_len_1:
                    invalid_return_values.append(0)
                else:
                    invalid_return_values.append(1)

        # Case 2: only one/zero unique return value, no invalid return value
        elif number_of_unique_return_values == 1 or number_of_unique_return_values == 0:
            pass
        # Case 3: Other cases, -1 is invalid, also add 0xffffffff(deprecated)
        # Case 3: Other cases, consider any value between 0xffffffe0 to 0xffffffff as invalid
        if number_of_unique_return_values > 1 and len(invalid_return_values) == 0:
            invalid_return_values.append(-1)

            # Add any value between <0xffffffe0> to <0xffffffff>
            # Determine BV size according to arch.bits
            for value in range(0xffffffe0, 0xffffffff + 1):
                invalid_return_values.append(claripy.BVV(value, self.p_new.arch.bits))

        # Case 4: if there are invalid ret values from config file, add them
        if len(self.binary_info['invalid_ret_values']) > 0:
            # Add BVs
            for value in self.binary_info['invalid_ret_values']:
                print("Adding invalid return value: %x" % value)
                invalid_return_values.append(claripy.BVV(value, self.p_new.arch.bits))

        # Check whether the return value is in the invalid return value list
        for path in paths_after_filtering_names:
            ret_value = path.return_value
            self._dprint("\tReturn value: %s\n" % ret_value)
            # if ret_value is None or (ret_value.size() >= 32 and
            #                          not claripy.is_true(claripy.Extract(31, 0, ret_value).SLT(0))):
            # Two situations:
            # 1. ret_value is None
            # 2. ret_value is not None, but it is not in the invalid return value list
            if ret_value is None or not any(claripy.is_true(ret_value == invalid_return_value_integer)
                            for invalid_return_value_integer in invalid_return_values):
                paths_after_filtering_ret_vals.append(path)
                self._dprint("\tADD\n")
            else:
                print("\tHeuristic B: ret_value in invalid_return_values\n")

        all_true_and_valid_paths = paths_after_filtering_ret_vals
        # For final valid paths, store the path constraint and path constraint string
        for path in all_true_and_valid_paths:
            try:
                path.path_constraint = claripy.simplify(path.path_constraint)
            except:
                pass
            path.path_constraint_str = str(path.path_constraint)

        return all_true_and_valid_paths

    def _filter_global_writes(self, path: Path):
        # global_writes_map = {}
        #
        # bp_pattern = r"\s?(r|e)?bp"
        # sp_pattern = r"\s?(r|e)?sp"
        # for (addr_expr, value) in path.symbolic_memory.items():
        #     # (addr_expr, size) = key
        #     if re.search(bp_pattern, addr_expr) is None and re.search(sp_pattern, addr_expr) is None:
        #         # global_writes_map[addr_expr] = value['value']
        #         global_writes_map[addr_expr] = value
        #
        # return global_writes_map
        return path.symbolic_memory.copy()

    # 3: Compare the return value
    def _check_condition_3(self):
        print("\n" + "*" * 5 + " Checking Condition 3: Whether the return value remains the same or not.")
        if not self.veribin_func_old.return_value_used and not self.veribin_func_new.return_value_used:
            print("Condition 3: No return value, stop.")
            self.condition_3_result = True
        elif self.veribin_func_old.return_value_used != self.veribin_func_new.return_value_used:
            print("Condition 3: Only one of the function has return value. Stop and return False.")
            self.condition_3_result = False
        else:
            result = True
            for old_path, new_paths in self.paths_mapping.items():
                self._dprint("Old path: %s" % ', '.join(hex(addr) for addr in old_path.visited_blocks))
                old_return_value = old_path.return_value
                if len(new_paths) == 0:
                    # For old path that doesn't have corresponding new paths, skip
                    continue
                else:
                    # Use a hash set and a value list to count and store unique return values
                    ret_val_hash_set = set()
                    unique_ret_val_list = []
                    for new_path in new_paths:
                        self._dprint("New path: %s" % ', '.join(hex(addr) for addr in new_path.visited_blocks))
                        new_return_value = new_path.return_value
                        # print(new_return_value)
                        _hash = hash(new_return_value)
                        if _hash not in ret_val_hash_set:
                            ret_val_hash_set.add(_hash)
                            unique_ret_val_list.append(new_return_value)

                # For each unique return value, compare (It's possible that the two values only differ in constraint,
                # and the constraint already implies, in which case we should accept)
                for new_return_value in unique_ret_val_list:

                    replaced_old_return_value, replaced_new_return_value = self.cons_gen. \
                        replace_matching_funcs(new_return_value, old_return_value, self.matching_functions)
                    current_result = self.cons_gen.check_equals_only(
                        replaced_old_return_value, replaced_new_return_value,
                        self.merged_valid_pc_old, self.merged_valid_pc_new,
                        output=True, update_assumption_map=self._update_assumption)

                    if current_result is False:
                        result &= self.handle_interactive(curr_cond_res=result, msg='P3_values_differs')

                    if result is False:
                        break

            self.condition_3_result = result

        if self.condition_3_result:
            print("==> Condition 3 is True.")
        else:
            print("==> Condition 3 is False.")

    def _check_condition_3_merge_all(self):
        print("\n" + "*" * 5 + " Checking Condition 3: Whether the return value remains the same or not.")
        if not self.veribin_func_old.return_value_used and not self.veribin_func_new.return_value_used:
            print("Condition 3: No return value, stop.")
            self.condition_3_result = True
        elif self.veribin_func_old.return_value_used != self.veribin_func_new.return_value_used:
            print("Condition 3: Only one of the function has return value. Stop and return False.")
            self.condition_3_result = False
        else:
            result = True
            old_return_value = self._merge_return_value(self.all_true_and_valid_paths_old)
            new_return_value = self._merge_return_value(self.all_true_and_valid_paths_new)

            replaced_old_return_value, replaced_new_return_value = self.cons_gen. \
                replace_matching_funcs(new_return_value, old_return_value, self.matching_functions)
            # args = self.veribin_func_old.calling_convention.args if self.veribin_func_old.calling_convention is not None else []
            comparison_result = self.cons_gen.check_equals_only(replaced_old_return_value, replaced_new_return_value,
                                                     self.merged_valid_pc_old, self.merged_valid_pc_new,
                                                     output=True,
                                                     update_assumption_map=self._update_assumption)
            if comparison_result is False:
                result &= self.handle_interactive(curr_cond_res=result, msg='P3_values_differs')
            self.condition_3_result = result

        if self.condition_3_result:
            print("==> Condition 3 is True.")
        else:
            print("==> Condition 3 is False.")

    def _merge_return_value(self, paths):
        symbolic_default_value = self.cons_gen.get_constant(0xdeadbeef)
        print("\nMerging the return value...")
        # Collect unique values
        unique_values_constraints = {}
        for path in paths:
            ret_value = path.return_value
            key = ret_value.cache_key
            # If key not in the dict, initialize it
            if key not in unique_values_constraints:
                unique_values_constraints[key] = path.path_constraint
            # Already in, merge constraints
            else:
                unique_values_constraints[key] = claripy.simplify(claripy.Or(unique_values_constraints[key], path.path_constraint))

        # Merge all unique values when len(unique_values_constraints) > 1
        if len(unique_values_constraints) > 1:
            merged_value = symbolic_default_value
            for key, merged_constraint in unique_values_constraints.items():
                value = key.ast
                merged_value = self.cons_gen.combine_vals(merged_value, merged_constraint, value)
        # When len(unique_values_constraints) == 1
        elif len(unique_values_constraints) == 1:
            merged_value = list(unique_values_constraints.keys())[0].ast

        print("Return value is: \n%s" % merged_value)

        return merged_value

    def _check_condition_4(self):
        print("\n" + "*" * 5 + " Checking Condition 4: Whether the functions' arguments remain the same or not.")
        condition_result = True
        for old_path, new_paths in self.paths_mapping.items():
            self._dprint("Old path: %s" % ', '.join(hex(addr) for addr in old_path.visited_blocks))
            for path in new_paths:
                self._dprint("New path: %s" % ', '.join(hex(addr) for addr in path.visited_blocks))
            old_funcs_addr_map = self._get_funcs_args([old_path])
            new_funcs_addr_map = self._get_funcs_args(new_paths)
            if len(old_funcs_addr_map) == 0 and len(new_funcs_addr_map) == 0:
                print("\nCondition 4: empty func_args_map, return True.")
                continue

            mapping_path_result = True
            # matching_functions_map = self.matching_functions
            # Instead of using all matching functions, only use the matching functions that are in the current old/new_funcs_addr_map
            matching_functions_map = {}
            for func_name, matching_func_info in self.matching_functions.items():
                original_func_name = func_name
                patched_func_name = matching_func_info['func_name_patched']
                if original_func_name in old_funcs_addr_map and patched_func_name in new_funcs_addr_map:
                    self._dprint(f"Get matching function: {original_func_name}, {patched_func_name}")
                    matching_functions_map[original_func_name] = matching_func_info

            unmatched_functions_old = list(
                func for func in old_funcs_addr_map.keys() if func not in matching_functions_map.keys())
            unmatched_functions_new = list(func for func in new_funcs_addr_map.keys() if
                                        func not in list(v['func_name_patched'] for v in matching_functions_map.values()))
            self._dprint(f"Global matching functions: {len(self.matching_functions)}, {self.matching_functions}")
            self._dprint(f"current mapping_functions_map: {len(matching_functions_map)}, {matching_functions_map}")
            self._dprint(f"unmatched_functions_old: {unmatched_functions_old}")
            self._dprint(f"unmatched_functions_new: {unmatched_functions_new}")
            # Matched functions
            for (old_func_name, old_func_addr_dict) in old_funcs_addr_map.items():
                if old_func_name in matching_functions_map:
                    new_func_name = matching_functions_map[old_func_name]['func_name_patched']
                    args_count = matching_functions_map[old_func_name]['args_count'] \
                        if 'args_count' in matching_functions_map[old_func_name] else None
                    if new_func_name in new_funcs_addr_map:
                        new_func_addr_dict = new_funcs_addr_map[new_func_name]

                        # Compare the total number of function calls for a given function name
                        if not self.is_num_of_call_equal_by_name(old_func_name, new_func_name,
                                                                old_func_addr_dict, new_func_addr_dict):
                            mapping_path_result &= self.handle_interactive(curr_cond_res=condition_result&mapping_path_result, msg='P4_num_of_call_by_name_differs')
                            continue

                        # func_addr_selected_dict: use to mark whether a function call at a given address is chosen or not
                        old_func_addr_selected_dict = {addr: False for addr in old_func_addr_dict.keys()}
                        new_func_addr_selected_dict = {addr: False for addr in new_func_addr_dict.keys()}

                        # 1: Match function calls according to BinDiff matching BBs
                        if len(self.matching_bb_addrs) > 0:
                            for old_call_addr, old_func_obj_list in old_func_addr_dict.items():
                                try:
                                    new_call_addr = self.matching_bb_addrs[old_call_addr]
                                    new_func_obj_list = new_func_addr_dict[new_call_addr]
                                    # Mark as selected in the selected dict
                                    old_func_addr_selected_dict[old_call_addr] = True
                                    new_func_addr_selected_dict[new_call_addr] = True
                                except KeyError:
                                    continue

                                # Compare the total number of function calls for a given function name and addr
                                if not self.is_num_of_call_equal_by_name_and_addr(
                                        old_func_name, new_func_name,
                                        old_call_addr, new_call_addr,
                                        old_func_obj_list, new_func_obj_list):
                                    mapping_path_result &= self.handle_interactive(curr_cond_res=condition_result&mapping_path_result,
                                                                                   msg='P4_num_of_call_by_name_and_addr_differs')
                                    continue

                                # Compare all occurences function arguments
                                # TODO: improve the ordering matching between function calls
                                for i in range(len(old_func_obj_list)):
                                    old_args = list(old_func_obj_list[i].ast.args)
                                    new_args = list(new_func_obj_list[i].ast.args)

                                    # Compare old_args with new_args
                                    single_func_obj_result = self.compare_one_args_list(old_args, new_args,
                                                                        old_func_name, new_func_name,
                                                                        args_count,
                                                                        curr_cond_res=condition_result&mapping_path_result)
                                    mapping_path_result &= single_func_obj_result

                        # 2. Match the remaining function calls ordered by BB address
                        remaining_old_func_addr_dict = {k: v for k, v in old_func_addr_dict.items() if
                                                        old_func_addr_selected_dict[k] is False}
                        remaining_new_func_addr_dict = {k: v for k, v in new_func_addr_dict.items() if
                                                        new_func_addr_selected_dict[k] is False}

                        # 2.1 Check length equal
                        if not self.is_num_of_remaining_calls_equal(old_func_name, new_func_name,
                                                                remaining_old_func_addr_dict,
                                                                remaining_new_func_addr_dict):
                            mapping_path_result &= self.handle_interactive(curr_cond_res=condition_result&mapping_path_result,
                                                                           msg='P4_num_of_remaining_calls_differs')
                            continue

                        # 2.2 Generate remaining list
                        # Remaining list: [func_obj_1, func_obj_2, ...]
                        remaining_old_func_obj_list = []
                        remaining_new_func_obj_list = []
                        for addr in sorted(remaining_old_func_addr_dict.keys()):
                            remaining_old_func_obj_list.extend(remaining_old_func_addr_dict[addr])
                        for addr in sorted(remaining_new_func_addr_dict.keys()):
                            remaining_new_func_obj_list.extend(remaining_new_func_addr_dict[addr])


                        # 2.3 Start to compare one by one
                        # Format: [func_obj_1, func_obj_2, ...]
                        for i in range(len(remaining_old_func_obj_list)):
                            # There could be multiple function calls at one addr
                            old_args = list(remaining_old_func_obj_list[i].ast.args)
                            new_args = list(remaining_new_func_obj_list[i].ast.args)

                            # Compare old_args with new_args
                            single_result = self.compare_one_args_list(old_args, new_args,
                                                                old_func_name, new_func_name,
                                                                args_count,
                                                                curr_cond_res=condition_result&mapping_path_result)
                            mapping_path_result &= single_result

            # For unmatched functions
            for old_func_name in unmatched_functions_old:
                old_func_addr_dict = old_funcs_addr_map[old_func_name]
                print(
                    "\nCondition 4: The function <%s> in the original binary doesn't have a corresponding function." % old_func_name)
                print("\tDetails:")
                for old_func_obj_list in old_func_addr_dict.values():
                    for i in range(len(old_func_obj_list)):
                        old_args = list(old_func_obj_list[i].ast.args)
                        print("\t%s(%s)" % (old_func_name, ', '.join(map(str, old_args))))

                mapping_path_result &= self.handle_interactive(curr_cond_res=condition_result&mapping_path_result,
                                                               msg='P4_unmatched_func_in_old')

            for new_func_name in unmatched_functions_new:
                new_func_addr_dict = new_funcs_addr_map[new_func_name]
                print(
                    "\nCondition 4: The function <%s> in the patched binary doesn't have a corresponding function." % new_func_name)
                print("\tDetails:")
                for new_func_obj_list in new_func_addr_dict.values():
                    for i in range(len(new_func_obj_list)):
                        new_args = list(new_func_obj_list[i].ast.args)
                        print("\t%s(%s)" % (new_func_name, ', '.join(map(str, new_args))))

                mapping_path_result &= self.handle_interactive(curr_cond_res=condition_result&mapping_path_result,
                                                               msg='P4_unmatched_func_in_new')

            condition_result &= mapping_path_result

        self.condition_4_result = condition_result
        if self.condition_4_result:
            print("==> Condition 4 is True.")
        else:
            print("==> Condition 4 is False.")


    def _check_condition_4_merge_all(self):
        print("\n" + "*" * 5 + " Checking Condition 4: Whether the functions' arguments remain the same or not.")
        condition_result = True
        # old_funcs_args_map = self._get_funcs_args(self.selected_paths_old)
        # new_funcs_args_map = self._get_funcs_args(self.selected_paths_new)
        old_funcs_addr_map = self._get_funcs_args(self.selected_paths_old)
        new_funcs_addr_map = self._get_funcs_args(self.selected_paths_new)
        if len(old_funcs_addr_map) == 0 and len(new_funcs_addr_map) == 0:
            print("\nCondition 4: empty func_args_map, return True.")
        matched_result = True
        unmatched_result = True
        # matching_functions_map = self.matching_functions

        # Instead of using all matching functions, only use the matching functions that are in the current old/new_funcs_addr_map
        # (only in current selected paths)
        matching_functions_map = {}
        for func_name, matching_func_info in self.matching_functions.items():
            original_func_name = func_name
            patched_func_name = matching_func_info['func_name_patched']
            if original_func_name in old_funcs_addr_map and patched_func_name in new_funcs_addr_map:
                self._dprint(f"Get matching function: {original_func_name}, {patched_func_name}")
                matching_functions_map[original_func_name] = matching_func_info

        unmatched_functions_old = list(
            func for func in old_funcs_addr_map.keys() if func not in matching_functions_map.keys())
        unmatched_functions_new = list(func for func in new_funcs_addr_map.keys() if
                                       func not in list(v['func_name_patched'] for v in matching_functions_map.values()))
        # Matched functions
        for (old_func_name, old_func_addr_dict) in old_funcs_addr_map.items():
            if old_func_name in matching_functions_map:
                new_func_name = matching_functions_map[old_func_name]['func_name_patched']
                args_count = matching_functions_map[old_func_name]['args_count'] \
                    if 'args_count' in matching_functions_map[old_func_name] else None
                if new_func_name in new_funcs_addr_map:
                    new_func_addr_dict = new_funcs_addr_map[new_func_name]

                    # Compare the total number of function calls for a given function name
                    if not self.is_num_of_call_equal_by_name(old_func_name, new_func_name,
                                                             old_func_addr_dict, new_func_addr_dict):
                        matched_result &= self.handle_interactive(curr_cond_res=condition_result&matched_result,
                                                                  msg='P4_num_of_call_by_name_differs')
                        continue

                    # func_addr_selected_dict: use to mark whether a function call at a given address is chosen or not
                    old_func_addr_selected_dict = {addr: False for addr in old_func_addr_dict.keys()}
                    new_func_addr_selected_dict = {addr: False for addr in new_func_addr_dict.keys()}

                    # 1: Match function calls according to BinDiff matching BBs
                    if len(self.matching_bb_addrs) > 0:
                        for old_call_addr, old_func_obj_list in old_func_addr_dict.items():
                            try:
                                new_call_addr = self.matching_bb_addrs[old_call_addr]
                                new_func_obj_list = new_func_addr_dict[new_call_addr]
                                # Mark as selected in the selected dict
                                old_func_addr_selected_dict[old_call_addr] = True
                                new_func_addr_selected_dict[new_call_addr] = True
                            except KeyError:
                                continue

                            # Compare the total number of function calls for a given function name and addr
                            if not self.is_num_of_call_equal_by_name_and_addr(
                                    old_func_name, new_func_name,
                                    old_call_addr, new_call_addr,
                                    old_func_obj_list, new_func_obj_list):
                                matched_result &= self.handle_interactive(curr_cond_res=condition_result&matched_result,
                                                                          msg='P4_num_of_call_by_name_and_addr_differs')
                                continue

                            # TODO: improve the ordering matching between function calls
                            for i in range(len(old_func_obj_list)):
                                old_args = list(old_func_obj_list[i].ast.args)
                                new_args = list(new_func_obj_list[i].ast.args)

                                # Compare old_args with new_args
                                temp_result = self.compare_one_args_list(old_args, new_args,
                                                                    old_func_name, new_func_name,
                                                                    args_count,
                                                                    curr_cond_res=condition_result&matched_result)
                                matched_result &= temp_result

                    # 2. Match the remaining function calls ordered by BB address
                    remaining_old_func_addr_dict = {k: v for k, v in old_func_addr_dict.items() if
                                                    old_func_addr_selected_dict[k] is False}
                    remaining_new_func_addr_dict = {k: v for k, v in new_func_addr_dict.items() if
                                                    new_func_addr_selected_dict[k] is False}

                    # 2.1 Check length equal
                    if not self.is_num_of_remaining_calls_equal(old_func_name, new_func_name,
                                                               remaining_old_func_addr_dict,
                                                               remaining_new_func_addr_dict):
                        matched_result &= self.handle_interactive(curr_cond_res=condition_result&matched_result,
                                                                  msg='P4_num_of_remaining_calls_differs')
                        continue

                    # 2.2 Generate remaining list
                    # Remaining list: [func_obj_1, func_obj_2, ...]
                    remaining_old_func_obj_list = []
                    remaining_new_func_obj_list = []
                    for addr in sorted(remaining_old_func_addr_dict.keys()):
                        remaining_old_func_obj_list.extend(remaining_old_func_addr_dict[addr])
                    for addr in sorted(remaining_new_func_addr_dict.keys()):
                        remaining_new_func_obj_list.extend(remaining_new_func_addr_dict[addr])


                    # 2.3 Start to compare one by one
                    # Format: [func_obj_1, func_obj_2, ...]
                    for i in range(len(remaining_old_func_obj_list)):
                        # There could be multiple function calls at one addr
                        old_args = list(remaining_old_func_obj_list[i].ast.args)
                        new_args = list(remaining_new_func_obj_list[i].ast.args)

                        # Compare old_args with new_args
                        temp_result = self.compare_one_args_list(old_args, new_args,
                                                            old_func_name, new_func_name,
                                                            args_count,
                                                            curr_cond_res=condition_result&matched_result)
                        matched_result &= temp_result

        # For unmatched functions
        for old_func_name in unmatched_functions_old:
            old_func_addr_dict = old_funcs_addr_map[old_func_name]
            print(
                "\nCondition 4: The function <%s> in the original binary doesn't have a corresponding function." % old_func_name)
            print("\tDetails:")
            for old_func_obj_list in old_func_addr_dict.values():
                for i in range(len(old_func_obj_list)):
                    old_args = list(old_func_obj_list[i].ast.args)
                    print("\t%s(%s)" % (old_func_name, ', '.join(map(str, old_args))))

            temp_result = self.handle_interactive(curr_cond_res=condition_result&unmatched_result,
                                                  msg='P4_unmatched_func_in_old')
            unmatched_result &= temp_result

        for new_func_name in unmatched_functions_new:
            new_func_addr_dict = new_funcs_addr_map[new_func_name]
            print(
                "\nCondition 4: The function <%s> in the patched binary doesn't have a corresponding function." % new_func_name)
            print("\tDetails:")
            for new_func_obj_list in new_func_addr_dict.values():
                for i in range(len(new_func_obj_list)):
                    new_args = list(new_func_obj_list[i].ast.args)
                    print("\t%s(%s)" % (new_func_name, ', '.join(map(str, new_args))))

            temp_result = self.handle_interactive(curr_cond_res=condition_result&unmatched_result,
                                                  msg='P4_unmatched_func_in_new')
            unmatched_result &= temp_result

        condition_result &= (matched_result and unmatched_result)

        self.condition_4_result = condition_result
        if self.condition_4_result:
            print("==> Condition 4 is True.")
        else:
            print("==> Condition 4 is False.")

    def _get_funcs_args(self, valid_paths):
        final_funcs_args_map = {}
        for path in valid_paths:
            for (func_name, args_map) in path.func_args_map.items():
                # func_name = func_name.replace('Func_', '')
                if func_name not in final_funcs_args_map:
                    final_funcs_args_map[func_name] = {}

                for bb_addr, func_obj_list in args_map.items():
                    if bb_addr not in final_funcs_args_map[func_name].keys():
                        final_funcs_args_map[func_name][bb_addr] = []
                    for func_obj in func_obj_list:
                        if func_obj.cache_key not in final_funcs_args_map[func_name][bb_addr]:
                            final_funcs_args_map[func_name][bb_addr].append(func_obj.cache_key)

        if len(final_funcs_args_map) > 0:
            print("\n\nFunction objects info\n")
            for func_name, info in final_funcs_args_map.items():
                print("\n\t%s" % func_name)
                for bb_addr, func_obj_list in info.items():
                    print("\t\t%s" % hex(bb_addr))
                    for func_obj in func_obj_list:
                        print("\t\t\t%s" % func_obj.ast)
            print("\nEnd of function objects info\n\n")
        return final_funcs_args_map

    def handle_interactive(self, curr_cond_res, msg=''):
        """
        Get result from user if in interactive mode
        Check for two arguments:
        - self._interactive: Whether to interact with user
        - self._interactive_skip_false: If the current condition result is False, whether to skip the interactive
        :param curr_cond_res: Current result for the condition
        :return: Whether user thinks the modificiation can be ignored
        """

        # When in interactive mode
        if self._interactive:
            # Skip false or not
            if self._interactive_skip_false and curr_cond_res is False:
                return False
            # Otherwise, ask user
            try:
                user_input = ask_user_for_modification(msg=msg)
            except:
                user_input = False
            return user_input
        else:
            # Not in interactive mode, return False
            return False



    @staticmethod
    def is_num_of_call_equal_by_name(old_func_name, new_func_name, old_func_addr_dict, new_func_addr_dict):
        """
        Return false if the number of calls to two functions is different
        :param old_func_name:
        :param new_func_name:
        :param old_func_addr_dict: {bb_addr: func_obj_list}
        :param new_func_addr_dict: {bb_addr: func_obj_list}
        :return:
        """

        old_func_call_num = sum(len(func_obj_list) for func_obj_list in old_func_addr_dict.values())
        new_func_call_num = sum(len(func_obj_list) for func_obj_list in new_func_addr_dict.values())
        if old_func_call_num != new_func_call_num:
            print("\nCondition 4: The number of calls to <%s> and <%s> is different (%d v.s. %d)."
                  % (old_func_name, new_func_name, old_func_call_num, new_func_call_num))
            print("\tDetails:")
            for bb_addr, func_obj_list in old_func_addr_dict.items():
                print("\n\t\t%s" % hex(bb_addr))
                for func_obj in func_obj_list:
                    print("\t\t\t%s" % func_obj.ast)
            print("\tV.S.")
            for bb_addr, func_obj_list in new_func_addr_dict.items():
                print("\n\t\t%s" % hex(bb_addr))
                for func_obj in func_obj_list:
                    print("\t\t\t%s" % func_obj.ast)
            return False
        else:
            return True

    @staticmethod
    def is_num_of_call_equal_by_name_and_addr(old_func_name, new_func_name,
                                              old_call_addr, new_call_addr,
                                              old_func_obj_list, new_func_obj_list):
        """
        Return false if the number of calls to two functions at matching address is different
        :param old_func_name:
        :param new_func_name:
        :param old_func_obj_list: [func_obj_1, func_obj_2, ...]
        :param new_func_obj_list: [func_obj_1, func_obj_2, ...]
        :return:
        """

        old_func_call_num = len(old_func_obj_list)
        new_func_call_num = len(new_func_obj_list)
        if old_func_call_num != new_func_call_num:
            print("\nCondition 4: The number of calls to <%s> and <%s> is different (%s: %d v.s. %s: %d)"
                  % (old_func_name, hex(old_call_addr), new_func_name,
                     old_func_call_num, hex(new_call_addr), new_func_call_num))
            print("\tDetails:")

            print("\n\t\t%s" % hex(old_call_addr))
            for func_obj in old_func_obj_list:
                print("\t\t\t%s" % func_obj.ast)

            print("\tV.S.")

            print("\n\t\t%s" % hex(new_call_addr))
            for func_obj in new_func_obj_list:
                print("\t\t\t%s" % func_obj.ast)
            return False
        else:
            return True

    @staticmethod
    def is_num_of_remaining_calls_equal(old_func_name, new_func_name,
                                      old_remaining_dict, new_remaining_dict):
        """
        Return false if the number of remaining calls is different
        :return:
        """

        old_func_call_num = sum(len(func_obj_list) for func_obj_list in old_remaining_dict.values())
        new_func_call_num = sum(len(func_obj_list) for func_obj_list in new_remaining_dict.values())

        if old_func_call_num != new_func_call_num:
            print("\nCondition 4: The number of remaining calls to <%s> and <%s> is different (%d v.s. %d)."
                  % (old_func_name, new_func_name, old_func_call_num, new_func_call_num))
            print("\tDetails:")
            for bb_addr, func_obj_list in old_remaining_dict.items():
                print("\n\t\t%s" % hex(bb_addr))
                for func_obj in func_obj_list:
                    print("\t\t\t%s" % func_obj.ast)
            print("\tV.S.")
            for bb_addr, func_obj_list in new_remaining_dict.items():
                print("\n\t\t%s" % hex(bb_addr))
                for func_obj in func_obj_list:
                    print("\t\t\t%s" % func_obj.ast)
            return False
        else:
            return True

    def compare_one_args_list(self, old_args, new_args,
                                    old_func_name, new_func_name,
                                    args_count,
                                    curr_cond_res):
        """
        Compare one pair of args list
        :param old_args: list of arguments, [arg_1, arg_2, ...]
        :param new_args: lift of arguments, [arg_1, arg_2, ...]
        :param old_func_name:
        :param new_func_name:
        :param args_count: number of args to be compared
        :param curr_cond_res: current condition result
        :return:
            result: Whether two arguments lists are the same
        """
        result = True
        # Compare old_args with new_args
        if args_count is None:
            # get the minimum argument length
            args_count = min(len(old_args), len(new_args))

        # Compare the length
        if len(old_args) != len(new_args):
            print("\nCondition 4: The args lists of %s(%s) and %s(%s) have different lengths, "
                  "only comparing the first %d argument(s)."
                  % (old_func_name, ', '.join(map(str, old_args)), new_func_name,
                     ', '.join(map(str, new_args)), args_count))
            # continue

        print("\nCondition 4: Comparing %s(%s) and %s(%s), args_count: %d" % (
            old_func_name, ', '.join(map(str, old_args)),
            new_func_name, ', '.join(map(str, new_args)),
            args_count))
        # Check equal for each argument
        for j in range(args_count):
            old_value = old_args[j]
            new_value = new_args[j]

            # If both old value and new value are concrete value,
            # And both of them are from '.rodata' section
            # Then we compare the string value stored in these two addresses
            if is_rodata_addr(self.p_old, old_value) and \
                    is_rodata_addr(self.p_new, new_value):
                old_value_string = load_string_content_from_binary(self.p_old, old_value)
                new_value_string = load_string_content_from_binary(self.p_new, new_value)
                if old_value_string is not None and new_value_string is not None:
                    current_result = self.cons_gen.check_equals_only(
                        old_value_string, new_value_string,
                        self.merged_valid_pc_old, self.merged_valid_pc_new,
                        output=True, update_assumption_map=False)
                    if current_result is False:
                        print("\nCondition 4: When comparing \n\t%s(%s)\n\twith\n\t%s(%s)" %
                              (old_func_name, ', '.join(map(str, old_args)), new_func_name,
                               ', '.join(map(str, new_args))))
                        print("\t\tThe %d-th argument is different:" % (j + 1))
                        print("\t\t\t%s" % old_value_string)
                        print("\t\tV.S.")
                        print("\t\t\t%s" % new_value_string)
                        interactive_result = self.handle_interactive(curr_cond_res=curr_cond_res&result, msg='P4_string_values_differs')
                        result &= interactive_result
                    continue

            # replace the old value with the new value
            replaced_old_value, replaced_new_value = self.cons_gen. \
                replace_matching_funcs(new_value, old_value, self.matching_functions)
            new_args[j] = replaced_new_value
            # todo: replace the whole list of arguments with matching functions
            current_result = self.cons_gen.check_equals_only(
                replaced_old_value, replaced_new_value,
                self.merged_valid_pc_old, self.merged_valid_pc_new,
                output=True, update_assumption_map=self._update_assumption)

            if current_result is False:
                print("\nCondition 4: When comparing \n\t%s(%s)\n\twith\n\t%s(%s)" %
                      (old_func_name, ', '.join(map(str, old_args)), new_func_name,
                       ', '.join(map(str, new_args))))
                print("\n\tThe #%d argument is different:\n\t%s\n\tand\n\t%s" % (
                    j + 1, old_value, replaced_new_value))

                interactive_result = self.handle_interactive(curr_cond_res=curr_cond_res&result, msg='P4_values_differs')
                result &= interactive_result

                # If the user accepts the difference, update the assumption map
                if interactive_result is True:
                    self.add_to_user_assumptions_map(old_value, replaced_new_value)

        return result

if __name__ == "__main__":

    parser = ArgumentParser(formatter_class=ArgumentDefaultsHelpFormatter, conflict_handler='resolve')
    parser.add_argument('--original_path', required=True, help='Original binary file path')
    parser.add_argument('--patched_path', required=True, help='Patched binary file path')
    parser.add_argument('--config_path', required=False, default=None, help='Path to the config file')
    parser.add_argument('--func_addr_original', required=True, help='Function address in the original binary, to be compared')
    parser.add_argument('--func_addr_patched', required=True, help='Function address in the patched binary, to be compared')
    parser.add_argument('--debug', required=False, type=str2bool, default=True, help='Enable debug mode or not')
    parser.add_argument('--interactive', required=False, type=str2bool, default=True,
                        help='Accept user input during the analysis or not')
    parser.add_argument('--interactive_skip_false', required=False, type=str2bool, default=True,
                        help='Skip the interactive mode if the result is False. Set it to False if you want to ask user for all modifications regardless of the result.')
    parser.add_argument('--limitation', required=False, type=int, default=20,
                        help='The maximum number of allowed comparisons per path in C1')
    parser.add_argument('--verbose', required=False, type=str2bool, default=False,
                        help='Verbose mode, with details of patch behavior')
    parser.add_argument('--merge_all', required=False, type=str2bool, default=False,
                        help='Comparison strategy: merge all or split into path pairs')
    parser.add_argument('--update_assumption', required=False, type=str2bool, default=True,
                        help='Whether to collect and replace offset changes or not.')
    parser.add_argument('--use_ida', required=False, type=str2bool, default=True,
                        help='Whether to use IDA to generate BinDiff or not.')
    parser.add_argument('--graph_format', required=False, type=str, default='dot',choices=['dot', 'png'],
                        help='The format for plotting out the CFGs.')
    parser.add_argument('--is_ppc', required=False, type=str, default=False,
                        help='Whether the binary is special PPC format or not.')
    parser.add_argument('--use_cache', required=False, type=str2bool, default=True,
                        help='Whether to use pickled CFG or not.')
    parser.add_argument('--load_debug_info', required=False, type=str2bool, default=True,
                        help='Whether to load debug info or not.')
    parser.add_argument('--symbolic_memory_read_zero', required=False, type=str2bool, default=False,
                        help='Whether to symbolic read zero or not.')


    args = parser.parse_args()
    filepath_original = args.original_path
    filepath_patched = args.patched_path
    func_addr_original = int(args.func_addr_original, base=16)
    func_addr_patched = int(args.func_addr_patched, base=16)
    config_path = args.config_path

    if not os.path.isfile(filepath_original):
        print(f'File {filepath_original} does not exist.')
        sys.exit(-1)

    if not os.path.isfile(filepath_patched):
        print(f'File {filepath_patched} does not exist.')
        sys.exit(-1)

    if config_path and not os.path.isfile(config_path):
        print(f'File {config_path} does not exist.')
        sys.exit(-1)

    global CHECK_CONSTRAINT_IMPLICATION_LIMIT
    CHECK_CONSTRAINT_IMPLICATION_LIMIT  = args.limitation

    tic = time.perf_counter()
    try:
        additional_params = {
            'debug': args.debug,
            'interactive': args.interactive,
            "interactive_skip_false": args.interactive_skip_false,
            'verbose': args.verbose,
            'merged': args.merge_all,
            'update_assumption': args.update_assumption,
            'use_ida': args.use_ida,
            'graph_format': args.graph_format,
            'is_ppc': args.is_ppc,
            'use_cache': args.use_cache,
            'load_debug_info': args.load_debug_info,
            'symbolic_memory_read_zero': args.symbolic_memory_read_zero
        }
        VeriBin(filepath_original, filepath_patched, config_path, func_addr_original, func_addr_patched, additional_params)
    except Exception as e:
        import traceback
        print(traceback.format_exc())
    toc = time.perf_counter()
    print("Time elapse for VeriBinCheck: %.4f seconds\n" % (toc - tic))
