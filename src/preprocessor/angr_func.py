import angr
import os
import pickle
import archinfo
import argparse

# Reset the recursion limit
import sys
sys.setrecursionlimit(10000)

load_options = {'auto_load_libs': False, 'load_debug_info': True}
flirt_path = os.path.realpath(os.path.join(os.path.dirname(__file__), "../flirt_signatures"))


class Func_info(object):
    def __init__(self, path, func_addr, output_file_path=None, is_ppc=False, skip_unmapped_addrs=True):
        # Initialize the class
        self.path = path
        self.func_addr = func_addr
        self.output_file_path = output_file_path
        self.is_ppc = is_ppc
        self.skip_unmapped_addrs = skip_unmapped_addrs

        self.func_info = {}

        # Construct the class
        self.construct()

        # Process the function info
        self.process_func_info()

        # Only output if the output file path is not None
        if self.output_file_path:
            # Write the function info to the output file
            self.write_func_info()


    def construct(self):
        try:
            self.cfg = pickle.load(open(self.path + ".cfg.p", "rb"))
            self.p = pickle.load(open(self.path + ".project.p", "rb"))
        except:
            if self.is_ppc:
                if self.is_ppc == "PowerPC:BE:32:e200":
                    import pypcode
                    arch = archinfo.ArchPcode("PowerPC:BE:32:e200")
                    self.p = angr.Project(self.path, arch=arch, auto_load_libs=False,
                                          engine=angr.engines.UberEnginePcode)
                    self.cfg = self.p.analyses.CFGFast(show_progressbar=False,
                                                       normalize=True, data_references=True,
                                                       force_complete_scan=False,
                                                       force_smart_scan=True,
                                                       skip_unmapped_addrs=self.skip_unmapped_addrs)
                # elif self.is_ppc == "PowerPC:BE:32:MPC8270":
                #     self.p = run_project(self.path)
                #     self.p, self.cfg = get_p_and_cfg(self.p)
                else:
                    raise ValueError("Unsupported PowerPC architecture")

                # Register the pcode arch default calling convention
                arch= archinfo.ArchPcode(self.p.arch.name)
                angr.engines.pcode.cc.register_pcode_arch_default_cc(arch)
            else:
                self.p = angr.Project(self.path, load_options=load_options)
                try:
                    self.cfg = self.p.analyses.CFGFast(show_progressbar=False,
                                                        normalize=True,
                                                        # Add function_starts to force angr to analyze the function
                                                        function_starts=[self.func_addr],
                                                        # Copy same default options from angr-management
                                                        resolve_indirect_jumps=True,
                                                        data_references=True,
                                                        cross_references=False,
                                                        skip_unmapped_addrs=self.skip_unmapped_addrs,
                                                        exclude_sparse_regions=True,
                                                        force_complete_scan=False,
                                                        force_smart_scan=True,
                                                        # End of angr-management options
                                                    )

                    # Try to load func, if not found, re-generated the cfg,
                    # without 'function_starts' set to the func_addr
                    # self.func = self.cfg.kb.functions.get_by_addr(self.func_addr)
                except KeyError:
                    # KeyError could happens when: 1) the function is not found in the cfg
                    # 2) during the CFGFast analysis, some other functions are not found
                    self.cfg = self.p.analyses.CFGFast(show_progressbar=True,
                                                    normalize=True, data_references=True,
                                                    force_complete_scan=False,
                                                    force_smart_scan=True,
                                                    skip_unmapped_addrs=self.skip_unmapped_addrs)

            angr.flirt.load_signatures(flirt_path)
            self.p.analyses.Flirt()
            if not os.path.exists(self.p.filename + ".cfg.p"):
                pickle.dump(self.cfg, open(self.p.filename + ".cfg.p", "wb"))
            if not os.path.exists(self.p.filename + ".project.p"):
                pickle.dump(self.p, open(self.p.filename + ".project.p", "wb"))

        self.func = self._get_func_by_addr(self.func_addr)
        self.func.normalize()

    def process_func_info(self):
        # Decompile current func
        try:
            self.p.analyses.Decompiler(self.func, cfg=self.cfg)
        except:
            import traceback
            traceback.print_exc()
            print(f"\nCannot decompile the function {hex(self.func_addr)}, continue")
            pass
        # Add current function to the function info
        current_func_name, current_func_prototype = self.get_func_prototype(self.func_addr)
        func_size = self.func.size
        self.func_info[self.func_addr] = {'func_name': current_func_name, 'prototype': current_func_prototype, 'size': func_size}

        # Get all the function calls prototypes within the given function
        for call_site_addr in self.func.get_call_sites():
            call_target_addr = self.func.get_call_target(call_site_addr)
            if call_target_addr not in self.func_info:
                try:
                    func_name, func_prototype = self.get_func_prototype(call_target_addr)
                    target_call_func = self._get_func_by_addr(call_target_addr)
                    self.func_info[call_target_addr] = {'func_name': func_name, 'prototype': func_prototype, 'size': target_call_func.size if target_call_func else None}
                except:
                    import traceback
                    traceback.print_exc()
                    print("Fail to get func info from angr for %s" % hex(call_target_addr))

    def get_func_info(self):
        return self.func_info

    def write_func_info(self):
        # Write the function info to the output file
        with open(self.output_file_path, 'w+') as f:
            for call_target_addr in self.func_info:
                func_name = self.func_info[call_target_addr]['func_name']
                prototype = self.func_info[call_target_addr]['prototype']
                size = self.func_info[call_target_addr]['size']
                f.write("%s;;%s;;%s;;%s\n" % (hex(call_target_addr),func_name, prototype, size))

    def get_func_prototype(self, call_target_addr):
        func = self._get_func_by_addr(call_target_addr)
        try:
            # Decompile the function
            self.p.analyses.Decompiler(func, cfg=self.cfg)
        except:
            import traceback
            traceback.print_exc()
            print(f"\nCannot decompile the function {hex(call_target_addr)}, continue")
            pass
        func_name = func.demangled_name.replace(".", "")
        # print("func info in kb functions:", func_name, func.prototype)
        if func.calling_convention is None:
            func.calling_convention = angr.calling_conventions.DEFAULT_CC[self.p.arch.name]['Linux'](self.p.arch)

        # Method 2: Variable Recovery + Calling Convention
        if func.prototype is None:
            try:
                _ = self.p.analyses.VariableRecoveryFast(func)
                cc_analysis = self.p.analyses.CallingConvention(func, analyze_callsites=True)
                if func.prototype is None:
                    func.prototype = cc_analysis.prototype
                # print("func info method 2 (Variable Recovery):", func_name, func.prototype, cc_analysis.prototype)
            except Exception as e:
                print(f"Exception caught during variable recovery: {e}")
        # Method 3: (ref: angr tests) DEFAULT_CC + find_declaration
        if func.prototype is None:
            # func.calling_convention = angr.calling_conventions.DEFAULT_CC[state.project.arch.name]\
            #     (state.project.arch)
            func.find_declaration()
            # print("func info method 3 (find declaration):", func_name, func.prototype)

        # Method 4: otherwise, the function argument should be empty (create a default prototype with 0 arg)
        if func.prototype is None:
            # func.arguments should be empty, thus prototype is expected to be () -> char*
            func.prototype = func.calling_convention.guess_prototype(func.arguments).with_arch(self.p.arch)
            # print("func info method 4 (empty):", func_name, func.prototype)

        if func.prototype is None:
            assert False and  "Function prototype is None"

        if func.prototype is not None and func.prototype._arch is None:
            func.prototype = func.prototype.with_arch(self.p.arch)

        return func_name, func.prototype

    def _get_func_by_addr(self, addr):
        # Check whether func addr is in the function map
        if self.cfg.kb.functions.contains_addr(addr):
            func = self.cfg.kb.functions.get_by_addr(addr)
        else:
            # Get floor function
            func = self.cfg.kb.functions.floor_func(addr)

        func.normalize()
        func.project
        # Fix a NoneType error
        if hasattr(func, '_project'):
            func._project = self.p

        return func

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Get function info from angr')
    # Required arguments: file_path, func_addr, output_log_path
    parser.add_argument('--file_path', type=str, help='The path to the binary file')
    parser.add_argument('--func_addr', type=str, help='The address of the function')
    parser.add_argument('--output_log_path', type=str, help='The path to the output log file')


    file_path = parser.parse_args().file_path
    func_addr = int(parser.parse_args().func_addr, 16)
    output_log_path = parser.parse_args().output_log_path
    Func_info(file_path, func_addr, output_log_path)
