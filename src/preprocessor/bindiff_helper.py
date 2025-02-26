import os
import sqlite3
import subprocess

g_differ_path = r"/usr/bin/bindiff"
ida_64_path = os.path.abspath(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                            '../../../ida8.3/idat64'))
ida_32_path = os.path.abspath(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                            '../../../ida8.3/idat'))
idapython_script_path = os.path.dirname(__file__) + '/bindiff_rebase.py'

class IdaBinDiff(object):
    def __init__(self, primary, secondary, func_addr_original, func_addr_patched, size, base_addr, debug=True):
        self.is_arm = func_addr_original % 2 == 1
        self.primary_path = primary
        self.secondary_path = secondary
        self.func_addr_original = func_addr_original - 1 if self.is_arm else func_addr_original
        self.func_addr_patched = func_addr_patched - 1 if self.is_arm else func_addr_patched
        self.ins_matching_map = None
        self.affected_func_info = None
        self.all_matching_func_info = None
        self._base_addr = base_addr
        self._debug = debug
        self._size = size

        if size == 32:
            self.ida_path = ida_32_path
        elif size == 64:
            self.ida_path = ida_64_path
        else:
            raise ValueError('SIZE must be either 32 or 64, {} provided'.format(size))

        self._analysis()

    def _dprint(self, msg):
        if self._debug:
            print('[+] {}'.format(msg))

    def _analysis(self):
        if self._make_BinExport(self.primary_path) != 0:
            raise Exception('primary BinExport failed: {}'.format(self.primary_path))
        if self._make_BinExport(self.secondary_path) != 0:
            raise Exception('secondary BinExport failed: {}'.format(self.secondary_path))
        self._make_BinDiff()

        # Load the .BinDiff database, assign to the class variable
        self._load_BinDiff()

    def _make_idb(self, target):
        ext = '.i64' if self._size == 64 else '.idb'
        binexp_path = target + ext
        if os.path.exists(binexp_path):
            self._dprint('already existed idb: {}'.format(binexp_path))
            return binexp_path

        cmd = [self.ida_path, '-B', '-S"%s" \"%s\"' % (idapython_script_path, int(self._base_addr)), '-P+', target]
        self._dprint(' '.join(cmd))

        self._dprint('getting idb for {}'.format(target))
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = proc.communicate()
        return binexp_path

    def _make_BinExport(self, target):
        idb_path = self._make_idb(target)
        binexp_path = target + '.BinExport'
        if os.path.exists(binexp_path):
            self._dprint('already existed BinExport: {}'.format(binexp_path))
            return 0

        cmd = [self.ida_path, '-A', '-OBinExportModule:{}'.format(binexp_path), '-OBinExportAutoAction:BinExportBinary',
               idb_path]
        self._dprint(' '.join(cmd))

        self._dprint('getting BinExport for {}'.format(target))
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = proc.communicate()
        return proc.returncode

    def _get_BinDiff_path(self):
        return self.primary_path + '_vs_' + os.path.basename(self.secondary_path) + '.BinDiff'

    def _make_BinDiff(self):
        pri_binexp = self.primary_path + '.BinExport'
        sec_binexp = self.secondary_path + '.BinExport'
        bindiff_path = self._get_BinDiff_path()
        if os.path.exists(bindiff_path):
            self._dprint('already existed BinDiff: {}'.format(bindiff_path))
            return

        cmd = [g_differ_path, '--primary={}'.format(pri_binexp), '--secondary={}'.format(sec_binexp),
               '--output_dir={}'.format(os.path.dirname(bindiff_path))]

        self._dprint('diffing the binaries..')
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = proc.communicate()
        self._dprint('differ output:')
        self._dprint(stdout)
        self._dprint(stderr)
        return

    def _load_BinDiff(self):
        bindiff_path = self._get_BinDiff_path()
        conn = sqlite3.connect(bindiff_path)
        c = conn.cursor()
        try:
            c.execute("SELECT similarity,confidence FROM metadata")
        except sqlite3.OperationalError as detail:
            self._dprint('[!] .BinDiff database ({}) is something wrong: {}'.format(bindiff_path, detail))
            return

        ws, wc = c.fetchone()
        self._dprint('whole binary similarity={} confidence={}'.format(ws, wc))

        # Get matching instructions
        ins_matching_map = self.get_matching_ins(c, self.func_addr_original, self.func_addr_patched)

        # Get patch affected functions
        affected_func_info = self.get_patch_affected_functions(c)

        # Get all matching functions
        all_matching_func_info = self.get_all_matching_functions(c)

        conn.close()

        # Assign to the class variable
        self.ins_matching_map = ins_matching_map
        self.affected_func_info = affected_func_info
        self.all_matching_func_info = all_matching_func_info

        return


    def conn_execute(self, cursor, query_str, parameters):
        result = None
        try:
            cursor.execute(query_str, parameters)
            result = cursor.fetchall()
        except sqlite3.OperationalError as detail:
            self._dprint('[!] .BinDiff database is something wrong: {}'.format(detail))

        return result

    def get_matching_ins(self, cursor, original_func_addr, patched_func_addr):
        query_str = "SELECT address1, address2 FROM instruction WHERE basicblockid IN(" \
                    "SELECT id FROM basicblock WHERE functionid IN (" \
                    "SELECT id FROM function WHERE address1 == ? AND address2 == ?))"
        parameters = (original_func_addr, patched_func_addr)

        block_matching_info = self.conn_execute(cursor, query_str, parameters)
        self._dprint('{} matching superblock(s) detected'.format(len(block_matching_info)))

        # if is arm, addr += 1
        block_matching_map = {self.handle_arm_addr(addrs[0]): self.handle_arm_addr(addrs[1])
                              for addrs in block_matching_info}

        # print out the matching super blocks
        self._dprint("Matching BBs:")
        for original_addr, patched_addr in block_matching_map.items():
            self._dprint("%s: %s" % (hex(original_addr), hex(patched_addr)))

        return block_matching_map

    # Get all not-perfectly matched functions (similarity != 1) in BinDiff
    def get_patch_affected_functions(self, cursor):
        query_str = "SELECT address1, address2, similarity FROM function WHERE similarity != 1"
        parameters = ()
        affected_func_info = self.conn_execute(cursor, query_str, parameters)
        self._dprint('{} target function(s) detected'.format(len(affected_func_info)))

        # # if is arm, addr += 1
        affected_func_info = [(self.handle_arm_addr(infos[0]), self.handle_arm_addr(infos[1]), infos[2])
                              for infos in affected_func_info]

        # print out the patch affected functions
        self._dprint("Patch affected functions:")
        for original_addr, patched_addr, similarity in affected_func_info:
            self._dprint("%s: %s (similarity=%s)" % (hex(original_addr), hex(patched_addr), similarity))

        return affected_func_info

    # Get all matching functions in BinDiff
    def get_all_matching_functions(self, cursor):
        query_str = "SELECT address1, address2 FROM function"
        parameters = ()
        all_matching_func_info = self.conn_execute(cursor, query_str, parameters)
        self._dprint('{} target function(s) detected'.format(len(all_matching_func_info)))

        # # if is arm, addr += 1
        all_matching_func_info = [(self.handle_arm_addr(infos[0]), self.handle_arm_addr(infos[1]))
                              for infos in all_matching_func_info]

        # print out the patch affected functions
        self._dprint("All matching functions:")
        for original_addr, patched_addr in all_matching_func_info:
            self._dprint("%s: %s" % (hex(original_addr), hex(patched_addr)))

        return all_matching_func_info

    def handle_arm_addr(self, addr):
        return addr + 1 if self.is_arm else addr