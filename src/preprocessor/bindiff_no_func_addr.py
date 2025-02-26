import os
import sqlite3
import subprocess
import timeout_decorator

g_differ_path = r"/usr/bin/bindiff"
ida_64_path = os.path.abspath(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                            '../../../ida8.3/idat64'))
ida_32_path = os.path.abspath(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                            '../../../ida8.3/idat'))
idapython_script_path = os.path.dirname(__file__) + '/bindiff_rebase.py'

@timeout_decorator.timeout(300)
class IdaBinDiff(object):
    def __init__(self, primary, secondary, size, base_addr, debug=True):
        self.primary_path = primary
        self.secondary_path = secondary
        self.bindiff_path = None
        self.affected_func_info = None
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
        if self.bindiff_path is not None:
            return self.bindiff_path
        else:
            self.bindiff_path = self.primary_path + '_vs_' + os.path.basename(self.secondary_path) + '.BinDiff'
            return self.bindiff_path

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

        # Get patch affected functions
        affected_func_info = self.get_patch_affected_functions()

        # Assign to the class variable
        self.affected_func_info = affected_func_info
        return


    def conn_execute(self, query_str, parameters):
        bindiff_path = self._get_BinDiff_path()
        conn = sqlite3.connect(bindiff_path)
        cursor = conn.cursor()
        result = None
        try:
            cursor.execute(query_str, parameters)
            result = cursor.fetchall()
        except sqlite3.OperationalError as detail:
            self._dprint('[!] .BinDiff database is something wrong: {}'.format(detail))

        conn.close()
        return result

    # Get all not-perfectly matched functions (similarity != 1) in BinDiff
    def get_patch_affected_functions(self):
        # If already computed, return the result
        if self.affected_func_info is not None:
            return self.affected_func_info

        query_str = "SELECT address1, address2, name1, name2, similarity FROM function WHERE similarity != 1"
        parameters = ()
        affected_func_info = self.conn_execute(query_str, parameters)
        self._dprint('{} target function(s) detected'.format(len(affected_func_info)))

        # print out the patch affected functions
        self._dprint("Target functions:")
        for original_addr, patched_addr, func_name_1, func_name_2, similarity in affected_func_info:
            self._dprint("%s(%s): %s(%s) (similarity=%s)" % (str(func_name_1), hex(original_addr), str(func_name_2), hex(patched_addr), str(similarity)))
        return affected_func_info
