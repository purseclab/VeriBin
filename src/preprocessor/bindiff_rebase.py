import idaapi
import idc

f = open("./bindiff.log", "w+")
try:
    base_addr = int(idc.ARGV[1])
    rebase_program(base_addr - idaapi.get_imagebase(), base_addr)
except Exception as e:
    import traceback
    f.write(traceback.format_exc())

f.close()
idc.qexit(0)