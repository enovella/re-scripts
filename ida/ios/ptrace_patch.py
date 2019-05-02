import idaapi
import idautils
import idc

num_imps = idaapi.get_import_module_qty()
print("[+] Found % d import(s)" % num_imps)

for i in xrange(0, num_imps):
    name = idaapi.get_import_module_name(i)
    if not name:
        print("[-] Failed to get import module name for #%d" % i)
        continue

    print("Walking-> %s" % name)
    idaapi.enum_import_names(i, imp_cb)


possible_ptrace_dlsym_calls = []

def patch(addr):
    nop = [0x00, 0xBF] #  IN LE 00 BF nop in thumb mode (iphone uses thumb code]
    addr = idc.next_head(addr)
    mnem = GetMnem(addr)
    dlsym_result_reg = None
    if mnem == "MOV":
        dlsym_result_reg = GetOpnd(addr, 0)
        print("\t\t %08x: MOV %s, %s" % (addr, GetOpnd(addr, 0), GetOpnd(addr,1)))

        while True:
            addr = idc.next_head(addr)
            mnem = GetMnem(addr)
            if mnem == "BLX" and GetOpnd(addr, 0) == dlsym_result_reg:
                print("\t\t\t %08x: BLX %s" % (addr, GetOpnd(addr, 0)))
                # patch the code.
                for i in xrange(len(nop)):
                    PatchByte(addr + i, nop[i])
                break


def is_ptrace_called(addr):
    """
        check if ptrace is called.
        looking for pattern dlsym, then check for PT_DENY_ATTACH = 0x1F.
    """
    print("Analyzing address: %x" % addr)
    for i in xrange(0, 2):
        addr = idc.next_head(addr)
        mnem = GetMnem(addr)
        if mnem == "BLX" and "_dlsym" in GetOpnd(addr, 0):
            print("\t BLX mnemonic found at address: %x, operand: %s, count: %d" % (addr, GetOpnd(addr, 0), i))
            possible_ptrace_dlsym_calls.append(addr)
            patch(addr)
            break


# XREFS FOR PTRACE
# source https://github.com/devttys0/ida/blob/master/scripts/wpsearch.py function xrefs()
# Search for ptrace string
for string in idautils.Strings():
    if "ptrace" in str(string):
        print("PTRACE FOUND %x: len=%d type=%d " % (string.ea, string.length, string.strtype))
        print("PTRACE referenced from:")
        for xref in idautils.XrefsTo(string.ea):
            print(hex(xref.frm))
            is_ptrace_called(xref.frm)


print("----------- Completed ---------------")