'''
Original source: https://exploiting.wordpress.com/2011/12/06/quickpost-idapython-script-to-identify-unrecognized-functions/
Modified by @enovella_
'''

import idc
import struct
import idautils

def find_all( opcode_str ):
    ret = []
    ea = idc.FindBinary(0, 1, opcode_str)
    while ea != idc.BADADDR:
        ret.append(ea)
        ea = idc.FindBinary(ea + 4, 1, opcode_str)
    return ret

def define_functions():
    # The function first searches for all user defined functions, reads
    # the opcodes and searches for that opcodes in the rest of the file.
    #
    # You can extend this by adding more disassembled instructions that
    # make you believe are function prologues.
    #
    # Obviously not any PUSH is a function start, this is only a filter
    # against erroneously defined functions. So if you define a function
    # that starts with other instruction (and you think there could be
    # other functions that start with that instruction), just add it here.
    prologues = ["STMFD", "push", "PUSH", "mov", "MOV", "STP"]

    print(">> Finding all signatures")
    #start = idaapi.cvar.inf.minEA # idaapi.get_imagebase()
    #end = idaapi.cvar.inf.maxEA
    seg = SegByBase(SegByName(".text"))
    start, end = SegStart(seg), SegEnd(seg)

    print ("Start-end!")
    print ("{:08x}".format(start))
    print ("{:08x}".format(end))

    opcodes = set()

    nr_fnc_in = len(list((Functions(start, end))))
    

    for funcea in Functions(start, end):
        # Get the opcode
        start_opcode = idc.Dword(funcea)

        # Get the disassembled text
        dis_text = idc.GetDisasm(funcea)
        candidate = False

        # Filter possible errors on manually defined functions
        for prologue in prologues:
            if prologue in dis_text:
                print ("{:08x} {:6s} YES prologue: {}".format(funcea,prologue,dis_text))
                candidate = True

        # If it passes the filter, add the opcode to the search list.
        if candidate:
            opcodes.add(start_opcode)

    print("# different opcodes: %x" % (len(opcodes)))

    while len(opcodes) > 0:
        # Search for this opcode in the rest of the file
        opcode_bin = opcodes.pop()
        opcode_str = "".join(x.encode("hex") for x in struct.pack("<L", opcode_bin))
        print("Searching for {}->{:08x}".format(opcode_str,opcode_bin))
        matches = find_all( opcode_str )
        for matchea in matches:
            # If the opcode is found in a non-function
            if not idc.GetFunctionName(matchea):
                # Try to make code and function
                print ("{:08x} -> defining function".format(matchea))
                idc.MakeCode(matchea)
                idc.MakeFunction(matchea)

    print ("#functions: {}".format(nr_fnc_in))
    print(">> Done!")

define_functions()
