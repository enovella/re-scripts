# (C) Copyright 2015/2016 Comsecuris UG
# 2018 @enovella_ Port to arm64

import idaapi
import idc
import idautils

def def_functions(s_start):

    num_added_functions = 0

    s_addr = s_start
    s_end = idc.GetSegmentAttr(s_start, SEGATTR_END) #idc.SegEnd(segm)
    print "0x%08x 0x%08x" % (s_start, s_end) 
    
    while (s_addr < s_end):

        #print "Testing address 0x%08x" % s_addr
        
        #optimization assumes that function chunks are consecutive (no "function-in-function" monkey business)
        if (idaapi.get_func(s_addr)):
            
            next_func = idc.NextFunction(s_addr)

            ea = s_addr
            for c in idautils.Chunks(s_addr):
                #only use chunks in lookahead that do not jump over the next function and that are not smaller than where we are atm.
                if (c[1] > ea) and (c[1] <= next_func):
                    ea = c[1]
            if ea == s_addr:
                s_addr += 2
            else:
                s_addr = ea            
            #s_addr += 4
            continue
            
        else:
            #This is not a good optimization, there WILL be data refs to function start addresses sometimes.
            '''
            if sum(1 for _ in (CodeRefsTo(s_addr, 1))) != 0:
                s_addr += 4
                continue

.text:00000000000130C4                 SUB             SP, SP, #0x80
.text:00000000000130C8                 STP             X24, X23, [SP,#0x70+var_30]

LOAD:0000000000015F20                 STP             X29, X30, [SP,#-0x10+var_s0]!
LOAD:0000000000015F24                 MOV             X29, SP

LOAD:00000000000178A4                 STP             X20, X19, [SP,#-0x10+var_10]!
LOAD:00000000000178A8                 STP             X29, X30, [SP,#0x10+var_s0]

LOAD:000000000001A1B0                 MOV             W8, #0x70 ; 'p'
LOAD:000000000001A1B4                 STR             WZR, [X0]

LOAD:000000000001C020                 MOV             X8, X1
LOAD:000000000001C024                 MOV             X9, X0

LOAD:000000000001D48C                 STP             X24, X23, [SP,#-0x10+var_30]!
LOAD:000000000001D490                 STP             X22, X21, [SP,#0x30+var_20]

LOAD:000000000001F07C                 SUBS            W8, W2, #1
LOAD:000000000001F080                 B.LT            loc_1F0B0

LOAD:00000000000000B0                 ADRP            X16, #off_A4060@PAGE
LOAD:00000000000000B4                 LDR             X17, [X16,#off_A4060@PAGEOFF]

LOAD:000000000000AAF8 000 28 00 40 39                 LDRB            W8, [X1] ; Load from Memory
LOAD:000000000000AAFC 000 29 04 40 F9                 LDR             X9, [X1,#8] ; Load from Memory

            '''
            if ((idc.GetMnem(s_addr) == "STP") and \
                    # ("X29" in idc.GetOpnd(s_addr, 0)) and  \
                    # ("X30" in idc.GetOpnd(s_addr, 1)) and \
                    ("SP" in idc.GetOpnd(s_addr, 2))) \
                or \
                ((idc.GetMnem(s_addr) == "ADRP") and \
                    # ("X" in idc.GetOpnd(s_addr, 0)) and  \
                    ("X" in idc.GetOpnd(s_addr, 0))) \
                or \
                ((idc.GetMnem(s_addr) == "LDRB")): # \
                # or \
                # (((idc.GetMnem(s_addr) == "PUSH") or (idc.GetMnem(s_addr) == "PUSH.W") or (idc.GetMnem(s_addr) == "STR.W") ) and \
                #     ("LR" in idc.GetOpnd(s_addr, 0))):

                print "Found function at 0x%08x" % s_addr
                idc.MakeFunction(s_addr)
                f = idaapi.get_func(s_addr)
                if (type(f) == type(None)):
                    print "Failed to create function! Undefined instructions?"
                    s_addr += 2
                else:
                    num_added_functions += 1
                    ea = -1
                    for c in idautils.Chunks(s_addr):
                        if c[1] > ea:
                            ea = c[1]
                    if ea != -1:
                        s_addr = ea
                    #failed?
                    else:
                        s_addr += 2
            else:
                s_addr += 2

    print "finished segment"
    return num_added_functions
 

num_total_added_functions = 0
for s in idautils.Segments():
    s_start = s   
    if idaapi.segtype(s_start) == idaapi.SEG_CODE:
        print "starting segment at 0x%08x" % s_start
        num_total_added_functions += def_functions(s)

print "Added %d functions in total" % num_total_added_functions
