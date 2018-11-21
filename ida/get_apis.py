def get_apis(func_addr):
        calls = 0
        apis = []
        flags = GetFunctionFlags(func_addr)
        # ignore library functions
        if flags & FUNC_LIB or flags & FUNC_THUNK:
            logging.debug("get_apis: Library code or thunk")
            return None
        # list of addresses
        dism_addr = list(FuncItems(func_addr))
        for instr in dism_addr:
            tmp_api_address = ""
            if idaapi.is_call_insn(instr):
                # In theory an API address should only have one xrefs
                # The xrefs approach was used because I could not find how to
                # get the API name by address.
                for xref in XrefsFrom(instr, idaapi.XREF_FAR):
                    if xref.to == None:
                        calls += 1
                        continue
                    tmp_api_address = xref.to
                    break
                # get next instr since api address could not be found
                if tmp_api_address == "":
                    calls += 1
                    continue
                api_flags = GetFunctionFlags(tmp_api_address)
                # check for lib code (api)
                if api_flags & idaapi.FUNC_LIB == True or api_flags & idaapi.FUNC_THUNK:
                    tmp_api_name = NameEx(0, tmp_api_address)
                    if tmp_api_name:
                        apis.append(tmp_api_name)
                else:
                    calls += 1
        return (calls, apis)