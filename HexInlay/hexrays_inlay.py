import re
import idaapi

def modifytext(cfunc:idaapi.cfunc_t, index_to_name_map:dict):
    rg = re.compile("\1\(([A-F0-9]{8,})")
    ps = cfunc.get_pseudocode()

    used = set()

    #current_line = ""

    def callback(m): 
        res = m.group(0)
        num = int(m.group(1),16)
        #print(f"Matched {repr(m.group(0))} {it} {m.group(1)}")


        name = index_to_name_map.get(num, None)
        if name is None:
            return res
        
        if num in used:
            #print(f"Already used {num} -  {repr(res)} in {repr(current_line)}")
            return res
        used.add(num)
        
        #print(f"Replacing {num} with {name} in {repr(res)}")
        
        # SCOLOR_REGCMT, SCOLOR_AUTOCMT, SCOLOR_RPTCMT
        res += idaapi.COLSTR(name + ": ", idaapi.SCOLOR_AUTOCMT)

        return res

    for l in ps:
        #print(repr(l.line))
        #current_line = l.line
        used = set()
        l.line = rg.sub(callback, l.line)

def type_to_argnames(t:idaapi.tinfo_t) -> dict:
    t.remove_ptr_or_array()
    funcdata = idaapi.func_type_data_t()
    got_data = t.get_func_details(funcdata)
    if not got_data:
        #print(f"Failed to get function details for {t.dstr()}")
        return

    argnames = {}
    for arg_idx, arg in enumerate(funcdata):
        #print(f"arg {arg_idx} {arg.name} {arg.type.dstr()}")
        argnames[arg_idx] = arg.name

    return argnames


class hexinlay_hooks_t(idaapi.Hexrays_Hooks):

    def func_printed(self, cfunc: "idaapi.cfunc_t") -> "int":
        # print(f"Function {cfunc.entry_ea:x} printed")
        
        call_item:idaapi.citem_t
        
        obj_id_pos_map = {}
        obj_id_name_map = {}

        for i, call_item in enumerate(cfunc.treeitems):
            obj_id_pos_map[call_item.obj_id] = i
            if call_item.op == idaapi.cot_call:
                call_expr: idaapi.cexpr_t = call_item.cexpr
                # 1. collect argument names from the function type
                #print(f"Function {t.dstr()}")
                t:idaapi.tinfo_t = call_expr.x.type
                argnames = type_to_argnames(t)
                if not argnames:
                    print(f"Failed to get function details for {t.dstr()} at {call_expr.ea:x}")
                    continue
                # 2. collect argument objects from the call expression
                arglist:idaapi.carglist_t = call_expr.a
                arg: idaapi.carg_t

                for arg_idx, arg in enumerate(arglist):
                    if not argnames.get(arg_idx, None):
                        continue
                    # skip to the leftmost object
                    # otherwise we get strings like " x a1: + y" instead of "a1: x + y"
                    while 1:
                        if  idaapi.is_binary(arg.op):
                            arg = arg.x
                            continue
                        if arg.op == idaapi.cot_call:
                            arg = arg.x
                            continue
                        break

                    #print(f"arg  {arg_idx} {arg.obj_id} {repr(arg.dstr())} should be named {argnames[arg_idx]}")
                    obj_id_name_map[arg.obj_id] = argnames[arg_idx]

        index_to_name_map = {}
        for obj_id, name in obj_id_name_map.items():
            index = obj_id_pos_map[obj_id]
            index_to_name_map[index] = name
            #print(f"Mapping {index} to {repr(name)}")

        modifytext(cfunc, index_to_name_map)
        return 0

if __name__ == "__main__":
    idaapi.msg_clear()
    if 'hex_cb_info' in globals():
        print(f"Unhooking {hex_cb_info}")
        hex_cb_info.unhook()

    hex_cb_info = hexinlay_hooks_t()
    hex_cb_info.hook()

    print("Hooked")


class HexInlayPlugin_t(idaapi.plugin_t):
    flags = 0
    comment = "Show function argument names in decompiled code as inlay hints"
    help = ""
    wanted_name = "HexInlay"
    wanted_hotkey = ""

    def init(self):
        self.hooked = False
        if not idaapi.init_hexrays_plugin():
            return idaapi.PLUGIN_SKIP

        self.hook = hexinlay_hooks_t()
        self.hook.hook()
        self.hooked = True


        addon = idaapi.addon_info_t()
        addon.id = "milan.bohacek.hexinlay"
        addon.name = "HexInlay"
        addon.producer = "Milan Bohacek"
        addon.url = "https://github.com/milankovo/hexinlay"
        addon.version = "9.0"
        idaapi.register_addon(addon)

        return idaapi.PLUGIN_KEEP

    def run(self, arg=0):
        if self.hooked:
            self.hook.unhook()
            self.hooked = False
        else:    
            self.hook.hook()
            self.hooked = True

    def term(self):
        if self.hooked:
            self.hook.unhook()
            self.hooked = False


def PLUGIN_ENTRY():
    return HexInlayPlugin_t()
