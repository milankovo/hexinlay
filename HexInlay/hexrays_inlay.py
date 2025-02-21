import re
import idaapi

 
class config_form_t(idaapi.Form):
    examples = [
        "memmove(buffer, src, 10)",
        "memmove(dst: buffer, src: src, len: 10)",
        "memmove(dst: buffer, src, len: 10)",
    ]

    def __init__(self, config:"config_t"):
        F = idaapi.Form

        F.__init__(
            self,
            r"""STARTITEM 0
BUTTON YES* OK
BUTTON CANCEL Cancel
HexInlay settings
{FormChangeCb}
<#Show function argument names in decompiled code as inlay hints#enabled:{rEnabled}>
<#Hide the inlay hint if the argument name is equal to the function's argument name#hide redundant:{rNoDuplicates}>{cGroup1}>
example:{example}
""",
            {
                "FormChangeCb": F.FormChangeCb(self.OnFormChange),
                "cGroup1": F.ChkGroupControl(["rEnabled", "rNoDuplicates"]),
                "example": F.StringLabel(max(self.examples, key=len)),
            },
        )
        self.config = config

    def OnFormChange(self, fid):
        match fid:
            case idaapi.CB_INIT:
                self.SetControlValue(self.rEnabled, self.config.enabled)
                self.SetControlValue(self.rNoDuplicates, self.config.hide_redundant)
                self.refresh()
            case self.rEnabled.id | self.rNoDuplicates.id:
                self.refresh()
            case idaapi.CB_YES:
                self.config.enabled = self.GetControlValue(self.rEnabled)
                self.config.hide_redundant = self.GetControlValue(self.rNoDuplicates)
        return 1

    def refresh(self):
        enabled = self.GetControlValue(self.rEnabled)
        hide_redundant = self.GetControlValue(self.rNoDuplicates)
        self.update_window(enabled, hide_redundant)

    def update_window(self, enabled:bool, hide_redundant:bool):
        self.EnableField(self.rNoDuplicates, enabled)
        match enabled, hide_redundant:
            case 0, _:
                self.SetControlValue(self.example, self.examples[0])
                
            case 1, 0:
                self.SetControlValue(self.example, self.examples[1])

            case 1, 1:
                self.SetControlValue(self.example, self.examples[2])

    @staticmethod
    def test(execute=True):
        cfg = config_t()
        cfg.load()
        f = config_form_t(cfg)
        f, args = f.Compile()
        print(f"{args=}")

        if execute:
            ok = f.Execute()
        else:
            print(args[0])
            print(args[1:])
            ok = 0
        if ok == 1:
            #print(f"OK {f.config.enabled=} {f.config.hide_redundant=}")
            cfg.save()
        f.Free()


class config_t:
    def __init__(self):
        self.enabled = True
        self.hide_redundant = False

    def load(self):
        self.enabled = idaapi.reg_read_bool( "enabled", True, "HexInlay")
        self.hide_redundant = idaapi.reg_read_bool("hide_redundant", False, "HexInlay")
        
    
    def save(self):
        idaapi.reg_write_bool("enabled", self.enabled, "HexInlay")
        idaapi.reg_write_bool("hide_redundant", self.hide_redundant, "HexInlay")

    def ask_user(self):
        form = config_form_t(self)        
        form, args = form.Compile()
        ok = form.Execute()
        if ok == 1:
            self.save()
            return True
        return False
    


def modifytext(cfunc:idaapi.cfunc_t, index_to_name_map:dict):
    rg = re.compile("\1\\(([A-F0-9]{8,})")
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

    def __init__(self, config:config_t=None):
        self.config = config
        super(hexinlay_hooks_t, self).__init__()

    def func_printed(self, cfunc: "idaapi.cfunc_t") -> "int":
        # print(f"Function {cfunc.entry_ea:x} printed")

        # should never happen as we are hooked only when the hints are enabled
        if not self.config.enabled:
            return 0
        
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
                    argname = argnames.get(arg_idx, None)
                    if not argname:
                        continue
                    
                    if self.config.hide_redundant:
                        # if the argument name is the same as the function argument name, skip it
                        if arg.op in [idaapi.cot_obj, idaapi.cot_var] and argname == arg.dstr():
                            #print(f"Skipping {arg_idx} {argname} {arg.dstr()} {idaapi.get_ctype_name(arg.op)=} ")
                            continue

                    # skip to the leftmost object
                    # otherwise we get strings like " x a1: + y" instead of "a1: x + y"
                    while 1:
                        if  idaapi.is_binary(arg.op):
                            arg = arg.x
                            continue
                        if arg.op in [idaapi.cot_call, idaapi.cot_memptr, idaapi.cot_memref]:
                            arg = arg.x
                            continue
                        break

                    #print(f"arg  {arg_idx} {arg.obj_id} {repr(arg.dstr())} should be named {argnames[arg_idx]}")
                    obj_id_name_map[arg.obj_id] = argname

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
    config_form_t.test()

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

        self.config = config_t()
        self.config.load()


        self.hook = hexinlay_hooks_t(self.config)
        self.enable(self.config.enabled)


        addon = idaapi.addon_info_t()
        addon.id = "milan.bohacek.hexinlay"
        addon.name = "HexInlay"
        addon.producer = "Milan Bohacek"
        addon.url = "https://github.com/milankovo/hexinlay"
        addon.version = "9.0"
        idaapi.register_addon(addon)

        return idaapi.PLUGIN_KEEP
    
    def enable(self, enable:bool):
        if enable:
            if not self.hooked:
                self.hook.hook()
                self.hooked = True
        else:
            if self.hooked:
                self.hook.unhook()
                self.hooked = False

    def run(self, arg=0):
        if self.config.ask_user():
            self.enable(self.config.enabled)
        

    def term(self):
        if self.hooked:
            self.hook.unhook()
            self.hooked = False


def PLUGIN_ENTRY():
    return HexInlayPlugin_t()
