import re
import idaapi
import enum


class plugin_state(enum.IntEnum):
    disabled = 0
    show_all = 1
    hide_some = 2
    hide_more = 3


plugin_state_examples = {
    plugin_state.disabled: "memmove(this->dst, src, 10)",
    plugin_state.show_all: "memmove(dst: this->dst, src: src, len: 10)",
    plugin_state.hide_some: "memmove(dst: this->dst, src, len: 10)",
    plugin_state.hide_more: "memmove(this->dst, src, len: 10)",
}

class config_form_t(idaapi.Form):
    def __init__(self, state: plugin_state):
        F = idaapi.Form

        F.__init__(
            self,
            r"""STARTITEM 0
BUTTON YES* OK
BUTTON CANCEL Cancel
HexInlay settings
{FormChangeCb}
<##inlay hints##~d~isabled:{rDisabled}>
<#Show function argument names in the decompiled code as inlay hints#~s~how all:{rShowAll}>
<#Hide the inlay hint if the argument name is equal to the function's argument name#~h~ide some:{rHideSome}>
<#Hide the inlay hint if the argument name is contained in the function's argument name or vice versa#hide ~m~ore:{rHideAll}>{cGroup1}>
example:{example}
""",
            {
                "FormChangeCb": F.FormChangeCb(self.OnFormChange),
                "cGroup1": F.RadGroupControl(
                    ["rDisabled", "rShowAll", "rHideSome", "rHideAll"], state.value
                ),
                "example": F.StringLabel(max(plugin_state_examples.values(), key=len)),
            },
        )
        self.state = state
        self.changed = False

    def read_state(self):
        return plugin_state(self.GetControlValue(self.cGroup1))

    def OnFormChange(self, fid):
        match fid:
            case self.cGroup1.id:
                state = self.read_state()
                self.SetControlValue(self.example, plugin_state_examples[state])

            case idaapi.CB_YES:
                state = self.read_state()
                self.changed = self.state != state
                self.state = state
        return 1

    @staticmethod
    def test(execute=True):
        cfg = config_t()
        cfg.load()
        f = config_form_t(cfg.state)
        f, args = f.Compile()
        print(f"{args=}")

        if execute:
            ok = f.Execute()
        else:
            print(args[0])
            print(args[1:])
            ok = 0
        if ok == 1:
            print(f"OK {f.state=} {f.changed=}")
            cfg.state = f.state
            cfg.save()
        f.Free()


class config_t:
    def __init__(self):
        self.state = plugin_state.show_all

    def load(self):
        self.state = plugin_state(
            idaapi.reg_read_int("state", plugin_state.show_all.value, "HexInlay")
        )

    def save(self):
        idaapi.reg_write_int("state", self.state.value, "HexInlay")

    def ask_user(self):
        form = config_form_t(self.state)
        form, args = form.Compile()
        ok = form.Execute()
        if ok == 1 and form.changed:
            self.state = form.state
            self.save()
            return True
        return False


def modifytext(cfunc: idaapi.cfunc_t, index_to_name_map: dict):
    rg = re.compile("\1\\(([A-F0-9]{8,})")
    ps = cfunc.get_pseudocode()

    used = set()

    # current_line = ""

    def callback(m):
        res = m.group(0)
        num = int(m.group(1), 16)
        # print(f"Matched {repr(m.group(0))} {it} {m.group(1)}")

        name = index_to_name_map.get(num, None)
        if name is None:
            return res

        if num in used:
            # print(f"Already used {num} -  {repr(res)} in {repr(current_line)}")
            return res
        used.add(num)

        # print(f"Replacing {num} with {name} in {repr(res)}")

        # SCOLOR_REGCMT, SCOLOR_AUTOCMT, SCOLOR_RPTCMT
        res += idaapi.COLSTR(name + ": ", idaapi.SCOLOR_AUTOCMT)

        return res

    for l in ps:
        # print(repr(l.line))
        # current_line = l.line
        used = set()
        l.line = rg.sub(callback, l.line)


def type_to_argnames(t: idaapi.tinfo_t) -> dict:
    t.remove_ptr_or_array()
    funcdata = idaapi.func_type_data_t()
    got_data = t.get_func_details(funcdata)
    if not got_data:
        # print(f"Failed to get function details for {t.dstr()}")
        return

    argnames = {}
    for arg_idx, arg in enumerate(funcdata):
        # print(f"arg {arg_idx} {arg.name} {arg.type.dstr()}")
        argnames[arg_idx] = arg.name

    return argnames


class hexinlay_hooks_t(idaapi.Hexrays_Hooks):
    def __init__(self, config: config_t = None):
        self.config = config
        super().__init__()

    def is_the_same_argument(self, argument_name: str, arg: idaapi.carg_t) -> bool:
        match self.config.state:
            case plugin_state.disabled:
                return False
            case plugin_state.show_all:
                return False
            case plugin_state.hide_some:
                if arg.op not in [idaapi.cot_obj, idaapi.cot_var]:
                    return False
        function_argument_name = arg.dstr()

        if argument_name == function_argument_name:
            return True

        if self.config.state == plugin_state.hide_some:
            return False

        assert self.config.state == plugin_state.hide_more
        # based on https://github.com/JetBrains/intellij-community/blob/6ddf70b998a05ce01b3d58f04553548ba5ff767f/java/java-impl/src/com/intellij/codeInsight/hints/JavaHintUtils.kt#L325

        if len(argument_name) < 3:
            return False

        if len(function_argument_name) < 3:
            return False

        if argument_name in function_argument_name:
            return True

        if function_argument_name in argument_name:
            return True
        return False

    def func_printed(self, cfunc: "idaapi.cfunc_t") -> "int":
        # print(f"Function {cfunc.entry_ea:x} printed")

        # should never happen as we are hooked only when the hints are enabled
        if self.config.state == plugin_state.disabled:
            return 0

        call_item: idaapi.citem_t

        obj_id_pos_map = {}
        obj_id_name_map = {}

        for i, call_item in enumerate(cfunc.treeitems):
            obj_id_pos_map[call_item.obj_id] = i
            if call_item.op == idaapi.cot_call:
                call_expr: idaapi.cexpr_t = call_item.cexpr
                # 1. collect argument names from the function type
                # print(f"Function {call_expr.type.dstr()}")
                t: idaapi.tinfo_t = call_expr.x.type
                argnames = type_to_argnames(t)
                if not argnames:
                    print(
                        f"Failed to get function details for {t.dstr()} at {call_expr.ea:x}"
                    )
                    continue
                # 2. collect argument objects from the call expression
                arglist: idaapi.carglist_t = call_expr.a
                arg: idaapi.carg_t

                for arg_idx, arg in enumerate(arglist):
                    argname = argnames.get(arg_idx, None)
                    if not argname:
                        continue

                    # if the argument name is the same as the function argument name, skip it
                    if self.is_the_same_argument(argname, arg):
                        # print( f"Skipping {arg_idx} {argname} {arg.dstr()} {idaapi.get_ctype_name(arg.op)=} " )
                        continue

                    # skip to the leftmost object
                    # otherwise we get strings like " x a1: + y" instead of "a1: x + y"
                    while 1:
                        if idaapi.is_binary(arg.op):
                            arg = arg.x
                            continue
                        if arg.op in [
                            idaapi.cot_call,
                            idaapi.cot_memptr,
                            idaapi.cot_memref,
                        ]:
                            arg = arg.x
                            continue
                        break

                    # print(f"arg  {arg_idx} {arg.obj_id} {repr(arg.dstr())} should be named {argnames[arg_idx]}")
                    obj_id_name_map[arg.obj_id] = argname

        index_to_name_map = {}
        for obj_id, name in obj_id_name_map.items():
            index = obj_id_pos_map[obj_id]
            index_to_name_map[index] = name
            # print(f"Mapping {index} to {repr(name)}")

        modifytext(cfunc, index_to_name_map)
        return 0


if __name__ == "__main__":
    idaapi.msg_clear()
    if "hex_cb_info" in globals():
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
        self.enable(self.config.state)

        addon = idaapi.addon_info_t()
        addon.id = "milan.bohacek.hexinlay"
        addon.name = "HexInlay"
        addon.producer = "Milan Bohacek"
        addon.url = "https://github.com/milankovo/hexinlay"
        addon.version = "9.0"
        idaapi.register_addon(addon)

        return idaapi.PLUGIN_KEEP

    def enable(self, state: plugin_state):
        match state > plugin_state.disabled, self.hooked:
            case True, False:
                self.hook.hook()
                self.hooked = True
                return True
            case False, True:
                self.hook.unhook()
                self.hooked = False
                return True
            case _:
                return False

    def run(self, arg=0):
        if not self.config.ask_user():
            return
        self.enable(self.config.state)
        self.refresh_pseudocode_widgets()

    def refresh_pseudocode_widgets(self):
        for name in "ABCDEFGHIJKLMNOPQRSTUVWXY":
            widget = idaapi.find_widget(f"Pseudocode-{name}")
            if not widget:
                continue
            vdui: idaapi.vdui_t = idaapi.get_widget_vdui(widget)
            if not vdui:
                continue
            vdui.refresh_ctext(False)

    def term(self):
        if self.hooked:
            self.hook.unhook()
            self.hooked = False


def PLUGIN_ENTRY():
    return HexInlayPlugin_t()
