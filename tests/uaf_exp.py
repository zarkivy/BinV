import angr
from angr.sim_type import SimTypeTop,SimTypeLength
from angr import sim_options as so
class malloc_hook(angr.procedures.libc.malloc.malloc):

    def run(self, sim_size):
        self.argument_types = {0: SimTypeLength(self.state.arch)}
        self.return_type = self.ty_ptr(SimTypeTop(sim_size))
        addr=self.state.heap._malloc(sim_size)
        size=self.state.solver.eval(sim_size)

        if "malloc_list" in self.state.globals:
            malloc_list=self.state.globals["malloc_list"]
        else:
            self.state.globals["malloc_list"]={}
            malloc_list=self.state.globals["malloc_list"]

        malloc_list[addr]=size
        return addr

class free_hook(angr.procedures.libc.free.free):
    def run(self, ptr):
        self.argument_types = {0: self.ty_ptr(SimTypeTop())}
        f_ptr=self.state.solver.eval(ptr)

        if "free_list" in self.state.globals:
            free_list=self.state.globals["free_list"]
            if f_ptr in free_list:
                print("double free:")
                print("stdout:\n",self.state.posix.dumps(1))
                print("stdin:\n",self.state.posix.dumps(0))

        else:
            self.state.globals["free_list"]={}
            free_list=self.state.globals["free_list"]
            if "malloc_list" in self.state.globals:
                malloc_list=self.state.globals["malloc_list"]
                if f_ptr in malloc_list:
                    free_list[f_ptr]=malloc_list[f_ptr]

        return self.state.heap._free(ptr)

def Check_UAF_R(state):
    if "free_list" not in state.globals:
        if "before_free" in state.globals:
            before_free=state.globals["before_free"]
        else:
            state.globals["before_free"]=[]
            before_free=state.globals["before_free"]
        action_now=reversed(state.history.actions.hardcopy)
        for act in action_now:
            if act not in before_free:
                before_free.append(act)
    else:
        before_free=state.globals["before_free"]
        action_now=reversed(state.history.actions.hardcopy)
        action=[i for i in action_now if i not in before_free]

        malloc_list=state.globals["malloc_list"]
        free_list=state.globals["free_list"]

        for act in action:
            if act.type=='mem' and act.action=='read' :
                addr=check_addr(state,act)
                if addr==0:
                    print("error addr:",act.addr)
                    break

                for f in free_list:
                    if f==addr:
                        print("\n[========find a UAF read========]")
                        print("[UAF-R]stdout:")
                        print(state.posix.dumps(1))
                        print("[UAF-R]trigger arbitrary read input:")
                        print(state.posix.dumps(0))
                        break

def Check_UAF_W(state):
    if "free_list" not in state.globals:
        if "before_free" in state.globals:
            before_free=state.globals["before_free"]
        else:
            state.globals["before_free"]=[]
            before_free=state.globals["before_free"]
        action_now=reversed(state.history.actions.hardcopy)
        for act in action_now:
            if act not in before_free:
                before_free.append(act)

    else:
        before_free=state.globals["before_free"]
        action_now=reversed(state.history.actions.hardcopy)
        action=[i for i in action_now if i not in before_free]

        malloc_list=state.globals["malloc_list"]
        free_list=state.globals["free_list"]

        for act in action:
            if act.type=='mem' and act.action=='write' :
                addr=check_addr(state,act)
                if addr==0:
                    print("error:",act.addr)
                    break

                for f in free_list:
                    if f==addr:
                        print("\n[========find a UAF write========]")
                        print("[UAF-W]stdout:")
                        print(state.posix.dumps(1))
                        print("[UAF-W]trigger arbitrary write input:")
                        print(state.posix.dumps(0))
                        break

if __name__ == '__main__':
    filename="./df"

    p = angr.Project(filename,auto_load_libs=False)#
    p.hook_symbol('malloc',malloc_hook())
    p.hook_symbol('free',free_hook())
    extras = {so.REVERSE_MEMORY_NAME_MAP, so.TRACK_ACTION_HISTORY,so.ZERO_FILL_UNCONSTRAINED_MEMORY}
    state=p.factory.entry_state(add_options=extras)
    simgr = p.factory.simulation_manager(state,save_unconstrained=True)
    simgr.use_technique(angr.exploration_techniques.Spiller())

    while simgr.active:
        for act in simgr.active:
            Check_UAF_R(act)
            Check_UAF_W(act)
        simgr.step()