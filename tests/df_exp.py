import angr
from angr import sim_options as so

class malloc_hook(angr.procedures.libc.malloc.malloc):
    def run(self, sim_size):
        # self.argument_types = {0: SimTypeLength(self.state.arch)}
        # self.return_type = self.ty_ptr(SimTypeTop(sim_size))
        addr=self.state.heap._malloc(sim_size)
        size=self.state.solver.eval(sim_size)

        if "malloc_listt" in self.state.globals:
            print("MIF")
            malloc_list=self.state.globals["malloc_listt"]
        else:
            print("MELSE")
            self.state.globals["malloc_listt"]={}
            malloc_list=self.state.globals["malloc_listt"]

        print(self.state.globals.items())
        malloc_list[addr]=size
        return addr

class free_hook(angr.procedures.libc.free.free):
    def run(self, ptr):
        # self.argument_types = {0: self.ty_ptr(SimTypeTop())}
        f_ptr=self.state.solver.eval(ptr)

        if "free_list" in self.state.globals:
            print("FIF")
            free_list=self.state.globals["free_list"]
            if f_ptr in free_list:
                print("double free:")
                print("stdout:\n",self.state.posix.dumps(1))
                print("stdin:\n",self.state.posix.dumps(0))

        else:
            print("FELSE")
            self.state.globals["free_list"]={}
            free_list=self.state.globals["free_list"]
            if "malloc_listt" in self.state.globals:
                malloc_list=self.state.globals["malloc_listt"]
                if f_ptr in malloc_list:
                    free_list[f_ptr]=malloc_list[f_ptr]

        print(self.state.globals.items())
        return self.state.heap._free(ptr)



if __name__ == '__main__':
    filename="./df"

    p = angr.Project(filename,auto_load_libs=False)
    p.hook_symbol('malloc',malloc_hook(cc=p.factory.cc(func_ty="void* malloc(int)")), replace=True)
    p.hook_symbol('free',free_hook(cc=p.factory.cc(func_ty="void free(void*)")), replace=True)
    extras = {so.REVERSE_MEMORY_NAME_MAP, so.TRACK_ACTION_HISTORY,so.ZERO_FILL_UNCONSTRAINED_MEMORY}
    state=p.factory.entry_state(add_options=extras)
    simgr = p.factory.simulation_manager(state,save_unconstrained=True)
    # simgr.use_technique(angr.exploration_techniques.Spiller())

    while simgr.active:
        simgr.step()
