from ..utils import log, RED, GRE, DRED, RST
import angr
from angr import sim_options


class MallocHook(angr.procedures.libc.malloc.malloc) :
    def run(self, sim_size) :
        malloc_addr = self.state.heap._malloc(sim_size)
        malloc_size = self.state.solver.eval(sim_size)
        # init the malloc list for current execution path
        if "MALLOC_LIST" not in self.state.globals :
            self.state.globals["MALLOC_LIST"] = {}
        # record a new malloc-call into the malloc list
        self.state.globals["MALLOC_LIST"][malloc_addr] = malloc_size
        return malloc_addr


class FreeHook(angr.procedures.libc.free.free) :
    def run(self, ptr) :
        free_addr = self.state.solver.eval(ptr)
        # init the free list for current execution path
        if "FREE_LIST" not in self.state.globals :
            self.state.globals["FREE_LIST"] = {}
            # if free a malloced address, record it
            if ("MALLOC_LIST" in self.state.globals) and (free_addr in self.state.globals["MALLOC_LIST"]) :
                self.state.globals["FREE_LIST"][free_addr] = self.state.globals["MALLOC_LIST"][free_addr]
        else :
            # if free address is already in free list, alert DOUBLE FREE
            if free_addr in self.state.globals["FREE_LIST"] :
                log("DOUBLE FREE detected! IO dump :", RED)
                print("{}< stdin >{}\n".format(DRED, RST), self.state.posix.dumps(0))
                print("{}< stdout >{}\n".format(DRED, RST), self.state.posix.dumps(1))


def check(file_name) :
    log("Checking DF", GRE)

    project = angr.Project(file_name)
    project.hook_symbol('malloc', MallocHook(cc=project.factory.cc(func_ty="void* malloc(int)")), replace=True)
    project.hook_symbol('free', FreeHook(cc=project.factory.cc(func_ty="void free(void*)")), replace=True)
    extra_option = {sim_options.REVERSE_MEMORY_NAME_MAP, sim_options.TRACK_ACTION_HISTORY, sim_options.ZERO_FILL_UNCONSTRAINED_MEMORY}
    state = project.factory.entry_state(add_options=extra_option)
    simgr = project.factory.simulation_manager(state, save_unconstrained=True)

    while simgr.active :
        simgr.step()
