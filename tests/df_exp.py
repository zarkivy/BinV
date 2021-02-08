import time
import angr
from angr import sim_options


# ANSI fonts
RST = "\x1b[0m"
RED = "\x1b[31m"
GRE = "\x1b[32m"
ORA = "\x1b[33m"
BLU = "\x1b[34m"
PUR = "\x1b[35m"
CYA = "\x1b[36m"
WHI = "\x1b[37m"
GRA = "\x1b[1;30m"
DRED = "\x1b[1;31m"
LGRE = "\x1b[1;32m"
YEL = "\x1b[1;33m"
AZU = "\x1b[1;34m"
DPUR = "\x1b[1;35m"
DCYA = "\x1b[1;36m"
WARN = "\x1b[5;31m"


def log(log_string, color) :
    print("{}[ {} ] {}".format(color, time.asctime().split(' ')[-2], log_string) + RST)


'''
class malloc(angr.simprocedure):
    def run(self, sim_size):
        return self.state.heap._malloc(sim_size)
'''
class MallocHook(angr.procedures.libc.malloc.malloc) :
    def run(self, sim_size) :
        malloc_addr = self.state.heap._malloc(sim_size)
        malloc_size = self.state.solver.eval(sim_size)
        # init the malloc list for current execution path
        if "malloc_list" not in self.state.globals :
            self.state.globals["malloc_list"] = {}
        # record a new malloc-call into the malloc list
        self.state.globals["malloc_list"][malloc_addr] = malloc_size
        return malloc_addr

'''
class free(angr.SimProcedure):
    def run(self, ptr):
        self.state.heap._free(ptr)
'''
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
    log("Checking DOUBLE FREE", GRE)

    try :
        project = angr.Project(file_name, load_options={'auto_load_libs': False})
        log("Load binary successfully", GRE)
    except :
        log("Not a valid binary file: " + file_name + "\n", RED)
        return
    project.hook_symbol('malloc', MallocHook(cc=project.factory.cc(func_ty="void* malloc(int)")), replace=True)
    project.hook_symbol('free', FreeHook(cc=project.factory.cc(func_ty="void free(void*)")), replace=True)
    log("Hook symbols successfully", GRE)
    # extra_option = {sim_options.REVERSE_MEMORY_NAME_MAP, sim_options.TRACK_ACTION_HISTORY, sim_options.ZERO_FILL_UNCONSTRAINED_MEMORY}
    # state = project.factory.entry_state(add_options=extra_option)
    simmgr = project.factory.simgr()#save_unconstrained=True)

    project.analyses.CFG()
    malloc_plt, free_plt = project.kb.functions.get("malloc").addr, project.kb.functions.get("free").addr
    log("Malloc_plt : {} ; Free_plt : {}".format(hex(malloc_plt), hex(free_plt)), GRE)

    log("LEVEL 1", GRE)
    simmgr.explore(find=malloc_plt, avoid=free_plt, num_find=1)
    log("LEVEL 2", GRE)
    simmgr.explore(stash="found", find=free_plt, find_stash="malloc_free_stash")
    log("LEVEL 3", GRE)
    simmgr.explore(stash="malloc_free_stash", find=free_plt, find_stash="malloc_free_free_stash")
    log("RUN 1", GRE)
    simmgr.explore(stash="malloc_free_free_stash")
    # log("RUN 2", GRE)
    # simmgr.explore(stash="malloc_free_stash")
    # log("RUN 3", GRE)
    # simmgr.explore(stash="malloc_stash")
    # log("RUN 4", GRE)
    # simmgr.explore(stash="active")




if __name__ == '__main__':
    check("./df")