from ..utils import log, RED, CYA, DRED, RST
from ..prune_algorithms import isSimilarPath
import angr
from angr import sim_options
import logging

logging.getLogger('angr').setLevel('DEBUG')

paths_with_bug = []


'''
class malloc(angr.SimProcedure):
    def run(self, sim_size):
        return self.state.heap._malloc(sim_size)
'''
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
            # and is a new path containning bug          
            if free_addr in self.state.globals["FREE_LIST"] \
               and not isSimilarPath([bbl_addr for bbl_addr in self.state.history.bbl_addrs], paths_with_bug) :
                log("DOUBLE FREE detected! IO dump :", RED)
                print("{}< stdin >{}\n".format(DRED, RST), self.state.posix.dumps(0))
                print("{}< stdout >{}\n".format(DRED, RST), self.state.posix.dumps(1).decode())
                paths_with_bug.append([bbl_addr for bbl_addr in self.state.history.bbl_addrs])
        
        return self.state.heap._free(ptr)


def check(file_name: str) :
    log("Checking DOUBLE FREE", CYA)

    try :
        project = angr.Project(file_name, load_options={'auto_load_libs': False})
    except :
        log("Not a valid binary file: " + file_name + "\n", RED)
        return

    project.analyses.CFG()
    malloc_plt, free_plt = project.kb.functions.get("malloc").addr, project.kb.functions.get("free").addr

    project.hook_symbol('malloc', 
                        MallocHook(cc=project.factory.cc(func_ty="void* malloc(int)")), 
                        replace=True)
    project.hook_symbol('free', 
                        FreeHook(cc=project.factory.cc(func_ty="void free(void*)")), 
                        replace=True)

    extra_option = {sim_options.REVERSE_MEMORY_NAME_MAP, 
                    sim_options.TRACK_ACTION_HISTORY, 
                    sim_options.ZERO_FILL_UNCONSTRAINED_MEMORY,
                    sim_options.ZERO_FILL_UNCONSTRAINED_REGISTERS}
    init_state = project.factory.entry_state(add_options=extra_option)
    simgr = project.factory.simulation_manager(init_state, save_unconstrained=True)

    simgr_m_f = simgr.copy(deep=True)

    simgr_m_f.explore(find=malloc_plt, avoid=free_plt, num_find=1, find_stash="OP_malloc")
    simgr_m = simgr_m_f.copy(deep=True)

    simgr_m_f.explore(stash="OP_malloc", find=free_plt, find_stash="OP_malloc_free")

    # quick scan
    simgr_m_f.run(stash="OP_malloc_free")
    simgr_m.run(stash="OP_malloc")
    # full scan
    while simgr.active :
        simgr.step()

    # TODO: 循环程序的执行深度是无限的，故需要限定符号执行时间或执行深度